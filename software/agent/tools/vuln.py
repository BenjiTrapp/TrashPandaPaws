#!/usr/bin/env python3
"""CVE lookup and exploit check.

The lookup is the one place the agent talks to a third party about a target:
it sends osv.dev and nvd.nist.gov the service and version just found on the
client's network, from the operator's own address, while the engagement is
running. The inputs are therefore narrowed to a plain name and version before
anything leaves the host, and nothing else about the target is sent.

The pipeline, in order:

    1. normalise the inputs, build the cache key from service + version
    2. check cve_cache, TTL 7 days
    3. query OSV.dev (primary, no rate limit)
    4. fill missing CVSS from NVD, at most 5 calls, rate limited
    5. if OSV returned nothing, fall back to an NVD CPE query
    6. write the results to cve_cache
    7. return

No stage raises. An unreachable or misbehaving source is a `warning` on a
result that carries whatever the other stages produced: a campaign must not
end because a public database is down. A failed lookup is not cached, so the
next call tries again.
"""

import asyncio
import json
import re
import time

from software.agent.llm import provider
from software.agent.llm.provider import ToolSpec
from software.agent.store import queries
from software.agent.tools import CORE, Entry

# ── Limits ──

OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_DAYS = 7
NVD_MAX_FILL_CALLS = 5
# NVD allows 5 requests per 30 seconds without an API key, i.e. one every 6.
# No configuration carries a key, so this is the only gap there is.
NVD_MIN_GAP_SECONDS = 6.0
MAX_CVES = 25
_NVD_TIMEOUT_SECONDS = 30
_SEARCHSPLOIT_TIMEOUT_SECONDS = 30
_DESCRIPTION_CLIP = 300
_MAX_REFERENCES = 5
_MAX_EXPLOITS = 10

# A name and a version, nothing else. Both go into a third party's request
# and, for NVD, into a CPE string where `:` and `*` mean something; a
# character outside this set is refused rather than escaped.
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


# ── Severity ──


def severity_for(score):
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


# ── Sources ──
#
# The two functions the tests replace. Blocking, run in a thread by the
# caller. Each raises provider.TransportError with a message built from a
# status code or an exception class alone, never from a URL or a body.


def _osv_query(body):
    return provider.http_post_json(
        OSV_URL, {"Content-Type": "application/json"}, body)


def _nvd_query(params):
    # Imported here, not at module level: the agent package has to import
    # with no HTTP library loaded (test_status_quo pins it).
    import requests

    failure = None
    try:
        # allow_redirects=False for the same reason as the LLM transport.
        resp = requests.get(NVD_URL, params=params,
                            timeout=_NVD_TIMEOUT_SECONDS,
                            allow_redirects=False)
    except requests.RequestException as exc:
        failure = "request failed (%s)" % type(exc).__name__
    if failure is not None:
        raise provider.TransportError(failure)
    if resp.status_code != 200:
        raise provider.TransportError("HTTP %d" % resp.status_code)
    try:
        payload = resp.json()
    except ValueError:
        raise provider.TransportError("response was not JSON") from None
    if not isinstance(payload, dict):
        raise provider.TransportError("response was not a JSON object")
    return payload


# ── NVD rate limit ──
#
# A minimum gap between calls, process-wide: the limit is per address, and
# parallel executors share one. The slot is claimed before the sleep and with
# no await in between, so two lookups cannot both read the same "next free
# time" and fire together. That is also why no asyncio.Lock is used: on
# Python 3.9 one binds to whichever loop is current when it is created.

_clock = time.monotonic
_sleep = asyncio.sleep
_next_nvd_slot = 0.0


async def _nvd(params):
    global _next_nvd_slot
    now = _clock()
    start = max(now, _next_nvd_slot)
    _next_nvd_slot = start + NVD_MIN_GAP_SECONDS
    if start > now:
        await _sleep(start - now)
    return await asyncio.to_thread(_nvd_query, params)


def _why(exc):
    # TransportError messages are built to be shown. Anything else gets its
    # class only: an arbitrary exception's message may hold a URL or a header.
    if isinstance(exc, provider.TransportError):
        return str(exc)
    return type(exc).__name__


# ── Reading the sources ──


def _first_text(*values):
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _urls(references):
    if not isinstance(references, list):
        return []
    return [r["url"] for r in references
            if isinstance(r, dict) and isinstance(r.get("url"), str)]


def _entry(cve_id, description, score, vector, published, references, source):
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        score = None
    return {"cve_id": cve_id,
            "description": (description or "")[:_DESCRIPTION_CLIP],
            "cvss_score": score, "cvss_vector": vector,
            "severity": severity_for(score), "published": published,
            "references": references[:_MAX_REFERENCES], "source": source}


def _from_osv(record):
    """One OSV record as an entry, or None if it has no CVE identity.

    Records with no CVE alias are dropped: this tool answers in CVE ids, and
    check_exploit and the NVD fill both need one. OSV gives a CVSS vector, not
    a base score, which is what the NVD fill is for.
    """
    if not isinstance(record, dict):
        return None
    aliases = record.get("aliases")
    ids = [record.get("id")] + (aliases if isinstance(aliases, list) else [])
    cve_id = next((i.upper() for i in ids
                   if isinstance(i, str) and i.upper().startswith("CVE-")), None)
    if cve_id is None:
        return None
    vector = score = None
    severities = record.get("severity")
    for sev in severities if isinstance(severities, list) else []:
        value = sev.get("score") if isinstance(sev, dict) else None
        if isinstance(value, str) and value.startswith("CVSS:"):
            vector = value
            break
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            score = value
            break
    return _entry(cve_id,
                  _first_text(record.get("summary"), record.get("details")),
                  score, vector, record.get("published"),
                  _urls(record.get("references")), "osv")


def _nvd_metrics(cve):
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                "cvssMetricV2"):
        listed = metrics.get(key)
        if isinstance(listed, list) and listed and isinstance(listed[0], dict):
            data = listed[0].get("cvssData")
            if isinstance(data, dict) and "baseScore" in data:
                return data["baseScore"], data.get("vectorString")
    return None, None


def _from_nvd(item):
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
        return None
    descriptions = cve.get("descriptions")
    description = _first_text(*[
        d.get("value") for d in descriptions
        if isinstance(d, dict) and d.get("lang") == "en"]
    ) if isinstance(descriptions, list) else None
    score, vector = _nvd_metrics(cve)
    return _entry(cve["id"].upper(), description, score, vector,
                  cve.get("published"), _urls(cve.get("references")), "nvd")


def _nvd_items(payload):
    items = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    return items if isinstance(items, list) else []


def _from_row(row):
    try:
        references = json.loads(row["references_json"])
    except (TypeError, ValueError):
        references = []
    return _entry(row["cve_id"], row["description"], row["cvss_score"],
                  row["cvss_vector"], row["published"],
                  [r for r in references if isinstance(r, str)]
                  if isinstance(references, list) else [], row["source"])


# ── The pipeline ──


def _normalise(service, version):
    """(service, version) as plain tokens, or None."""
    if not isinstance(service, str) or not isinstance(version, str):
        return None
    name = re.sub(r"\s+", "_", service.strip().lower())
    ver = version.strip().lower()
    if _TOKEN.fullmatch(name) and _TOKEN.fullmatch(ver):
        return name, ver
    return None


def _answer(cves, warnings, **extra):
    out = {"cves": cves}
    out.update(extra)
    if warnings:
        out["warning"] = "; ".join(warnings)
    return out


async def lookup_cves(conn, service, version):
    try:
        return await _lookup(conn, service, version)
    except Exception as exc:
        # The stages guard themselves; this is for the one nobody thought of.
        return _answer([], ["CVE lookup failed (%s)" % type(exc).__name__])


async def _lookup(conn, service, version):
    warnings = []

    # 1
    forms = _normalise(service, version)
    if forms is None:
        return _answer([], ["service and version must each be a plain name: "
                            "letters, digits, '.', '_' or '-' only"])
    name, ver = forms
    key = "%s@%s" % (name, ver)

    # 2
    try:
        cached = queries.get_cached_cves(conn, key, CACHE_TTL_DAYS)
    except Exception as exc:
        cached = []
        warnings.append("cache unavailable (%s)" % type(exc).__name__)
    if cached:
        return _answer([_from_row(r) for r in cached], [], cached=True,
                       service=name, version=ver)

    # 3
    found = []
    source = "osv"
    try:
        payload = await asyncio.to_thread(_osv_query, {
            "package": {"purl": "pkg:generic/" + name}, "version": ver})
        records = payload.get("vulns") if isinstance(payload, dict) else None
        seen = set()
        for record in records if isinstance(records, list) else []:
            entry = _from_osv(record)
            if entry is not None and entry["cve_id"] not in seen:
                seen.add(entry["cve_id"])
                found.append(entry)
    except Exception as exc:
        warnings.append("osv.dev: %s" % _why(exc))

    # 4
    filled = 0
    for entry in [e for e in found if e["cvss_score"] is None][:NVD_MAX_FILL_CALLS]:
        try:
            items = _nvd_items(await _nvd({"cveId": entry["cve_id"]}))
            scored = _from_nvd(items[0]) if items else None
        except Exception as exc:
            # One failure ends the fill: with the source down, the remaining
            # calls would each wait out the gap to learn the same thing.
            warnings.append("nvd.nist.gov (scores): %s" % _why(exc))
            break
        if scored is not None and scored["cvss_score"] is not None:
            entry.update(cvss_score=scored["cvss_score"],
                         cvss_vector=scored["cvss_vector"] or entry["cvss_vector"],
                         severity=scored["severity"])
            filled += 1
    if filled:
        source = "osv+nvd"

    # 5
    if not found:
        try:
            payload = await _nvd({
                "virtualMatchString":
                    "cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*" % (name, ver),
                "resultsPerPage": 50})
            for item in _nvd_items(payload):
                entry = _from_nvd(item)
                if entry is not None:
                    found.append(entry)
            source = "nvd"
        except Exception as exc:
            warnings.append("nvd.nist.gov (cpe): %s" % _why(exc))

    found.sort(key=lambda e: (e["cvss_score"] is None,
                              -(e["cvss_score"] or 0), e["cve_id"]))
    found = found[:MAX_CVES]

    # 6
    if found:
        try:
            queries.cache_cves(conn, key, source, found)
        except Exception as exc:
            warnings.append("not cached (%s)" % type(exc).__name__)

    # 7
    return _answer(found, warnings, cached=False, service=name, version=ver)


# ── searchsploit ──

_CVE_ID = re.compile(r"(?:CVE-)?(\d{4}-\d{4,})", re.IGNORECASE)


async def _run_searchsploit(cve):
    """(exit code, stdout). Raises FileNotFoundError if the binary is absent."""
    proc = await asyncio.create_subprocess_exec(
        "searchsploit", "--json", "--cve", cve,
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL)
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(),
                                           _SEARCHSPLOIT_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode, stdout.decode("utf-8", errors="replace")


async def exploit_check(cve_id):
    match = _CVE_ID.fullmatch(cve_id.strip()) if isinstance(cve_id, str) else None
    if match is None:
        # Nothing malformed reaches the command line: a value starting with
        # '-' would be read as one of searchsploit's own options.
        return {"error": "cve_id must look like CVE-2021-44228"}
    arg = match.group(1)
    out = {"cve_id": "CVE-" + arg, "has_exploit": False, "exploits": []}
    try:
        code, stdout = await _run_searchsploit(arg)
    except FileNotFoundError:
        out["warning"] = ("searchsploit is not installed on the host running "
                          "the agent, so exploit availability is unknown")
        return out
    except Exception as exc:
        out["warning"] = "searchsploit could not be run (%s)" % type(exc).__name__
        return out
    # Parsed whatever the exit status: searchsploit returns usable output
    # with a non-zero one, and trusting the code alone discards it.
    try:
        results = json.loads(stdout).get("RESULTS_EXPLOIT")
        if not isinstance(results, list):
            raise ValueError("no result list")
    except (ValueError, AttributeError):
        out["warning"] = ("searchsploit gave no readable output (exit status "
                          "%s)" % code)
        return out
    out["exploits"] = [
        {"title": r.get("Title"), "edb_id": r.get("EDB-ID"),
         "type": r.get("Type"), "platform": r.get("Platform")}
        for r in results[:_MAX_EXPLOITS] if isinstance(r, dict)]
    out["has_exploit"] = bool(out["exploits"])
    return out


# ── Tool declarations ──


def _lookup_cve(ctx):
    async def lookup_cve(service, version):
        return await lookup_cves(ctx.conn, service, version)
    return lookup_cve


def _check_exploit(ctx):
    async def check_exploit(cve_id):
        return await exploit_check(cve_id)
    return check_exploit


def entries():
    return [
        Entry(
            ToolSpec(
                "check_exploit",
                "Check whether a public exploit exists for a CVE, using the "
                "local exploit database. This does not touch the network.",
                {"type": "object",
                 "properties": {
                     "cve_id": {"type": "string",
                                "description": "the CVE, such as "
                                               "CVE-2021-44228"}},
                 "required": ["cve_id"]}),
            ("executor",), CORE, _check_exploit),
        Entry(
            ToolSpec(
                "lookup_cve",
                "Look up known CVEs for a service and version you have "
                "identified. This sends that service name and version to "
                "public CVE databases, so use it for what you found, not for "
                "guesses. Results are cached for a week.",
                {"type": "object",
                 "properties": {
                     "service": {"type": "string",
                                 "description": "the product name, such as "
                                                "openssh"},
                     "version": {"type": "string",
                                 "description": "the version, such as 8.2"}},
                 "required": ["service", "version"]}),
            ("executor",), CORE, _lookup_cve),
    ]
