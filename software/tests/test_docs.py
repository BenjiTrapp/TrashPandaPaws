#!/usr/bin/env python3
"""The documentation's factual tables, checked against the code.

docs/AGENT.md states numbers: capability tiers, risk profile values, the
forced scan flags, the eight actions that are never permitted, the eleven
that are gated. Those are the parts a reader will rely on and the parts
that go stale silently -- a renamed action or a changed default leaves prose
that is confidently wrong, which is worse than prose that is vague.

So this does for the documentation what test_c2_agent_gui does for the GUI's
JavaScript tables: compares them to the source of truth, and fails when they
drift. It asserts that every key and every number is *present*, not that the
surrounding sentences are unchanged -- the prose is free, the facts are not.
"""

import argparse
import asyncio
import inspect
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from software.agent import config, orchestrator, prompts
from software.agent.llm import failover, mock
from software.agent.store import db, queries  # noqa: E402
from software.agent import safety  # noqa: E402
from software.agent.executor import server_tool  # noqa: E402
from software.agent.llm import provider  # noqa: E402
from software.c2 import server as c2_server  # noqa: E402
from software.c2.sliver import SliverManager  # noqa: E402

AGENT_DOC = REPO / "docs" / "AGENT.md"
DEMO_DOC = REPO / "docs" / "C2_DEMO.md"
REDIRECTOR_DOC = REPO / "docs" / "REDIRECTOR.md"
README = REPO / "README.md"


def _rows_under(text, heading):
    """Markdown table rows in the section introduced by `heading`."""
    body = text.split(heading, 1)
    if len(body) < 2:
        raise AssertionError("no section %r" % heading)
    out = []
    for line in body[1].splitlines():
        # Any heading ends the section, not only a level-two one: a "###"
        # below it would otherwise pull the next table's rows in.
        if line.startswith("#") and out:
            break
        if line.startswith("|") and not set(line) <= set("|- :"):
            out.append(line)
    return out


class _DocCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = AGENT_DOC.read_text()

    def present(self, needle, what):
        """assertIn without printing the haystack, and across line wraps.

        Prose wraps, so a phrase that reads as one sentence is two lines in
        the file. Comparing against a whitespace-normalised copy keeps the
        test about the sentence rather than about the column it broke at.
        """
        # Case-insensitive as well: the same sentence is capitalised at the
        # start of a line and lowercase mid-sentence, and the test is about
        # the claim, not about where it happened to land.
        flat = " ".join(self.doc.split()).lower()
        self.assertTrue(" ".join(needle.split()).lower() in flat,
                        "%s: %r is not in AGENT.md" % (what, needle))

    def states_number(self, text, what):
        """Like present(), but a number must stand on its own.

        `present("2 minutes")` passed against "22 minutes of probing"
        further down the page -- an accidental substring match, so the
        cooldown figure was never actually checked. Numbers get word
        boundaries.
        """
        flat = " ".join(self.doc.split())
        self.assertRegex(flat, r"(?<![\d.])" + re.escape(text),
                         "%s: %r is not stated in AGENT.md" % (what, text))

    def absent(self, needle, what):
        self.assertTrue(needle not in self.doc, "%s: %r should not be in "
                        "AGENT.md" % (what, needle))


class TestTheCapabilityTiersAreStatedCorrectly(_DocCase):
    def test_every_tier_is_named(self):
        for tier in provider.TIER_LIMITS:
            self.present("`%s`" % tier, "capability tier")

    def test_each_tiers_turn_limits_appear_in_its_row(self):
        for tier, limits in provider.TIER_LIMITS.items():
            row = self._row_for(tier)
            for field in ("orchestrator_turns", "executor_turns",
                          "truncate_chars", "max_phase"):
                self.assertIn(str(limits[field]), row,
                              "%s: %s" % (tier, field))

    def _row_for(self, tier):
        for line in self.doc.splitlines():
            if line.startswith("|") and ("`%s`" % tier) in line:
                return line
        self.fail("no table row for tier %r" % tier)


class TestThePhasesAreStatedCorrectly(_DocCase):
    def test_every_phase_name_appears(self):
        for number, name in prompts.PHASE_NAMES.items():
            self.present(name, "phase %d" % number)

    def test_the_phase_table_uses_no_invented_name(self):
        # The GUI once called phase 3 "Credential access" and phase 4
        # "Lateral movement". Neither is a phase of this agent. The prose
        # may mention them -- the page explains that mistake on purpose --
        # but the table must not, which is why this reads the table.
        table = "\n".join(_rows_under(self.doc, "## Phases"))
        for ghost in ("Credential access", "Lateral movement"):
            self.assertNotIn(ghost, table, ghost)


class TestTheRiskProfilesAreStatedCorrectly(_DocCase):
    def test_every_profile_and_every_number_appears(self):
        rows = _rows_under(self.doc, "## Risk profiles")
        for name, values in config.RISK_PROFILES.items():
            row = next((r for r in rows
                        if r.split("|")[1].strip().strip("`") == name), None)
            self.assertIsNotNone(row, "no row for risk profile %r" % name)
            for field, value in values.items():
                # Written for a reader: 20.0 appears as "+20", -5.0 as a
                # minus sign, 0.25 as "0.25". Compare on the number.
                shown = ("%g" % value)
                candidates = {shown, "+" + shown, shown.replace("-", "\u2212")}
                self.assertTrue(any(c in row for c in candidates),
                                "%s/%s: %s not in its row" % (name, field, shown))


class TestTheOpsecProfilesAreStatedCorrectly(_DocCase):
    def test_every_profile_is_named(self):
        for name in config.OPSEC_PROFILES:
            self.present("`%s`" % name, "opsec profile")

    def test_the_yolo_promise_is_written_down(self):
        # The one sentence in this file that is load-bearing: the name
        # invites "safety off", and nine tests exist to refuse that reading.
        self.present("lifts the scan rate limits and nothing else",
                     "what yolo does")
        self.present("tier-1 actions stay blocked", "what yolo does not")


class TestTheGateListsMatchTheRiskTable(_DocCase):
    def _keys(self, tier):
        return {k for k, row in safety.RISK_TABLE.items() if row.tier == tier}

    def test_every_never_permitted_action_is_listed(self):
        for key in self._keys(safety.TIER_HARD):
            self.present("`%s`" % key, "tier-1 action")

    def test_every_gated_action_is_listed(self):
        for key in self._keys(safety.TIER_KNOCK):
            self.present("`%s`" % key, "gated action")

    def test_the_tier_one_table_has_exactly_the_tier_one_rows(self):
        # Counting the table, not parsing the prose: the sentence may be
        # rewritten, the table may not gain or lose a row silently.
        rows = _rows_under(self.doc, "### Never permitted, in any mode")
        # rows[0] is the header; the separator line is already filtered out.
        keys = {r.split("|")[1].strip().strip("`") for r in rows[1:]}
        self.assertEqual(keys, self._keys(safety.TIER_HARD))

    def test_a_tier_one_action_is_never_described_as_approvable(self):
        # The distinction the whole page rests on.
        self.present("cannot be approved", "the tier-1 promise")


class TestTheScanLimitsAreStatedCorrectly(_DocCase):
    def test_the_forced_flags_are_read_back_from_the_limiter(self):
        for program in ("nmap", "masscan", "netdiscover"):
            tokens = safety.enforce_scan_limits(
                "%s 192.0.2.1" % program).split()
            self.present(" ".join(tokens[1:-1]), "forced flags for " + program)

    def test_the_port_cap_and_the_nmap_timeout_are_the_real_numbers(self):
        self.present(str(safety.SCAN_TOP_PORTS), "the port cap")
        self.present(str(server_tool._TOOL_TIMEOUTS["nmap"]), "nmap's timeout")


class TestTheProvidersAreStatedCorrectly(_DocCase):
    def test_every_provider_the_code_accepts_is_documented(self):
        for name in provider._PROVIDERS:
            self.present("`%s`" % name, "provider")

    def test_the_shipped_config_lists_them_too(self):
        text = (REPO / "configs" / "raccoon.yaml").read_text()
        for name in provider._PROVIDERS:
            self.assertIn(name, text, name)


class TestTheUnattendedDefaultsAreStatedCorrectly(_DocCase):
    def test_every_behaviour_is_described(self):
        for name in config._UNATTENDED:
            self.present("`%s`" % name, "unattended behaviour")

    def test_the_asymmetric_default_is_explained(self):
        # Two defaults for one field is surprising, so the page has to say
        # which is which rather than leave a reader to find out.
        self.present("supervised \u2192 `pause`", "the supervised default")
        self.present("Full Automated \u2192\n`decide`",
                     "the Full Automated default")


class TestTheBudgetDefaultsAreStatedCorrectly(_DocCase):
    def test_the_numbers_match_the_form(self):
        form = config.CampaignConfig.from_form(
            {"beacons": ["b"], "scope_allow": ["10.0.0.0/24"],
             "mode": "auto"}, tier="full")
        for value in (form.max_runtime_seconds, form.max_tokens_total,
                      form.campaign_interval, form.restore_interval):
            number = int(value)
            # 500000 is written 500 000 for a reader.
            spaced = "{:,}".format(number).replace(",", " ")
            self.assertTrue(str(number) in self.doc or spaced in self.doc,
                            number)

    def test_the_approval_timeout_default_is_stated(self):
        self.present(str(int(config.AgentConfig().approval_timeout)),
                     "the approval timeout default")


class TestTheFiguresExist(unittest.TestCase):
    """A broken image is a broken promise in a document about evidence."""

    def _links(self, text):
        return re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text)

    def test_every_figure_in_the_agent_page_resolves(self):
        for link in self._links(AGENT_DOC.read_text()):
            self.assertTrue((AGENT_DOC.parent / link).exists(), link)

    def test_every_figure_in_the_demo_page_resolves(self):
        for link in self._links(DEMO_DOC.read_text()):
            self.assertTrue((DEMO_DOC.parent / link).exists(), link)

    def test_every_figure_in_the_readme_resolves(self):
        # The front page, where a broken image is seen first. It uses HTML
        # <img> tags as well as markdown links.
        import re as _re
        text = README.read_text()
        links = self._links(text) + _re.findall(r'<img src="([^"]+)"', text)
        for link in links:
            if link.startswith(("http://", "https://")):
                continue
            self.assertTrue((README.parent / link).exists(), link)

    def test_the_agent_page_shows_at_least_the_knock_card(self):
        # The one figure the design's own mockup is about.
        links = self._links(AGENT_DOC.read_text())
        self.assertTrue(any("knock" in link for link in links), links)


class TestTheDocumentationIsReachable(unittest.TestCase):
    def test_the_readme_points_at_the_agent_page(self):
        self.assertTrue("docs/AGENT.md" in README.read_text(),
                        "README.md does not link docs/AGENT.md")

    def test_the_demo_page_points_at_the_agent_page(self):
        self.assertTrue("AGENT.md" in DEMO_DOC.read_text(),
                        "C2_DEMO.md does not link AGENT.md")

    def test_the_agent_page_points_back_at_the_demo(self):
        self.assertTrue("C2_DEMO.md" in AGENT_DOC.read_text(),
                        "AGENT.md does not link C2_DEMO.md")


class TestTheStatusQuoPromiseIsStated(_DocCase):
    def test_the_page_says_the_c2_runs_without_a_model(self):
        # The promise an evaluator checks first, and the one the whole
        # separate-service architecture exists to keep.
        self.present("run exactly as they do today", "the status-quo promise")
        self.present("test_status_quo.py", "where to verify it")



class TestTheProofBasesAreStatedCorrectly(_DocCase):
    """Three values and no free text -- so all three have to be documented,
    and the documentation must not invent a fourth."""

    def test_every_basis_the_code_accepts_is_documented(self):
        for basis in queries.PROOF_BASES:
            self.present(basis, "proof basis")

    def _table(self):
        """The proof-basis table's rows, by its header."""
        after = self.doc.split("| `proof_basis` | means |", 1)
        self.assertEqual(len(after), 2, "the proof-basis table is gone")
        rows = []
        # lstrip: the text after the header starts with the newline that
        # ended it, so the first splitlines() element is empty and the
        # loop used to break before reading a single row.
        for line in after[1].lstrip("\n").splitlines():
            if not line.startswith("|"):
                break
            rows.append(line)
        return [r for r in rows if "---" not in r]

    def test_the_table_lists_exactly_the_three(self):
        # Scoped to the table, not the page: "inferred" also appears in the
        # report example further down, so a table row renamed to `guessed`
        # was invisible to a page-wide search for each known value.
        listed = []
        for row in self._table():
            found = re.findall(r"`([a-z-]+)`", row)
            listed.extend(found)
        self.assertEqual(sorted(listed), sorted(queries.PROOF_BASES),
                         "the table lists %s; the code accepts %s"
                         % (sorted(listed), sorted(queries.PROOF_BASES)))


class TestTheFallbackFieldsAreStatedCorrectly(_DocCase):
    """A config example that names a field the parser refuses is worse than
    no example: it is followed, and then the agent will not start."""

    def test_every_field_an_entry_takes_is_documented(self):
        for field in config._FALLBACK_FIELDS:
            self.present(field, "fallback field")

    def test_the_example_uses_no_field_the_parser_refuses(self):
        block = self.doc.split("fallbacks:", 1)[1].split("```", 1)[0]
        for key in re.findall(r"^\s*[-\s]*([a-z_]+):", block, re.M):
            self.assertIn(key, config._FALLBACK_FIELDS,
                          "the example sets %r, which an entry does not take"
                          % key)

    def test_the_literal_key_refusal_is_written_down(self):
        # The one thing someone will try, and the reason it is refused.
        self.present("api_key", "the refused literal")
        self.present("under git", "why a literal key is refused")

    def test_the_trip_and_cooldown_are_the_real_numbers(self):
        self.states_number("%d minutes"
                           % round(failover.DEFAULT_COOLDOWN / 60), "cooldown")
        self.present("twice in a row", "the trip threshold in words")
        self.assertEqual(failover.DEFAULT_TRIP_AFTER, 2,
                         "AGENT.md says 'twice in a row'; the code no longer "
                         "agrees")


class TestTheDeadlineThresholdsAreStatedCorrectly(_DocCase):
    def test_the_numbers_match_the_prompt(self):
        self.states_number(
            "%d minutes" % round(prompts._NEARLY_SPENT_SECONDS / 60),
            "the nearly-spent runtime")
        self.states_number("%d tokens" % prompts._NEARLY_SPENT_TOKENS,
                           "the nearly-spent token figure")


class TestTheReadmeCountsTheDemoSections(unittest.TestCase):
    """The README advertised "22 sections" while the tour had 23.

    A number written once and never derived goes stale on the next
    addition, and this one is the first thing an evaluator reads.
    """

    def test_the_count_matches_the_tour(self):
        root = Path(__file__).resolve().parents[2]
        demo = (root / "docs" / "C2_DEMO.md").read_text()
        readme = (root / "README.md").read_text()
        sections = len(re.findall(r"^## \d+\. ", demo, re.M))
        found = re.search(r"\u2014 (\d+) sections covering", readme)
        self.assertIsNotNone(found, "the README no longer states a count")
        self.assertEqual(int(found.group(1)), sections)

    def test_the_badge_counts_the_figures(self):
        # Three numbers in the README now derive from the repository:
        # the section count, and the stills and GIFs in the badge. Each
        # one written by hand is one that goes stale on the next addition.
        root = Path(__file__).resolve().parents[2]
        shots = root / "docs" / "screenshots"
        readme = (root / "README.md").read_text()
        found = re.search(r"C2%20Demo-(\d+)%20stills%20%2B%20(\d+)%20GIFs",
                          readme)
        self.assertIsNotNone(found, "the README no longer counts the figures")
        self.assertEqual(int(found.group(1)),
                         len(list(shots.glob("*.png"))), "stills")
        self.assertEqual(int(found.group(2)),
                         len(list(shots.glob("*.gif"))), "GIFs")

    def test_the_tour_numbers_its_sections_consecutively(self):
        # A gap or a repeat means the table of contents and the headings
        # have drifted apart.
        root = Path(__file__).resolve().parents[2]
        demo = (root / "docs" / "C2_DEMO.md").read_text()
        numbers = [int(n) for n in re.findall(r"^## (\d+)\. ", demo, re.M)]
        self.assertEqual(numbers, list(range(1, len(numbers) + 1)))


class TestTheDocsSayHowToSignIn(unittest.TestCase):
    """The page no longer carries the operator token; it asks for it.

    A reader who opens the GUI meets a prompt, so the two pages that tell
    them how to open it say what to enter and where it is kept -- and
    neither may suggest the rejected alternative, a token in the URL.
    """

    def test_both_pages_say_where_the_token_is_kept(self):
        for doc in (README, DEMO_DOC):
            text = doc.read_text()
            self.assertIn("sessionStorage", text, doc.name)
            self.assertIn("`Token:`", text, doc.name)

    def test_no_page_puts_the_token_in_a_url(self):
        for doc in (README, DEMO_DOC, AGENT_DOC):
            text = doc.read_text()
            for needle in ("?t=", "&t=", "token="):
                self.assertNotIn(needle, text, "%s in %s" % (needle, doc.name))


# ── Known limits: the findings the hardening pass left open ──
#
# Each entry is a phrase the section must carry, in the group it belongs to,
# and -- where the code can say -- a function that is True for as long as the
# finding is still open. When someone fixes one, its predicate turns False and
# the test fails until the entry is deleted from the section and from here: the
# section cannot go on calling a fixed thing open. When someone deletes an
# entry from the section, the phrase goes missing. When someone adds a bullet
# without adding it here, the count is off.
#
# The predicates are deliberately narrow. The first draft of the rate-limiting
# one matched "X-RateLimit" header values in a C2 profile example and reported
# a limiter that does not exist, so the ones that can be behavioural are:
# they send the request and look at what comes back.

_C2 = REPO / "software" / "c2"
_BEACON_KEY = bytes(range(32))
_BEACON_TOKEN = "known-limits-probe-token"


def _read(*parts):
    return REPO.joinpath(*parts).read_text()


def _config():
    return yaml.safe_load(_read("configs", "raccoon.yaml"))


class _ProbeServer:
    """A throwaway C2 on the Flask test client, with the globals put back."""

    def __enter__(self):
        self.data_dir = Path(tempfile.mkdtemp())
        self.crypto = c2_server.ServerCrypto(_BEACON_KEY)
        self.app = c2_server.create_app(self.crypto, _BEACON_TOKEN,
                                        self.data_dir)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.auth = {"Authorization": "Bearer " + _BEACON_TOKEN}
        self._clear()
        return self

    def __exit__(self, *exc):
        self._clear()

    def _clear(self):
        for store in (c2_server.agents, c2_server.task_queues,
                      c2_server.history, c2_server.results):
            store.clear()
        c2_server._name_counter = 0

    def post(self, payload):
        reply = self.client.post("/b", data=json.dumps(
            self.crypto.wrap(payload)), content_type="application/json")
        return self.crypto.unwrap(reply.get_json())


def _beacon_cannot_verify_tls():
    text = _read("software", "c2", "beacon.py")
    mentions = re.findall(r"^.*\bverify_ssl\b.*$", text, re.M)
    return (len(mentions) == 1 and "self.verify_ssl = " in mentions[0]
            and "ssl_ctx.verify_mode = ssl.CERT_NONE" in text)


def _a_replayed_result_is_applied_again():
    with _ProbeServer() as srv:
        registered = srv.post({"action": "register", "id": "probe",
                               "hostname": "h", "os": "L", "arch": "x",
                               "user": "u", "pid": 1, "interval": 5})
        captured = {"action": "result", "agent_id": registered["agent_id"],
                    "task_id": "t1", "status": "ok", "output": "first"}
        srv.post(captured)
        c2_server.results["t1"]["output"] = "tampered"
        srv.post(captured)
        return c2_server.results["t1"]["output"] == "first"


def _the_staged_download_is_unchecked():
    sliver = _config()["c2"]["sliver"]
    source = inspect.getsource(SliverManager._stage_implant)
    return (sliver["staging_url"] == "" and sliver["sha256"] == ""
            and "verify=False" in source and "if self.expected_hash:" in source)


def _rdp_hands_request_text_to_a_shell():
    text = _read("software", "c2", "server.py")
    return ("cmd_str, shell=True" in text
            and "echo '{password}' | vncpasswd -f" in text)


def _the_loot_download_reaches_the_data_directory():
    with _ProbeServer() as srv:
        (srv.data_dir / "loot").mkdir()
        (srv.data_dir / "key.pem").write_text("outside-loot")
        reply = srv.client.get("/api/loot/%2e%2e/key.pem", headers=srv.auth)
        return reply.status_code == 200 and reply.data == b"outside-loot"


def _the_server_image_is_root_with_net_admin():
    image = _read("software", "c2", "Dockerfile")
    compose = _read("software", "c2", "docker-compose.yml")
    return (not re.search(r"^\s*USER\s", image, re.M)
            and "NET_ADMIN" in compose and "/tmp/.X11-unix" in compose)


def _file_browser_names_reach_onclick_strings():
    text = _read("software", "c2", "server.py")
    return bool(re.search(
        r"""onclick="[^"\n]*\\'\s*'\s*\+\s*esc\(full""", text))


def _nothing_is_pinned():
    reqs = [_read("software", "requirements.txt"),
            _read("software", "agent", "requirements.txt"),
            _read("tools", "requirements.txt"),
            _read("software", "tests", "requirements.txt")]
    image = _read("software", "c2", "Dockerfile")
    pip_block = image.split("RUN pip install", 1)[1].split("\n\n", 1)[0]
    # The third clause used to be `re.search(r"NetExec\s*$", image, re.M)`:
    # the NetExec line happening to end the line was read as "its git ref
    # carries no tag". Adding a `\` continuation to that line defeated the
    # probe without changing a thing about pinning, and the suite reported
    # this finding as fixed. So ask the question the finding actually
    # asks -- are the three source builds pulling a moving ref? -- which a
    # reformat cannot answer differently.
    sources = re.findall(r"(?:git\+https://|https://)github\.com/\S+", image)
    moving = [url for url in sources
              if "@" not in url.split("github.com/", 1)[1]]
    return (not any("==" in line for text in reqs
                    for line in text.splitlines()
                    if not line.lstrip().startswith("#"))
            and not re.search(r"[<>=]", pip_block)
            and len(moving) >= 3)


def _the_old_dependencies_are_still_declared():
    return ("netifaces" in _read("software", "requirements.txt")
            and "ldap3" in _read("software", "c2", "Dockerfile"))


def _there_is_no_size_cap_and_no_rate_limit():
    with _ProbeServer() as srv:
        wrong = {"Authorization": "Bearer not-the-token"}
        codes = {srv.client.get("/api/loot", headers=wrong).status_code
                 for _ in range(60)}
        right = srv.client.get("/api/loot", headers=srv.auth).status_code
        return (srv.app.config.get("MAX_CONTENT_LENGTH") is None
                and codes == {401} and right == 200)


def _the_shipped_config_carries_a_vnc_password():
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "vnc_password":
                    yield value
                yield from walk(value)
    return "raccoon" in list(walk(_config()))


def _the_token_is_compared_with_plain_equality():
    text = _read("software", "c2", "server.py")
    # Only the operator token's own comparison counts. This used to also
    # require that `compare_digest` appeared nowhere in the file, which
    # read as a shortcut for "nothing here compares tokens properly yet".
    # The listener tasking route then added a second, correct comparison,
    # and the shortcut made this probe report the finding fixed while
    # line 350 still held an `==`. A probe that names one comparison has
    # to look at that comparison.
    return "return auth[7:] == operator_token" in text


def _project_files_are_world_readable():
    sources = [REPO / "software" / "main.py", REPO / "software" / "watchdog.py"]
    for sub in ("c2", "agent"):
        # A virtualenv inside the tree is not the project's code, and pip's
        # own os.umask call in one once made this report the file modes fixed.
        sources.extend(p for p in (REPO / "software" / sub).rglob("*.py")
                       if not {".venv", "site-packages"} & set(p.parts))
    no_umask = not any("os.umask" in p.read_text() for p in sources)
    before = os.umask(0o022)
    try:
        with _ProbeServer() as srv:
            c2_server._save_state(srv.data_dir)
            mode = (srv.data_dir / "state.json").stat().st_mode & 0o777
    finally:
        os.umask(before)
    return no_umask and mode == 0o644


def _there_is_no_licence_file():
    return not any(p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING"))
                   for p in REPO.iterdir() if p.is_file())


class _StubLink(provider.LlmClient):
    """A chain link that fails, or keeps calling a tool, under a given name."""

    def __init__(self, provider_name, model, fails):
        self.provider = provider_name
        self.model = model
        self._fails = fails

    async def complete(self, system, messages, tools, max_tokens, temperature):
        if self._fails:
            raise provider.ProviderError("down")
        return mock.calls(("set_phase", {"phase": 1}))


class _StubC2:
    """Just enough of the C2 for a campaign to start, run and wind up."""

    async def get_agent(self, agent_id):
        return {"id": agent_id, "status": "online", "caps": []}

    async def set_beacon_interval(self, agent_id, seconds, jitter):
        return None


def _a_failover_keeps_the_primarys_tier():
    # Behavioural, at the point of use: a campaign is run over a chain whose
    # primary is down and which has already failed over to a `local` link
    # (never above `reduced`), and the model never stops calling tools. The
    # report says how many orchestrator turns it was allowed, which is the
    # limit the run actually held. Open while that is the primary's figure
    # and the answering link's own tier would have allowed fewer.
    #
    # The tier the run is given comes from config.load, from a YAML naming
    # the same chain, and not from an AgentConfig built by hand: a fix that
    # derives the tier at load from the weakest link would otherwise leave
    # this green and the entry stale. So both places a fix could land, the
    # load and the run, are watched.
    async def turns_allowed():
        chain = failover.FailoverClient([
            _StubLink("anthropic", "claude-sonnet-4-5", fails=True),
            _StubLink("local", "small-local-model", fails=False)])
        # Failed over before the campaign is built, so a fix that reads the
        # answering link when the campaign starts sees the small one too.
        await chain.complete("", [], [], 16, 0.0)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "raccoon.yaml")
            with open(path, "w") as handle:
                yaml.safe_dump({"agent": {"llm": {
                    "provider": "anthropic", "model": "claude-sonnet-4-5",
                    "fallbacks": [{"provider": "local",
                                   "model": "small-local-model",
                                   "base_url": "http://127.0.0.1:1/v1"}],
                }}}, handle)
            agent_cfg = config.load(argv=[], yaml_path=path,
                                    env={"AGENT_API_KEY": "sk-fake-tier"})
        campaign_cfg = config.CampaignConfig.from_form(
            {"beacons": ["b1"], "scope_allow": ["10.0.1.0/24"],
             "mode": "auto"}, tier=agent_cfg.capability_tier)
        conn = db.open_store(":memory:")
        try:
            campaign = orchestrator.Campaign(
                agent_cfg, campaign_cfg, conn, _StubC2(), chain)
            await campaign.start()
            report = await campaign.wait()
        finally:
            conn.close()
        found = re.search(r"MAX_TURNS reached after (\d+) turns", report)
        answering = provider.capability_tier(chain.model, chain.provider)
        return (int(found.group(1)) if found else None,
                provider.TIER_LIMITS["full"]["orchestrator_turns"],
                provider.TIER_LIMITS[answering]["orchestrator_turns"])

    allowed, primarys, answerings = asyncio.run(turns_allowed())
    return allowed == primarys and answerings < primarys


# group -> [(phrase the entry must contain, True-while-open or None)].
# None means nothing in the working tree can show it: the six commits are on
# a GitHub reference, and the deferred minors are properties of tests, of
# prose and of a GUI that this file cannot run. Those are checked for being
# present, in the right group and counted, and no more than that.
def _the_sleep_floor_overrides_a_short_interval():
    # Two halves, and the second is what makes it a defect rather than a
    # policy: the beacon floors its sleep at 10 s, and still reports the
    # configured interval to the server, which sizes its freshness windows
    # from that number.
    # Behavioural rather than a search for a literal. The old version
    # looked for `time.sleep(max(10, delay))`, which would have reported
    # the finding closed the moment that number was given a name -- and
    # the name was the smallest part of the fix. What matters is whether a
    # beacon can report an interval it will not honour.
    import base64
    import os

    from software.c2.beacon import Beacon

    beacon = Beacon({"c2": {
        "beacon_interval_seconds": 2,
        "jitter_percent": 0,
        "encryption_key": base64.b64encode(os.urandom(32)).decode(),
        "proxy": {"mode": "none"},
        "https": {"enabled": False},
        "dns": {"enabled": False, "domain": "", "resolver": "1.1.1.1"},
    }})
    slept = []
    with patch("software.c2.beacon.time.sleep", slept.append):
        beacon._jittered_sleep()
    reported = beacon._system_info()["interval"]
    return bool(slept) and abs(slept[0] - reported) > 0.01


def _the_quic_client_trusts_any_sender():
    """The beacon reassembles datagrams without checking where they came from.

    `_quic_send` reads answers with `recvfrom` and ignores the returned
    address, so anything that can reach the beacon's source port can
    inject fragments into a reassembly in progress. The listener cannot
    compensate: the client is the one that trusts.
    """
    text = _read("software", "c2", "beacon.py")
    start = text.find("def _quic_send")
    if start < 0:
        return False
    body = text[start:start + 4000]
    uses_recvfrom = "recvfrom(" in body
    # A fix would compare the address it got against the one it sent to.
    compares = "addr ==" in body or "address ==" in body or "src ==" in body
    return uses_recvfrom and not compares


def _a_task_delivered_over_dns_stays_pending():
    """`/api/tasks/<id>` answers from `results` alone.

    A task that went out over DNS never produces a result, so it reports
    `pending` for ever -- the same answer as a task still sitting in the
    queue. Nothing distinguishes "not delivered yet" from "delivered, and
    you will never hear about it".
    """
    text = _read("software", "c2", "server.py")
    start = text.find("def api_task_result")
    if start < 0:
        return False
    body = text[start:start + 400]
    return 'return jsonify({"status": "pending"})' in body \
        and "dispatched" not in body


def _a_beacons_implant_id_is_one_per_host():
    """`_generate_id` hashes the hostname and architecture, not the implant.

    So two implants on one host are one agent to the server, sharing one
    task queue -- and since tasking is dequeued, whichever polls first
    takes the task. The id is also computable by anyone who knows the
    hostname, on any host without `/sys/class/net/eth0/address`.
    """
    text = _read("software", "c2", "beacon.py")
    start = text.find("def _generate_id")
    if start < 0:
        return False
    body = text[start:start + 500]
    return "platform.node()" in body and "platform.machine()" in body


_OPEN_FINDINGS = {
    "Would stop a deployment": [
        ("cannot verify TLS at all", _beacon_cannot_verify_tls),
        ("No replay protection", _a_replayed_result_is_applied_again),
        ("staged-implant download", _the_staged_download_is_unchecked),
        ("`shell=True`", _rdp_hands_request_text_to_a_shell),
        ("loot download escapes its directory",
         _the_loot_download_reaches_the_data_directory),
        ("server image runs as root", _the_server_image_is_root_with_net_admin),
    ],
    "Would stop a release": [
        ("handler-body injections", _file_browser_names_reach_onclick_strings),
        ("Nothing is pinned", _nothing_is_pinned),
        ("Two dependencies", _the_old_dependencies_are_still_declared),
        ("No request-size cap and no rate limiting",
         _there_is_no_size_cap_and_no_rate_limit),
        ("`vnc_password`", _the_shipped_config_carries_a_vnc_password),
        ("QUIC client accepts fragments from any sender",
         _the_quic_client_trusts_any_sender),
        ("stays `pending` for ever", _a_task_delivered_over_dns_stays_pending),
        ("implant id is one per host", _a_beacons_implant_id_is_one_per_host),
    ],
    "Housekeeping, but visible": [
        ("compared with `==`", _the_token_is_compared_with_plain_equality),
        ("land at `0644`", _project_files_are_world_readable),
        ("no `LICENSE` file", _there_is_no_licence_file),
        ("Six commits", None),
    ],
    "Found while hardening, not by the audit": [
        ("A correction to the audit's severity", None),
    ],
    "Minor, deferred": [
        ("`_handle_result` still does bookkeeping", None),
        ("unit-file test", None),
        ("operator listener runs unsupervised", None),
        ("PowerShell launchers are unverified", None),
        ("no-echo test helper", None),
        ("unhashable `agent_id`", None),
        ("`OSError`", None),
        ("do not normalise `..`", None),
        ("line continuation", None),
        ("`beacon.decode_key`'s docstring", None),
        ("`except ImportError`", None),
        ("loopback-equivalent", None),
        ("Settings panel", None),
        ("`aiCall()`", None),
        ("`tokenRejected`", None),
        ("route-walk test", None),
        ("scanner flags an `echo`", None),
        ("single-dash", None),
    ],
}

# Nineteen findings were deferred; two say nearly the same thing and are one
# entry, so eighteen entries stand for nineteen. The section says both.
_DEFERRED_FINDINGS = 19
_DEFERRED_MERGED = 1


class TestTheListenersGuide(_DocCase):
    """What `docs/LISTENERS.md` has to say, and what the README may not.

    The drift this project actually suffered was a renamed flag left
    standing in a document, so the config keys are read out of the
    registry rather than written here as literals: a key that is renamed
    in code and not in the guide fails this.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.guide = _read("docs", "LISTENERS.md")
        cls.readme = _read("README.md")

    def test_the_guide_exists_and_the_readme_links_it(self):
        self.assertIn("docs/LISTENERS.md", self.readme,
                      "the README does not link the guide")
        self.assertGreater(len(self.guide), 2000,
                           "the guide is a stub")

    def test_the_guide_names_the_real_transports(self):
        from software.c2.listeners.registry import transport_names

        for transport in transport_names():
            self.assertIn(transport, self.guide,
                          "the guide does not mention %s" % transport)

    def test_the_guide_names_the_real_config_keys(self):
        # Read from the code, not written here. A field renamed in
        # `ListenerSpec` and not in the guide is exactly the drift this
        # test exists for.
        import dataclasses

        from software.c2.listeners.registry import ListenerSpec

        for field in dataclasses.fields(ListenerSpec):
            self.assertIn(field.name, self.guide,
                          "the guide never mentions %s, which is a field of "
                          "every configured listener" % field.name)

    def test_the_guide_names_the_environment_variables(self):
        for variable in ("RACCOON_LISTENER_TOKEN", "LISTEN_FDS"):
            self.assertIn(variable, self.guide,
                          "the guide does not mention %s" % variable)

    def test_the_guide_states_the_dns_limit(self):
        flat = " ".join(self.guide.split()).lower()
        for phrase in ("tasking only", "never report"):
            self.assertTrue(phrase in flat,
                            "the guide does not say %r about DNS" % phrase)

    def test_the_guide_states_that_no_listener_holds_the_key(self):
        flat = " ".join(self.guide.split()).lower()
        self.assertTrue("never" in flat)
        self.assertTrue("encryption key" in flat)

    # ── what this work made false ──

    def test_the_readme_no_longer_says_only_https_has_a_counterpart(self):
        flat = " ".join(self.readme.split()).lower()
        self.assertTrue("only https has a server counterpart" not in flat,
                        "the README still says what this work made false")

    def test_the_dns_side_channel_statement_survives(self):
        # DNS is still a dependent channel after this work: nothing
        # registers over it and no result comes back. The claim must not
        # be quietly upgraded to four independent channels again.
        flat = " ".join(self.readme.split()).lower()
        self.assertTrue("side channel" in flat,
                        "the README no longer calls DNS a side channel")
        self.assertTrue("4 independent channels" not in flat)
        self.assertTrue("four independent channels" not in flat)

    def test_the_readme_says_the_counterparts_now_exist(self):
        flat = " ".join(self.readme.split()).lower()
        self.assertTrue("listener" in flat,
                        "the README never mentions the listeners")


TUNNEL_DOC = REPO / "docs" / "TUNNEL.md"
DESIGN_DOC = (REPO / "docs" / "superpowers" / "specs"
              / "2026-11-19-operator-shell-window-design.md")


class TestTheTunnelPageDocumentsTheShellSession(unittest.TestCase):
    """The shell session, which is recorded nowhere an operator reads.

    The whole feature -- a terminal served over the tunnel, its two
    server-side switches, the attach client, what a transcript holds, and
    what the session leaves on the host -- was built across ten tasks and
    documented in none of them. This is the page a reader has, so these
    assert the facts they cannot get anywhere else. Claims, not sentences:
    the prose is free, the facts are not.
    """

    @classmethod
    def setUpClass(cls):
        cls.doc = " ".join(TUNNEL_DOC.read_text().split()).lower()

    def present(self, needle, what):
        self.assertTrue(" ".join(needle.split()).lower() in self.doc,
                        "%s: %r is not in docs/TUNNEL.md" % (what, needle))

    def absent(self, needle, what):
        self.assertFalse(" ".join(needle.split()).lower() in self.doc,
                         "%s: %r should no longer be in docs/TUNNEL.md"
                         % (what, needle))

    def test_the_tunnel_page_documents_the_shell_switch_and_the_attach_command(
            self):
        # Two server-side switches and nothing on the implant. The shell
        # port range opens the port at all; absent, there is none. The
        # transcript directory is the second switch, off by default.
        self.present("shell session", "what the feature is called")
        self.present("nothing listens on the", "no port is opened on the "
                     "implant itself")
        self.present("shell_port_first", "the first half of the shell "
                     "port range switch")
        self.present("shell_port_last", "the second half of it")
        self.present("shell_transcript_dir", "the transcript directory "
                     "switch, the second of the two")
        # The forward is first, then the recommended attach client, then
        # the socat fallback with its Ctrl-] escape.
        self.present("ssh -L", "the forward the port is reached over")
        self.present("python3 tools/raccoon_shell.py 127.0.0.1",
                     "the recommended attach client")
        self.present("socat -,raw,echo=0,escape=0x1d TCP:127.0.0.1:",
                     "the documented socat fallback")
        self.present("Ctrl-]", "what the socat escape byte is")

    def test_the_tunnel_page_says_the_session_is_root_and_how_to_resize(self):
        # The port grants a shell as the user the endpoint runs as, which
        # under the shipped unit is root. And the geometry is fixed at
        # attach; the remedy for a resize is one stty line.
        self.present("root", "the user the session runs as under the "
                     "shipped unit")
        self.present("set once", "that the geometry is fixed at attach")
        self.present("stty rows", "the resize remedy the attach client "
                     "prints")
        self.present("SIGWINCH", "when the client prints that line")

    def test_the_tunnel_page_says_what_a_transcript_holds(self):
        # The output direction byte for byte, which already contains what
        # the operator typed because the terminal echoes it -- so a
        # credential typed inside a session is in it, unavoidably.
        self.present("output direction", "what a transcript records")
        self.present("the terminal echoes it", "why it also holds input")
        self.present("credentials typed inside a session are in it",
                     "the consequence, in those words")
        self.present("0600 files in a 0700 directory", "the file modes")
        self.present("a .typescript with no .json beside it",
                     "the shape of an interrupted session's files")

    def test_the_tunnel_page_states_the_platform_facts_about_setsid(self):
        # setsid -c is what makes job control work, and util-linux >= 2.21
        # is what it needs. Where it is absent the session still runs but
        # has no controlling terminal.
        self.present("setsid -c", "what the shell is spawned through")
        self.present("util-linux", "what setsid -c needs")
        self.present("2.21", "the version of it")
        self.present("no controlling terminal", "what a host without "
                     "setsid gives the session")
        self.present("job control", "what is off without it")

    def test_the_tunnel_page_says_it_needs_a_feature_advertising_build(self):
        # A build older than this branch is refused with a reason, not
        # asked for a shell and dropped.
        self.present("advertise", "that the endpoint advertises the feature")
        self.present("refused", "what happens to a build that does not")

    def test_the_tunnel_page_lists_the_detection_indicators(self):
        # What the session leaves on the host, in the voice this project
        # already uses for such notes.
        # Not the word `bash`: a zsh login shell is the shell child there,
        # and a pin on the word held the false "a bash child" in place.
        self.present("child of the `python3 -`", "the process the shell "
                     "is a child of")
        self.present("the login shell, `bash` or `zsh`, else `bash` or "
                     "`/bin/sh`", "which shells the child can be")
        self.present("python3 -", "the process it is a child of")
        self.present("pseudo-terminal", "the pty on the host")
        self.present("second connection", "the extra connection on the "
                     "same outbound port")

    def test_the_curl_section_no_longer_claims_the_form_cannot_ask_for_a_tunnel(
            self):
        # Task 10 made that false: the Beacon Gen form now has a tunnel
        # section, posts the block on both delivery paths, and renders the
        # returned identity. The section keeps `drops` and the stagers,
        # which are still curl-only, and loses its tunnel half.
        self.absent("the Beacon Gen form cannot do yet",
                    "the claim Task 10 made false")
        self.absent("posts no `tunnel` block",
                    "the stale half of the old sentence")
        self.present("drops", "what the section still covers")
        self.present("stager_nix", "the other thing it still covers")
        self.present("stager_win", "and the other")

    def test_the_readme_capability_table_names_the_shell_session(self):
        rows = _rows_under(README.read_text(), "| Area | Capability |")
        flat = " ".join(" ".join(rows).split()).lower()
        self.assertIn("shell", flat,
                      "the README capability table does not name the shell "
                      "session")
        self.assertIn("tunnel.md", flat,
                      "the capability row does not point at docs/TUNNEL.md")


class TestTheOperatorShellIsDocumentedAsAWindow(unittest.TestCase):
    """The panel became a window, and three pages still described a modal.

    It died on every page load; now the card survives a reload, `_` parks
    it with the shell still running, and only `✕` ends it. Each of those
    changed a promise a reader relies on -- and one of them, "leaving the
    session queues the shutdown", was left standing as a page promising
    behaviour the code no longer has. These are the claims the prose may
    not soften back: what a closed tab costs, that a reattach is a new
    shell, and what a parked session holds while it waits.
    """

    def test_the_tunnel_page_states_what_a_closed_tab_now_costs(self):
        """The bound changed, and a page that still says "immediately"
        would be the lying documentation this branch keeps finding."""
        text = (REPO / "docs" / "TUNNEL.md").read_text()
        self.assertRegex(text, r"(?i)minimis|parked|window")
        self.assertRegex(text, r"240|four minutes")
        self.assertNotRegex(
            text, r"(?i)closing the (view|panel)[^.]*queues the shutdown",
            "the page still promises that closing the view queues the "
            "shutdown; only the cross does that now")
        # The three above are the task brief's, and measured against the
        # page as this task found it, two of them could not fail and the
        # third was red for the wrong reason:
        #   * "window" was already there, in the geometry paragraph;
        #   * `240|four minutes` failed only because the page's "four
        #     minutes" is wrapped across a line, so what answered that
        #     regex is prose reflowing and not the bound;
        #   * the forbidden sentence read "queues the channel's shutdown",
        #     which the pattern does not match, so it was green over the
        #     very page it was written to forbid.
        # The claims the six tasks actually changed are below, on a
        # whitespace-flattened copy for the reason the second one above
        # demonstrates: a phrase that reads as one sentence is two lines
        # in the file.
        flat = " ".join(text.split())
        self.assertNotRegex(
            flat, r"(?i)clicking outside it",
            "the card is a flex sibling of the content column and not a "
            "modal, so there is no outside to click")
        self.assertNotRegex(
            flat, r"(?i)closing the browser tab all post the same close",
            "a closed tab posts nothing now -- the pagehide handler is "
            "gone -- so the page may not go on charging it nothing")
        self.assertRegex(
            flat, r"240\s*(?:s\b|seconds)",
            "the page does not state, in seconds, the lapse a closed tab "
            "now costs")
        # This half the page already had right, and it is pinned so that a
        # rewrite around it cannot drop it: the lapse is noticed by a
        # check-in, so the margin is only ever paid with one on top.
        self.assertRegex(
            flat, r"(?i)plus one (?:check-in|interval)",
            "the bound is the lapse plus one check-in, and the check-in is "
            "the half an operator waits through")

    def test_the_demo_page_no_longer_promises_that_leaving_ends_it(self):
        """`docs/C2_DEMO.md:89` carried "Leaving the session queues the
        shutdown", which six tasks made false: leaving parks it, and only
        the cross ends it."""
        text = (REPO / "docs" / "C2_DEMO.md").read_text()
        self.assertNotRegex(text, r"(?i)leaving the session queues")
        self.assertRegex(text, r"(?i)minimis|parked")
        # The two above are the brief's, and the second is a floor rather
        # than a pin: "parked" also appears in the reload sentence, so
        # deleting the minimise sentence outright left it green -- measured,
        # not assumed. So the pair that actually changed is named, and in
        # the section that describes the header rather than anywhere on a
        # 1,200-line page.
        header = text.split("### Header Bar", 1)
        self.assertEqual(len(header), 2, "the tour has no Header Bar "
                         "section any more")
        flat = " ".join(header[1].split("\n###", 1)[0].split()).lower()
        for pattern, what in (
                (r"minimis", "that `_` parks the card and the shell keeps "
                             "running"),
                # Tied to the glyph, not to the words: "ends the session"
                # alone is answered by the sentence about a reload no
                # longer ending it, which measured green with the cross's
                # own clause deleted.
                (r"\u2715[^.]{0,80}end", "that `\u2715` is what ends it")):
            self.assertRegex(flat, pattern, "the tour's Header Bar section "
                             "does not say %s" % what)

    def test_the_tunnel_page_says_a_reload_gives_a_new_shell(self):
        """The connection *is* the shell, so a reattach is a fresh `bash`.

        Measured for the design: the pid went 75 -> 78, the working
        directory was back at `/`, and a variable that had been set was
        gone. A page that said a reload "restores your session" would be
        worse than one that said nothing at all, because the operator
        would type into a prompt believing their work was behind it.

        Scoped to the paragraphs that make the claim: "process" and
        "variable" each appear elsewhere on this page, so a
        document-wide search for them proves nothing about this sentence.
        """
        text = TUNNEL_DOC.read_text()
        said = [" ".join(p.split()) for p in text.split("\n\n")
                if re.search(r"(?i)a new shell", " ".join(p.split()))]
        self.assertTrue(said, "the page does not say anywhere that what a "
                        "reload attaches is a new shell")
        flat = " ".join(said).lower()
        for lost, what in (("director", "that the working directory resets"),
                           ("variable", "that the variables are gone"),
                           ("process", "that the processes went with it")):
            self.assertIn(lost, flat, "the page says the shell is a new one "
                          "and not %s" % what)
        # One reload measured `/`, which is where the spawn puts a session
        # and not where every login shell stays; the sentence says which.
        self.assertIn("back where the spawn puts it", flat,
                      "the reload's working directory reads as a rule and "
                      "not as where the spawn puts it")

    def test_the_tunnel_page_prices_a_parked_session(self):
        """Parking is the answer the page recommends, so it costs something.

        A parked session is not a paused one: the stream stays up, which
        means a worker thread on the team server, the connection to the
        shell port, a pty on the device and one of that port's four
        session slots (`beacon.py:_SHELL_MAX_SESSIONS`,
        `tunnel/shell.py:DEFAULT_MAX_SESSIONS`, both 4), for as long as it
        is parked.

        Scoped to the paragraph that makes the claim, and not to every
        paragraph containing "parked": the first version took the latter,
        which swept in the reload paragraph ("open or parked") and got
        `connection` and `pseudo-terminal` from there for free. Measured by
        the review: with that scope, cutting the cost list down to the
        thread and the four slots left this green, so two of the four costs
        were held by nothing.
        """
        text = TUNNEL_DOC.read_text()
        held = [" ".join(p.split()) for p in text.split("\n\n")
                if re.search(r"(?i)parked session is not a free one",
                             " ".join(p.split()))]
        self.assertEqual(len(held), 1, "the page has no one paragraph that "
                         "prices a parked session")
        flat = held[0].lower()
        for cost, what in (("thread", "the worker thread the stream holds"),
                           ("connection", "the connection to the shell port"),
                           ("pseudo-terminal", "the pty on the device"),
                           ("four", "one of the port's four session slots")):
            self.assertIn(cost, flat, "a parked session is not a free one, "
                          "and the page does not name %s" % what)

    def test_the_readme_row_says_the_card_can_be_parked(self):
        """The front page's one clause about the window.

        Read off the row rather than the page: "minimise" and "reload"
        both appear elsewhere in the README, so a row rewritten without
        them would pass a document-wide search. Emphasis is stripped
        first -- `a **new** shell` is the same claim as `a **new shell**`,
        and a test that can be defeated by moving a pair of asterisks is
        a test about formatting.
        """
        row = next((line for line in README.read_text().splitlines()
                    if line.startswith("| Operator Shell |")), None)
        self.assertIsNotNone(row, "the GUI feature table has no Operator "
                             "Shell row")
        flat = re.sub(r"[*`]", "", row).lower()
        for claim, what in (("minimis", "that `_` parks it and the shell "
                                        "keeps running"),
                            ("reload", "that a reload brings the card back"),
                            ("new shell", "that what it attaches is a new "
                                          "shell")):
            self.assertIn(claim, flat,
                          "the capability row does not say %s" % what)

    def _window_prose(self):
        """The three passages that describe the window, and nothing else.

        Scoped, because the patterns in the test below are unambiguous
        only here: "come back" is a true statement about the generator's
        response further up `docs/TUNNEL.md`, and "it is restored" is a
        true statement about the card in the tour's own paragraph. A
        page-wide `assertNotRegex` for either would be a test about the
        rest of the page.
        """
        section = TUNNEL_DOC.read_text().split(
            "\n## Opening one from the interface", 1)
        self.assertEqual(len(section), 2, "docs/TUNNEL.md no longer has the "
                         "section that describes the window")
        found = [("docs/TUNNEL.md", section[1].split("\n## ", 1)[0])]
        for doc, lead in ((DEMO_DOC, "The **Operator Shell** panel"),
                          (README, "| Operator Shell |")):
            lines = [line for line in doc.read_text().splitlines()
                     if line.startswith(lead)]
            self.assertEqual(len(lines), 1, "%s has no single passage "
                             "starting %r" % (doc.name, lead))
            found.append((doc.name, lines[0]))
        return [(name, " ".join(text.split())) for name, text in found]

    def test_no_page_reverses_the_claims_these_tests_pin(self):
        """Softening is caught above; a reversal was not.

        Measured by the review against four of the nine assertions in this
        class: "`_` cannot minimise it: the card is hidden and the shell is
        torn down", "your directory, your variables and your running
        processes all come back", "are restored for you", and "the shell is
        killed ... attaches the same shell, never a new shell" each left
        the file green. Every assertion above asks whether a subject is
        mentioned, and none of them asks what is said about it -- so a page
        that stated the opposite of the measurement would pass. These ask
        the other question, on all three passages.

        The pairs are subject-then-verb inside one sentence rather than two
        separate searches, because "the card survives a page load" and
        "until it is restored" are both true and both sit next to these.
        """
        for name, flat in self._window_prose():
            for lie, what in (
                    (r"(?i)(director|variable|process)\w*[^.;]{0,70}"
                     r"(come back|restored|survive)",
                     "that the shell's own directory, variables or "
                     "processes survive a reload -- the pid went 75 to 78"),
                    (r"(?i)the same shell",
                     "that a reattach gets the same shell"),
                    (r"(?i)never a new shell",
                     "that a reattach is never a new shell"),
                    (r"(?i)cannot minimis",
                     "that the card cannot be parked"),
                    (r"(?i)minimis\w*[^.;]{0,70}"
                     r"(torn down|tears? down|killed|ends the session)",
                     "that `_` ends the session, which is what `\u2715` is "
                     "for")):
                self.assertNotRegex(flat, lie, "%s claims %s" % (name, what))
            # And the positive half of the same claim, so the passage has to
            # say what `_` does and not merely avoid saying the opposite.
            self.assertRegex(flat, r"(?i)keeps running|still running",
                             "%s does not say the shell keeps running while "
                             "the card is parked" % name)

    def test_the_design_records_the_seven_things_this_cannot_do(self):
        """The seven known limitations, which nothing else holds.

        A design is not usually tested here. These seven are the only
        written record of what the feature deliberately cannot do -- each
        one ruled during execution, against a change the plan forbade --
        and the three operator claims above are now pinned while these
        were held by nothing, so they could rot or be dropped silently.
        Subjects, not sentences: the reasoning is free to be rewritten,
        the seven subjects are not. The seventh arrived with the login
        shell: what the view says about history is what the endpoint said
        about itself.
        """
        section = DESIGN_DOC.read_text().split(
            "\n## Known limitations, as built\n", 1)
        self.assertEqual(len(section), 2, "the design no longer records what "
                         "this feature cannot do")
        body = section[1].split("\n## ", 1)[0].split("\n---", 1)[0]
        entries = re.findall(r"^\d+\. \*\*", body, re.M)
        self.assertEqual(len(entries), 7, "the section has %d entries; seven "
                         "limitations were ruled" % len(entries))
        flat = " ".join(body.split()).lower()
        for subject, what in (
                ("count, not an identity",
                 "that the resume checks how many sessions the claim has, "
                 "not whether this id is one of them"),
                ("duplicated tab", "that Duplicate Tab clones the id and "
                                   "both tabs resume it"),
                ("content column is hidden",
                 "that an agent clicked while the card is open renders "
                 "into a hidden node"),
                ("fixed for the life of the connection",
                 "that nothing resizes a terminal after it is attached"),
                ("while parked is read after a restore",
                 "that a refusal is read on the restore and not in the "
                 "parked entry -- the subject changed with the merge "
                 "blocker: the sentence used to be written only into a "
                 "terminal the next poll tick disposed, and now rides on "
                 "`opshellLast` into the card"),
                ("not a free one", "what a parked session holds"),
                ("what the endpoint reported about itself",
                 "that the history guard is the endpoint's own claim, which "
                 "the team server cannot verify")):
            self.assertIn(subject, flat,
                          "the section does not record %s" % what)


class TestTheShellAccountIsTrueOfTheLoginShellWork(unittest.TestCase):
    """What six tasks changed about the shell, said where a reader looks.

    The session now runs the user's own login shell where there is one, so
    five statements that were true of a session that was always bash became
    false, and one thing the user asked for -- colour -- was written down
    nowhere. Each test here takes the paragraph that makes a claim and reads
    that paragraph, flattened, and not the page: the pages wrap, and a
    pattern run over a whole document has twice been green over the very
    sentence it was written to forbid, because it was answered by a
    different paragraph.
    """

    @staticmethod
    def flat(text):
        return " ".join(text.split())

    def blocks(self, text):
        return [self.flat(b) for b in text.split("\n\n") if b.strip()]

    def one_block(self, text, pattern, what):
        found = [b for b in self.blocks(text) if re.search(pattern, b)]
        self.assertEqual(len(found), 1, "%d paragraphs say %s, wanted one "
                         "(pattern %r)" % (len(found), what, pattern))
        return found[0]

    def tunnel_section(self, heading, end="\n#"):
        parts = TUNNEL_DOC.read_text().split("\n" + heading + "\n", 1)
        self.assertEqual(len(parts), 2, "docs/TUNNEL.md has no %r" % heading)
        return parts[1].split(end, 1)[0]

    def design_section(self, heading):
        parts = DESIGN_DOC.read_text().split("\n" + heading + "\n", 1)
        self.assertEqual(len(parts), 2, "the design has no %r" % heading)
        return parts[1].split("\n## ", 1)[0]

    def test_the_tunnel_page_says_which_shell_runs_and_what_history_costs(self):
        text = " ".join(TUNNEL_DOC.read_text().split())
        self.assertRegex(text, r"(?i)login shell")
        self.assertRegex(text, r"(?i)not guaranteed off")
        self.assertNotRegex(
            text, r"(?i)history is (always )?off (on|in) every session",
            "the page still promises history is off for every shell")

    def test_the_tunnel_page_says_why_the_passwd_entry_and_not_shell(self):
        section = self.tunnel_section(
            "### Which shell a session runs, and what it costs for history",
            "\n### ")
        said = self.one_block(section, r"(?i)passwd",
                              "which shell is chosen and from where")
        for pattern, what in (
                (r"(?i)login shell", "that it is the login shell"),
                (r"passwd entry[^.]*and not from `\$SHELL`",
                 "that the passwd entry is what is read and `$SHELL` is "
                 "not -- in that order, since both words appear in the "
                 "reversal too"),
                (r"(?i)service manager", "why `$SHELL` is nobody's choice "
                                         "under the shipped unit"),
                (r"(?i)\broot\b", "that a shipped implant runs as root, "
                                  "so nothing changes there"),
                (r"(?i)own machine", "that the operator's own machine is "
                                     "the case this helps"),
                (r"(?i)bash and zsh|zsh or bash|bash or zsh",
                 "which two shells are driven"),
                (r"(?i)/bin/sh", "the floor when there is no bash")):
            self.assertRegex(said, pattern, "the paragraph does not say "
                             + what)

    def test_no_paragraph_still_says_the_shell_is_always_bash(self):
        """The statements the pin on the word `bash` held in place.

        The introduction said "the host's own shell, `bash` where there is
        one", and the detection list said a live session shows "a `bash`
        child". Both are false for a zsh login shell, and the second is
        what an operator reads to judge their own exposure. So the page may
        not say, of the session's shell, that it is bash, anywhere an
        unconditional claim would be made: the two paragraphs are read, and
        so is the one about a shipped root implant.
        """
        text = TUNNEL_DOC.read_text()
        intro = self.one_block(text, r"(?i)can also serve an \*\*interactive "
                                     r"terminal\*\*", "what the feature is")
        self.assertNotRegex(intro, r"(?i)host's own shell, `bash`",
                            "the introduction says the shell is bash")
        self.assertRegex(intro, r"(?i)login shell, else `bash`")
        listed = self.one_block(
            self.tunnel_section("### What it leaves on the host", "\n---"),
            r"(?i)child of the `python3 -`", "what the shell child is")
        self.assertNotRegex(listed, r"(?i)a \*\*`bash` child",
                            "the indicator list says the child is bash")
        section = self.tunnel_section(
            "### Which shell a session runs, and what it costs for history",
            "\n### ")
        root = self.one_block(section, r"(?i)passwd", "the shipped root case")
        self.assertNotRegex(root, r"(?i)nothing changes there",
                            "a root implant's prompt is red now, so "
                            "nothing does not change; the same shell runs")
        self.assertRegex(root, r"(?i)same shell runs there")
        completion = self.one_block(text, r"(?i)flag completion needs one "
                                          r"extra step", "completion")
        self.assertNotRegex(completion, r"(?i)a session here is `bash -i`",
                            "the completion paragraph says every session "
                            "is bash")

    def test_the_session_is_given_root_but_may_not_stay_there(self):
        """Statement 3: "The session starts in `/`" is a spawn argument.

        A login shell's own startup files run after the spawn and may
        change directory -- measured, with a zsh whose startup file
        left the session in the home directory. The page may still say
        what the spawn is given; it may not say where the session is.
        """
        text = TUNNEL_DOC.read_text()
        paragraph = self.one_block(text, r"(?i)install directory",
                                   "where the session starts")
        self.assertNotRegex(
            paragraph, r"(?i)session starts in\s*`?/`?(?![\w.])",
            "the page still says, as a rule, that the session starts in /")
        self.assertRegex(paragraph, r"(?i)\bgiven\s+`/`",
                         "the paragraph does not say that `/` is what the "
                         "spawn is given")
        self.assertRegex(paragraph,
                         r"(?i)startup files[^.]*\b(change|move)[^.]*director"
                         r"|startup files[^.]*\bcd\b",
                         "the paragraph does not say a login shell's own "
                         "startup files may change the directory")
        self.assertRegex(paragraph, r"(?i)measured",
                         "the paragraph does not say that this was measured")
        self.assertRegex(paragraph, r"started from `/`[^.]*found in the "
                                    r"home directory",
                         "the paragraph does not say what the measurement "
                         "found: a shell started from / was in the home "
                         "directory")
        self.assertNotRegex(paragraph, r"(?i)left the session in `/`",
                            "the paragraph says the session stayed in /")
        self.assertNotRegex(
            self.flat(text), r"(?i)session starts in\s*`?/`?(?![\w.])",
            "another paragraph still says the session starts in /")

    def test_the_artifact_list_separates_history_off_from_not_guaranteed(self):
        """Statement 4: the list now makes the distinction the page makes."""
        section = self.tunnel_section("### What it leaves on the host",
                                      "\n---")
        items = [self.flat(i.split("\n\n", 1)[0])
                 for i in re.split(r"\n(?=- )", section)
                 if i.startswith("- ")]
        said = [i for i in items if re.search(r"(?i)history", i)]
        self.assertEqual(len(said), 1, "the artifact list has %d items about "
                         "history, wanted one" % len(said))
        item = said[0]
        for pattern, what in (
                (r"(?i)not guaranteed off",
                 "that history is only *not guaranteed* off in some sessions"),
                (r"(?i)generated rcfile|rcfile",
                 "that where bash took the rcfile there is no file"),
                (r"(?i)HISTFILE=/dev/null",
                 "what the weaker guard is"),
                (r"(?i)can undo|may undo|free to",
                 "that the user's own files can undo the weaker guard"),
                (r"(?i)first line",
                 "that the view says which of the two applies")):
            self.assertRegex(item, pattern, "the history item does not say "
                             + what)
        # A direction, not two words: the sentence about bash taking the
        # rcfile may not say anything about being not guaranteed.
        took = [x for x in re.split(r"(?<=[.;])\s", item)
                if re.search(r"(?i)bash took", x)]
        self.assertEqual(len(took), 1, "the item has %d sentences about "
                         "bash taking the rcfile" % len(took))
        self.assertRegex(took[0], r"(?i)^Where bash took the generated "
                                  r"rcfile history is off, and none is "
                                  r"written")
        self.assertNotRegex(took[0], r"(?i)guaranteed|even where",
                            "history is said to be only not guaranteed off "
                            "where bash took the rcfile")
        self.assertRegex(item, r"(?i)`/bin/sh`|bin/sh",
                         "the item leaves out the /bin/sh fallback, which "
                         "takes the weaker guard too")
        self.assertNotRegex(
            self.flat(section),
            r"(?i)`HISTFILE` is unset for the session\s*(?:\u2014|--?)\s*"
            r"though",
            "the old, unconditional sentence about HISTFILE is still there")

    def test_a_pipe_failure_or_a_changed_guard_refuses_the_session(self):
        section = self.tunnel_section(
            "### Which shell a session runs, and what it costs for history",
            "\n### ")
        said = self.one_block(section, r"(?i)\brefused\b",
                              "that a session history cannot be held off for "
                              "is refused")
        for pattern, what in (
                (r"(?i)pipe", "the pipe that carries the rcfile"),
                (r"(?i)now that session is refused, with a reason that names "
                 r"history",
                 "that a pipe failure refuses the session and says why"),
                (r"(?i)declined the same way",
                 "that a changed guard is refused too"),
                (r"(?i)record", "that falling back would record what is "
                                "typed"),
                (r"(?i)chsh|login shell (?:has )?changed|changed since",
                 "that a guard that changed since connecting is refused"),
                (r"(?i)reconnect", "what to do about a changed guard")):
            self.assertRegex(said, pattern, "the paragraph does not say "
                             + what)

    def test_the_history_mechanisms_are_named_with_their_reasons(self):
        section = self.tunnel_section(
            "### Which shell a session runs, and what it costs for history",
            "\n### ")
        said = self.one_block(section, r"(?i)not guaranteed off",
                              "what the two history guards are")
        for pattern, what in (
                (r"(?i)only bash takes `?--rcfile|zsh takes no `?--rcfile",
                 "why a non-bash shell gets the weaker one"),
                (r"/dev/fd", "that a host without /dev/fd gets it too"),
                (r"(?i)bash login shell gets that file too, which is the "
                 r"stronger guard and not the weaker",
                 "that a bash login shell gets the stronger one, and not "
                 "the reverse -- `[^.]*stronger` also matched the reversal"),
                (r"(?i)after that|run after", "that the user's files run "
                                              "after the weaker guard"),
                (r"history is off in this session",
                 "the first line's wording for the stronger guard"),
                (r"history is not guaranteed off in this session",
                 "the first line's wording for the weaker guard"),
                (r"(?i)the team server cannot verify it",
                 "that the word is the endpoint's own claim, as the user "
                 "is")):
            self.assertRegex(said, pattern, "the paragraph does not say "
                             + what)
        self.assertNotRegex(said, r"(?i)team server (?:checks|verifies)",
                            "the paragraph says the team server checks it")

    def test_the_page_says_what_the_first_line_shows_in_each_of_three_cases(
            self):
        """The report reaching the page is not uniform.

        Each case is read off its own bullet, so that a sentence about one
        cannot be answered by a word in another.
        """
        section = TUNNEL_DOC.read_text().split(
            "\n## Opening one from the interface", 1)[1].split("\n## ", 1)[0]
        block = self.one_block(section, r"(?i)\bno row\b",
                               "the three cases the first line can be in")
        cases = [c for c in re.split(r"\s-\s(?=\*\*)", block)[1:]]
        self.assertEqual(len(cases), 3, "the paragraph has %d cases, wanted "
                         "three: %r" % (len(cases), cases))
        old, none, unknown = cases
        # Each bullet is pinned by the sentence that says what the line
        # reads, and by what it may not say: `off` is the one reading that
        # misleads, and a bullet that said the reverse kept every word
        # these checks used to look for.
        self.assertRegex(old, r"(?i)built before")
        self.assertRegex(old, r"(?i)reads as `not guaranteed off` with "
                              r"\*\*no reason\*\*",
                         "an endpoint too old to send the field must read as "
                         "the weaker word with no reason beside it")
        for what, bullet in (("old", old), ("unknown", unknown)):
            self.assertNotRegex(
                bullet, r"(?i)(?:reads|treated|shown|taken|counted) as "
                        r"`?off\b|never as `?not guaranteed|history is off",
                "the %s case is described as reading `off`" % what)
        self.assertRegex(none, r"(?i)\bno row\b")
        self.assertRegex(none, r"(?i)relay[^.]*too old|too old[^.]*relay")
        self.assertRegex(none, r"(?i)says nothing about history\W+neither "
                               r"word")
        self.assertNotRegex(none, r"(?i)reads? (?:as )?`?(?:history is )?"
                                  r"(?:not guaranteed )?off|history is "
                                  r"(?:not guaranteed )?off",
                            "the nothing case must not be described as "
                            "either word")
        self.assertRegex(unknown, r"(?i)recognis")
        self.assertRegex(unknown, r"(?i)reads as `not guaranteed off` as "
                                  r"well")
        self.assertRegex(unknown, r"(?i)\bkeeps\b[^.]*reason")

    def test_the_page_documents_the_colour_the_user_asked_for(self):
        """Statement 5: colour was the request, and was written down nowhere."""
        section = self.tunnel_section(
            "### Which shell a session runs, and what it costs for history",
            "\n### ")
        said = self.one_block(section, r"(?i)colou?r defaults",
                              "that bash gets colour defaults")
        self.assertNotRegex(self.flat(section), r"(?i)only where it has none "
                                                r"of its own",
                            "the prompt is set regardless; only the two "
                            "variables yield to the environment")
        for pattern, what in (
                (r"(?i)\bbash\b", "that it is bash that gets them"),
                (r"~/\.bashrc|\$HOME/\.bashrc", "that the user's own file "
                                                "is what is read after"),
                (r"(?i)\bwins?\b|\bwin\b|take precedence|override",
                 "that the user's own settings win"),
                (r"(?i)before\W{0,3}the user's own `~/\.bashrc`",
                 "that the defaults come before the user's own file"),
                (r"the prompt goes after the distribution's "
                 r"`/etc/bash\.bashrc`",
                 "that the prompt follows the system file, which sets one "
                 "of its own"),
                (r"each only if the environment has none",
                 "that the two variables yield to the environment"),
                (r"(?i)only the user's own `~/\.bashrc` overrides it",
                 "that the prompt is set regardless and only the user's own "
                 "file overrides it"),
                (r"(?i)highlighting", "as-you-type highlighting"),
                (r"(?i)install[^.]*themselves|themselves[^.]*install",
                 "that highlighting is something the user installs")):
            self.assertRegex(said, pattern, "the paragraph does not say "
                             + what)

    def test_the_readme_row_names_the_login_shell(self):
        row = next((line for line in README.read_text().splitlines()
                    if line.startswith("| Operator Shell |")), None)
        self.assertIsNotNone(row, "the GUI feature table has no Operator "
                             "Shell row")
        self.assertRegex(re.sub(r"[*`]", "", row),
                         r"(?i)login shell where that is bash or zsh",
                         "the row does not say whose shell the session runs, "
                         "and which two it drives")

    def test_the_demo_tour_says_what_the_first_line_claims_about_history(self):
        line = next((l for l in DEMO_DOC.read_text().splitlines()
                     if l.startswith("The **Operator Shell** panel")), None)
        self.assertIsNotNone(line, "the tour has no Operator Shell paragraph")
        flat = self.flat(line)
        for pattern, what in (
                (r"(?i)login shell", "whose shell it is"),
                (r"(?i)not guaranteed off", "the weaker claim"),
                (r"(?i)reason beside it, where it gave one",
                 "that an old endpoint's weaker word has no reason"),
                (r"(?i)nothing about history when the team server has no "
                 r"row", "that the line is silent only when there is no row "
                          "to read")):
            self.assertRegex(flat, pattern, "the tour's paragraph does not "
                             "say " + what)
        self.assertNotRegex(flat, r"(?i)endpoint reported nothing",
                            "the tour says the line is silent for an "
                            "endpoint that reported nothing, which is the "
                            "other case: it reads as the weaker word")

    def test_the_design_does_not_say_nothing_runs_for_a_login_shell(self):
        """Statement 1: a bash login shell does get the generated file."""
        section = self.design_section(
            "## Colour defaults, for a bash session only")
        flat = self.flat(section)
        self.assertNotRegex(flat, r"(?i)nothing here runs when the session "
                                  r"is a login shell")
        said = self.one_block(section, r"(?i)login shell",
                              "what a login shell gets")
        self.assertRegex(said, r"(?i)bash login shell gets it too")
        self.assertRegex(said, r"(?i)stronger history guard and not the "
                               r"weaker")
        self.assertRegex(said, r"(?i)only a login shell that is not bash"
                               r"[^.]*never sees the file")
        self.assertRegex(said, r"(?i)no `/dev/fd` runs plain `-i` and sees "
                               r"none of it")
        self.assertRegex(flat, r"/etc/bash\.bashrc",
                         "the section does not say where the prompt sits "
                         "relative to the system file")

    def test_the_design_says_part_two_was_built(self):
        head = DESIGN_DOC.read_text().split("\n## ", 1)[0]
        self.assertNotRegex(self.flat(head),
                            r"(?i)was \*\*not\*\* built|still a proposal",
                            "the status still says part two was not built")
        self.assertRegex(self.flat(head), r"(?i)part two[^.]*\bbuilt\b")

    def test_the_designs_first_line_is_not_a_constant_any_more(self):
        text = self.flat(DESIGN_DOC.read_text())
        self.assertNotRegex(
            text, r"the host, that history is off, the pair",
            "part one still says the first line always claims history off")
        self.assertRegex(text, r"off, or only not guaranteed off, or "
                               r"nothing at all",
                         "part one leaves out the third state, in which the "
                         "line says nothing about history")

    def test_the_design_records_what_was_built_for_history(self):
        section = self.design_section(
            "## The consequence that has to be said out loud")
        flat = self.flat(section)
        self.assertNotRegex(
            flat, r"(?i)reports which history mechanism it used[^.]*"
                  r"as a field on the shell session",
            "the section still describes a per-session report")
        self.assertRegex(flat, r"(?i)host capability")
        self.assertRegex(flat, r"(?i)\bHELLO\b")
        self.assertRegex(flat, r"(?i)no message the page reads before its "
                               r"first line",
                         "the section does not say why the mechanism cannot "
                         "be reported per session")
        self.assertNotRegex(flat, r"(?i)there is no way to do that",
                            "the session stream does run upward; it carries "
                            "raw bytes only")
        self.assertRegex(flat, r"(?i)no longer matches is \*\*refused\*\*",
                         "the section does not say a changed guard is "
                         "refused")
        self.assertRegex(flat, r"(?i)pipe[^.]*\.\s+It is now a "
                               r"\*\*refusal\*\* that names history",
                         "the section does not say the pipe failure is a "
                         "refusal")
        self.assertRegex(flat, r"(?i)worst trade on this branch",
                         "the section lost its conclusion")

    def test_the_seventh_limitation_says_whose_claim_the_guard_is(self):
        body = self.design_section("## Known limitations, as built") \
            .split("\n---", 1)[0]
        entries = re.split(r"\n(?=\d+\. \*\*)", body)
        seventh = [self.flat(e) for e in entries if e.startswith("7. **")]
        self.assertEqual(len(seventh), 1, "no seventh entry")
        self.assertNotRegex(seventh[0], r"(?i)team server "
                            r"(?:checks|verifies|validates) it",
                            "the entry says the team server checks the guard")
        for pattern, what in (
                (r"(?i)team server cannot verify it, exactly as it cannot "
                 r"verify `user`", "that the team server cannot verify it"),
                (r"(?i)\buser\b", "that `user` is the same boundary"),
                (r"(?i)modified endpoint[^.]*\boff\b",
                 "what a modified endpoint could claim"),
                (r"TUNNEL\.md", "where the same boundary is already stated")):
            self.assertRegex(seventh[0], pattern, "the seventh entry does "
                             "not say " + what)

    def test_the_design_answers_what_it_left_to_the_builder(self):
        from software.c2 import beacon
        # The second heading of that name is part two's; the first belongs
        # to part one and is not under test.
        parts = DESIGN_DOC.read_text().split("\n## Left to the builder\n")
        self.assertEqual(len(parts), 3, "the design no longer has both "
                         "'Left to the builder' sections")
        flat = self.flat(parts[2].split("\n## ", 1)[0])
        self.assertIn("history_detail", flat)
        self.assertRegex(flat, r"`history`\s*/\s*`history_detail`")
        default = re.search(r'LSCOLORS:-([A-Za-z]+)', beacon._SHELL_RCFILE)
        self.assertIsNotNone(default, "the generated file has no LSCOLORS "
                             "default to compare to")
        self.assertIn(default.group(1), flat,
                      "the design does not record the LSCOLORS string the "
                      "code uses")
        self.assertRegex(flat, r"(?i)zsh[^.]*no[^.]*(rc|startup)[^.]*variant"
                               r"|no .?no rc.? variant")

    def test_the_comment_above_the_generated_file_does_not_say_every_bash(
            self):
        """Statement 2, in the one place outside the documents.

        A bash on a host with no `/dev/fd` runs plain `-i` and never sees
        the file. Read off the comment itself, and then off the function
        that decides, so the comment cannot be right by agreeing with a
        sentence nobody checks.
        """
        lines = (REPO / "software" / "c2" / "beacon.py").read_text() \
            .splitlines()
        end = next(i for i, l in enumerate(lines)
                   if l.startswith("_SHELL_RCFILE = ("))
        start = end
        while lines[start - 1].startswith("#"):
            start -= 1
        comment = "\n".join(l[1:] for l in lines[start:end])
        paragraph = self.one_block(comment, r"(?i)handed to",
                                   "which shells the file is handed to")
        self.assertNotRegex(paragraph, r"(?i)every bash")
        self.assertRegex(paragraph, r"/dev/fd")
        # The direction, and not two words: a comment that said a bash with
        # no /dev/fd is handed the file "all the same" mentions the path
        # and bans nothing above.
        self.assertRegex(paragraph, r"no `/dev/fd`[^.;]*plain[^.;]*`-i`"
                                    r"[^.;]*never sees the file",
                         "the comment does not say that a bash on a host "
                         "with no /dev/fd runs plain -i and never sees "
                         "the file")
        from software.c2 import beacon
        with patch("software.c2.beacon.os.path.isdir", return_value=True):
            self.assertEqual(beacon._guard_of("/bin/bash")[0], "off")
            self.assertEqual(beacon._guard_of("/opt/homebrew/bin/bash")[0],
                             "off", "a bash login shell is handed the file")
            self.assertEqual(beacon._guard_of("/bin/zsh")[0], "weak")
        with patch("software.c2.beacon.os.path.isdir", return_value=False):
            self.assertEqual(beacon._guard_of("/bin/bash")[0], "weak",
                             "a bash with no /dev/fd is not handed the file")


class TestTheGuiTourKeepsUpWithTheHeader(unittest.TestCase):
    """The tour lists the header buttons; the page defines them.

    A document that enumerates buttons drifts the moment one is added,
    and one just was. So the list is checked against the page rather than
    read for plausibility.
    """

    @classmethod
    def setUpClass(cls):
        cls.tour = _read("docs", "C2_DEMO.md")
        cls.page = _read("software", "c2", "server.py")

    def test_every_header_button_is_named_in_the_tour(self):
        import re

        header = self.page[self.page.index('<button class="topbar-ico-btn"'):]
        header = header[:header.index("</header>")]
        titles = re.findall(r'title="([^"]+)"', header)
        self.assertGreaterEqual(len(titles), 4,
                                "the header was not parsed: %r" % titles)

        # Scoped to the section that describes the header, not the whole
        # tour. Searching the document for "listeners" passed while the
        # Header Bar paragraph did not mention the button, because the
        # word appears three times elsewhere -- "unusual listeners" in the
        # connection analyser, and an SMB listener in a diagram. The sixth
        # time on this branch that a check was looser than the property it
        # named.
        section = self.tour.split("### Header Bar", 1)
        self.assertEqual(len(section), 2,
                         "the tour has no Header Bar section any more")
        body = section[1].split("\n###", 1)[0]
        flat = " ".join(body.split()).lower()
        for title in titles:
            self.assertTrue(title.lower() in flat,
                            "the tour's Header Bar section never mentions "
                            "the %r button" % title)

    def test_no_heading_has_its_paragraph_glued_to_it(self):
        """A heading and its text need the blank line between them.

        Found by a reviewer, not by a test: an edit on this branch removed
        the newline after `### Agent Sidebar (left)` and the whole
        paragraph became part of the H3 -- 302 characters of prose
        rendered as a heading. Nothing noticed, because every docs test
        here searches for substrings and the substrings were all still
        there; only the rendering was wrong.

        Two signals, because one alone misfires. Length catches it on its
        own (the next longest heading in these three files is 89
        characters, and that one is a shell comment), and the sentence
        rule catches a short run-on that length would let through.
        `#` lines inside a fenced block are shell comments, not headings,
        so the fences are tracked rather than assumed away -- without that
        the rule flagged four code comments and no real defect.
        """
        for doc in (DEMO_DOC, REPO / "docs" / "TUNNEL.md", REPO / "README.md"):
            fenced = False
            for n, line in enumerate(doc.read_text().splitlines(), 1):
                if line.lstrip().startswith("```"):
                    fenced = not fenced
                    continue
                if fenced or not line.startswith("#"):
                    continue
                where = "%s:%d: %r" % (doc.name, n, line[:80])
                self.assertLessEqual(
                    len(line), 120,
                    "a heading this long is a paragraph with a lost "
                    "newline -- " + where)
                # A title does not end in a full stop and carry on. The
                # lookbehind spares "## 1. Operator Dashboard", which is a
                # numbered heading and not a sentence.
                self.assertNotRegex(
                    line.lstrip("#"), r"(?<![0-9])[.!?]\s+\S",
                    "a heading does not contain a sentence break -- " + where)

    def test_the_tour_links_the_listener_guide(self):
        self.assertIn("LISTENERS.md", self.tour,
                      "the tour describes a Listeners panel and does not "
                      "say where to read about it")


class TestTheRedirectorGuideKnowsAboutListeners(unittest.TestCase):
    def test_it_points_at_the_listener_guide(self):
        # Same shape, different transport: a front host that carries
        # traffic and holds no key. A reader who found one should find the
        # other.
        text = _read("docs", "REDIRECTOR.md")
        self.assertIn("LISTENERS.md", text,
                      "the redirector guide does not mention the listeners, "
                      "which are the same arrangement for the other three "
                      "transports")


class TestKnownLimitsDropsWhatThisWorkFixed(_DocCase):
    def test_the_line_continuation_half_is_gone(self):
        # `_unit_reach` joins systemd continuations now, with a test. The
        # other half of that deferred finding -- that it sees only
        # `/bin/sh` for a `sh -c` wrapper -- is still true and still
        # recorded.
        flat = " ".join(self.doc.split())
        self.assertTrue(
            "raises a raw `ValueError` on a systemd line continuation"
            not in flat,
            "Known limits still records the continuation fault, which is "
            "fixed")
        self.assertTrue("/bin/sh" in flat,
                        "the half that is still open was dropped too")

    def test_the_severity_correction_records_that_the_gap_is_closed(self):
        # The entry says SMB and QUIC "could not be reached at all", which
        # was true and is the reason their unencrypted fallbacks were
        # latent rather than exploitable. It is a statement about the
        # past; now that listeners exist it has to say so, or a reader
        # takes it for a current description.
        flat = " ".join(self.doc.split()).lower()
        self.assertTrue("could not be reached at all" in flat)
        self.assertTrue("listener" in flat,
                        "nothing in Known limits mentions that the "
                        "counterparts now exist")


class TestTheKnownLimitsRecordTheOpenFindings(_DocCase):
    def _groups(self):
        body = self.doc.split("\n## Known limits\n", 1)[1].split("\n## ", 1)[0]
        parts = re.split(r"^#### (.+)$", body, flags=re.M)
        return {parts[i].strip(): parts[i + 1] for i in range(1, len(parts), 2)}

    def test_the_section_holds_exactly_the_findings_that_are_still_open(self):
        groups = self._groups()
        self.assertEqual(sorted(groups), sorted(_OPEN_FINDINGS),
                         "the severity groups in Known limits changed")
        for group, entries in _OPEN_FINDINGS.items():
            flat = " ".join(groups[group].split()).lower()
            bullets = re.findall(r"^- \*\*", groups[group], re.M)
            self.assertEqual(len(bullets), len(entries),
                             "%s: the section has %d entries, the record %d"
                             % (group, len(bullets), len(entries)))
            for phrase, still_open in entries:
                with self.subTest(group=group, entry=phrase):
                    self.assertIn(" ".join(phrase.split()).lower(), flat,
                                  "%r is not under %r" % (phrase, group))
                    if still_open is not None:
                        self.assertTrue(
                            still_open(),
                            "%r is no longer true of the code: it has been "
                            "fixed. Delete it from Known limits and from "
                            "_OPEN_FINDINGS." % phrase)
        deferred = " ".join(groups["Minor, deferred"].split()).lower()
        self.assertIn("nineteen", deferred)
        self.assertEqual(
            len(_OPEN_FINDINGS["Minor, deferred"]) + _DEFERRED_MERGED,
            _DEFERRED_FINDINGS, "the merge count and the entry count differ")


# The entries under "The agent layer" that the code can answer for. They are
# kept apart from _OPEN_FINDINGS, whose groups are the hardening pass's and
# are counted against it; these are counted, with those, against the README's
# sentence about how many entries have a test.
#
# READ THIS WHEN ONE OF THEM FAILS. The assertion states a limitation as
# true. It fails when the limitation stops being true, which means the fix
# has landed: delete the entry from Known limits, delete its predicate here,
# and delete this record. Do not "fix" the test by changing what it asserts.
#
# One exception, and the tier entry is it. Its predicate watches the
# orchestrator-turn limit only, with the tier taken from config.load and the
# run driven through a failover, so a fix at either place turns it red. The
# two fixes close different amounts, and the entry says which:
#   * the run's tier made the weakest link's in config.load closes both
#     halves, phases included -- delete the entry as usual;
#   * the tier re-read per active link closes the turn limit only. The phase
#     ceiling, fixed when the form becomes a CampaignConfig, stays open, so
#     if nothing caps or aborts a run at failover, cut the entry down to the
#     phase ceiling instead, and say there that no test ties it.
# The failover note in config.available() is not a fix and leaves this green.
_OPEN_AGENT_LIMITS = [
    ("A failover does not re-derive the capability tier",
     _a_failover_keeps_the_primarys_tier),
]


class TestTheAgentLayerLimitsAreStillOpen(_DocCase):
    def _section(self):
        return self.doc.split("\n### The agent layer\n", 1)[1].split(
            "\n### ", 1)[0]

    def test_each_tied_entry_is_listed_and_still_true_of_the_code(self):
        flat = " ".join(self._section().split()).lower()
        for phrase, still_open in _OPEN_AGENT_LIMITS:
            with self.subTest(entry=phrase):
                self.assertIn(" ".join(phrase.split()).lower(), flat,
                              "%r is not under 'The agent layer'" % phrase)
                self.assertTrue(
                    still_open(),
                    "%r is no longer true of the code: it has been fixed. "
                    "Delete it from Known limits and from "
                    "_OPEN_AGENT_LIMITS." % phrase)


_NUMBER_WORDS = ("zero one two three four five six seven eight nine ten eleven "
                 "twelve thirteen fourteen fifteen sixteen seventeen eighteen "
                 "nineteen twenty").split()


class TestTheReadmeCountsTheTiedLimits(unittest.TestCase):
    """The README promises a test for every limit the code can answer for.

    It says how many, in words. The number was written once and drifted by
    one when an entry was added, so it is derived here: whoever ties another
    limit is sent to the sentence by this test failing.
    """

    def test_the_sentence_states_how_many_entries_are_tied(self):
        tied = (sum(1 for entries in _OPEN_FINDINGS.values()
                    for _, still_open in entries if still_open is not None)
                + len(_OPEN_AGENT_LIMITS))
        found = re.search(r"for the (\w+) of those the code can answer for",
                          README.read_text())
        self.assertIsNotNone(found, "README.md no longer states the count")
        self.assertEqual(found.group(1), _NUMBER_WORDS[tied],
                         "README.md says %r; %d entries have a test tied to "
                         "the code" % (found.group(1), tied))


class _ParserReached(Exception):
    def __init__(self, parser):
        Exception.__init__(self)
        self.parser = parser


# Why this calls main() at all, and why the create_app patch must stay:
# main() builds its parser inline, and extracting a _build_parser() would be a
# production change. So the test runs main() and stops it at parse_args, which
# is the first thing it does. That is only safe while it stays the first
# thing. create_app is patched to raise so that if someone puts work ahead of
# the parse -- reads a key, binds a socket -- this fails loudly instead of
# starting a server from inside the test suite. Do not "simplify" the patch
# away: it is the guard that makes calling main() acceptable.
def _server_parser():
    """The argument parser main() builds, without main() going any further.

    main() builds its parser and parses in one function, and it is the first
    thing the function does. Stopping at parse_args hands back the real
    parser -- every option and default exactly as the server would see them --
    before a key is read, a directory made or a socket opened. create_app is
    patched to fail as well, so that if main() is ever reordered to do
    something before it parses, the test fails instead of serving.
    """
    def stop(self, *args, **kwargs):
        raise _ParserReached(self)

    went_on = AssertionError("main() went past its argument parser")
    with patch.object(argparse.ArgumentParser, "parse_args", stop), \
            patch.object(c2_server, "create_app", side_effect=went_on):
        try:
            c2_server.main()
        except _ParserReached as reached:
            return reached.parser
    raise AssertionError("main() returned without parsing its arguments")


def _fenced(text, *languages):
    """The bodies of the fenced code blocks tagged with one of `languages`."""
    return [body for lang, body in re.findall(r"^```(\w*)\n(.*?)^```", text,
                                              re.M | re.S)
            if lang in languages]


class TestTheRedirectorPageMatchesTheServer(unittest.TestCase):
    """docs/REDIRECTOR.md hands a reader configuration to paste. Its flags and
    ports were once read off the parser by hand; these read them again."""

    @classmethod
    def setUpClass(cls):
        cls.text = REDIRECTOR_DOC.read_text()
        cls.options = _server_parser()._option_string_actions

    def default(self, flag):
        if flag not in self.options:
            self.fail("the server's parser has no %s, which the page's "
                      "proxy targets are checked against" % flag)
        return self.options[flag].default

    def test_the_page_exists_and_the_readme_links_it(self):
        self.assertTrue(REDIRECTOR_DOC.is_file(), "docs/REDIRECTOR.md is gone")
        # A markdown link, not the bare path: the path also appears in prose.
        self.assertTrue(
            re.search(r"\]\((?:\./)?docs/REDIRECTOR\.md(?:#[^)]*)?\)",
                      README.read_text()),
            "README.md does not link docs/REDIRECTOR.md")

    def _proxy_targets(self):
        """(directive, target) for each proxy_pass in an nginx block and each
        reverse_proxy in a Caddy block. Anchored to the start of a line, so
        prose that mentions `proxy_pass` is not a target."""
        found = []
        for body in _fenced(self.text, "nginx"):
            found += [("proxy_pass", t) for t in re.findall(
                r"^\s*proxy_pass\s+(\S+?);?\s*$", body, re.M)]
        for body in _fenced(self.text, "caddyfile", "caddy"):
            found += [("reverse_proxy", t) for t in re.findall(
                r"^\s*reverse_proxy\s+(\S+)", body, re.M)]
        return found

    def test_every_proxy_target_is_the_agent_port_and_none_is_the_operators(self):
        agent = self.default("--port")
        operator = self.default("--operator-port")
        self.assertNotEqual(agent, operator,
                            "the two sockets share a default port, so the "
                            "page cannot tell a proxy target from the GUI")
        targets = self._proxy_targets()
        for directive in ("proxy_pass", "reverse_proxy"):
            self.assertTrue(any(d == directive for d, _ in targets),
                            "no %s target found in the page" % directive)
        for directive, target in targets:
            port = re.search(r":(\d+)$", target)
            self.assertIsNotNone(port, "%s %s names no port" %
                                 (directive, target))
            self.assertNotEqual(int(port.group(1)), operator,
                                "%s %s points at the operator interface"
                                % (directive, target))
            self.assertEqual(int(port.group(1)), agent,
                             "%s %s is not the agent socket's default port"
                             % (directive, target))

    def _flag_table(self):
        """(flag, default) for each row of the 'two sockets' table."""
        rows = _rows_under(self.text, "## The two sockets")
        found = []
        for row in rows[1:]:
            cells = re.match(r"\|\s*`(--[a-z][a-z0-9-]*)`\s*\|\s*`([^`]*)`\s*\|",
                             row)
            self.assertIsNotNone(cells, "a flag-table row names no flag or "
                                 "no default in backticks: %s" % row)
            found.append((cells.group(1), cells.group(2)))
        return found

    def test_every_default_in_the_flag_table_is_the_parsers(self):
        table = self._flag_table()
        self.assertEqual(
            sorted(flag for flag, _ in table),
            ["--host", "--operator-host", "--operator-port", "--port"],
            "the flag table no longer covers the four socket flags")
        for flag, shown in table:
            self.assertEqual(shown, str(self.default(flag)),
                             "the table gives %s a default of %s; the "
                             "parser's is %s"
                             % (flag, shown, self.default(flag)))

    def test_every_default_the_prose_states_is_the_parsers(self):
        # "`--port`, default `8443`": the sentence form of the same fact.
        flat = re.sub(r"\n\s*>?\s*", " ", self.text)
        stated = re.findall(r"`(--[a-z][a-z0-9-]*)`, default `([^`]+)`", flat)
        self.assertTrue(stated, "the page no longer states a default in prose")
        for flag, shown in stated:
            self.assertEqual(shown, str(self.default(flag)),
                             "the prose gives %s a default of %s; the "
                             "parser's is %s"
                             % (flag, shown, self.default(flag)))

    def test_the_ssh_forward_names_the_operator_interface(self):
        # The startup banner builds this line from the operator port and host
        # (server.py: "ssh -L {operator_port}:{operator_host}:{operator_port}
        # <user>@<this-host>"). The banner is printed deep inside main(),
        # past the point this file stops it, so the line is rebuilt here from
        # the parser's defaults rather than read from the banner.
        port = self.default("--operator-port")
        host = self.default("--operator-host")
        # Any other option on the command (ssh -N -L ...) is the page's own
        # business; the forward's three fields are the claim.
        forwards = re.findall(r"^ssh\b[^\n]*?-L (\S+) <user>@<this-host>",
                              self.text, re.M)
        self.assertTrue(forwards, "the page no longer shows an ssh forward")
        for forward in forwards:
            self.assertEqual(forward, "%s:%s:%s" % (port, host, port),
                             "the ssh forward is not the banner's form for "
                             "the operator interface's defaults")
        opened = re.findall(r"://localhost:(\d+)", self.text)
        self.assertTrue(opened, "the page no longer says where to open the GUI")
        for shown in opened:
            self.assertEqual(shown, str(port), "the page opens localhost:%s; "
                             "the operator interface is on %s" % (shown, port))

    def _server_flags(self):
        """The flags the page applies to this server, and nothing else.

        Three places, each one where the subject is unambiguously the server:

        - the flag table's first column;
        - a command line that runs the server (it names software/c2/server.py
          or software.c2.server), with its backslash continuations, up to a
          pipe, `;`, `&&` or comment. Another program's command is not one,
          even in the same code block;
        - an inline code span in prose that is bare flags -- it starts with
          `--` -- or that runs the server. A span led by another command
          (`curl --insecure`, `ssh -L ...`) belongs to that command.

        Everything else is left alone: other programs' flags, the nginx and
        Caddy blocks, a "--" in a sentence.
        """
        flag = r"(?<![^\s])(--[a-z][a-z0-9-]*)"
        runs_server = re.compile(r"software[/.]c2[/.]server")
        flags = {f for f, _ in self._flag_table()}

        fenced = [b for _, b in re.findall(r"^```(\w*)\n(.*?)^```", self.text,
                                           re.M | re.S)]
        for body in fenced:
            for command in re.sub(r"\\\n", " ", body).splitlines():
                ran = runs_server.search(command)
                if ran:
                    rest = re.split(r"[|;]|&&|\s#", command[ran.end():])[0]
                    flags.update(re.findall(flag, rest))

        prose = re.sub(r"^```\w*\n.*?^```", "", self.text, flags=re.M | re.S)
        for span in re.findall(r"`([^`]+)`", prose):
            if span.lstrip().startswith("--") or runs_server.search(span):
                flags.update(re.findall(r"(?<![^\s])(--[a-z][a-z0-9-]*)", span))
        return flags

    def test_every_flag_the_page_applies_to_the_server_is_an_option_of_it(self):
        flags = self._server_flags()
        self.assertTrue(flags, "no server flag found in the page")
        for flag in sorted(flags):
            self.assertTrue(flag in self.options,
                            "the page names %s for the server; the server's "
                            "parser has no such option" % flag)


if __name__ == "__main__":
    unittest.main()
