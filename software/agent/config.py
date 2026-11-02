#!/usr/bin/env python3
"""Configuration for the autonomous agent: the service, and a campaign.

Two things live here. AgentConfig is what the service is started with: which
model, where the C2 is, where to bind. CampaignConfig is what the operator's
form posts for one run: which beacons, what scope, how much risk.

AgentConfig resolves each field on its own through four levels, strongest
first: command line, the `agent:` block of raccoon.yaml, an environment
variable, a built-in default. A flag for one field therefore leaves the YAML
value of every other field alone.

Secrets are the exception to the cascade. The LLM API key, the C2 token and
the agent token are never read from the YAML: it lives in git, and a key
committed to it is the failure this project most wants to avoid. They come
from the environment, and the API key may instead come from a file that only
its owner can read. Nor do they come from the command line, where `ps` shows
them.

Usage:
    from software.agent import config

    cfg = config.load(yaml_path="configs/raccoon.yaml")
    ok, reason = cfg.available()
    campaign = config.CampaignConfig.from_form(payload, tier=cfg.capability_tier)
"""

import argparse
import math
import os
import stat
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Set, Tuple

import yaml

from software.agent import scope
from software.agent.llm import provider as llm_provider


class ConfigError(Exception):
    """A configuration that cannot be used. Never carries a secret's value."""


def _warn(message: str) -> None:
    print("agent config: %s" % message, file=sys.stderr)


# ── Values ──
#
# A converter takes a raw value and a label for the error message, and
# returns the value or raises ConfigError. Blank (None, or an empty string)
# is handled before conversion and means "not set": the shipped YAML carries
# `provider: ""`, which must fall through to the environment rather than
# shadow it with nothing.


def _blank(raw: Any) -> bool:
    return raw is None or (isinstance(raw, str) and not raw.strip())


def _text(raw, label):
    return str(raw).strip()


def _lowered(raw, label):
    return str(raw).strip().lower()


def _enum(*valid: str) -> Callable:
    def convert(raw, label):
        value = str(raw).strip().lower()
        if value not in valid:
            raise ConfigError("%s: %r is not valid; valid values: %s"
                              % (label, str(raw), ", ".join(valid)))
        return value
    return convert


def _to_float(raw, label):
    # bool is an int to Python, and True would otherwise read as 1.0.
    if isinstance(raw, bool):
        raise ConfigError("%s: expected a number, got %r" % (label, raw))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ConfigError("%s: %r is not a number" % (label, raw)) from None
    # float("nan") parses, and nan compares false against every bound.
    if not math.isfinite(value):
        raise ConfigError("%s: %r is not a finite number" % (label, raw))
    return value


def _to_int(raw, label):
    value = _to_float(raw, label)
    if value != int(value):
        raise ConfigError("%s: %r is not a whole number" % (label, raw))
    return int(value)


def _to_bool(raw, label):
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise ConfigError("%s: %r is not true or false" % (label, str(raw)))


def _bounded(convert: Callable, low=None, high=None,
             low_open: bool = False) -> Callable:
    def check(raw, label):
        value = convert(raw, label)
        if low is not None and (value <= low if low_open else value < low):
            raise ConfigError("%s: %s is out of range (must be %s %s)"
                              % (label, value, ">" if low_open else ">=", low))
        if high is not None and value > high:
            raise ConfigError("%s: %s is out of range (must be <= %s)"
                              % (label, value, high))
        return value
    return check


# ── AgentConfig ──

LOG_LEVELS = ("off", "full")

_DEFAULT_DB_PATH = "/data/raccoon-c2/agent.db"
_DEFAULT_C2_URL = "https://127.0.0.1:8443"
_DEFAULT_BIND_HOST = "127.0.0.1"
_DEFAULT_BIND_PORT = 8099
_DEFAULT_MAX_EXECUTORS = 4
_DEFAULT_APPROVAL_TIMEOUT = 300.0

_SLIVER_REASON = (
    "Sliver is enabled (c2.sliver.enabled in raccoon.yaml): a Sliver-managed "
    "drop-box runs the Sliver implant and never checks in to the Raccoon C2 "
    "server, so the agent would see no beacons. Set c2.sliver.enabled to "
    "false and restart the drop-box to run the Python beacon the agent drives")

# Shorter than this, a replace() would mangle the reason around a coincidental
# match; a real key is far longer.
_SCRUB_MIN_LENGTH = 8


@dataclass
class AgentConfig:
    provider: Optional[str] = None
    # repr=False on every secret: a dataclass prints each field by default,
    # and a config object ends up in logs and in exception messages.
    api_key: Optional[str] = field(default=None, repr=False)
    model: Optional[str] = None
    base_url: Optional[str] = None
    capability_tier: str = "reduced"
    llm_log_level: str = "off"
    db_path: str = _DEFAULT_DB_PATH
    c2_url: str = _DEFAULT_C2_URL
    c2_token: Optional[str] = field(default=None, repr=False)
    c2_verify_tls: bool = False
    bind_host: str = _DEFAULT_BIND_HOST
    bind_port: int = _DEFAULT_BIND_PORT
    agent_token: Optional[str] = field(default=None, repr=False)
    max_concurrent_executors: int = _DEFAULT_MAX_EXECUTORS
    approval_timeout: float = _DEFAULT_APPROVAL_TIMEOUT
    # Not an agent setting but a fact about the drop-box, read from the C2
    # block of the same file, because available() has to answer for it.
    sliver_enabled: bool = False

    def available(self) -> Tuple[bool, str]:
        """(usable, reason) for the status endpoint; reason is "" when usable.

        Every problem is reported, not the first: an operator who fixes the
        provider only to meet the Sliver conflict next has been sent round
        twice. The provider checks are create_client's own, so what this
        reports and what starting a campaign refuses cannot disagree.
        """
        problems = []
        try:
            llm_provider.create_client(self)
        except llm_provider.ProviderError as exc:
            problems.append(str(exc))
        # Spec §5.2. A comment in the YAML is not enough: this is what the
        # status endpoint shows, and the alternative is an empty beacon list
        # with no explanation.
        if self.sliver_enabled:
            problems.append(_SLIVER_REASON)
        if not problems:
            return True, ""
        reason = "; ".join(problems)
        # ProviderError promises not to carry the key, and this is not the
        # place to find out it broke that promise.
        if self.api_key and len(self.api_key) >= _SCRUB_MIN_LENGTH:
            reason = reason.replace(self.api_key, "<redacted>")
        return False, reason


class _Field(NamedTuple):
    name: str
    path: Tuple[str, ...]
    env: str
    convert: Callable
    default: Any
    help: str


_FIELDS = (
    _Field("provider", ("agent", "llm", "provider"), "AGENT_PROVIDER",
           _lowered, None, "LLM provider name"),
    _Field("model", ("agent", "llm", "model"), "AGENT_MODEL", _text, None,
           "model id; required, there is no default that would not go stale"),
    _Field("base_url", ("agent", "llm", "base_url"), "AGENT_BASE_URL", _text,
           None, "endpoint, for providers with no built-in one"),
    _Field("llm_log_level", ("agent", "llm", "llm_log_level"),
           "AGENT_LLM_LOG_LEVEL", _enum(*LOG_LEVELS), "off",
           "store prompt and response text (%s)" % ", ".join(LOG_LEVELS)),
    # An override: left unset, the tier is derived from model and provider.
    _Field("capability_tier", ("agent", "llm", "capability_tier"),
           "AGENT_CAPABILITY_TIER", _enum(*llm_provider.TIER_LIMITS), None,
           "force a capability tier instead of deriving it from the model"),
    _Field("api_key_file", ("agent", "llm", "api_key_file"),
           "AGENT_API_KEY_FILE", _text, None,
           "file holding the API key; must be readable by its owner only"),
    _Field("db_path", ("agent", "service", "db_path"), "AGENT_DB_PATH", _text,
           _DEFAULT_DB_PATH, "SQLite database of the agent"),
    _Field("c2_url", ("agent", "c2", "url"), "AGENT_C2_URL", _text,
           _DEFAULT_C2_URL, "base URL of the Raccoon C2 server"),
    _Field("c2_verify_tls", ("agent", "c2", "verify_tls"),
           "AGENT_C2_VERIFY_TLS", _to_bool, False,
           "verify the C2 certificate; off because it is self-signed"),
    _Field("bind_host", ("agent", "service", "bind_host"), "AGENT_BIND_HOST",
           _text, _DEFAULT_BIND_HOST, "address the agent service binds to"),
    _Field("bind_port", ("agent", "service", "bind_port"), "AGENT_BIND_PORT",
           _bounded(_to_int, 1, 65535), _DEFAULT_BIND_PORT,
           "port the agent service binds to"),
    _Field("max_concurrent_executors",
           ("agent", "limits", "max_concurrent_executors"),
           "AGENT_MAX_CONCURRENT_EXECUTORS", _bounded(_to_int, 1),
           _DEFAULT_MAX_EXECUTORS, "executors running at once"),
    _Field("approval_timeout", ("agent", "limits", "approval_timeout"),
           "AGENT_APPROVAL_TIMEOUT", _bounded(_to_float, 0, low_open=True),
           _DEFAULT_APPROVAL_TIMEOUT,
           "seconds to wait for an operator's answer"),
)

# Where a secret could be written in the YAML. Looked for only to say it was
# ignored: a secret that sits in a file under git needs rotating, and the
# operator should hear it.
_YAML_SECRET_PATHS = (("agent", "llm", "api_key"),
                      ("agent", "c2", "token"),
                      ("agent", "service", "agent_token"))

_API_KEY_ENV = "AGENT_API_KEY"
_C2_TOKEN_ENV = "RACCOON_TOKEN"
_AGENT_TOKEN_ENV = "RACCOON_AGENT_TOKEN"


def _parse_cli(argv) -> Dict[str, Any]:
    # allow_abbrev off: `--prov` quietly meaning `--provider` is fine until
    # a later flag makes it ambiguous.
    parser = argparse.ArgumentParser(
        prog="agent", description="Autonomous agent service",
        allow_abbrev=False)
    for f in _FIELDS:
        flag = "--" + f.name.replace("_", "-")
        if f.convert is _to_bool:
            parser.add_argument(flag, dest=f.name, default=None, help=f.help,
                                action=argparse.BooleanOptionalAction)
        else:
            # Everything is taken as text and converted by the same code the
            # other levels use, so a bad value is a ConfigError wherever it
            # came from and not an argparse exit for this level alone.
            parser.add_argument(flag, dest=f.name, default=None, help=f.help)
    return vars(parser.parse_args(argv))


def _read_yaml(path: Optional[str]) -> dict:
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        # The class only: a YAML error quotes the offending lines, and this
        # file is one an operator may have put something sensitive in.
        _warn("cannot read %s (%s); using defaults" % (path, type(exc).__name__))
        return {}
    if data is None:
        return {}
    if not isinstance(data, dict):
        _warn("%s is not a mapping; using defaults" % path)
        return {}
    return data


def _dig(data: dict, path: Tuple[str, ...]) -> Any:
    node = data
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _resolve(f: _Field, cli: dict, data: dict, env) -> Any:
    sources = (
        ("command line", cli.get(f.name)),
        ("%s in the YAML" % ".".join(f.path), _dig(data, f.path)),
        ("environment variable %s" % f.env, env.get(f.env)),
    )
    for where, raw in sources:
        if not _blank(raw):
            return f.convert(raw, "%s (%s)" % (f.name, where))
    return f.default


def _from_env(env, name: str) -> Optional[str]:
    raw = env.get(name)
    return None if _blank(raw) else str(raw).strip()


def _read_keyfile(path: str) -> str:
    """The key in a file only its owner can read.

    The mode is checked on the descriptor that is then read, not on the path
    beforehand, so the file cannot be swapped between check and read. Every
    message names the path and the mode and nothing of the content.
    """
    path = os.path.expanduser(path)
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        raise ConfigError("api_key_file %s cannot be opened (%s)"
                          % (path, exc.strerror)) from None
    # fstat before fdopen: opening a directory as text raises at fdopen.
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("api_key_file %s is not a regular file" % path)
        # Any group or other bit, not only "not 0644": 0640 shares the key
        # with a group just as surely. 0400 passes; it is stricter than 0600.
        if info.st_mode & 0o077:
            raise ConfigError(
                "api_key_file %s has mode %04o; it holds a secret and must be "
                "readable by its owner only (chmod 600)"
                % (path, stat.S_IMODE(info.st_mode)))
    except ConfigError:
        os.close(fd)
        raise
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        try:
            key = handle.read().strip()
        except (OSError, UnicodeDecodeError):
            raise ConfigError("api_key_file %s cannot be read as text"
                              % path) from None
    if not key:
        raise ConfigError("api_key_file %s is empty" % path)
    return key


def load(argv=None, yaml_path=None, env=None) -> AgentConfig:
    """Resolve the service configuration.

    argv=None reads the process's own arguments and env=None its own
    environment; both are parameters so that nothing here depends on the
    machine it runs on when a caller passes its own. yaml_path=None means no
    YAML at all, not a search: the caller knows where its file is. A YAML
    that is missing or unreadable is warned about on stderr and the defaults
    stand.
    """
    env = os.environ if env is None else env
    cli = _parse_cli(argv)
    data = _read_yaml(yaml_path)

    if "agent" in data and not isinstance(data["agent"], dict):
        _warn("`agent` in %s is not a mapping; ignoring it" % yaml_path)
    for path in _YAML_SECRET_PATHS:
        if not _blank(_dig(data, path)):
            _warn("%s in %s is ignored: secrets are read from the environment "
                  "(or api_key_file), never from a file under git; rotate "
                  "anything that was written there" % (".".join(path), yaml_path))

    values = {f.name: _resolve(f, cli, data, env) for f in _FIELDS}

    key_file = values.pop("api_key_file")
    api_key = _read_keyfile(key_file) if key_file else _from_env(env, _API_KEY_ENV)

    tier = values.pop("capability_tier") or llm_provider.capability_tier(
        values["model"], values["provider"])

    sliver = _dig(data, ("c2", "sliver", "enabled"))
    sliver_enabled = False if _blank(sliver) else _to_bool(
        sliver, "c2.sliver.enabled")

    return AgentConfig(
        api_key=api_key, capability_tier=tier,
        c2_token=_from_env(env, _C2_TOKEN_ENV),
        agent_token=_from_env(env, _AGENT_TOKEN_ENV),
        sliver_enabled=sliver_enabled, **values)


# ── Risk profiles ──
#
# Each profile sets the four numbers the EV gate arbitrates with. See the EV
# calibration amendment (docs/superpowers/specs/2026-11-02-ev-calibration-
# amendment.md): EV = points * p_success - risk_coefficient * p_detect.
#
# risk_coefficient is its own setting rather than derived from the budget, so
# that changing the budget cannot silently shift how aggressive a profile is.
# Roughly 100 / detection_budget: a detection spends that share of the run's
# tolerance.
#
# Measured against safety.RISK_TABLE with no detection yet: normal allows the
# eight actions that unlock something and refuses the three worth nothing
# (device_write_unknown, log_clear, shadow_copy_delete); passive allows only
# exploit_known_poc, persist and remote_exec; aggressive allows the same eight
# as normal.
#
# The three worth-nothing actions are what a threshold can quietly admit, so
# aggressive's threshold is -5, not the -15 the amendment's table gives. At
# R=25 the unknown device write has EV -7.5: -15 let it through, and every
# other tier-2 row is already positive under that profile, so a threshold
# below -7.5 bought nothing except an unwatched write to storage. -5 keeps the
# profile looser than normal and that action refused. The property is pinned
# by TestZeroValueActionsStayRefused, which walks every profile.
# ── OpSec profiles ──
#
# A different axis from the risk profile, and the distinction matters. The
# risk profile prices being noticed *on the target network*. This prices what
# leaves the operator's own host to a third party, and what the target hears
# in terms of raw scan volume.
#
# What the agent sends outward, measured:
#   · the CVE lookup  → osv.dev and nvd.nist.gov learn a service and version
#                       found on a client host, timed with the engagement
#   · the LLM provider → sees the whole conversation: hostnames, versions,
#                       recovered credentials, topology
#   · the C2          → the operator's own infrastructure, not a third party
#
# So "quiet" is honest only about the first. The provider is the larger
# exposure by far and cannot be switched off — no model, no agent — which is
# what `opsec_warnings` says out loud. A genuinely quiet run is quiet plus
# `provider: local`, which the provider matrix already supports.
#
# `yolo` lifts the scan rate limits. It does **not** touch the tier-1 blocks
# or the approval gate, and TestOpsecProfilesAreNotSafetySwitches pins that:
# the name invites exactly that reading, so the suite refuses it.
OPSEC_PROFILES = {
    "quiet":  {"online_lookups": False, "limit_scan_rate": True},
    "normal": {"online_lookups": True,  "limit_scan_rate": True},
    "yolo":   {"online_lookups": True,  "limit_scan_rate": False},
}


def opsec_warnings(agent, campaign) -> List[str]:
    """What a chosen profile does not deliver, in the operator's words.

    A profile named "quiet" that leaves every finding flowing to a hosted
    model would be a promise the configuration does not keep.
    """
    out = []
    profile = getattr(campaign, "opsec_profile", "normal")
    if profile == "quiet" and getattr(agent, "provider", None) != "local":
        out.append(
            "opsec_profile is quiet, but the model provider is %r: every "
            "finding, hostname and recovered credential still goes to it. "
            "Set provider to local for a run that leaves nothing."
            % (getattr(agent, "provider", None),))
    if not OPSEC_PROFILES.get(profile, {}).get("limit_scan_rate", True):
        out.append(
            "opsec_profile is %s: scan rate limits are not applied, so scans "
            "are as loud as the tool's defaults. Tier-1 blocks and the "
            "approval gate are unaffected." % profile)
    return out


RISK_PROFILES = {
    "passive":    {"ev_threshold":  20.0, "p_detect_prior": 0.25,
                   "detection_budget": 2, "risk_coefficient": 50.0},
    "normal":     {"ev_threshold":   0.0, "p_detect_prior": 0.15,
                   "detection_budget": 3, "risk_coefficient": 33.0},
    "aggressive": {"ev_threshold":  -5.0, "p_detect_prior": 0.10,
                   "detection_budget": 4, "risk_coefficient": 25.0},
}  # type: Dict[str, dict]


# ── CampaignConfig ──

_DEFAULT_PHASES = (1, 2, 3, 4)
# 1-5 are the engagement phases and 6-8 the Wifi ones. All are accepted from
# the form and then capped with the rest above the tier's max_phase.
_phase = _bounded(_to_int, 1, 8)
_MODES = ("supervised", "auto")
_UNATTENDED = ("decide", "skip", "pause")


@dataclass
class CampaignConfig:
    beacons: List[str]
    scope_allow: List[str]
    scope_deny: List[str]
    phases: Set[int]
    risk_profile: str
    ev_threshold: float
    p_detect_prior: float
    detection_budget: int
    risk_coefficient: float
    unattended_behavior: str
    max_runtime_seconds: float
    max_tokens_total: int
    campaign_interval: int
    restore_interval: int
    mode: str
    opsec_profile: str = "normal"
    online_lookups: bool = True
    limit_scan_rate: bool = True

    @classmethod
    def from_form(cls, payload: dict, *, tier: str) -> "CampaignConfig":
        """The form's payload as a campaign, with the tier's ceiling applied.

        The risk profile is the base; a field the form supplies explicitly
        replaces the profile's value for that field alone. A field that is
        absent, null or blank counts as not supplied, so zero stays a value.
        """
        if not isinstance(payload, dict):
            raise ConfigError("the campaign form must be a JSON object")
        if tier not in llm_provider.TIER_LIMITS:
            raise ConfigError("unknown capability tier %r; valid values: %s"
                              % (tier, ", ".join(llm_provider.TIER_LIMITS)))

        def pick(key, convert, default):
            raw = payload.get(key)
            return default if _blank(raw) else convert(raw, key)

        profile = pick("risk_profile", _enum(*RISK_PROFILES), "normal")
        base = RISK_PROFILES[profile]
        opsec = pick("opsec_profile", _enum(*OPSEC_PROFILES), "normal")
        opsec_base = OPSEC_PROFILES[opsec]

        beacons = _string_list(payload, "beacons")
        allow = _string_list(payload, "scope_allow")
        deny = _string_list(payload, "scope_deny")
        if not beacons:
            raise ConfigError("beacons is empty; a campaign needs a target")
        if not allow:
            raise ConfigError(
                "scope_allow is empty; a campaign needs an authorised scope, "
                "and an empty one would authorise nothing")
        # Scope's own parser, so a typo is refused here and not at the first
        # command. It also refuses an allow entry with host bits set.
        try:
            scope.Scope(allow, deny)
        except ValueError as exc:
            raise ConfigError("scope: %s" % exc) from None

        return cls(
            beacons=beacons, scope_allow=allow, scope_deny=deny,
            phases=_phases(payload, tier), risk_profile=profile,
            ev_threshold=pick("ev_threshold", _to_float, base["ev_threshold"]),
            p_detect_prior=pick("p_detect_prior", _bounded(_to_float, 0, 1),
                                base["p_detect_prior"]),
            detection_budget=pick("detection_budget", _bounded(_to_int, 1),
                                  base["detection_budget"]),
            # Not zero: R=0 prices a detection at nothing, and a negative R
            # would pay for being noticed.
            risk_coefficient=pick("risk_coefficient",
                                  _bounded(_to_float, 0, low_open=True),
                                  base["risk_coefficient"]),
            opsec_profile=opsec,
            online_lookups=pick("online_lookups", _to_bool,
                                opsec_base["online_lookups"]),
            limit_scan_rate=pick("limit_scan_rate", _to_bool,
                                 opsec_base["limit_scan_rate"]),
            unattended_behavior=pick("unattended_behavior",
                                     _enum(*_UNATTENDED), "decide"),
            max_runtime_seconds=pick("max_runtime_seconds",
                                     _bounded(_to_float, 0, low_open=True),
                                     7200.0),
            max_tokens_total=pick("max_tokens_total", _bounded(_to_int, 1),
                                  500_000),
            campaign_interval=pick("campaign_interval", _bounded(_to_int, 1),
                                   15),
            # The C2's own beacon interval, which the run puts back afterwards.
            restore_interval=pick("restore_interval", _bounded(_to_int, 1),
                                  300),
            # Supervised unless auto is asked for: unattended operation is the
            # thing that must be a decision, not a fallback.
            mode=pick("mode", _enum(*_MODES), "supervised"),
        )


def _string_list(payload: dict, key: str) -> List[str]:
    raw = payload.get(key)
    if raw is None:
        return []
    # A bare string is a list of characters to the loop below.
    if not isinstance(raw, (list, tuple)):
        raise ConfigError("%s must be a list" % key)
    items = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError("%s must hold non-empty strings" % key)
        items.append(item.strip())
    return items


def _phases(payload: dict, tier: str) -> Set[int]:
    raw = payload.get("phases")
    if raw is None:
        requested = set(_DEFAULT_PHASES)
    else:
        if not isinstance(raw, (list, tuple, set)):
            raise ConfigError("phases must be a list")
        requested = set()
        for item in raw:
            requested.add(_phase(item, "phases"))
    if not requested:
        raise ConfigError("phases is empty; a campaign needs at least one")
    ceiling = llm_provider.TIER_LIMITS[tier]["max_phase"]
    # Capped silently on purpose: the form shows the tier so the operator can
    # see why phase 5 is locked, and a model that cannot be trusted with
    # exploitation must not get it because a form asked.
    allowed = {p for p in requested if p <= ceiling}
    if not allowed:
        raise ConfigError(
            "none of the requested phases %s are available at capability "
            "tier %r (highest phase %d)" % (sorted(requested), tier, ceiling))
    return allowed
