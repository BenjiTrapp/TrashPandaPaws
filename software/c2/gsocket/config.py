"""Both sides of the gsocket carrier, read from config and refused loudly.

Two blocks in `configs/raccoon.yaml` look alike and mean opposite things:

  * `c2.gsocket_carrier` is **this host as a server** -- the carrier
    processes the team server runs beside its own beacon socket. Each one
    is a `gs-netcat` listening on the relay network under one implant's
    secret and forwarding whatever arrives into the beacon socket. That
    is what `load_carriers` reads.
  * `c2.fallback.gsocket` is **this host as a client** -- the leg an
    implant running here will try, alongside the other four in
    `c2.fallback`. That is what `validate_leg` reads.

Confusing the two would have an operator run a relay listener on a
drop-box, or configure an implant's leg on the team server and then
wonder why no implant ever arrives. `listeners/registry.py` carries the
same warning for `c2.listeners` and `c2.fallback`, and this module
follows it closely, including in the two habits that matter most:

**Every refusal names the offending value**, because the two ways a
gsocket misconfiguration shows up -- a wrong port, a secret file that is
not there -- surface as a carrier that joins the relay network and never
finds its peer. That reads as a relay problem rather than as a wrong
number, and it is the hardest failure in this feature to tell from a
network that is simply hostile.

**A disabled entry is validated exactly as strictly as an enabled one**,
because a typo that waits until the day somebody switches it on has
chosen the worst possible moment to appear. What `enabled` changes is
only whether a *value that nothing has minted yet* may be absent: the
implant's `secret_file` comes from the build generator, so the block
shipped in git cannot name one. That is the rule `c2.encryption_key`
already states one screen up in the same file -- required while the
fallback is enabled, and there is no default.

A missing block is not an error on either side. Every deployment that
predates this feature has neither, and all of them have to keep starting;
`load_listeners` answers the same way for the same reason.

**No secret appears in either block.** The secret is the address on the
relay network, and a config file is something somebody pastes into a
ticket. The server side looks its secrets up in
`gsocket/secrets.py` by `identity`, which is only a name here; the
implant side names a *file*, so that `gs-netcat` can be handed
`-k <path>` instead of `-s <secret>`, which would put the credential in a
world-readable `ps` line.

Nothing here spawns a process or touches the filesystem. In particular
neither side is asked whether its `gs-netcat` binary exists: the carrier
block is validated on the team server, the leg block describes a path on
someone else's hardware, and an existence check would refuse a sound
config for a file it cannot see. The failure that matters arrives at exec
time, from the process that actually needs the binary.
"""

import dataclasses
import os.path
from typing import Any, Dict, List, Optional, Set

_PORT_MIN = 1
_PORT_MAX = 65535

# What the implant's leg takes when the file does not say. Public: this is
# the one place the numbers are written down for anything that can import
# them. `beacon.py` cannot -- it is served to a target as source text and
# may import only the standard library -- so it carries them as a copy,
# and drift between the two is a forward that lands on the wrong port.
#
# `scheme` is "http" and not "https", which is a fact about this
# repository rather than a preference: `server.py`'s `--ssl` is
# `store_true` and off by default, and every shipped `relay_url` in
# `configs/raccoon.yaml` is `http://127.0.0.1:8443`. The beacon socket
# the carrier's forward lands on speaks plain HTTP in the default
# deployment. Confidentiality on that hop rests on two layers that are
# already there: the SRP/AES-256 session gsocket negotiates end to end,
# and the AES-256-GCM envelope inside it.
#
# `max_restarts: 0` means unlimited, the meaning `c2.sliver.max_restarts`
# already has in the same file.
LEG_DEFAULTS = {
    "scheme": "http",
    "local_port": 16443,
    "restart_delay_seconds": 30,
    "max_restarts": 0,
    "ready_timeout_seconds": 20,
}

# Every key each block takes. Anything else is refused rather than
# ignored, and the two lists are also how a refusal can tell an operator
# that the key they wrote is real but lives on the other side.
_CARRIER_KEYS = ("name", "identity", "enabled", "beacon_host", "beacon_port",
                 "binary_path", "sha256")
_LEG_KEYS = ("enabled", "secret_file", "binary_path", "scheme", "local_port",
             "restart_delay_seconds", "max_restarts", "ready_timeout_seconds")

_CARRIER_WHERE = "c2.gsocket_carrier"
_LEG_WHERE = "c2.fallback.gsocket"

# What this host is in each block, in the words a refusal uses.
_CARRIER_ROLE = ("this host as a server: a carrier runs "
                 "`gs-netcat -l -d <beacon_host> -p <beacon_port>` and opens "
                 "no forward of its own")
_LEG_ROLE = ("this host as a client: the leg an implant running here "
             "will try")

# A bind address, which is what `beacon_host` must not be. It is a
# destination for `gs-netcat -d`, and the one way it goes wrong is an
# operator copying `bind_host: 0.0.0.0` out of `c2.listeners` -- which is
# precisely the two sides this module exists to keep apart.
_WILDCARDS = frozenset({"0.0.0.0", "", "*", "::"})

_SHA256_LEN = 64
_HEX = frozenset("0123456789abcdef")


@dataclasses.dataclass
class CarrierSpec:
    """One configured carrier process, validated.

    There is deliberately **no `local_port`**. The server side listens on
    the relay network and connects straight to the beacon socket, so it
    opens no local forward and a `local_port` here would be a
    configurable value with no reader -- the kind that is wrong for a
    year before anybody notices, because nothing ever read it. The
    implant's forward port is `c2.fallback.gsocket.local_port`.

    There is no secret either. `identity` is only a name: the carrier
    supervisor hands it to `secrets.SecretStore.secret_file_for`, which
    writes the credential to a 0600 file and returns the path that
    `gs-netcat -k` is pointed at.

    `sha256` is empty when the binary is not to be verified, the meaning
    `c2.sliver.sha256` already has.
    """

    name: str
    identity: str
    enabled: bool
    beacon_host: str
    beacon_port: int
    binary_path: str
    sha256: str = ""


def load_carriers(config: Optional[dict]) -> List[CarrierSpec]:
    """Read `c2.gsocket_carrier` into validated specs, or raise `ValueError`.

    A config with no such block yields no carriers and is not an error:
    every deployment that predates this feature has none, and all of them
    have to keep starting.
    """
    block = _carrier_block(config)
    specs = []            # type: List[CarrierSpec]
    seen_names = set()    # type: Set[str]
    seen_identities = {}  # type: Dict[str, str]

    for index, entry in enumerate(block):
        if not isinstance(entry, dict):
            raise ValueError(
                "%s[%d] is %s, not a mapping"
                % (_CARRIER_WHERE, index, type(entry).__name__))
        spec = _spec_of(entry, index)

        if spec.name in seen_names:
            raise ValueError(
                "two carriers are called %r; the supervisor starts and stops "
                "by name and the panel shows it, so a duplicate name means "
                "one of them could be neither controlled nor reported"
                % spec.name)
        seen_names.add(spec.name)

        other = seen_identities.get(spec.identity)
        if other is not None:
            # Not a cosmetic clash. The identity selects the secret, and
            # the secret is the address on the relay network: two carrier
            # processes listening under one implant's secret means that
            # implant's connection lands on whichever of them the relay
            # happened to pair it with, which is a coin toss on every
            # check-in rather than an error anybody sees.
            raise ValueError(
                "carriers %r and %r both use identity %r; that is one "
                "implant's secret, so both would listen on one relay "
                "address and its connections would land on whichever of "
                "them the relay network paired them with"
                % (other, spec.name, spec.identity))
        seen_identities[spec.identity] = spec.name

        # No port-collision check here, unlike `load_listeners`: every
        # carrier forwards *into* the team server's single beacon socket
        # rather than binding one, so one carrier per implant all naming
        # 127.0.0.1:8443 is the normal deployment and not a clash.
        specs.append(spec)

    return specs


def validate_leg(block: Optional[dict]) -> dict:
    """Return `c2.fallback.gsocket` with defaults filled, or `ValueError`.

    A missing block validates to a disabled leg carrying `LEG_DEFAULTS`,
    for the same reason an absent `c2.gsocket_carrier` yields no
    carriers.

    `secret_file` and `binary_path` are required only while the leg is
    enabled, because neither exists before a build is generated and the
    block that ships in git therefore cannot name them. Every other
    check runs whether the leg is enabled or not: the value is wrong now,
    and switching the leg on will not make it right.
    """
    if block is None:
        block = {}
    if not isinstance(block, dict):
        raise ValueError("%s is %s, not a mapping"
                         % (_LEG_WHERE, type(block).__name__))
    _refuse_unknown(_LEG_WHERE, block, _LEG_KEYS, _LEG_ROLE,
                    _CARRIER_WHERE, _CARRIER_KEYS, _CARRIER_ROLE)

    enabled = bool(block.get("enabled", False))
    leg = {"enabled": enabled}  # type: Dict[str, Any]

    leg["secret_file"] = _checked_path(
        "%s.secret_file" % _LEG_WHERE, block.get("secret_file"),
        required=enabled,
        why="the secret is this leg's whole address on the relay network, "
            "and it is passed to `gs-netcat -k <path>` rather than "
            "`-s <secret>` so that it never reaches a world-readable `ps` "
            "line. The build generator writes the file")
    leg["binary_path"] = _checked_path(
        "%s.binary_path" % _LEG_WHERE, block.get("binary_path"),
        required=enabled,
        why="it is the `gs-netcat` this leg execs")

    scheme = block.get("scheme", LEG_DEFAULTS["scheme"])
    # Normalised rather than compared as written: a URL scheme is
    # case-insensitive, so refusing "HTTPS" would be pedantry, and the
    # value is turned into a URL by the beacon, which wants one spelling.
    normalised = scheme.strip().lower() if isinstance(scheme, str) else None
    if normalised not in ("http", "https"):
        raise ValueError(
            "%s.scheme is %r; it must be http or https. It is the scheme of "
            "the URL the beacon builds against its own forward, and the "
            "default is http because the team server's `--ssl` is off by "
            "default and every shipped relay_url is http://"
            % (_LEG_WHERE, scheme))
    leg["scheme"] = normalised

    leg["local_port"] = _checked_port(
        "%s.local_port" % _LEG_WHERE,
        block.get("local_port", LEG_DEFAULTS["local_port"]),
        why="it is the loopback port `gs-netcat` forwards from on the "
            "implant, which the beacon then addresses")
    leg["restart_delay_seconds"] = _checked_whole(
        "%s.restart_delay_seconds" % _LEG_WHERE,
        block.get("restart_delay_seconds",
                  LEG_DEFAULTS["restart_delay_seconds"]),
        minimum=1,
        why="zero would restart the carrier as fast as `gs-netcat` can "
            "fail, which is a busy loop on the implant's CPU and a flood "
            "of joins on the relay network -- both of them loud in exactly "
            "the place an implant has to be quiet")
    leg["max_restarts"] = _checked_whole(
        "%s.max_restarts" % _LEG_WHERE,
        block.get("max_restarts", LEG_DEFAULTS["max_restarts"]),
        minimum=0,
        why="0 means unlimited, as it does for c2.sliver.max_restarts")
    leg["ready_timeout_seconds"] = _checked_whole(
        "%s.ready_timeout_seconds" % _LEG_WHERE,
        block.get("ready_timeout_seconds",
                  LEG_DEFAULTS["ready_timeout_seconds"]),
        minimum=1,
        why="it is how long the forward is given to come up, and zero "
            "would declare every carrier not-ready the instant it started, "
            "so the leg would never be used and nothing would say why")

    return leg


def _carrier_block(config: Optional[dict]) -> list:
    if not isinstance(config, dict):
        return []
    c2 = config.get("c2")
    if not isinstance(c2, dict):
        return []
    block = c2.get("gsocket_carrier")
    if block is None:
        return []
    if not isinstance(block, list):
        raise ValueError(
            "%s is %s, not a list of carriers. It is one carrier per "
            "implant, because one secret per implant is what keeps a "
            "recovered device from handing its finder a path to every "
            "other one" % (_CARRIER_WHERE, type(block).__name__))
    return block


def _spec_of(entry: dict, index: int) -> CarrierSpec:
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("%s[%d] has no name" % (_CARRIER_WHERE, index))
    name = name.strip()

    _refuse_unknown("carrier %r" % name, entry, _CARRIER_KEYS, _CARRIER_ROLE,
                    _LEG_WHERE, _LEG_KEYS, _LEG_ROLE)

    identity = entry.get("identity")
    if not isinstance(identity, str) or not identity.strip():
        raise ValueError(
            "carrier %r has identity %r; it must be a non-empty string. The "
            "identity is which implant's secret this carrier listens under, "
            "looked up in the secret store, and the secret is the whole "
            "address on the relay network" % (name, identity))
    identity = identity.strip()

    beacon_host = entry.get("beacon_host")
    if not isinstance(beacon_host, str) \
            or beacon_host.strip() in _WILDCARDS:
        raise ValueError(
            "carrier %r has beacon_host %r; it must be a host this machine "
            "can connect to, usually 127.0.0.1. It is the destination of "
            "`gs-netcat -d`, not an address to bind: a wildcard here is a "
            "`bind_host` copied out of c2.listeners, which is the other "
            "side of this file" % (name, beacon_host))
    beacon_host = beacon_host.strip()

    beacon_port = _checked_port(
        "carrier %r: beacon_port" % name, entry.get("beacon_port"),
        why="it is the team server's beacon socket, which this carrier "
            "forwards into")

    binary_path = _checked_path(
        "carrier %r: binary_path" % name, entry.get("binary_path"),
        required=True,
        why="it is the `gs-netcat` the supervisor execs")

    return CarrierSpec(name=name, identity=identity,
                       enabled=bool(entry.get("enabled", False)),
                       beacon_host=beacon_host, beacon_port=beacon_port,
                       binary_path=binary_path,
                       sha256=_checked_sha256(name, entry.get("sha256", "")))


def _refuse_unknown(label: str, mapping: dict, accepted, role: str,
                    other_where: str, other_keys, other_role: str) -> None:
    """Raise if `mapping` holds a key this block does not take.

    Refused rather than ignored, for the reason `listeners/registry.py`
    gives: a setting that is silently dropped looks exactly like one that
    was applied.

    A key that is real but belongs to the *other* block gets told so by
    name. That is the mistake this pair of blocks actually produces --
    they read almost identically and mean opposite things -- and
    "unknown setting" alone would send an operator looking for a typo in
    a word they spelled correctly.
    """
    unknown = sorted(set(mapping) - set(accepted))
    if not unknown:
        return
    message = (
        "%s takes no setting called %s; it accepts %s. A setting dropped "
        "silently looks exactly like one that was applied"
        % (label, ", ".join(unknown), ", ".join(sorted(accepted))))
    crossed = [key for key in unknown if key in other_keys]
    if crossed:
        message += (
            ". %s belongs to %s, which is %s, while this block is %s"
            % (", ".join(crossed), other_where, other_role, role))
    raise ValueError(message)


def _checked_port(label: str, value, why: str) -> int:
    """`value` as a port, or raise naming it."""
    # bool is an int in Python, and `beacon_port: true` is a plausible
    # YAML typo that would otherwise pass as port 1.
    if isinstance(value, bool) or not isinstance(value, int) \
            or not _PORT_MIN <= value <= _PORT_MAX:
        raise ValueError(
            "%s is %r; it must be an integer between %d and %d: %s"
            % (label, value, _PORT_MIN, _PORT_MAX, why))
    return value


def _checked_whole(label: str, value, minimum: int, why: str) -> int:
    """`value` as an integer of at least `minimum`, or raise naming it."""
    if isinstance(value, bool) or not isinstance(value, int) \
            or value < minimum:
        raise ValueError(
            "%s is %r; it must be an integer of at least %d: %s"
            % (label, value, minimum, why))
    return value


def _checked_path(label: str, value, required: bool, why: str) -> str:
    """`value` as an absolute path, "" when nothing needs one yet, or raise.

    `None` counts as absent, because that is what a bare `secret_file:`
    in YAML parses to and a block shipped before any build is generated
    is written exactly that way.
    """
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(
            "%s is %r, which is %s and not a path: %s"
            % (label, value, type(value).__name__, why))
    text = value.strip()
    if not text:
        if required:
            raise ValueError("%s is empty and is needed: %s" % (label, why))
        return ""
    if not os.path.isabs(text):
        raise ValueError(
            "%s is %r, which is relative. The working directory of the "
            "process that reads it is not ours to assume -- systemd hands a "
            "unit `/`, an operator's shell hands it their home -- so a "
            "relative path is a different file depending on who started "
            "the process, or none at all. Write it out in full"
            % (label, text))
    return text


def _checked_sha256(name: str, value) -> str:
    """A lower-cased hex digest, or "" for "do not verify"."""
    if not isinstance(value, str):
        raise ValueError(
            "carrier %r has sha256 %r, which is %s and not a hex digest"
            % (name, value, type(value).__name__))
    digest = value.strip().lower()
    if not digest:
        # Empty is "do not verify", the meaning `c2.sliver.sha256` has.
        return ""
    if len(digest) != _SHA256_LEN or set(digest) - _HEX:
        raise ValueError(
            "carrier %r has sha256 %r; it must be %d hex characters, which "
            "is what `sha256sum` prints, or empty to skip the check"
            % (name, value, _SHA256_LEN))
    # Lower-cased because what it is compared against is
    # `hashlib.sha256(...).hexdigest()`, and an upper-case digest pasted
    # out of a Windows tool would never match.
    return digest
