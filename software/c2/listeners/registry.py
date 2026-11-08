"""Turning a configuration block into listeners, and refusing the ones that lie.

Two blocks in `configs/raccoon.yaml` look alike and mean opposite things:

  * `c2.listeners` is the **server** side -- sockets this deployment opens
    for beacons to reach. That is what this module reads.
  * `c2.fallback.*` is the **beacon** side -- channels an implant running
    on this host will try. That is read by
    `beacon.beacon_config_from_fallback`.

Confusing the two would have an operator open a listening socket on a
drop-box, or configure a beacon and then wonder why nothing answers.

Everything here is refused loudly and early. A listener is a socket on a
network-facing host, and the two ways a misconfiguration usually shows up
-- a port that was already taken, a relay that points nowhere -- surface
as a beacon that simply never checks in, which is the hardest failure in
this project to tell from a dozen others. So a config that cannot work is
an error when it is read, with the offending value in the message, and a
disabled listener is validated exactly as strictly as an enabled one: a
typo that waits until the day somebody switches it on has chosen the
worst possible moment to appear.
"""

import dataclasses
from typing import Any, Dict, List, Optional

from .dns import DnsListener
from .quic import QuicListener
from .smb import SmbListener

# transport name -> (class, settings it requires, settings it accepts)
#
# This is the one list of transports the running system has. The rig and
# the local environment read it through `transport_names` rather than
# keeping a second copy, because two lists of the same three things drift.
_TRANSPORTS = {
    "smb": (SmbListener, (), ("pipe_name",)),
    "quic": (QuicListener, (), ()),
    "dns": (DnsListener, ("zone",), ("zone", "ttl")),
}

_PORT_MIN = 1
_PORT_MAX = 65535

# A bind address that covers every interface, so it collides with any
# specific address on the same port rather than coexisting with it.
_WILDCARDS = frozenset({"0.0.0.0", "", "*", "::"})


@dataclasses.dataclass
class ListenerSpec:
    """One configured listener, validated.

    `settings` holds whatever that transport takes beyond the common
    fields. It never holds the listener token: that is a shared secret, it
    belongs with the other secrets rather than in a configuration file
    somebody will paste into a ticket, and `build` takes it as an
    argument.
    """

    name: str
    transport: str
    enabled: bool
    bind_host: str
    bind_port: int
    relay_url: str
    settings: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def build(self, listener_token: Optional[str] = None, sock=None):
        """Construct the listener this spec describes.

        `sock` is a pre-bound socket for socket activation: when systemd
        or dockerd owns the privileged port, the descriptor is handed over
        and `bind_host`/`bind_port` are only what the panel displays.

        Raises `ValueError` if the transport needs a token and none was
        given, rather than building something that will refuse every
        beacon for a reason nobody can see from the outside.
        """
        cls, _required, _accepted = _TRANSPORTS[self.transport]
        kwargs = dict(self.settings)
        kwargs["relay_url"] = self.relay_url
        if sock is not None:
            kwargs["sock"] = sock
        if self.transport == "dns":
            if not listener_token:
                raise ValueError(
                    "listener %r is a DNS listener and needs the listener "
                    "token: it reads tasking from the team server over an "
                    "authenticated route, and without the token every "
                    "answer would be empty" % self.name)
            kwargs["listener_token"] = listener_token
        return cls(self.bind_host, self.bind_port, **kwargs)


def transport_names() -> List[str]:
    return sorted(_TRANSPORTS)


def load_listeners(config: Optional[dict]) -> List[ListenerSpec]:
    """Read `c2.listeners` into validated specs, or raise `ValueError`.

    A config with no such block yields no listeners and is not an error:
    every deployment that predates this feature has none, and all of them
    have to keep starting.
    """
    block = _listeners_block(config)
    specs = []                       # type: List[ListenerSpec]
    seen_names = {}                  # type: Dict[str, str]
    seen_ports = {}                  # type: Dict[int, str]

    for index, entry in enumerate(block):
        if not isinstance(entry, dict):
            raise ValueError(
                "c2.listeners[%d] is %s, not a mapping"
                % (index, type(entry).__name__))
        spec = _spec_of(entry, index)

        if spec.name in seen_names:
            raise ValueError(
                "two listeners are called %r; task 8 starts and stops by "
                "name and the panel shows it, so a duplicate name means one "
                "of them could be neither controlled nor reported"
                % spec.name)
        seen_names[spec.name] = spec.name

        other = seen_ports.get(spec.bind_port)
        if other is not None and _collides(spec, specs, other):
            raise ValueError(
                "listeners %r and %r both bind port %d; that is one socket, "
                "and the second to start would fail at bind time with an "
                "error nobody is watching for"
                % (other, spec.name, spec.bind_port))
        seen_ports.setdefault(spec.bind_port, spec.name)
        specs.append(spec)

    return specs


def _listeners_block(config: Optional[dict]) -> list:
    if not isinstance(config, dict):
        return []
    c2 = config.get("c2")
    if not isinstance(c2, dict):
        return []
    block = c2.get("listeners")
    if block is None:
        return []
    if not isinstance(block, list):
        raise ValueError("c2.listeners is %s, not a list of listeners"
                         % type(block).__name__)
    return block


def _spec_of(entry: dict, index: int) -> ListenerSpec:
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("c2.listeners[%d] has no name" % index)
    name = name.strip()

    transport = entry.get("transport")
    if transport not in _TRANSPORTS:
        raise ValueError(
            "listener %r names transport %r, which does not exist; have %s"
            % (name, transport, ", ".join(transport_names())))

    relay_url = entry.get("relay_url")
    if not isinstance(relay_url, str) or not relay_url.strip():
        raise ValueError(
            "listener %r has no relay_url; that is the team server's agent "
            "socket, and without it the listener has nowhere to carry a "
            "payload" % name)

    port = entry.get("bind_port")
    # bool is an int in Python, and `bind_port: true` is a plausible typo
    # in YAML that would otherwise bind port 1.
    if isinstance(port, bool) or not isinstance(port, int) \
            or not _PORT_MIN <= port <= _PORT_MAX:
        raise ValueError(
            "listener %r has bind_port %r; it must be an integer between "
            "%d and %d" % (name, port, _PORT_MIN, _PORT_MAX))

    bind_host = entry.get("bind_host", "0.0.0.0")
    if not isinstance(bind_host, str):
        raise ValueError("listener %r has a non-string bind_host %r"
                         % (name, bind_host))

    settings = entry.get("settings") or {}
    if not isinstance(settings, dict):
        raise ValueError("listener %r has non-mapping settings %r"
                         % (name, settings))
    _check_settings(name, transport, settings)

    return ListenerSpec(name=name, transport=transport,
                        enabled=bool(entry.get("enabled", False)),
                        bind_host=bind_host, bind_port=port,
                        relay_url=relay_url.strip(), settings=dict(settings))


def _check_settings(name: str, transport: str, settings: dict) -> None:
    _cls, required, accepted = _TRANSPORTS[transport]
    for key in required:
        value = settings.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                "listener %r is a %s listener and needs settings.%s"
                % (name, transport, key))
    unknown = sorted(set(settings) - set(accepted))
    if unknown:
        # Refused rather than ignored: a setting that is silently dropped
        # looks exactly like one that was applied.
        raise ValueError(
            "listener %r passes settings a %s listener does not take: %s"
            % (name, transport, ", ".join(unknown)))


def _collides(spec: ListenerSpec, existing: List[ListenerSpec],
              other_name: str) -> bool:
    """True if this spec's bind address overlaps one already accepted."""
    for seen in existing:
        if seen.bind_port != spec.bind_port:
            continue
        if seen.bind_host == spec.bind_host:
            return True
        if seen.bind_host in _WILDCARDS or spec.bind_host in _WILDCARDS:
            return True
    return False
