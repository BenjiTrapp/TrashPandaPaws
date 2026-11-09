"""The transport table that both the rig and the demo environment read.

A listener and the beacon configuration that reaches it are two halves of
one fact. They were about to exist twice -- once in `listener_rig.py`,
which proves a cycle and exits, and once in `demo_env.py`, which stands up
something you open in a browser -- and `listener_rig` already imports
`demo_env`, so the shared half cannot live in either of them.

Nothing here is production code. The listeners themselves are, in
`software/c2/listeners/`; this module only knows how to point one at a
team server and how to configure a beacon that will talk to it.
"""

import base64
import json
import urllib.request
from contextlib import contextmanager

from software.c2 import beacon as beacon_mod
from software.c2.listeners.registry import ListenerSpec, transport_names

# Defaults, overridable at every call site. A listener token is a shared
# secret between the team server and a listener, so in a real deployment
# it comes from configuration -- these values exist so a local
# environment needs no arguments to stand up.
LISTENER_TOKEN = "lab-listener-token"
DNS_ZONE = "c2.lab"


def _quic_beacon_config(key, address, interval, zone):
    host, port = address
    return {
        "beacon_interval_seconds": interval,
        "jitter_percent": 0,
        "encryption_key": _key_b64(key),
        "proxy": {"mode": "none"},
        "https": {"enabled": False},
        "smb": {"enabled": False},
        "dns": {"enabled": False, "domain": "", "resolver": "127.0.0.1"},
        "quic": {"enabled": True, "server": "%s:%d" % (host, port)},
    }


def _dns_beacon_config(key, address, interval, zone):
    host, _port = address
    return {
        "beacon_interval_seconds": interval,
        "jitter_percent": 0,
        "encryption_key": _key_b64(key),
        "proxy": {"mode": "none"},
        "https": {"enabled": False},
        "smb": {"enabled": False},
        "quic": {"enabled": False},
        # The resolver is the listener itself here. In production the
        # beacon asks a real resolver, which reaches an authoritative
        # nameserver; this collapses that to one hop, because the hop under
        # test is the listener and not the DNS hierarchy.
        "dns": {"enabled": True, "domain": zone, "resolver": host},
    }


def _smb_beacon_config(key, address, interval, zone):
    host, port = address
    return {
        "beacon_interval_seconds": interval,
        "jitter_percent": 0,
        "encryption_key": _key_b64(key),
        "proxy": {"mode": "none"},
        "https": {"enabled": False},
        "dns": {"enabled": False, "domain": "", "resolver": "127.0.0.1"},
        "quic": {"enabled": False},
        # Port 445 is where a real deployment puts this, and binding it
        # needs root. The client takes "host:port", so nothing local has to
        # -- in production dockerd maps it.
        "smb": {"enabled": True, "server": "%s:%d" % (host, port),
                "pipe_name": "msrpc_6e2f"},
    }


# transport -> the beacon configuration that reaches a listener of it.
#
# Only this half lives here. Which transports exist, and how to construct
# a listener for one, belongs to `listeners.registry`, which the running
# system reads. A second list of the same three things is how `smb` and
# `quic` came to be missing from two config mappings at once, and how an
# SMB listener could have been added without the rig ever driving it.
_BEACON_CONFIGS = {
    "quic": _quic_beacon_config,
    "dns": _dns_beacon_config,
    "smb": _smb_beacon_config,
}

# Transports with no upstream path. A beacon reached over one of these can
# be commanded and will never report, so a cycle over it stops at "the
# task arrived", and a panel has to say so rather than show a silent gap.
TASKING_ONLY = frozenset({"dns"})

# What a listener's relay URL points at. The DNS tasking route takes the
# socket root and appends its own path; the beacon endpoint is a full URL.
_RELAY_SHAPE = {
    "dns": "http://127.0.0.1:%d",
    "quic": "http://127.0.0.1:%d/api/v1/beacon",
    "smb": "http://127.0.0.1:%d/api/v1/beacon",
}


def available_transports():
    """The transports the running system has that we can also drive."""
    return sorted(set(transport_names()) & set(_BEACON_CONFIGS))


def is_tasking_only(transport):
    return transport in TASKING_ONLY


def relay_url_for(transport, beacon_port):
    """The team-server URL a listener of this transport should relay to."""
    return _RELAY_SHAPE[transport] % beacon_port


def make_listener(transport, bind_port, relay_url, *,
                  token=LISTENER_TOKEN, zone=DNS_ZONE):
    if transport not in _BEACON_CONFIGS:
        raise ValueError("no listener for %r; have %s"
                         % (transport, ", ".join(available_transports())))
    # Built through the same path a deployment uses. `bind_port=0` is
    # deliberate here and refused in a configuration file: an operator
    # needs a fixed port because the beacon is configured with one, while
    # a rig only needs a port nothing else holds right now.
    settings = {"zone": zone} if transport == "dns" else {}
    spec = ListenerSpec(name="lab-%s" % transport, transport=transport,
                        enabled=True, bind_host="127.0.0.1",
                        bind_port=bind_port, relay_url=relay_url,
                        settings=settings)
    return spec.build(listener_token=token)


def beacon_config_for(transport, key, listener_address, *, interval=2,
                      zone=DNS_ZONE):
    """A whole beacon config that reaches `listener_address` and nothing else.

    Every other transport is switched off on purpose: a beacon with HTTPS
    still enabled would fall back to it and a cycle would prove nothing
    about the listener.
    """
    if transport not in _BEACON_CONFIGS:
        raise ValueError("no beacon config for %r; have %s"
                         % (transport, ", ".join(available_transports())))
    block = _BEACON_CONFIGS[transport](key, listener_address, interval, zone)
    return {"c2": block}


def set_resolver_port(port):
    """Point the beacon's resolver at `port` until something sets it back.

    The form a long-running environment needs: `resolver_port` below
    restores the previous value on the way out, which is right for a cycle
    that exits and wrong for a process you leave running.
    """
    previous = beacon_mod._DNS_PORT
    beacon_mod._DNS_PORT = port
    return previous


@contextmanager
def resolver_port(port):
    """Point the beacon's resolver at `port` for the duration.

    `_beacon_dns` asks its resolver on `beacon._DNS_PORT`, which is 53.
    Binding 53 needs root, so nothing local can serve it; in a real
    deployment dockerd or systemd owns the port and forwards to an
    unprivileged listener, so nothing in this project ever binds it
    either. The named constant exists for exactly this redirection.
    """
    previous = set_resolver_port(port)
    try:
        yield
    finally:
        beacon_mod._DNS_PORT = previous


def register_out_of_band(beacon_port, key, implant_id, interval=None):
    """Register an agent the way a bidirectional transport would, and name it.

    A tasking-only transport has no registration, so a beacon that speaks
    only that one needs an identity the server already knows. This is what
    HTTPS, SMB or QUIC would have done on first contact.

    It has to be *that beacon's* implant id. `_beacon_dns` sends
    `self._agent_id or self._implant_id` and never learns an agent name
    over DNS, so the identity registered here is the only thing the server
    can match against; registering some other id stands up a channel that
    cannot possibly deliver.
    """
    from software.c2.server import ServerCrypto, agents

    before = set(agents)
    body = json.dumps(ServerCrypto(key).wrap({
        "action": "register", "id": implant_id, "agent_id": None,
        "hostname": "lab", "os": "Linux 6.1", "user": "nobody",
        "pid": 1, "uptime": 1,
        # The interval the beacon will really use, not a convenient
        # constant. The server sizes its freshness windows from this
        # number, so a registration that understates it makes a healthy
        # agent flap between online and stale -- which is exactly the
        # defect the beacon's own interval floor caused, reintroduced here
        # by a test helper. Measured: the DNS agent reported 2 and checked
        # in every 10 seconds.
        "interval": interval if interval else beacon_mod._MIN_INTERVAL,
    })).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:%d/api/v1/beacon" % beacon_port,
        data=body, method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10):
        pass
    new = set(agents) - before
    if not new:
        raise RuntimeError("the out-of-band registration was not accepted")
    return new.pop()


def query_name_for(agent_id, zone=DNS_ZONE):
    """The DNS name a beacon with this id queries, as the client builds it."""
    label = base64.b32encode(agent_id.encode()).decode().rstrip("=").lower()
    return "%s.b.%s" % (label, zone)


def _key_b64(key):
    return base64.b64encode(key).decode()
