"""The team server's side of the gsocket carrier, the beacon's fifth leg.

The other four transports give the beacon an address to reach: a host and
a port, or a resolver to ask. This one does not. A `gs-netcat` carrier
process on each side joins the Global Socket Relay Network and the two
find each other by a **shared secret**, so the implant needs no route to
the team server, no open inbound port on it, and no DNS name that a
blue team can pivot from the implant's disk to the operator's
infrastructure.

What belongs here is everything the server does and the implant does not:
the per-implant secret store, the carrier process the server runs beside
its beacon socket, and the supervisor that keeps one carrier alive per
configured leg.

Stdlib only, like the beacon and the tunnel. Nothing here may import from
`software.c2.server`, which pulls in flask, werkzeug, jinja2 and click.
"""
