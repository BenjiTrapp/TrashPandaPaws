"""The server side of the reverse SOCKS5 pivot tunnel.

The implant end of this tunnel is a mode of the generated beacon artifact,
and `api_beacon_gen` builds that artifact by reading exactly one file,
`software/c2/beacon.py`. So every byte of the protocol — the framing, the
command messages, the SOCKS5 codec and the Noise state machine under them
— is implemented there, and the modules in this package import it from
there rather than keeping a second copy. One implementation cannot
disagree with itself about a wire format; two will, eventually, and the
symptom is a tunnel that fails on target while every test on both sides
passes.

What belongs here is everything the server does and the implant does not:
the implant-facing socket and its session table, the key and identity
registry, the operator-facing SOCKS5 port, and the process wrapper that
supervises them.

Stdlib only, like the beacon. Nothing here may import from
`software.c2.server`, which pulls in flask, werkzeug, jinja2 and click.
"""
