"""Server-side listeners for the beacon's non-HTTP transports.

The team server answers HTTPS and nothing else, deliberately: it holds the
fleet, the loot and the operator interface, and the hardening pass that
preceded this package established that it listens on exactly two sockets
and parses one protocol. These listeners live beside it instead.

Each one terminates a transport the beacon already speaks -- an SMB named
pipe, a UDP framing, DNS TXT -- and hands the payload to the team server's
existing agent socket over HTTP. None of them is given the encryption key:
they move opaque ciphertext in both directions, so a listener can neither
read beacon traffic nor forge it, and the blast radius of a compromised
listener container is dropping or replaying messages.

Stdlib only, like the beacon. Nothing here may import from
`software.c2.server`, which pulls in flask, werkzeug, cryptography, jinja2
and click -- a listener container has no business carrying those.
"""
