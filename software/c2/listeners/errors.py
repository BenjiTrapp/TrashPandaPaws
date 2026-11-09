"""The one name the team server needs from this package, and nothing else.

`server.py` has to catch a supervisor's refusals to turn them into status
codes. Importing `supervisor` for that would pull in `registry`, and
`registry` imports all three listener classes -- so the DNS parser, the
QUIC reassembler and the hand-written SMB2 parser would all be loaded
into the team-server process.

They must not be. The whole reason listeners are separate processes is
that a fault in one of those parsers costs one transport instead of the
fleet and the operator interface together. Code that is merely imported
cannot crash a process by itself, but it can be reached, and the
arrangement is easier to reason about when the parsers are simply not
there. A test holds it.

So the exception lives here, with no imports at all, and `supervisor`
re-exports it for everything that does work with listeners.
"""


class SupervisorError(Exception):
    """A refusal with a reason in it, for the panel to show verbatim."""
