#!/usr/bin/env python3
"""
Signals that end or suspend a run, rather than failing one step of it.

The tool-calling loop deliberately turns every tool failure into a tool
result: a command that failed, a tool that raised, an argument that would not
bind. The model reads the message and tries something else, which is what
keeps one bad step from ending a campaign.

Two things must not be handled that way. The detection budget is a hard stop
— spec §10.6 calls it an abort condition, not a statistic — and an operator
pause is an instruction, not an error. Swallowed into a tool result, both
became a line the model read and worked around: the budget was measured as
spent and the run carried on regardless.

So they are a type, not a convention. Anything deriving from `ControlSignal`
travels straight out of the loop. A `passthrough` argument on `loop.run`
would have worked too, and it would have been one more thing a later caller
had to remember to pass.
"""


class ControlSignal(Exception):
    """Base for anything that must escape the tool-calling loop."""
