"""The scout: the implant's own evidence collector and evaluator.

A separate process from `beacon.py`, which is served to a target as source
text and may import only the standard library. Everything in this package
that needs scapy, PyYAML or a model client lives here, and the two halves
meet over files -- see `handoff.py`.
"""
