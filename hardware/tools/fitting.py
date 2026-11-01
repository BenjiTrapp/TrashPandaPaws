"""
What gets fitted: the two per-component switches in netlist.yaml, read the same
way by gen_bom.py and gen_schematic.py.

    populate: false   the position exists on the board but nothing is fitted
                      (DNP, "do not populate"). It stays on the schematic and
                      in the BOM, marked as not to be fitted.
    bom: false        a board feature that is not a purchasable part (a bare
                      test pad, a cut-open solder jumper). It stays on the
                      schematic and the PCB, and is left out of the BOM.

Both must be real booleans. A value of "false" or "no" is a typo that YAML
reads as a string, and silently treating a string as "fit it" is exactly the
failure this module exists to prevent, so it is refused.
"""

import re


def _flag(ref, comp, key):
    value = comp.get(key, True)
    if not isinstance(value, bool):
        raise ValueError(f"{ref}: {key} must be true or false, got {value!r}")
    return value


def is_populated(ref, comp):
    """False only for `populate: false`. A value text that says DNP without
    `populate: false` is refused: the schematic would show the part as fitted
    while its label says it is not."""
    if not _flag(ref, comp, "populate"):
        return False
    if re.search(r"\bdnp\b", str(comp.get("value", "")), re.IGNORECASE):
        raise ValueError(
            f"{ref}: value {comp['value']!r} says DNP but the component does "
            f"not say `populate: false`")
    return True


def in_bom(ref, comp):
    """False only for `bom: false`."""
    return _flag(ref, comp, "bom")
