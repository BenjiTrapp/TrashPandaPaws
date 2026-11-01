#!/usr/bin/env python3
"""
Fabrication-release checks on hardware/netlist.yaml.

Each test encodes one finding from the pre-fab review that the structural
checks in check_netlist.py cannot see, because the netlist is perfectly
consistent while the design is still wrong.

Usage:
    python3 check_fab_release.py [-v]
"""

import re
import sys
import unittest
from pathlib import Path

import yaml

NETLIST = Path(__file__).resolve().parent.parent / "netlist.yaml"

# A USB device may present at most 10 uF of capacitance across VBUS at attach
# (the USB inrush limit). Limit as stated in the release plan, Task 5.
VBUS_MAX_UF = 10.0

_UNITS_UF = {"pf": 1e-6, "nf": 1e-3, "uf": 1.0, "mf": 1e3}


def load_netlist(path=NETLIST):
    with open(path) as handle:
        return yaml.safe_load(handle)


def parse_capacitance_uf(value):
    """'100nF' -> 0.1, '2.2uF' -> 2.2, 'DNP' or anything unparsable -> None."""
    match = re.fullmatch(r"\s*([0-9]*\.?[0-9]+)\s*([pnum]F)\b.*", str(value),
                         re.IGNORECASE)
    if not match:
        return None
    return float(match.group(1)) * _UNITS_UF[match.group(2).lower()]


def sum_bulk_capacitance(netlist, rail):
    """Total capacitance, in microfarad, of every capacitor on `rail`.

    A capacitor counts once per rail pin it touches, so a capacitor wired from
    the rail to GND adds its value once. Parts whose value is not a
    capacitance (a DNP placeholder) add nothing.
    """
    components = netlist["components"]
    total = 0.0
    for endpoint in netlist["nets"][rail]:
        ref = endpoint.rpartition(".")[0]
        if not re.fullmatch(r"C\d+", ref):
            continue
        farads = parse_capacitance_uf(components[ref].get("value"))
        if farads is not None:
            total += farads
    return total


class FabReleaseChecks(unittest.TestCase):

    def test_vbus_bulk_capacitance_within_usb_limit(self):
        total_uf = sum_bulk_capacitance(load_netlist(), rail="+5V")
        self.assertLessEqual(
            total_uf, VBUS_MAX_UF,
            f"{total_uf:.1f} uF an VBUS, USB erlaubt {VBUS_MAX_UF:.0f} uF")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
