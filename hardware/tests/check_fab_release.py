#!/usr/bin/env python3
"""
Fabrication-release checks on hardware/netlist.yaml.

Each test encodes one finding from the pre-fab review that the structural
checks in check_netlist.py cannot see, because the netlist is perfectly
consistent while the design is still wrong.

The VBUS test is a guard that the person fixing it is allowed to edit the very
values it reads, so it must not be silenced by a change of formatting. Two
rules make that so:

  * a capacitor on the rail whose value does not parse is an ERROR, never 0 uF;
  * a capacitor is left out of the sum only if it says `populate: false`, an
    explicit field, never because its value text happens to be unparsable.

Usage:
    python3 check_fab_release.py [-v]
"""

import copy
import re
import sys
import unittest
from pathlib import Path

import yaml

NETLIST = Path(__file__).resolve().parent.parent / "netlist.yaml"

# A USB device may present at most 10 uF of capacitance across VBUS at attach
# (the USB inrush limit). Limit as stated in the release plan, Task 5.
VBUS_MAX_UF = 10.0

_UNITS_UF = {"p": 1e-6, "n": 1e-3, "u": 1.0, "µ": 1.0, "μ": 1.0, "m": 1e3}
_CAPACITANCE = re.compile(r"([0-9]*\.?[0-9]+)\s*([pnuµμm])F")


class UnparsableCapacitance(ValueError):
    """A capacitor's value could not be turned into microfarad."""


def load_netlist(path=NETLIST):
    with open(path) as handle:
        return yaml.safe_load(handle)


def parse_capacitance_uf(value):
    """'100nF' -> 0.1, '2.2uF' -> 2.2, '10µF' -> 10.0.

    The whole string must be a number and a unit. Anything else ('4u7', '10u',
    '10uF DNP', 'DNP', '') raises UnparsableCapacitance.
    """
    text = str(value).strip()
    match = _CAPACITANCE.fullmatch(text)
    if not match:
        raise UnparsableCapacitance(
            f"cannot read {value!r} as a capacitance (expected e.g. '100nF', "
            f"'2.2uF', '10µF')")
    return float(match.group(1)) * _UNITS_UF[match.group(2)]


def is_populated(ref, component):
    """True unless the component says `populate: false`, as a real boolean."""
    populate = component.get("populate", True)
    if not isinstance(populate, bool):
        raise ValueError(
            f"{ref}: populate must be true or false, got {populate!r}")
    if not populate:
        return False
    if re.search(r"\bdnp\b", str(component.get("value", "")), re.IGNORECASE):
        raise ValueError(
            f"{ref}: value {component['value']!r} says DNP but the component "
            f"does not say `populate: false`")
    return True


def sum_bulk_capacitance(netlist, rail):
    """Total capacitance, in microfarad, of every populated capacitor on `rail`.

    A capacitor counts once per rail pin it touches, so a capacitor wired from
    the rail to GND adds its value once. Raises UnparsableCapacitance for a
    populated capacitor on the rail whose value cannot be read.
    """
    components = netlist["components"]
    total = 0.0
    for endpoint in netlist["nets"][rail]:
        ref = endpoint.rpartition(".")[0]
        if not re.fullmatch(r"C\d+", ref):
            continue
        component = components[ref]
        if not is_populated(ref, component):
            continue
        try:
            total += parse_capacitance_uf(component.get("value"))
        except UnparsableCapacitance as error:
            raise UnparsableCapacitance(f"{ref} on {rail}: {error}") from None
    return total


class FabReleaseChecks(unittest.TestCase):

    def test_vbus_bulk_capacitance_within_usb_limit(self):
        total_uf = sum_bulk_capacitance(load_netlist(), rail="+5V")
        self.assertLessEqual(
            total_uf, VBUS_MAX_UF,
            f"{total_uf:.1f} uF an VBUS, USB erlaubt {VBUS_MAX_UF:.0f} uF")


class VbusGuardCannotBeSilenced(unittest.TestCase):
    """The VBUS test must not pass for the wrong reason. These all pass today
    and exist so that editing capacitor values in Task 6 cannot hide the
    capacitance from it."""

    @staticmethod
    def netlist():
        return load_netlist()

    @staticmethod
    def vbus_caps(netlist):
        return [e.rpartition(".")[0] for e in netlist["nets"]["+5V"]
                if re.fullmatch(r"C\d+", e.rpartition(".")[0])]

    def test_every_capacitor_value_in_the_netlist_is_readable(self):
        netlist = self.netlist()
        for ref, comp in netlist["components"].items():
            if re.fullmatch(r"C\d+", ref) and is_populated(ref, comp):
                parse_capacitance_uf(comp["value"])

    def test_parser_reads_the_supported_spellings(self):
        for text, expected in [("100nF", 0.1), ("2.2uF", 2.2), ("27pF", 27e-6),
                               ("10µF", 10.0), ("10μF", 10.0), ("1mF", 1000.0),
                               (" 4.7 uF ", 4.7)]:
            self.assertAlmostEqual(parse_capacitance_uf(text), expected,
                                   msg=text)

    def test_parser_rejects_everything_else_instead_of_returning_zero(self):
        for text in ["4u7", "10u", "10uF DNP", "DNP", "", "10", "uF",
                     "10 F", "10MF", "10uF, X5R", None]:
            with self.assertRaises(UnparsableCapacitance, msg=repr(text)):
                parse_capacitance_uf(text)

    def test_unreadable_value_on_the_rail_raises(self):
        for bad in ["4u7", "10u", "10uF DNP", ""]:
            netlist = self.netlist()
            ref = self.vbus_caps(netlist)[0]
            netlist["components"][ref]["value"] = bad
            with self.assertRaises(ValueError, msg=bad):
                sum_bulk_capacitance(netlist, "+5V")

    def test_dnp_text_without_populate_false_raises(self):
        netlist = self.netlist()
        ref = self.vbus_caps(netlist)[0]
        netlist["components"][ref]["value"] = "DNP"
        with self.assertRaises(ValueError):
            sum_bulk_capacitance(netlist, "+5V")

    def test_populate_must_be_a_boolean(self):
        netlist = self.netlist()
        ref = self.vbus_caps(netlist)[0]
        netlist["components"][ref]["populate"] = "false"
        with self.assertRaises(ValueError):
            sum_bulk_capacitance(netlist, "+5V")

    def test_populate_false_is_skipped_explicitly(self):
        netlist = self.netlist()
        before = sum_bulk_capacitance(netlist, "+5V")
        ref = self.vbus_caps(netlist)[0]
        value = parse_capacitance_uf(netlist["components"][ref]["value"])
        netlist["components"][ref]["populate"] = False
        netlist["components"][ref]["value"] = "DNP"
        self.assertAlmostEqual(sum_bulk_capacitance(netlist, "+5V"),
                               before - value)

    def test_populate_false_with_a_readable_value_is_still_skipped(self):
        netlist = self.netlist()
        before = sum_bulk_capacitance(netlist, "+5V")
        ref = self.vbus_caps(netlist)[0]
        value = parse_capacitance_uf(netlist["components"][ref]["value"])
        netlist["components"][ref]["populate"] = False
        self.assertAlmostEqual(sum_bulk_capacitance(netlist, "+5V"),
                               before - value)

    def test_adding_a_capacitor_to_the_rail_raises_the_sum(self):
        netlist = copy.deepcopy(self.netlist())
        before = sum_bulk_capacitance(netlist, "+5V")
        ref = self.vbus_caps(netlist)[0]
        old = parse_capacitance_uf(netlist["components"][ref]["value"])
        netlist["components"][ref]["value"] = f"{old + 12.0}uF"
        self.assertAlmostEqual(sum_bulk_capacitance(netlist, "+5V"),
                               before + 12.0)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
