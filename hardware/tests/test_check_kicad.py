#!/usr/bin/env python3
"""
Tests for check_kicad.py itself.

check_kicad.py is the guard on the KiCad sources; a guard that cannot fail is
worthless, so this file feeds it the real tap board (must pass) and
deliberately corrupted copies of it (must fail, for the right reason).

pytest is not installed on the build machines, so this uses unittest:

    python3 hardware/tests/test_check_kicad.py -v
"""

import contextlib
import io
import re
import subprocess
import sys
import unittest

import yaml
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_kicad as ck  # noqa: E402

TAP_PCB = ck.HARDWARE / "kicad" / "raccoon-tap.kicad_pcb"
HAT_PCB = ck.LEGACY_PCB


def load_netlist():
    with open(ck.NETLIST) as handle:
        return yaml.safe_load(handle)


def run_nets(text, netlist=None):
    report = ck.Report()
    with contextlib.redirect_stdout(io.StringIO()):
        ck.check_pcb_nets(text, ck.parse_sexp(text), report, netlist)
    return report


def run_connectivity(text, netlist=None):
    report = ck.Report()
    with contextlib.redirect_stdout(io.StringIO()):
        ck.check_pcb_connectivity(ck.parse_sexp(text),
                                  netlist or load_netlist(), report)
    return report


def zone_count(text):
    """Zones in the (possibly mutated) board text, as the checker will see them."""
    return len(ck.children(ck.parse_sexp(text), "zone"))


def labels(report):
    return [label for label, _ in report.failures]


def details(report):
    return " ".join(detail for _, detail in report.failures)


def set_pad_net(text, ref, pad_number, new_net):
    """Rewrite the (net ...) line of one pad in the tap board text.

    new_net=None removes the net line entirely (an unconnected pad).
    """
    start = text.index(f'(property "Reference" "{ref}"')
    nxt = text.find("\n\t(footprint ", start)
    end = nxt if nxt != -1 else len(text)
    block = text[start:end]
    pad = re.search(rf'\(pad "{re.escape(pad_number)}".*?\n\t\t\)', block,
                    re.DOTALL)
    assert pad, f"{ref} pad {pad_number} not found"
    old = pad.group(0)
    if new_net is None:
        new = re.sub(r'\n\t\t\t\(net "[^"]*"\)', "", old, count=1)
    elif re.search(r'\(net "[^"]*"\)', old):
        new = re.sub(r'\(net "[^"]*"\)', f'(net "{new_net}")', old, count=1)
    else:
        new = old.replace("(uuid", f'(net "{new_net}")\n\t\t\t(uuid', 1)
    assert new != old, f"{ref} pad {pad_number}: edit changed nothing"
    return text[:start] + block.replace(old, new, 1) + text[end:]


class TapBoardAccepted(unittest.TestCase):
    """The real board, written by KiCad 10's pcbnew, must be left alone."""

    @classmethod
    def setUpClass(cls):
        cls.text = TAP_PCB.read_text(encoding="utf-8")

    def test_kicad10_named_pad_nets_are_accepted(self):
        report = run_nets(self.text, load_netlist())
        self.assertEqual(report.failures, [])

    def test_tap_board_connectivity_matches_netlist(self):
        report = run_connectivity(self.text)
        self.assertEqual(report.failures, [])


class KiCad10NetEncodingRejectsDefects(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = TAP_PCB.read_text(encoding="utf-8")
        cls.netlist = load_netlist()

    def test_pad_on_unknown_net_name_fails(self):
        text = set_pad_net(self.text, "C1", "1", "NOT_A_NET")
        report = run_nets(text, self.netlist)
        self.assertIn("every referenced net name is in netlist.yaml",
                      labels(report))
        self.assertIn("NOT_A_NET", details(report))

    def test_integer_net_reference_fails(self):
        text = set_pad_net(self.text, "C1", "1", "GND").replace(
            '(net "GND")', "(net 7)", 1)
        report = run_nets(text, self.netlist)
        self.assertIn("no integer net references in a table-less board",
                      labels(report))

    def test_zone_without_net_fails(self):
        text = self.text.replace('(zone\n\t\t(net "GND")', "(zone", 1)
        self.assertNotEqual(text, self.text)
        report = run_nets(text, self.netlist)
        self.assertIn(f"all {zone_count(text)} zone(s) carry a netlist net name",
                      labels(report))

    def test_zone_on_unknown_net_fails(self):
        text = self.text.replace('(zone\n\t\t(net "GND")',
                                 '(zone\n\t\t(net "BOGUS")', 1)
        report = run_nets(text, self.netlist)
        self.assertIn(f"all {zone_count(text)} zone(s) carry a netlist net name",
                      labels(report))
        self.assertIn("BOGUS", details(report))

    def test_via_on_unknown_net_fails(self):
        text = self.text.replace('(layers "F.Cu" "B.Cu")\n\t\t(net "GND")',
                                 '(layers "F.Cu" "B.Cu")\n\t\t(net "BOGUS")', 1)
        self.assertNotEqual(text, self.text)
        report = run_nets(text, self.netlist)
        self.assertIn("every referenced net name is in netlist.yaml",
                      labels(report))

    def test_board_without_any_net_reference_fails(self):
        text = re.sub(r'\n\t+\(net "[^"]*"\)', "", self.text)
        report = run_nets(text, self.netlist)
        self.assertIn("pads carry net references", labels(report))

    def test_table_less_board_needs_the_netlist(self):
        report = run_nets(self.text, None)
        self.assertIn("netlist supplied to validate net names", labels(report))


class ConnectivityRejectsDefects(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = TAP_PCB.read_text(encoding="utf-8")
        cls.netlist = load_netlist()

    def test_pad_moved_to_another_valid_net_fails(self):
        # R11.1 is RSET; put it on GND. Every name is still a valid net, so
        # the encoding check is blind to this and only connectivity sees it.
        text = set_pad_net(self.text, "R11", "1", "GND")
        self.assertEqual(run_nets(text, self.netlist).failures, [])
        report = run_connectivity(text)
        self.assertIn("net RSET: PCB pads match netlist", labels(report))
        self.assertIn("net GND: PCB pads match netlist", labels(report))
        self.assertIn("R11.1", details(report))

    def test_usb3_pair_swap_fails(self):
        # The error-prone crossover from netlist design_notes.usb3_crossover.
        text = set_pad_net(self.text, "U3", "13", "USB3_TX_N")
        text = set_pad_net(text, "U3", "12", "USB3_TX_P")
        self.assertEqual(run_nets(text, self.netlist).failures, [])
        report = run_connectivity(text)
        self.assertIn("net USB3_TX_P: PCB pads match netlist", labels(report))
        self.assertIn("net USB3_TX_N: PCB pads match netlist", labels(report))

    def test_pad_left_without_net_fails(self):
        text = set_pad_net(self.text, "U3", "38", None)
        report = run_connectivity(text)
        self.assertIn("net RSET: PCB pads match netlist", labels(report))
        self.assertIn("U3.38", details(report))

    def test_no_connect_pin_that_got_wired_fails(self):
        text = set_pad_net(self.text, "U3", "28", "GND")
        report = run_connectivity(text)
        self.assertIn("no_connect pins have no net in the PCB", labels(report))

    def test_net_name_missing_from_netlist_fails(self):
        text = set_pad_net(self.text, "C1", "1", "NOT_A_NET")
        report = run_connectivity(text)
        self.assertIn("no PCB pad sits on a net the netlist lacks",
                      labels(report))

    def test_missing_footprint_fails(self):
        # Rename C21 to a reference the netlist does not know.
        text = self.text.replace('(property "Reference" "C21"',
                                 '(property "Reference" "C99"', 1)
        report = run_connectivity(text)
        count = len(self.netlist["components"])
        self.assertIn(f"PCB has exactly the {count} netlist components",
                      labels(report))

    def test_netlist_is_the_authority_not_the_pcb(self):
        # Change the netlist, leave the PCB alone: the PCB must be the one
        # reported as wrong.
        netlist = load_netlist()
        netlist["nets"]["RSET"].remove("R11.1")
        netlist["nets"]["GND"].append("R11.1")
        report = run_connectivity(self.text, netlist)
        self.assertIn("net RSET: PCB pads match netlist", labels(report))


class LegacyFormatStillUnderstood(unittest.TestCase):
    """The archived hat board is KiCad 9 format; the check must still read it
    even though main() no longer gates on it."""

    @unittest.skipUnless(HAT_PCB.exists(), "archived hat board not present")
    def test_kicad9_table_board_is_accepted(self):
        text = HAT_PCB.read_text(encoding="utf-8")
        self.assertEqual(run_nets(text).failures, [])

    @unittest.skipUnless(HAT_PCB.exists(), "archived hat board not present")
    def test_kicad9_name_only_reference_still_fails(self):
        text = HAT_PCB.read_text(encoding="utf-8")
        text = re.sub(r"\(net (\d+)\)", '(net "X")', text, count=1)
        report = run_nets(text)
        self.assertIn("no name-only net references remain", labels(report))


class MainEntryPoint(unittest.TestCase):
    def test_script_exits_zero_and_checks_the_tap_board(self):
        proc = subprocess.run(
            [sys.executable, str(Path(ck.__file__)), "-v"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("raccoon-tap.kicad_pcb: parentheses balanced",
                      proc.stdout)
        self.assertIn("PCB connectivity vs netlist.yaml", proc.stdout)
        self.assertNotIn("raccoon-hat", proc.stdout)


if __name__ == "__main__":
    unittest.main()
