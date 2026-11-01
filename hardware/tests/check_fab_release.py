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

Added in task 6:

  * check_mpn_coverage: every BOM row has a part number, and a DNP row has none
    in the "Part Number" column (so a buyer cannot order it) plus quantity 0;
  * the DNP tests: a `populate: false` part is (dnp yes) on the schematic and
    DNP in the BOM, driven by the data and not by a hard-coded reference;
  * gated_rail_inrush_ma: the capacitance moved behind the load switch is
    charged slowly enough, computed from the netlist, so the 10 uF test cannot
    be satisfied by merely renaming a net;
  * the committed bom.csv and schematic are what the generators write.

Usage:
    python3 check_fab_release.py [-v]
"""

import copy
import csv
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

HARDWARE = Path(__file__).resolve().parent.parent
NETLIST = HARDWARE / "netlist.yaml"
BOM = HARDWARE / "bom.csv"
SCHEMATIC = HARDWARE / "kicad" / "raccoon-tap.kicad_sch"
GEN_BOM = HARDWARE / "tools" / "gen_bom.py"
GEN_SCHEMATIC = HARDWARE / "tools" / "gen_schematic.py"

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


def load_bom(path=BOM):
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle))


# Part-number cells that are present but say nothing. PCBWay buys by part
# number, so these are as good as an empty cell.
_NO_PART = {"", "tbd", "tba", "n/a", "na", "-", "--", "?", "none", "unknown"}


def _blank(cell):
    return (cell or "").strip().lower() in _NO_PART


def check_mpn_coverage(bom_rows):
    """One message per BOM row that cannot be bought or must not be bought.

    A row to be fitted ("Populate" = yes) needs a "Part Number". A DNP row
    ("Populate" = DNP) needs the opposite: its "Part Number" stays EMPTY, so a
    buyer working down that column cannot order it, its Quantity is 0, and the
    part that goes there if it is ever fitted lives in "Part If Fitted". A
    BOM without a "Populate" column is read as all rows to be fitted.
    """
    problems = []
    for row in bom_rows:
        what = f"{row.get('Reference')} ({row.get('Value')})"
        populate = (row.get("Populate") or "yes").strip()
        part = row.get("Part Number")
        if populate == "yes":
            if _blank(part):
                problems.append(f"{what}: no part number")
            if (row.get("Quantity") or "").strip() in ("", "0"):
                problems.append(f"{what}: to be fitted but quantity is "
                                f"{row.get('Quantity')!r}")
        elif populate == "DNP":
            if not _blank(part):
                problems.append(f"{what}: DNP row carries part number "
                                f"{part!r}; a buyer would order it")
            if _blank(row.get("Part If Fitted")):
                problems.append(f"{what}: DNP row names no part to fit if "
                                f"it is ever needed")
            if (row.get("Quantity") or "").strip() != "0":
                problems.append(f"{what}: DNP but quantity is "
                                f"{row.get('Quantity')!r}, not 0")
        else:
            problems.append(f"{what}: Populate is {populate!r}, "
                            f"expected 'yes' or 'DNP'")
    return problems


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


# The USB attach test counts current above 100 mA as an inrush event, and
# 100 mA is the low-power unit load (SLYT118 table 1, the USB-IF text itself
# not read; see netlist.yaml design_notes.vbus_inrush). Under it there is no
# inrush region at all.
INRUSH_MAX_MA = 100.0
# CT is an X7R part: tolerance and DC bias can take 20 % off it.
CT_MARGIN = 0.20


def interpolate_rise_us(table, ct_pf):
    """10-90 % rise time in microseconds for a CT capacitance in pF, by linear
    interpolation in a datasheet table {pF: us}. Refuses to extrapolate: a CT
    larger than the table's last entry is a CT nobody has characterised."""
    points = sorted((float(k), float(v)) for k, v in table.items())
    if ct_pf < points[0][0] or ct_pf > points[-1][0]:
        raise ValueError(f"CT {ct_pf:g} pF is outside the table "
                         f"{points[0][0]:g}..{points[-1][0]:g} pF")
    for (x0, y0), (x1, y1) in zip(points, points[1:]):
        if x0 <= ct_pf <= x1:
            return y0 + (y1 - y0) * (ct_pf - x0) / (x1 - x0)


def gated_rail_inrush_ma(netlist, gated_rail):
    """Current in mA that charges everything behind the load switch of
    `gated_rail` while its output ramps, with CT taken CT_MARGIN low.

    The capacitance on the gated rail counts in full; the capacitance on each
    rail fed from it through a regulator counts as the charge that has to pass
    the switch to fill it (C x V_rail x charge_in_per_charge_out), expressed as
    an equivalent capacitance at the gated rail's voltage. Raises ValueError if
    the switch has no readable CT capacitor on its CT pin.
    """
    rails = netlist["rails"]
    spec = rails[gated_rail]
    components = netlist["components"]
    nets = netlist["nets"]

    switch = spec["gated_by"]["switch"]
    ct_ref = spec["gated_by"]["ct_cap"]
    soft = components[switch]["soft_start"]
    if soft["ct_cap"] != ct_ref:
        raise ValueError(f"{switch}.soft_start.ct_cap is {soft['ct_cap']}, "
                         f"the rail says {ct_ref}")

    ct_pins = [n for n, p in components[switch]["pins"].items()
               if (p or {}).get("name") == "CT"]
    if len(ct_pins) != 1:
        raise ValueError(f"{switch} has no unique CT pin")
    ct_net = next((name for name, ends in nets.items()
                   if f"{switch}.{ct_pins[0]}" in ends), None)
    if ct_net is None or not any(e.startswith(f"{ct_ref}.") for e in nets[ct_net]):
        raise ValueError(f"{ct_ref} is not on the CT pin of {switch}")
    if not is_populated(ct_ref, components[ct_ref]):
        raise ValueError(f"{ct_ref} is not fitted")
    ct_pf = parse_capacitance_uf(components[ct_ref]["value"]) * 1e6

    v_gated = float(spec["nominal_v"])
    equivalent_uf = sum_bulk_capacitance(netlist, gated_rail)
    for rail_name, down in spec["downstream_rails"].items():
        v_out = float(rails[rail_name]["nominal_v"])
        charged_uf = sum(sum_bulk_capacitance(netlist, n) for n in down["nets"])
        equivalent_uf += (charged_uf * v_out
                          * float(down["charge_in_per_charge_out"]) / v_gated)

    rise_us = interpolate_rise_us(soft["rise_time_us_10_90_at_5v"],
                                  ct_pf * (1.0 - CT_MARGIN))
    volts_per_second = soft["swing_fraction"] * v_gated / (rise_us * 1e-6)
    return equivalent_uf * 1e-6 * volts_per_second * 1e3



class FabReleaseChecks(unittest.TestCase):

    def test_vbus_bulk_capacitance_within_usb_limit(self):
        total_uf = sum_bulk_capacitance(load_netlist(), rail="+5V")
        self.assertLessEqual(
            total_uf, VBUS_MAX_UF,
            f"{total_uf:.1f} uF an VBUS, USB erlaubt {VBUS_MAX_UF:.0f} uF")

    def test_every_bom_row_has_a_part_number(self):
        self.assertEqual(check_mpn_coverage(load_bom()), [])


class MpnCoverageCanFail(unittest.TestCase):
    """check_mpn_coverage must reject what it claims to reject."""

    @staticmethod
    def row(**cells):
        base = {"Reference": "R1", "Quantity": "1", "Populate": "yes",
                "Value": "1K", "Part Number": "RC0603FR-071KL",
                "Part If Fitted": ""}
        base.update(cells)
        return base

    def test_a_good_row_passes(self):
        self.assertEqual(check_mpn_coverage([self.row()]), [])

    def test_empty_part_number_is_reported_with_reference_and_value(self):
        problems = check_mpn_coverage([self.row(**{"Part Number": ""})])
        self.assertEqual(len(problems), 1)
        self.assertIn("R1", problems[0])
        self.assertIn("1K", problems[0])

    def test_placeholder_part_numbers_count_as_missing(self):
        for text in ["TBD", "n/a", "-", "  ", "None", "?"]:
            problems = check_mpn_coverage([self.row(**{"Part Number": text})])
            self.assertEqual(len(problems), 1, text)

    def test_dnp_row_with_a_part_number_is_reported(self):
        problems = check_mpn_coverage([self.row(
            Populate="DNP", Quantity="0", **{"Part If Fitted": "RC0603JR-070RL"})])
        self.assertEqual(len(problems), 1)
        self.assertIn("would order", problems[0])

    def test_dnp_row_with_positive_quantity_is_reported(self):
        problems = check_mpn_coverage([self.row(
            Populate="DNP", Quantity="1",
            **{"Part Number": "", "Part If Fitted": "RC0603JR-070RL"})])
        self.assertEqual(len(problems), 1)
        self.assertIn("not 0", problems[0])

    def test_dnp_row_without_a_part_to_fit_is_reported(self):
        problems = check_mpn_coverage([self.row(
            Populate="DNP", Quantity="0", **{"Part Number": ""})])
        self.assertEqual(len(problems), 1)

    def test_a_correct_dnp_row_passes(self):
        self.assertEqual(check_mpn_coverage([self.row(
            Populate="DNP", Quantity="0",
            **{"Part Number": "", "Part If Fitted": "RC0603JR-070RL"})]), [])

    def test_unknown_populate_value_is_reported(self):
        for text in ["no", "DNP ", "false", "0", "dnp"]:
            problems = check_mpn_coverage([self.row(Populate=text)])
            self.assertTrue(problems, text)

    def test_row_to_be_fitted_with_quantity_zero_is_reported(self):
        self.assertTrue(check_mpn_coverage([self.row(Quantity="0")]))


def fitted_refs_of(netlist):
    return {ref for ref, comp in netlist["components"].items()
            if is_populated(ref, comp) and comp.get("bom", True)}


def expand(reference_cell):
    refs = []
    for part in reference_cell.split(","):
        span = re.fullmatch(r"([A-Z]+)(\d+)-([A-Z]+)(\d+)", part.strip())
        if span:
            refs += [f"{span.group(1)}{n}"
                     for n in range(int(span.group(2)), int(span.group(4)) + 1)]
        elif part.strip():
            refs.append(part.strip())
    return refs


def schematic_instances(text):
    """{ref: (in_bom, dnp)} for every component instance in a generated
    .kicad_sch, power symbols left out."""
    found = re.findall(
        r'\(symbol \(lib_id "raccoon:RACCOON_([A-Za-z0-9]+)"\) \(at [^)]*\) '
        r'\(unit 1\)\s*\(exclude_from_sim no\) \(in_bom (yes|no)\) '
        r'\(on_board yes\) \(dnp (yes|no)\)', text)
    return {ref: (in_bom, dnp) for ref, in_bom, dnp in found
            if not ref.startswith("PWR_")}


def generate(netlist, directory):
    """Run the real generators on `netlist`; return (bom_rows, schematic_text)."""
    directory = Path(directory)
    source = directory / "netlist.yaml"
    source.write_text(yaml.safe_dump(netlist, sort_keys=False, width=10_000))
    bom = directory / "bom.csv"
    sch = directory / "tap.kicad_sch"
    subprocess.run([sys.executable, str(GEN_BOM), str(source), "--out", str(bom)],
                   check=True, capture_output=True)
    subprocess.run([sys.executable, str(GEN_SCHEMATIC), str(source),
                    "--out", str(sch), "--symlib", str(directory / "x.kicad_sym")],
                   check=True, capture_output=True)
    return load_bom(bom), sch.read_text(encoding="utf-8")


class SoftStartCannotBeFaked(unittest.TestCase):
    """The 10 uF test reads only the raw VBUS net, so moving capacitance behind
    a load switch would pass it. These tests make the move honest: the switch
    must really exist, its slew must be set, and the current into everything
    behind it must stay under the attach limit."""

    @staticmethod
    def netlist():
        return load_netlist()

    def test_inrush_behind_the_load_switch_is_under_the_limit(self):
        ma = gated_rail_inrush_ma(self.netlist(), "+5V_SW")
        self.assertLessEqual(ma, INRUSH_MAX_MA,
                             f"{ma:.0f} mA into +5V_SW, limit {INRUSH_MAX_MA:.0f} mA")

    def test_the_number_is_the_one_in_the_design_note(self):
        # design_notes.vbus_inrush quotes 42 mA for the CT 20 % low case
        ma = gated_rail_inrush_ma(self.netlist(), "+5V_SW")
        self.assertAlmostEqual(ma, 42.3, delta=1.5)

    def test_switch_output_is_the_gated_rail_and_its_input_is_raw_vbus(self):
        netlist = self.netlist()
        spec = netlist["rails"]["+5V_SW"]["gated_by"]
        self.assertIn(f"{spec['switch']}.6", netlist["nets"]["+5V_SW"])
        self.assertIn(f"{spec['switch']}.1", netlist["nets"]["+5V"])

    def test_no_pin_of_the_load_pins_still_hangs_on_raw_vbus(self):
        netlist = self.netlist()
        raw = set(netlist["nets"]["+5V"])
        for pin in ["U3.21", "U3.27", "U4.1", "U6.4"]:
            self.assertNotIn(pin, raw, pin)

    def test_removing_the_ct_capacitor_fails(self):
        netlist = self.netlist()
        netlist["nets"]["LS_CT"] = [e for e in netlist["nets"]["LS_CT"]
                                    if not e.startswith("C26")]
        with self.assertRaises(ValueError):
            gated_rail_inrush_ma(netlist, "+5V_SW")

    def test_a_small_ct_capacitor_fails(self):
        netlist = self.netlist()
        netlist["components"]["C26"]["value"] = "1nF"
        self.assertGreater(gated_rail_inrush_ma(netlist, "+5V_SW"), INRUSH_MAX_MA)

    def test_bulk_added_behind_the_switch_fails(self):
        netlist = self.netlist()
        netlist["components"]["C3"]["value"] = "47uF"
        self.assertGreater(gated_rail_inrush_ma(netlist, "+5V_SW"), INRUSH_MAX_MA)

    def test_bulk_added_on_the_regulated_rails_behind_it_fails(self):
        netlist = self.netlist()
        netlist["components"]["C6"]["value"] = "220uF"
        self.assertGreater(gated_rail_inrush_ma(netlist, "+5V_SW"), INRUSH_MAX_MA)

    def test_unreadable_capacitor_behind_the_switch_raises(self):
        netlist = self.netlist()
        netlist["components"]["C3"]["value"] = "10u"
        with self.assertRaises(UnparsableCapacitance):
            gated_rail_inrush_ma(netlist, "+5V_SW")

    def test_dnp_capacitor_behind_the_switch_is_not_counted(self):
        netlist = self.netlist()
        before = gated_rail_inrush_ma(netlist, "+5V_SW")
        netlist["components"]["C24"]["value"] = "100uF"
        self.assertAlmostEqual(gated_rail_inrush_ma(netlist, "+5V_SW"), before)

    def test_only_the_switch_the_esd_clamp_and_capacitors_hang_on_raw_vbus(self):
        # a regulator wired back to raw VBUS would take its bulk past the
        # switch and the inrush calculation would never see it
        netlist = self.netlist()
        for endpoint in netlist["nets"]["+5V"]:
            ref = endpoint.rpartition(".")[0]
            self.assertTrue(re.fullmatch(r"C\d+", ref) or ref in
                            {"J3", "U7", "U9", "TP2"}, endpoint)

    def test_interpolation_reproduces_the_datasheet_points(self):
        table = {0: 60, 470: 63, 1000: 91, 10000: 864, 27000: 2245}
        for ct, t in table.items():
            self.assertAlmostEqual(interpolate_rise_us(table, ct), t)
        self.assertAlmostEqual(interpolate_rise_us(table, 18500),
                               (864 + 2245) / 2)

    def test_interpolation_refuses_to_extrapolate_upwards(self):
        with self.assertRaises(ValueError):
            interpolate_rise_us({0: 60, 27000: 2245}, 40000)


class DnpIsExplicitEndToEnd(unittest.TestCase):
    """A part marked `populate: false` must not be fittable by anyone who
    follows the schematic or the BOM. R12 exists so that it stays empty:
    fitting it silently reverses the pin 20 isolation decision."""

    @classmethod
    def setUpClass(cls):
        cls.netlist = load_netlist()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bom, cls.sch = generate(cls.netlist, cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def dnp_refs(self, netlist=None):
        return {ref for ref, comp in (netlist or self.netlist)["components"].items()
                if comp.get("populate", True) is False}

    def test_the_netlist_has_dnp_parts_to_test_with(self):
        self.assertTrue({"R12", "C24"} <= self.dnp_refs())

    def test_schematic_marks_every_dnp_part_dnp_and_nothing_else(self):
        instances = schematic_instances(self.sch)
        self.assertEqual(set(instances), set(self.netlist["components"]))
        marked = {ref for ref, (_, dnp) in instances.items() if dnp == "yes"}
        self.assertEqual(marked, self.dnp_refs())

    def test_no_dnp_part_sits_in_a_row_that_is_to_be_fitted(self):
        for row in self.bom:
            refs = set(expand(row["Reference"]))
            if row["Populate"] == "yes":
                self.assertFalse(refs & self.dnp_refs(), row)
            else:
                self.assertTrue(refs <= self.dnp_refs(), row)

    def test_dnp_rows_have_quantity_zero_and_no_part_number(self):
        dnp_rows = [r for r in self.bom if r["Populate"] == "DNP"]
        self.assertEqual({r for row in dnp_rows for r in expand(row["Reference"])},
                         self.dnp_refs())
        for row in dnp_rows:
            self.assertEqual(row["Quantity"], "0", row)
            self.assertEqual(row["Part Number"], "", row)
            self.assertNotEqual(row["Part If Fitted"], "", row)

    def test_fitted_quantities_add_up_to_the_fitted_parts(self):
        fitted = sum(int(r["Quantity"]) for r in self.bom)
        self.assertEqual(fitted, len(fitted_refs_of(self.netlist)))

    def test_it_follows_the_data_not_a_hard_coded_ref(self):
        netlist = copy.deepcopy(self.netlist)
        netlist["components"]["R7"]["populate"] = False
        with tempfile.TemporaryDirectory() as tmp:
            bom, sch = generate(netlist, tmp)
        self.assertEqual(schematic_instances(sch)["R7"][1], "yes")
        row = next(r for r in bom if "R7" in expand(r["Reference"]))
        self.assertEqual((row["Populate"], row["Quantity"], row["Part Number"]),
                         ("DNP", "0", ""))
        row8 = next(r for r in bom if "R8" in expand(r["Reference"]))
        self.assertEqual(row8["Populate"], "yes")

    def test_a_dnp_part_never_shares_a_row_with_a_fitted_twin(self):
        netlist = copy.deepcopy(self.netlist)
        netlist["components"]["R8"]["populate"] = False
        with tempfile.TemporaryDirectory() as tmp:
            bom, _ = generate(netlist, tmp)
        for row in bom:
            refs = set(expand(row["Reference"]))
            self.assertFalse({"R7", "R8"} <= refs, row)

    def test_a_part_that_says_dnp_in_its_value_but_not_populate_false_is_refused(self):
        netlist = copy.deepcopy(self.netlist)
        netlist["components"]["R7"]["value"] = "1K DNP"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "n.yaml"
            source.write_text(yaml.safe_dump(netlist, sort_keys=False))
            result = subprocess.run(
                [sys.executable, str(GEN_BOM), str(source),
                 "--out", str(Path(tmp) / "b.csv")], capture_output=True)
        self.assertNotEqual(result.returncode, 0)


class GeneratedFilesAreCurrent(unittest.TestCase):
    """bom.csv and the schematic are generated, never edited by hand. A
    committed copy that differs from a fresh run is stale or hand-edited."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        generate(load_netlist(), cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_bom_csv_is_what_the_generator_writes(self):
        self.assertEqual(BOM.read_text(), (Path(self.tmp.name) / "bom.csv").read_text())

    def test_schematic_symbols_carry_the_part_number(self):
        netlist = load_netlist()
        text = SCHEMATIC.read_text(encoding="utf-8")
        for ref, comp in netlist["components"].items():
            if comp.get("mpn"):
                self.assertIn(f'(property "MPN" "{comp["mpn"]}"', text, ref)

    def test_schematic_is_what_the_generator_writes(self):
        self.assertEqual(SCHEMATIC.read_text(encoding="utf-8"),
                         (Path(self.tmp.name) / "tap.kicad_sch").read_text(encoding="utf-8"))


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
