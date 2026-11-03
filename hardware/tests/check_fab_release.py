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

Added in task 7:

  * check_no_placeholder_geometry: the USB3 and MDI net classes in the KiCad
    project carry the differential-pair width and gap that hardware/fab/
    stackup-note.md documents, and those numbers reproduce the impedance
    targets of netlist.yaml under PCBWay's own published formula less its
    published solder-mask offset, so a guess cannot pass by being copied
    into both places; a pair gap below the class clearance needs a scoped
    rule in raccoon-tap.kicad_dru, never a lower class clearance.

Added in task 8:

  * u3_track_rule_problems: the rule in raccoon-tap.kicad_dru that lets a track
    pass a U3 pad at 0.2 mm (the Power class asks 0.3 mm, which U3's 0.4 mm
    pitch cannot give) must exist, be scoped to tracks and to U3 and to nothing
    else, in either direction, and have exactly the signal class's 0.2 mm as
    its minimum. Without it task 9 cannot route out of U3's pads; loosened or
    widened it would weaken the board's clearances.
  * mdi_group_problems: MDI0 and MDI1 (the 10/100 pairs, BI_DA and BI_DB) must
    sit on cable pairs A and B, MDI2 and MDI3 (BI_DC, BI_DD) on C and D, each
    MDI pair whole on one cable pair, all four cable pairs used once. Exchanging
    MDI2 with MDI3 or MDI0 with MDI1 and turning polarity are allowed; moving a
    net across the A/B - C/D boundary gives a board with no link at all.

Added in task 10 (ruling BJ), the two properties of the routed board that the
DRC cannot see, measured on the committed board under KiCad's Python
(board_probe.py; they error, not skip, if it is missing):

  * in1_continuity_problems: every pair track on F.Cu has In1 GND under its
    centre line and both edges, all along, with three named exceptions and
    ruling AR's conditions for the USB 2.0 stretch on B.Cu;
  * pair_coupling_problems: the length of each pair net outside its +/-10 %
    differential-impedance window lies in a named region with a cap (what the
    rulings granted), nowhere else, and the share inside the window stays above
    the floor those caps leave.
  Both have mutation tests on scratch copies of the board (board_mutate.py), and
  hardware/review/2026-11-03-routed/mutation_evidence.py runs them on the real
  boards of task 9 that carried the defects.

Added in task 11 (the PCBWay package in hardware/fab/):

  * check_gerber_freshness: the gerber set binds to the SHA-256 of the board, its
    rules and its project file through release-manifest.json, every file is what
    the manifest says, and the DRC report beside it is clean; a fresh export of
    the board must reproduce the committed files. Mutation tests damage a copy.
  * cpl_pin1_problems: the CPL rotation is derived from pad 1 in the copper
    gerber and the footprint's silkscreen pin-1 marking, never from the
    placement table; the paste layer opens only U3 and Y1; the assembly BOM has
    exactly those two; ORDERING.md states every ruled requirement and its numbers
    agree with the board; the release set is not git-ignored (ruling E).

Usage:
    python3 check_fab_release.py [-v]
"""

import copy
import csv
import json
import math
import re
import shutil
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
PRO = HARDWARE / "kicad" / "raccoon-tap.kicad_pro"
STACKUP_NOTE = HARDWARE / "fab" / "stackup-note.md"
DRU = HARDWARE / "kicad" / "raccoon-tap.kicad_dru"
GEN_BOM = HARDWARE / "tools" / "gen_bom.py"
GEN_SCHEMATIC = HARDWARE / "tools" / "gen_schematic.py"
GEN_PCB = HARDWARE / "tools" / "gen_pcb.py"
PCB = HARDWARE / "kicad" / "raccoon-tap.kicad_pcb"

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


def load_pro(path=PRO):
    with open(path) as handle:
        return json.load(handle)


def load_stackup_note(path=STACKUP_NOTE):
    """The stackup note as text, or None if it does not exist."""
    path = Path(path)
    return path.read_text(encoding="utf-8") if path.exists() else None


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


def gated_rail_inrush_profile(netlist, gated_rail, tss_scale=1.0, uvlo_v=None):
    """Model the current drawn through a load switch while its output ramps.

    Returns {"peak_ma", "average_ma", "slew_v_per_s", ...}. It is a MODEL of
    the capacitive charging only, in phases, with the CT capacitor taken
    CT_MARGIN low:

      * the gated rail's own capacitance charges at the full slew for the
        whole ramp;
      * a linear regulator (model: ldo) passes its output charge straight
        through: while its input is within `dropout_assumed_v` of the output
        voltage the output tracks the input, so the capacitance behind it
        charges at the same slew, in the first part of the ramp;
      * a buck (model: buck) starts when the input crosses its UVLO and then
        brings its output up linearly in its soft-start time; the input
        current is the output charging current times Vout/(Vin x efficiency),
        evaluated at every instant, not at a fixed ratio.

    NOT in it: the start-up load of U3 itself, the 10-90 % table's missing
    first and last tenth, hot-plug ringing. `tss_scale` and `uvlo_v` replace
    the buck's soft-start time factor and UVLO for sensitivity runs, because
    the committed SY8089 note gives TSS as a typical value only and the UVLO
    as a maximum only. Raises ValueError if the switch has no readable CT
    capacitor on its CT pin or a downstream model is unknown.
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
    rise_us = interpolate_rise_us(soft["rise_time_us_10_90_at_5v"],
                                  ct_pf * (1.0 - CT_MARGIN))
    slew = soft["swing_fraction"] * v_gated / (rise_us * 1e-6)   # V/s
    ramp_s = v_gated / slew

    own_f = sum_bulk_capacitance(netlist, gated_rail) * 1e-6
    phases = []
    for rail_name, down in spec["downstream_rails"].items():
        v_out = float(rails[rail_name]["nominal_v"])
        c_f = sum(sum_bulk_capacitance(netlist, n) for n in down["nets"]) * 1e-6
        via = components[down["via"]]
        if down["model"] == "ldo":
            phases.append(("ldo", c_f, v_out,
                           float(via["tracking"]["dropout_assumed_v"])))
        elif down["model"] == "buck":
            ss = via["soft_start"]
            phases.append(("buck", c_f, v_out,
                           float(ss["tss_ms"]) * 1e-3 * tss_scale,
                           float(ss["uvlo_v"]) if uvlo_v is None else uvlo_v,
                           float(ss["efficiency_assumed"])))
        else:
            raise ValueError(f"{rail_name}: unknown model {down['model']!r}")

    step = 1e-6
    end = ramp_s
    for ph in phases:
        if ph[0] == "buck":
            end = max(end, ph[4] / slew + ph[3])
    peak = total = 0.0
    t_peak = 0.0
    n = int(end / step) + 1
    for i in range(n):
        t = i * step
        v_in = min(v_gated, slew * t)
        current = own_f * slew if t < ramp_s else 0.0
        for ph in phases:
            if ph[0] == "ldo":
                _, c_f, v_out, dropout = ph
                if t < ramp_s and v_in - dropout < v_out:
                    current += c_f * slew
            else:
                _, c_f, v_out, tss, uvlo, eff = ph
                t0 = uvlo / slew
                if t >= t0 and (t - t0) < tss:
                    v_o = v_out * (t - t0) / tss
                    current += c_f * (v_out / tss) * v_o / (v_in * eff)
        if current > peak:
            peak, t_peak = current, t
        if t < ramp_s:
            total += current * step
    return {"peak_ma": peak * 1e3, "average_ma": total / ramp_s * 1e3,
            "slew_v_per_s": slew, "ramp_ms": ramp_s * 1e3,
            "t_peak_ms": t_peak * 1e3}


def gated_rail_inrush_ma(netlist, gated_rail):
    """Modelled peak charging current in mA; see gated_rail_inrush_profile."""
    return gated_rail_inrush_profile(netlist, gated_rail)["peak_ma"]


# --- Differential-pair geometry (task 7) -----------------------------------

# PCBWay's "Edge Coupled Microstrip" calculator, https://www.pcbway.com/
# pcb_prototype/impedance_calculator.html, function EdgeCoupledMicrostrip().
# The page converts every input to mil with these factors (its <li data-val>
# lists); they are kept as the page has them, not rounded to 25.4 / 39.37.
# Excerpt of the page source: hardware/fab/pcbway-source-excerpts.txt [1].
_PCBWAY_MIL_PER_OZ = 1.379
_PCBWAY_MIL_PER_MM = 39.3

# The calculator leaves solder mask out ("the outer layer impedance testing
# does not include the solder mask", excerpt [1]). PCBWay's own figure for it,
# https://www.pcbway.com/pcb_prototype/Impedance_Control.html, "Factors that
# Influence Impedance", Soldermask thickness (excerpt [4]): "Typically,
# printing one pass of solder mask reduces single-ended impedance by 2 ohms
# and differential impedance by 8 ohms." The net classes are centred on the
# as-built value, calculator minus this offset. One pass is assumed; how many
# passes PCBWay prints on this order is an open item in stackup-note.md.
PCBWAY_MASK_OFFSET_OHM = 8.0

# Net class -> the stackup.impedance keys of netlist.yaml that set its target.
GEOMETRY_CLASSES = {"USB3": ("usb3_superspeed", "usb2_dp_dm"),
                    "MDI": ("mdi_pairs",)}
# How far the as-built value may sit from the target before the geometry
# counts as not computed. PCBWay quotes +/-10 % for the process (capabilities
# row 35); this guard is much tighter, because it only has to catch a number
# that was never run through the formula.
GEOMETRY_FORMULA_TOLERANCE = 0.03
# Class clearance floor. It also governs pair-to-pair spacing, so it must not
# follow the in-pair gap down; the in-pair gap gets its own rule in
# raccoon-tap.kicad_dru instead.
PAIR_CLEARANCE_MIN = 0.2
# A 0.20 mm trace leaving a U3 pad runs 0.175 mm from the neighbouring pad of
# another pair (0.25 mm pads, 0.4 mm pitch), under the class clearance. Decided
# in review: neck the trace at the pad, no clearance exception. The limits are
# the most the note may allow task 9: a neck no wider than this and no longer
# than this, measured from the pad.
NECK_MAX_WIDTH_MM = 0.15
NECK_MAX_LENGTH_MM = 1.0

NOTE_REQUIRED_HEADINGS = (
    "## Stackup",
    "## Dielectric constant",
    "## Result per impedance target",
    "## Tolerance",
    "## Minimum trace width and spacing",
    "## Constraints for task 9",
    "## Fit on 58 x 36 mm",
    "## Open items",
)
_GEOMETRY_BLOCK = re.compile(
    r"<!-- netclass-geometry -->\s*```yaml\n(.*?)\n```", re.DOTALL)
_DRU_RULE = re.compile(
    r'\(rule\s+"([^"]+)"\s*\(condition\s+"([^"]*)"\)\s*'
    r'\(constraint\s+clearance\s+\(min\s+([0-9.]+)mm\)\)\s*\)')


def pcbway_edge_coupled_zd(t_oz, h_mm, w_mm, s_mm, er):
    """Differential impedance in ohm that PCBWay's Edge Coupled Microstrip
    calculator prints for copper thickness t (oz/ft2), dielectric height h,
    trace width w and spacing s (mm), and dielectric constant er. Bare
    copper: no solder mask."""
    t, h = t_oz * _PCBWAY_MIL_PER_OZ, h_mm * _PCBWAY_MIL_PER_MM
    w, s = w_mm * _PCBWAY_MIL_PER_MM, s_mm * _PCBWAY_MIL_PER_MM
    zo = 87.0 / math.sqrt(1.41 + er) * math.log(5.98 * h / (0.8 * w + t))
    return 2.0 * zo * (1.0 - 0.48 * math.exp(-0.96 * s / h))


def as_built_zd(t_oz, h_mm, w_mm, s_mm, er,
                mask_offset_ohm=PCBWAY_MASK_OFFSET_OHM):
    """The calculator's value minus the solder-mask offset: what the board is
    expected to measure with one pass of mask."""
    return pcbway_edge_coupled_zd(t_oz, h_mm, w_mm, s_mm, er) - mask_offset_ohm


def netlist_impedance_targets(netlist):
    """{net class: target in ohm} read from netlist.yaml stackup.impedance.

    Each value is a sentence such as '90 ohm differential, +/-10%, ...'; the
    number in front of 'ohm' is the target. Classes with several keys (USB3 is
    set by the SuperSpeed and the USB 2.0 entry) must agree. Raises ValueError
    for a missing key, an unreadable entry or a disagreement."""
    impedance = netlist["stackup"]["impedance"]
    targets = {}
    for name, keys in GEOMETRY_CLASSES.items():
        values = set()
        for key in keys:
            match = re.match(r"\s*([0-9]+(?:\.[0-9]+)?)\s*ohm\b",
                             str(impedance.get(key, "")))
            if not match:
                raise ValueError(f"netlist.yaml stackup.impedance.{key} does "
                                 f"not start with '<number> ohm': "
                                 f"{impedance.get(key)!r}")
            values.add(float(match.group(1)))
        if len(values) != 1:
            raise ValueError(f"netlist.yaml stackup.impedance entries {keys} "
                             f"of class {name} disagree: {sorted(values)}")
        targets[name] = values.pop()
    return targets


def load_dru(path=DRU):
    """The project's custom DRC rules as text, or None if there is no file."""
    path = Path(path)
    return path.read_text(encoding="utf-8") if path.exists() else None


def unpaired_diff_pair_nets(netlist, pro_json):
    """Nets of the USB3 and MDI net classes that KiCad's differential-pair
    router and A.isCoupledDiffPair() would not pair, one message each.

    KiCad pairs two nets on a trailing _P / _N (or +/-) with the same stem in
    front of it. A net of those classes that carries a _P or _N token but does
    not end in it (USB3_TX_P_CONN), or whose partner is missing, is not a pair
    to KiCad, and the pair-gap rule in the .kicad_dru would not apply to it.
    Nets without a _P / _N token (MDI_CT, the centre tap) are not pair nets."""
    import fnmatch
    patterns = [(e["pattern"], e["netclass"])
                for e in pro_json.get("net_settings", {}).get(
                    "netclass_patterns", [])
                if e.get("netclass") in GEOMETRY_CLASSES]
    nets = [n for n in netlist["nets"]
            if any(fnmatch.fnmatchcase(n, pat) for pat, _ in patterns)]
    problems = []
    for net in sorted(nets):
        if not re.search(r"_[PN](_|$)", net):
            continue
        if not re.search(r"_[PN]$", net):
            problems.append(f"{net}: _P / _N is not the last part of the "
                            f"name, KiCad will not treat it as a pair")
            continue
        partner = net[:-1] + ("N" if net.endswith("P") else "P")
        if partner not in netlist["nets"]:
            problems.append(f"{net}: no partner net {partner}")
    return problems


_LOAD = object()


U3_TRACK_RULE = "track to U3 pad on fine-pitch parts"
# Tracks only (not vias, zones or pads), pads of U3 only, any net on either
# side: a signal track against a supply pad and a supply escape against a signal
# pad are the same condition.
U3_TRACK_RULE_CONDITION = ("A.Type == 'Track' && B.Type == 'Pad' && "
                           "B.memberOfFootprint('U3')")
U3_TRACK_RULE_MIN_MM = PAIR_CLEARANCE_MIN


def u3_track_rule_problems(dru_text=_LOAD):
    """One message per reason the U3 track-to-pad rule is not what task 8 wrote.

    It must be present, its condition must be exactly U3_TRACK_RULE_CONDITION
    (whitespace aside: no other item type, no other footprint, no net or net
    class restriction that would drop one of the two directions) and its minimum
    must be U3_TRACK_RULE_MIN_MM, the signal classes' own clearance, so nothing
    is allowed nearer than a signal track already was."""
    if dru_text is _LOAD:
        dru_text = load_dru()
    rules = {name: (" ".join(condition.split()), float(minimum))
             for name, condition, minimum in _DRU_RULE.findall(dru_text or "")}
    if U3_TRACK_RULE not in rules:
        return [f"raccoon-tap.kicad_dru has no rule {U3_TRACK_RULE!r}: a track "
                f"cannot leave a U3 pad next to a supply pad at the Power "
                f"class's 0.3 mm"]
    condition, minimum = rules[U3_TRACK_RULE]
    problems = []
    if condition != U3_TRACK_RULE_CONDITION:
        problems.append(f"rule {U3_TRACK_RULE!r} has condition {condition!r}, "
                        f"it must be {U3_TRACK_RULE_CONDITION!r}: tracks "
                        f"against pads of U3, any net")
    if not math.isclose(minimum, U3_TRACK_RULE_MIN_MM, abs_tol=1e-9):
        problems.append(f"rule {U3_TRACK_RULE!r} says min {minimum:g}, it must "
                        f"be {U3_TRACK_RULE_MIN_MM:g} (the signal class "
                        f"clearance: lower weakens the board, higher does not "
                        f"clear the 0.4 mm pitch)")
    return problems


U3_ESCAPE_RULE = "track to track at the U3 escape"
U3_ESCAPE_AREA = "U3_escape"
# Tracks against tracks only, both inside the area round U3's escape, any net
# on either side (ruling AU).
U3_ESCAPE_RULE_CONDITION = ("A.Type == 'Track' && B.Type == 'Track' && "
                            "A.insideArea('U3_escape') && B.insideArea('U3_escape')")
U3_ESCAPE_RULE_MIN_MM = PAIR_CLEARANCE_MIN
# The area takes in U3's pads (outer ends 2.85 mm from the centre) and the
# 1.0 mm necks (3.44 mm); gen_pcb.py U3_ESCAPE_HALF. Wider would let the 0.2 mm
# reach tracks that have left U3.
U3_ESCAPE_HALF_MAX_MM = 3.45


def _rule_area(pcb_text, name):
    """(layers, keepout block or '', [(x, y), ...]) of the zone named `name`,
    or None."""
    for block in re.findall(r"\n\t\(zone\n.*?\n\t\)", pcb_text, re.S):
        if f'(name "{name}")' not in block:
            continue
        layers = re.search(r"\(layers? ([^)]*)\)", block).group(1)
        keepout = re.search(r"\(keepout(.*?)\n\t\t\)", block, re.S)
        pts = [(float(x), float(y)) for x, y in
               re.findall(r"\(xy ([-0-9.]+) ([-0-9.]+)\)", block.split("(polygon", 1)[1])]
        return layers, keepout.group(1) if keepout else "", pts
    return None


def _footprint_at(pcb_text, ref):
    for block in re.split(r"\n\t\(footprint ", pcb_text)[1:]:
        if re.search(r'\(property "Reference" "%s"' % re.escape(ref), block):
            x, y = re.search(r"\n\t\t\(at ([-0-9.]+) ([-0-9.]+)", block).groups()
            return float(x), float(y)
    return None


def u3_escape_rule_problems(dru_text=_LOAD, pcb_text=_LOAD):
    """One message per reason the rule of ruling AU, or the area it is scoped
    to, is not what task 9 wrote: the rule must exist with exactly
    U3_ESCAPE_RULE_CONDITION and U3_ESCAPE_RULE_MIN_MM; the area must exist on
    the board as a rule area on F.Cu that forbids nothing, and reach no
    further than U3_ESCAPE_HALF_MAX_MM from U3's centre."""
    if dru_text is _LOAD:
        dru_text = load_dru()
    if pcb_text is _LOAD:
        pcb_text = PCB.read_text(encoding="utf-8")
    rules = {name: (" ".join(condition.split()), float(minimum))
             for name, condition, minimum in _DRU_RULE.findall(dru_text or "")}
    problems = []
    if U3_ESCAPE_RULE not in rules:
        problems.append(f"raccoon-tap.kicad_dru has no rule {U3_ESCAPE_RULE!r}: "
                        f"a supply escape cannot leave U3 beside another escape "
                        f"at the Power class's 0.3 mm")
    else:
        condition, minimum = rules[U3_ESCAPE_RULE]
        if condition != U3_ESCAPE_RULE_CONDITION:
            problems.append(f"rule {U3_ESCAPE_RULE!r} has condition {condition!r}, "
                            f"it must be {U3_ESCAPE_RULE_CONDITION!r}: tracks "
                            f"against tracks, both in the area, any net")
        if not math.isclose(minimum, U3_ESCAPE_RULE_MIN_MM, abs_tol=1e-9):
            problems.append(f"rule {U3_ESCAPE_RULE!r} says min {minimum:g}, it must "
                            f"be {U3_ESCAPE_RULE_MIN_MM:g} (the signal class "
                            f"clearance)")
    area = _rule_area(pcb_text or "", U3_ESCAPE_AREA)
    if area is None:
        problems.append(f"the board has no zone named {U3_ESCAPE_AREA!r}: the rule "
                        f"{U3_ESCAPE_RULE!r} would match nothing")
        return problems
    layers, keepout, pts = area
    if not keepout:
        problems.append(f"zone {U3_ESCAPE_AREA!r} is not a rule area")
    elif "not_allowed" in keepout:
        problems.append(f"rule area {U3_ESCAPE_AREA!r} forbids something; it is "
                        f"there to name a region, not to keep anything out")
    if layers.split() != ['"F.Cu"']:
        problems.append(f"rule area {U3_ESCAPE_AREA!r} is on {layers}, it must be "
                        f"on F.Cu only (U3's escape)")
    centre = _footprint_at(pcb_text, "U3")
    if centre is None or not pts:
        problems.append("U3 or the area's outline cannot be read")
    else:
        reach = max(max(abs(x - centre[0]), abs(y - centre[1])) for x, y in pts)
        if reach > U3_ESCAPE_HALF_MAX_MM + 1e-6:
            problems.append(f"rule area {U3_ESCAPE_AREA!r} reaches {reach:.2f} mm "
                            f"from U3's centre, at most {U3_ESCAPE_HALF_MAX_MM} "
                            f"(pads and 1.0 mm necks)")
    return problems


# RJ45 pins of the four cable pairs of 1000BASE-T (IEEE 802.3 clause 40) and the
# group each MDI pair of the RTL8153B belongs to ([RTL-DS] Table 4: MDI0 BI_DA,
# MDI1 BI_DB, MDI2 BI_DC, MDI3 BI_DD). A and B carry 10/100 and auto-negotiation.
CABLE_PAIRS = {"A": (1, 2), "B": (3, 6), "C": (4, 5), "D": (7, 8)}
MDI_GROUPS = {"MDI0": "AB", "MDI1": "AB", "MDI2": "CD", "MDI3": "CD"}


# Ruling BF (task 9 review 1): ruling AU's 0.2 mm may reach past the edge of
# U3's escape area only as far as a track's round end does. Every place where
# it is used there, with the least gap and how far past the edge it reaches;
# a new place, a smaller gap or a longer reach fails. The two of pin 14's
# +1V0 escape are the named exception of ruling BF (first-build check:
# fabrication-note.md); the others were found by the review (Minor) and are
# geometry the U3 placement forces at its pins.
# Ruling BQ's second cut changed no copper but moved the segment ends the
# 0.01 mm sampling starts from: four reaches read 0.001-0.005 mm longer and
# were updated by hand (RX_N 0.201 -> 0.206, RSET 0.200 -> 0.203, MDI1_P
# 0.110 -> 0.113, +3V3 0.040 -> 0.041); no gap got smaller.
AU_OVERHANGS = {
    # (net, net): (least gap mm, reach past the edge mm)
    ("+1V0", "USB3_RX_N"): (0.228, 0.206),     # BF exception: pin 14
    ("+1V0", "USB3_TX_P"): (0.250, 0.120),     # BF exception: pin 14
    ("+1V0", "+3V3"): (0.289, 0.041),
    ("+1V0", "MDI1_P"): (0.262, 0.113),
    ("+1V0", "MDI2_N"): (0.262, 0.120),
    ("+1V0", "RSET"): (0.250, 0.203),
    ("+1V0", "XTAL1"): (0.297, 0.020),
    ("+1V0", "XTAL2"): (0.297, 0.020),
    ("+3V3", "DVDD10_UPS"): (0.225, 0.143),
}
AU_CUT_OUT = 0.25     # ruling BQ: route_pcb.AU_CUT_OUT, the second cut past the edge
AU_POWER_NETS = {"GND", "+5V", "+3V3", "+1V0", "SW_1V0"}   # the Power class, as route_grid.POWER
_SEGMENT = re.compile(r"\n\t\(segment\n\t\t\(start ([-0-9.]+) ([-0-9.]+)\)\n\t\t\(end ([-0-9.]+) ([-0-9.]+)\)"
                      r"\n\t\t\(width ([0-9.]+)\)\n\t\t\(layer \"F.Cu\"\)\n\t\t\(net \"([^\"]*)\"\)")


def _seg_dist(a, b, q):
    dx, dy = b[0] - a[0], b[1] - a[1]
    t = 0.0 if dx == dy == 0 else max(0.0, min(1.0, ((q[0] - a[0]) * dx + (q[1] - a[1]) * dy) / (dx * dx + dy * dy)))
    return math.hypot(q[0] - a[0] - t * dx, q[1] - a[1] - t * dy)


def _partner(net):
    for a, b in (("_P", "_N"), ("_N", "_P")):
        if net.endswith(a):
            return net[:-2] + b
    return None


def u3_area_edge_problems(pcb_text=_LOAD, step=0.01):
    """Ruling BF: one message per F.Cu segment that runs both inside and
    outside U3's escape area, and per place where ruling AU is used past the
    area's edge that AU_OVERHANGS does not list or that is nearer or reaches
    further than it says."""
    pcb_text = PCB.read_text(encoding="utf-8") if pcb_text is _LOAD else pcb_text
    area = _rule_area(pcb_text, U3_ESCAPE_AREA)
    if area is None:
        return [f"no zone named {U3_ESCAPE_AREA}"]
    xs, ys = [p[0] for p in area[2]], [p[1] for p in area[2]]
    A = (min(xs), min(ys), max(xs), max(ys))
    eps = 1e-4

    def inside(q):
        return A[0] + eps < q[0] < A[2] - eps and A[1] + eps < q[1] < A[3] - eps

    def outside(q):
        return q[0] < A[0] - eps or q[0] > A[2] + eps or q[1] < A[1] - eps or q[1] > A[3] + eps

    def outside_by(q):
        return math.hypot(max(A[0] - q[0], 0, q[0] - A[2]), max(A[1] - q[1], 0, q[1] - A[3]))
    problems, touching = [], []
    for m in _SEGMENT.finditer(pcb_text):
        a, b = (float(m.group(1)), float(m.group(2))), (float(m.group(3)), float(m.group(4)))
        w, net = float(m.group(5)), m.group(6)
        if (inside(a) and outside(b)) or (inside(b) and outside(a)):
            problems.append(f"{net} segment {a} -> {b} runs across the edge of {U3_ESCAPE_AREA}: "
                            "cut it there (ruling BF)")
        dx = max(A[0] - max(a[0], b[0]), 0, min(a[0], b[0]) - A[2])
        dy = max(A[1] - max(a[1], b[1]), 0, min(a[1], b[1]) - A[3])
        if math.hypot(dx, dy) <= w / 2:
            touching.append((net, a, b, w))
            # ruling BQ: a segment that touches the area carries ruling AU over
            # its whole length, so it must end at the second cut
            far = max(outside_by(a), outside_by(b))
            if far > AU_CUT_OUT + w / 2 + 0.002:
                problems.append(f"{net} segment {a} -> {b} touches {U3_ESCAPE_AREA} and runs {far:.3f} mm "
                                f"past its edge: ruling AU's 0.2 mm reaches that far (cut it "
                                f"{AU_CUT_OUT} mm + half its width past the edge, ruling BQ)")
    found = {}
    for na, a, b, wa in touching:
        k = max(1, int(math.hypot(b[0] - a[0], b[1] - a[1]) / step))
        for i in range(k + 1):
            q = (a[0] + (b[0] - a[0]) * i / k, a[1] + (b[1] - a[1]) * i / k)
            o = outside_by(q)
            if o <= 0:
                continue
            for nb, c, d, wb in touching:
                if nb in (na, _partner(na)):
                    continue
                cls = 0.3 if na in AU_POWER_NETS or nb in AU_POWER_NETS else 0.2
                g = _seg_dist(c, d, q) - wa / 2 - wb / 2
                if g < cls - 1e-4:
                    key = tuple(sorted((na, nb)))
                    gap, reach = found.get(key, (9.0, 0.0))
                    found[key] = (min(gap, g), max(reach, o))
    for key, (g, o) in sorted(found.items()):
        if key not in AU_OVERHANGS:
            problems.append(f"{key[0]} / {key[1]}: ruling AU used {o:.3f} mm past the edge of "
                            f"{U3_ESCAPE_AREA} at {g:.3f} mm, not in AU_OVERHANGS")
            continue
        g0, o0 = AU_OVERHANGS[key]
        if g < g0 - 0.002 or o > o0 + 0.002:
            problems.append(f"{key[0]} / {key[1]}: {g:.3f} mm at {o:.3f} mm past the edge, "
                            f"AU_OVERHANGS allows {g0} mm at {o0} mm")
    return problems


def mdi_group_problems(netlist):
    """One message per reason the MDI nets do not stay inside their group of
    cable pairs. J2's pin -> RJ45 pin table is read from the pin notes
    ("... -> cable J4 ...": the RJ45 pin), so it is the netlist's own."""
    problems = []
    rj45 = {}
    pins = netlist["components"]["J2"].get("pins", {})
    for pin, info in pins.items():
        match = re.search(r"cable J(\d)\b", str((info or {}).get("note", "")))
        if match:
            rj45[str(pin)] = int(match.group(1))
    pair_of = {pin: letter for letter, pins_ in CABLE_PAIRS.items()
               for pin in pins_}
    landing = {}
    for net, endpoints in netlist["nets"].items():
        match = re.fullmatch(r"(MDI[0-3])_([PN])", net)
        if not match:
            continue
        j2 = [str(e).split(".", 1)[1] for e in endpoints or []
              if str(e).startswith("J2.")]
        if len(j2) != 1:
            problems.append(f"{net}: expected one J2 pin, found {j2}")
            continue
        if j2[0] not in rj45:
            problems.append(f"{net}: J2 pin {j2[0]} has no 'cable J<n>' in its "
                            f"note, the RJ45 pin is unknown")
            continue
        cable = pair_of.get(rj45[j2[0]])
        landing.setdefault(match.group(1), set()).add(cable)
        if cable is None or cable not in MDI_GROUPS[match.group(1)]:
            problems.append(
                f"{net} is on J2 pin {j2[0]} = RJ45 pin {rj45[j2[0]]} = cable "
                f"pair {cable}, outside its group {MDI_GROUPS[match.group(1)]} "
                f"({match.group(1)} is "
                f"{'10/100 and auto-negotiation' if MDI_GROUPS[match.group(1)] == 'AB' else 'gigabit only'})")
    used = []
    for mdi, cables in sorted(landing.items()):
        if len(cables) != 1:
            problems.append(f"{mdi}: its two nets are on different cable pairs "
                            f"{sorted(str(c) for c in cables)}")
        used += list(cables)
    if sorted(map(str, used)) != sorted(CABLE_PAIRS):
        problems.append(f"the four MDI pairs must use cable pairs A, B, C and D "
                        f"once each, they use {sorted(map(str, used))}")
    return problems



def check_no_placeholder_geometry(pro_json, stackup_note, dru_text=_LOAD,
                                  netlist=_LOAD):
    """One message per reason the USB3 and MDI net classes are not the
    geometry that hardware/fab/stackup-note.md documents.

    `stackup_note` is the note's text, or None if the file does not exist.
    `dru_text` and `netlist` default to the committed files. The note carries
    a machine-readable block (the `netclass-geometry` marker followed by a
    yaml fence) with the inputs fed to the calculator, the solder-mask offset
    and, per class, the width, gap and clearance that came out. The check

      * reports a missing note, a missing block and a missing heading;
      * takes each class's target from netlist.yaml stackup.impedance, not
        from the note, and reports a note that disagrees with it;
      * compares diff_pair_width, diff_pair_gap, track_width and clearance of
        each class with the note;
      * recomputes the impedance from the note's own inputs with PCBWay's
        published formula, subtracts the solder-mask offset (which must be
        PCBWAY_MASK_OFFSET_OHM) and reports an as-built value further than
        GEOMETRY_FORMULA_TOLERANCE from the target;
      * requires class clearance >= PAIR_CLEARANCE_MIN, because it also
        governs pair-to-pair spacing, and, where the pair gap is below the
        class clearance, a rule in the .kicad_dru that scopes the smaller
        clearance to the two traces of one coupled pair of that class;
      * requires the neck limits for the U3 pads (`task9` in the block) to be
        present and no looser than NECK_MAX_WIDTH_MM / NECK_MAX_LENGTH_MM;
      * requires every non-zero differential-pair preset of the interactive
        router to be one of the documented geometries.
    """
    if not stackup_note or not stackup_note.strip():
        return ["hardware/fab/stackup-note.md is missing or empty: the "
                "diff-pair geometry has no documented source"]
    problems = [f"stackup note has no section {h!r}"
                for h in NOTE_REQUIRED_HEADINGS if h not in stackup_note]
    block = _GEOMETRY_BLOCK.search(stackup_note)
    if not block:
        return problems + ["stackup note has no machine-readable "
                           "`<!-- netclass-geometry -->` yaml block"]
    try:
        documented = yaml.safe_load(block.group(1))
        inputs = documented["inputs"]
        t_oz, h_mm, er = (float(inputs[k]) for k in ("t_oz", "h_mm", "er"))
        mask_offset = float(inputs["mask_offset_ohm"])
        classes = documented["classes"]
    except (yaml.YAMLError, KeyError, TypeError, ValueError) as error:
        return problems + [f"netclass-geometry block is unreadable: {error!r}"]
    try:
        neck = documented["task9"]
        neck_width = float(neck["neck_max_width_mm"])
        neck_length = float(neck["neck_max_length_mm"])
    except (KeyError, TypeError, ValueError) as error:
        problems.append(f"netclass-geometry block has no readable `task9` "
                        f"neck limits: {error!r}")
    else:
        if not 0 < neck_width <= NECK_MAX_WIDTH_MM:
            problems.append(f"task9 neck_max_width_mm is {neck_width:g}, "
                            f"it must be above 0 and at most "
                            f"{NECK_MAX_WIDTH_MM:g}")
        if not 0 < neck_length <= NECK_MAX_LENGTH_MM:
            problems.append(f"task9 neck_max_length_mm is {neck_length:g}, "
                            f"it must be above 0 and at most "
                            f"{NECK_MAX_LENGTH_MM:g}")
    if not math.isclose(mask_offset, PCBWAY_MASK_OFFSET_OHM, abs_tol=1e-9):
        problems.append(
            f"mask_offset_ohm is {mask_offset:g} in the note, PCBWay's "
            f"published figure is {PCBWAY_MASK_OFFSET_OHM:g} ohm for "
            f"differential pairs (Impedance_Control page, excerpt [4])")

    if netlist is _LOAD:
        netlist = load_netlist()
    try:
        targets = netlist_impedance_targets(netlist)
    except (KeyError, TypeError, ValueError) as error:
        return problems + [f"netlist.yaml impedance targets unreadable: "
                           f"{error!r}"]
    if dru_text is _LOAD:
        dru_text = load_dru()
    rules = {name: (condition, float(minimum))
             for name, condition, minimum in _DRU_RULE.findall(dru_text or "")}

    by_name = {c.get("name"): c
               for c in pro_json.get("net_settings", {}).get("classes", [])}
    allowed = set()
    for name, target in targets.items():
        entry = classes.get(name) if isinstance(classes, dict) else None
        if not isinstance(entry, dict):
            problems.append(f"{name}: not documented in the stackup note")
            continue
        try:
            width, gap = float(entry["width_mm"]), float(entry["gap_mm"])
            clearance = float(entry["clearance_mm"])
            documented_target = float(entry["target_ohm"])
        except (KeyError, TypeError, ValueError) as error:
            problems.append(f"{name}: note entry is incomplete: {error!r}")
            continue
        if documented_target != target:
            problems.append(f"{name}: note targets {documented_target:g} ohm, "
                            f"netlist.yaml stackup.impedance says {target:g}")
        allowed.add((width, gap))
        zd = as_built_zd(t_oz, h_mm, width, gap, er, mask_offset)
        if abs(zd - target) > GEOMETRY_FORMULA_TOLERANCE * target:
            problems.append(
                f"{name}: width {width} / gap {gap} give {zd:.1f} ohm as built "
                f"(PCBWay's formula {zd + mask_offset:.1f} minus the "
                f"solder-mask offset {mask_offset:g}) for the note's inputs, "
                f"target {target:g}")
        if not 0.1 <= width / h_mm <= 2.0:
            problems.append(f"{name}: w/h = {width / h_mm:.2f} is outside "
                            f"0.1..2.0, where PCBWay's calculator warns")
        if clearance < PAIR_CLEARANCE_MIN:
            problems.append(
                f"{name}: clearance {clearance} is below "
                f"{PAIR_CLEARANCE_MIN}; it also sets the spacing between "
                f"pairs, give the pair gap its own rule in the .kicad_dru")
        if gap < clearance:
            rule = rules.get(f"intra-pair clearance {name}")
            if rule is None:
                problems.append(
                    f"{name}: gap {gap} is below clearance {clearance} but "
                    f"raccoon-tap.kicad_dru has no rule "
                    f"'intra-pair clearance {name}'")
            else:
                condition, minimum = rule
                for needle in (f"A.NetClass == '{name}'",
                               f"B.NetClass == '{name}'",
                               "A.isCoupledDiffPair()",
                               "A.Type != 'Pad' || B.Type != 'Pad'"):
                    if needle not in condition:
                        problems.append(
                            f"{name}: rule 'intra-pair clearance {name}' is "
                            f"not scoped to one coupled pair of the class: "
                            f"condition lacks {needle!r}")
                if not math.isclose(minimum, gap, abs_tol=1e-9):
                    problems.append(
                        f"{name}: rule 'intra-pair clearance {name}' says "
                        f"min {minimum}, the pair gap is {gap}")
        netclass = by_name.get(name)
        if netclass is None:
            problems.append(f"{name}: no such net class in the project")
            continue
        for key, want in (("diff_pair_width", width), ("diff_pair_gap", gap),
                          ("track_width", width), ("clearance", clearance)):
            if not math.isclose(netclass.get(key, math.nan), want,
                                abs_tol=1e-9):
                problems.append(
                    f"{name}: {key} is {netclass.get(key)!r}, the stackup "
                    f"note documents {want}")
    presets = pro_json.get("board", {}).get("design_settings", {}).get(
        "diff_pair_dimensions", [])
    shown = set()
    for preset in presets:
        pair = (preset.get("width"), preset.get("gap"))
        if pair == (0.0, 0.0):
            continue
        shown.add(pair)
        if not any(math.isclose(pair[0], w, abs_tol=1e-9)
                   and math.isclose(pair[1], g, abs_tol=1e-9)
                   for w, g in allowed):
            problems.append(f"router preset width {pair[0]} / gap {pair[1]} "
                            f"is not a documented geometry")
    for w, g in sorted(allowed):
        if not any(math.isclose(w, a, abs_tol=1e-9)
                   and math.isclose(g, b, abs_tol=1e-9) for a, b in shown):
            problems.append(f"documented geometry width {w} / gap {g} is "
                            f"missing from the router's diff-pair presets")
    return problems


class FabReleaseChecks(unittest.TestCase):

    def test_vbus_bulk_capacitance_within_usb_limit(self):
        total_uf = sum_bulk_capacitance(load_netlist(), rail="+5V")
        self.assertLessEqual(
            total_uf, VBUS_MAX_UF,
            f"{total_uf:.1f} uF an VBUS, USB erlaubt {VBUS_MAX_UF:.0f} uF")

    def test_every_bom_row_has_a_part_number(self):
        self.assertEqual(check_mpn_coverage(load_bom()), [])


class DiffPairGeometry(unittest.TestCase):

    def test_diff_pair_geometry_is_calculated_not_placeholder(self):
        self.assertEqual(
            check_no_placeholder_geometry(load_pro(), load_stackup_note()), [])


class DiffPairGeometryCheckCanFail(unittest.TestCase):
    """check_no_placeholder_geometry must reject what it claims to reject."""

    @staticmethod
    def netclass(pro, name):
        return next(c for c in pro["net_settings"]["classes"]
                    if c["name"] == name)

    @staticmethod
    def check(pro=None, note=None, dru=_LOAD, netlist=_LOAD):
        return check_no_placeholder_geometry(
            load_pro() if pro is None else pro,
            load_stackup_note() if note is None else note, dru, netlist)

    def test_the_committed_files_pass(self):
        self.assertEqual(self.check(), [])

    def test_a_missing_note_is_reported(self):
        for note in (None, "", "  \n"):
            problems = check_no_placeholder_geometry(load_pro(), note)
            self.assertEqual(len(problems), 1, repr(note))
            self.assertIn("stackup-note.md", problems[0])

    def test_the_old_placeholders_are_reported(self):
        # the values the net classes carried before task 7
        pro = load_pro()
        usb3, mdi = self.netclass(pro, "USB3"), self.netclass(pro, "MDI")
        usb3.update(diff_pair_width=0.2, diff_pair_gap=0.2, track_width=0.2)
        mdi.update(diff_pair_width=0.18, diff_pair_gap=0.25, track_width=0.18)
        problems = self.check(pro)
        # (the widths were already the computed ones; the gaps were not)
        for name, key in [("USB3", "diff_pair_gap"), ("MDI", "diff_pair_gap")]:
            self.assertTrue(any(p.startswith(name) and key in p
                                for p in problems), (name, key, problems))

    def test_a_change_of_one_value_is_reported(self):
        for name, key in [("USB3", "diff_pair_gap"), ("MDI", "diff_pair_width"),
                          ("USB3", "track_width"), ("MDI", "clearance")]:
            pro = load_pro()
            self.netclass(pro, name)[key] += 0.01
            problems = self.check(pro)
            self.assertTrue(any(p.startswith(name) and key in p
                                for p in problems), (name, key, problems))

    def test_a_note_edited_to_match_a_guess_is_still_reported(self):
        # copying 0.2 / 0.2 into both files does not make 0.2 / 0.2 a 90 ohm
        # geometry: 101.2 ohm from the formula, 93.2 as built
        note = load_stackup_note().replace("width_mm: 0.20, gap_mm: 0.17,",
                                           "width_mm: 0.2, gap_mm: 0.2,")
        self.assertNotEqual(note, load_stackup_note())
        pro = load_pro()
        self.netclass(pro, "USB3").update(diff_pair_width=0.2,
                                          diff_pair_gap=0.2, track_width=0.2)
        pro["board"]["design_settings"]["diff_pair_dimensions"][1].update(
            width=0.2, gap=0.2)
        problems = self.check(pro, note)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("as built", problems[0])

    def test_a_geometry_centred_on_bare_copper_is_reported(self):
        # 0.23 / 0.16 was the first answer: 89.9 ohm from the calculator, 81.9
        # once PCBWay's own 8 ohm for solder mask is taken off
        note = load_stackup_note().replace("width_mm: 0.20, gap_mm: 0.17,",
                                           "width_mm: 0.23, gap_mm: 0.16,")
        pro = load_pro()
        self.netclass(pro, "USB3").update(diff_pair_width=0.23,
                                          diff_pair_gap=0.16, track_width=0.23)
        pro["board"]["design_settings"]["diff_pair_dimensions"][1].update(
            width=0.23, gap=0.16)
        problems = self.check(pro, note)
        self.assertTrue(any("81.9 ohm as built" in p for p in problems),
                        problems)

    def test_a_changed_mask_offset_is_reported(self):
        note = load_stackup_note().replace("mask_offset_ohm: 8.0",
                                           "mask_offset_ohm: 0.0")
        problems = self.check(note=note)
        self.assertTrue(any("mask_offset_ohm" in p for p in problems), problems)
        self.assertTrue(any("as built" in p for p in problems), problems)

    def test_targets_come_from_the_netlist_not_the_note(self):
        netlist = copy.deepcopy(load_netlist())
        netlist["stackup"]["impedance"]["mdi_pairs"] = "85 ohm differential"
        problems = self.check(netlist=netlist)
        self.assertTrue(any(p.startswith("MDI") and "netlist.yaml" in p
                            and "85" in p for p in problems), problems)
        # and the netlist target, not the note's, is what the geometry is
        # held to
        self.assertTrue(any("as built" in p for p in problems), problems)

    def test_netlist_targets_that_disagree_or_cannot_be_read_are_reported(self):
        for key, value in [("usb2_dp_dm", "100 ohm differential"),
                           ("usb3_superspeed", "ninety ohm")]:
            netlist = copy.deepcopy(load_netlist())
            netlist["stackup"]["impedance"][key] = value
            problems = self.check(netlist=netlist)
            self.assertTrue(any("netlist.yaml" in p for p in problems),
                            (key, problems))

    def test_netlist_targets_are_read_as_documented(self):
        self.assertEqual(netlist_impedance_targets(load_netlist()),
                         {"USB3": 90.0, "MDI": 100.0})

    def test_every_diff_pair_net_is_a_pair_to_kicad(self):
        # AH: USB3_TX_P_CONN was not; USB3_TX_CONN_P is
        self.assertEqual(unpaired_diff_pair_nets(load_netlist(), load_pro()),
                         [])

    def test_a_net_with_the_suffix_in_the_wrong_place_is_reported(self):
        netlist = copy.deepcopy(load_netlist())
        nets = netlist["nets"]
        nets["USB3_TX_P_CONN"] = nets.pop("USB3_TX_CONN_P")
        nets["USB3_TX_N_CONN"] = nets.pop("USB3_TX_CONN_N")
        problems = unpaired_diff_pair_nets(netlist, load_pro())
        self.assertEqual(len(problems), 2, problems)
        self.assertTrue(all("USB3_TX_" in p and "not treat it as a pair" in p
                            for p in problems), problems)

    def test_a_pair_net_without_its_partner_is_reported(self):
        netlist = copy.deepcopy(load_netlist())
        del netlist["nets"]["MDI3_N"]
        problems = unpaired_diff_pair_nets(netlist, load_pro())
        self.assertEqual(problems, ["MDI3_P: no partner net MDI3_N"])

    def test_the_neck_limits_must_be_recorded_and_not_grow(self):
        note = load_stackup_note()
        for old, new in [("neck_max_length_mm: 1.0", "neck_max_length_mm: 2.0"),
                         ("neck_max_width_mm: 0.15", "neck_max_width_mm: 0.2"),
                         ("neck_max_length_mm: 1.0", "neck_max_length_mm: 0")]:
            problems = self.check(note=note.replace(old, new))
            self.assertEqual(len(problems), 1, (new, problems))
            self.assertIn("task9", problems[0])
        problems = self.check(note=note.replace("task9:", "other:"))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("task9", problems[0])

    def test_the_rule_must_exclude_pad_against_pad(self):
        dru = load_dru().replace(" && (A.Type != 'Pad' || B.Type != 'Pad')", "")
        problems = self.check(dru=dru)
        self.assertTrue(any("not scoped" in p and "Pad" in p
                            for p in problems), problems)

    def test_a_class_clearance_below_the_floor_is_reported(self):
        # clearance also sets pair-to-pair spacing; it must not follow the pair
        # gap down
        pro = load_pro()
        note = load_stackup_note().replace("gap_mm: 0.17, clearance_mm: 0.2",
                                           "gap_mm: 0.17, clearance_mm: 0.16")
        self.netclass(pro, "USB3")["clearance"] = 0.16
        problems = self.check(pro, note)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("spacing between pairs", problems[0])

    def test_a_pair_gap_below_clearance_needs_its_scoped_rule(self):
        dru = load_dru().replace("intra-pair clearance USB3 after", "x").replace(
            "intra-pair clearance USB3", "other")
        problems = self.check(dru=dru)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith("USB3") and "no rule" in problems[0])
        self.assertEqual(len(self.check(dru=None)), 1)

    def test_a_pair_gap_above_clearance_needs_no_rule(self):
        # MDI: gap 0.21 against class clearance 0.2
        dru = "(version 1)\n" + load_dru()[load_dru().index(
            '(rule "intra-pair clearance USB3"'):]
        self.assertEqual(self.check(dru=dru), [])
        self.assertFalse(any("MDI" in n for n in re.findall(
            r'\(rule "([^"]+)"', dru)))

    def test_the_rule_must_be_scoped_to_one_coupled_pair_of_the_class(self):
        dru = load_dru().replace(" && A.isCoupledDiffPair()", "")
        problems = self.check(dru=dru)
        self.assertTrue(any("not scoped" in p and "isCoupledDiffPair" in p
                            for p in problems), problems)
        dru = load_dru().replace("B.NetClass == 'USB3'", "B.NetClass == 'MDI'")
        problems = self.check(dru=dru)
        self.assertTrue(any(p.startswith("USB3") and "not scoped" in p
                            for p in problems), problems)

    def test_the_rule_minimum_must_be_the_pair_gap(self):
        dru = load_dru().replace("(min 0.17mm)", "(min 0.1mm)", 1)
        problems = self.check(dru=dru)
        self.assertTrue(any(p.startswith("USB3") and "min 0.1" in p
                            for p in problems), problems)

    def test_a_stale_router_preset_is_reported(self):
        pro = load_pro()
        pro["board"]["design_settings"]["diff_pair_dimensions"].append(
            {"gap": 0.2, "via_gap": 0.25, "width": 0.2})
        problems = self.check(pro)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("preset", problems[0])

    def test_a_documented_geometry_missing_from_the_presets_is_reported(self):
        pro = load_pro()
        presets = pro["board"]["design_settings"]["diff_pair_dimensions"]
        del presets[2]
        problems = self.check(pro)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("missing from the router", problems[0])

    def test_a_note_without_the_machine_readable_block_is_reported(self):
        note = load_stackup_note().replace("<!-- netclass-geometry -->", "")
        problems = self.check(note=note)
        self.assertTrue(any("netclass-geometry" in p for p in problems))

    def test_a_note_without_a_required_section_is_reported(self):
        for heading in NOTE_REQUIRED_HEADINGS:
            note = load_stackup_note().replace(heading, "## Renamed")
            problems = self.check(note=note)
            self.assertTrue(any(heading in p for p in problems), heading)

    def test_a_class_missing_from_the_project_is_reported(self):
        pro = load_pro()
        pro["net_settings"]["classes"] = [
            c for c in pro["net_settings"]["classes"] if c["name"] != "MDI"]
        problems = self.check(pro)
        self.assertTrue(any(p.startswith("MDI") and "no such net class" in p
                            for p in problems), problems)

    def test_the_formula_port_reproduces_the_pcbway_page_arithmetic(self):
        # what the page's own JavaScript returns for these inputs (run under
        # Node, see stackup-note.md)
        self.assertAlmostEqual(
            pcbway_edge_coupled_zd(1.0, 0.1855, 0.20, 0.17, 4.74), 97.7,
            delta=0.06)
        self.assertAlmostEqual(
            pcbway_edge_coupled_zd(1.0, 0.1855, 0.18, 0.21, 4.74), 107.2,
            delta=0.06)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_formula_port_agrees_with_the_page_function_itself(self):
        # the page's JavaScript, unchanged, from the committed excerpt
        script = HARDWARE / "fab" / "run_pcbway_page_formula.js"
        for t, h, w, s, er in [(1, 0.1855, 0.20, 0.17, 4.74),
                               (1, 0.1855, 0.18, 0.21, 4.74),
                               (1, 0.1715, 0.15, 0.25, 4.5)]:
            printed = subprocess.run(
                ["node", str(script), str(t), str(h), str(w), str(s), str(er)],
                check=True, capture_output=True, text=True).stdout
            page = float(re.search(r"Zd = ([0-9.]+) ohm", printed).group(1))
            self.assertAlmostEqual(
                pcbway_edge_coupled_zd(t, h, w, s, er), page, delta=0.006)


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


def instance_block(text, ref):
    """The text of one component instance in a generated .kicad_sch."""
    start = text.index(f'(symbol (lib_id "raccoon:RACCOON_{ref}") (at')
    end = text.index("\n\t)\n", start)
    return text[start:end]


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
        # A necessary condition, not a sufficient one: it bounds the capacitive
        # charging in the model, not U3's own start-up load.
        ma = gated_rail_inrush_ma(self.netlist(), "+5V_SW")
        self.assertLessEqual(ma, INRUSH_MAX_MA,
                             f"{ma:.0f} mA into +5V_SW, limit {INRUSH_MAX_MA:.0f} mA")

    def test_the_numbers_are_the_ones_in_the_design_note(self):
        # design_notes.vbus_inrush quotes a modelled peak of about 50 mA and a
        # ramp average of about 42 mA, CT taken 20 % low
        profile = gated_rail_inrush_profile(self.netlist(), "+5V_SW")
        self.assertAlmostEqual(profile["peak_ma"], 50.2, delta=1.5)
        self.assertAlmostEqual(profile["average_ma"], 42.3, delta=1.5)

    def test_the_peak_is_above_the_ramp_average(self):
        profile = gated_rail_inrush_profile(self.netlist(), "+5V_SW")
        self.assertGreater(profile["peak_ma"], profile["average_ma"])

    def test_the_buck_phase_is_really_in_the_model(self):
        # without U6's soft-start contribution the peak would be the pure
        # LDO-window figure; the buck adds to it
        netlist = self.netlist()
        with_buck = gated_rail_inrush_profile(netlist, "+5V_SW")["peak_ma"]
        netlist["components"]["C4"]["value"] = "1nF"
        for ref in ("C12", "C13", "C14", "C15", "C16"):
            netlist["components"][ref]["value"] = "1nF"
        without = gated_rail_inrush_profile(netlist, "+5V_SW")["peak_ma"]
        self.assertGreater(with_buck, without + 1.0)

    def test_the_ldo_charges_at_full_slew_during_its_tracking_window(self):
        # (C on +5V_SW + C behind U4) x slew is the floor of the peak
        netlist = self.netlist()
        profile = gated_rail_inrush_profile(netlist, "+5V_SW")
        c_uf = (sum_bulk_capacitance(netlist, "+5V_SW")
                + sum_bulk_capacitance(netlist, "+3V3_REG")
                + sum_bulk_capacitance(netlist, "+3V3"))
        self.assertGreaterEqual(profile["peak_ma"],
                                c_uf * 1e-6 * profile["slew_v_per_s"] * 1e3 - 0.1)

    def test_the_peak_is_not_bounded_by_the_committed_evidence(self):
        # SY8089 gives TSS as a typical value only and the UVLO as a maximum
        # only. A faster soft start or an earlier start raises the peak; the
        # model must respond to both, which is why the note does not claim
        # a margin.
        netlist = self.netlist()
        typical = gated_rail_inrush_profile(netlist, "+5V_SW")["peak_ma"]
        fast = gated_rail_inrush_profile(netlist, "+5V_SW", tss_scale=0.25,
                                         uvlo_v=2.0)["peak_ma"]
        early = gated_rail_inrush_profile(netlist, "+5V_SW", tss_scale=0.25,
                                          uvlo_v=0.5)["peak_ma"]
        self.assertGreater(fast, typical)
        self.assertGreater(early, INRUSH_MAX_MA)

    def test_an_unknown_downstream_model_raises(self):
        netlist = self.netlist()
        netlist["rails"]["+5V_SW"]["downstream_rails"]["+3V3"]["model"] = "magic"
        with self.assertRaises(ValueError):
            gated_rail_inrush_ma(netlist, "+5V_SW")

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

    def test_a_dnp_part_carries_no_orderable_mpn_in_the_schematic(self):
        # a BOM exported from KiCad itself must not list R12 with a part number
        for ref in self.dnp_refs():
            block = instance_block(self.sch, ref)
            self.assertNotIn('(property "MPN"', block, ref)
            self.assertIn('(property "MPN_If_Fitted"', block, ref)

    def test_a_dnp_part_is_out_of_a_kicad_exported_bom(self):
        instances = schematic_instances(self.sch)
        for ref in self.dnp_refs():
            self.assertEqual(instances[ref], ("no", "yes"), ref)

    def test_a_fitted_part_keeps_its_mpn(self):
        block = instance_block(self.sch, "R14")
        self.assertIn('(property "MPN" "', block)
        self.assertNotIn("MPN_If_Fitted", block)

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


class CommittedDatasheetsMatchTheirHashes(unittest.TestCase):
    """Every datasheet the netlist header cites by path and md5 must be on disk
    with that md5: a cited source that cannot be checked is not a source."""

    def test_header_paths_exist_and_hashes_match(self):
        import hashlib
        header = NETLIST.read_text(encoding="utf-8")
        header = header[:header.index("\nmeta:")]
        cited = re.findall(r"(hardware/datasheets/[\w.\-]+\.pdf)[\s#]*\(?md5\s+([0-9a-f]{32})", header)
        self.assertGreaterEqual(len(cited), 8)
        names = {path for path, _ in cited}
        for path, md5 in cited:
            file = HARDWARE.parent / path
            self.assertTrue(file.exists(), path)
            self.assertEqual(hashlib.md5(file.read_bytes()).hexdigest(), md5, path)
        for needed in ("SP3019", "SY8089", "TI_SLVAF82B", "TI_SLYT118",
                       "TPS22810", "USBLC6", "AP2112"):
            self.assertTrue(any(needed in n for n in names), needed)


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
            if comp.get("mpn") and comp.get("populate", True):
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


class U3TrackRuleCannotBeLoosened(unittest.TestCase):
    """The rule is the only thing that lets task 9 route out of U3's pads; an
    untested rule could be deleted or widened without anything noticing."""

    def test_the_committed_rule_passes(self):
        self.assertEqual(u3_track_rule_problems(), [])

    def mutate(self, old, new):
        # edit inside this rule only: other rules carry similar text
        dru = load_dru()
        start = dru.index(f'(rule "{U3_TRACK_RULE}"')
        head, rule = dru[:start], dru[start:]
        self.assertIn(old, rule)
        return u3_track_rule_problems(head + rule.replace(old, new, 1))

    def test_a_missing_rule_is_reported(self):
        problems = u3_track_rule_problems(
            load_dru().replace(U3_TRACK_RULE, "renamed"))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("has no rule", problems[0])
        self.assertEqual(len(u3_track_rule_problems(None)), 1)

    def test_a_rule_that_is_not_limited_to_tracks_is_reported(self):
        # without the track scope it would also relax pad-to-pad and via spacing
        for old, new in [("A.Type == 'Track' && ", ""),
                         ("A.Type == 'Track'", "A.Type == 'Track' || A.Type == 'Via'"),
                         ("A.Type == 'Track'", "A.Type != 'Zone'")]:
            problems = self.mutate(old, new)
            self.assertTrue(any("condition" in p for p in problems), (new, problems))

    def test_a_rule_that_is_not_limited_to_u3_is_reported(self):
        for old, new in [(" && B.memberOfFootprint('U3')", ""),
                         ("B.memberOfFootprint('U3')", "B.memberOfFootprint('U8')"),
                         ("B.memberOfFootprint('U3')",
                          "B.memberOfFootprint('U3') || B.memberOfFootprint('U9')")]:
            problems = self.mutate(old, new)
            self.assertTrue(any("condition" in p for p in problems), (new, problems))

    def test_a_rule_that_drops_a_direction_is_reported(self):
        # restricting either side to a net class would leave a signal track
        # against a supply pad, or a supply escape against a signal pad, at 0.3
        for old, new in [("A.Type == 'Track'", "A.Type == 'Track' && A.NetClass == 'USB3'"),
                         ("B.Type == 'Pad'", "B.Type == 'Pad' && B.NetClass == 'Power'"),
                         ("B.Type == 'Pad'", "B.Type == 'Pad' && B.Net != 'GND'")]:
            problems = self.mutate(old, new)
            self.assertTrue(any("condition" in p for p in problems), (new, problems))

    def test_a_looser_or_useless_minimum_is_reported(self):
        for new in ("0.1mm", "0.15mm", "0.3mm"):
            problems = self.mutate("(min 0.2mm)", f"(min {new})")
            self.assertEqual(len(problems), 1, (new, problems))
            self.assertIn("must be 0.2", problems[0])


class U3EscapeRuleCannotBeLoosened(unittest.TestCase):
    """Ruling AU: the track-to-track rule at U3's escape and its rule area."""

    def test_the_committed_rule_and_area_pass(self):
        self.assertEqual(u3_escape_rule_problems(), [])

    def mutate(self, old, new):
        dru = load_dru()
        start = dru.index(f'(rule "{U3_ESCAPE_RULE}"')
        head, rule = dru[:start], dru[start:]
        self.assertIn(old, rule)
        return u3_escape_rule_problems(head + rule.replace(old, new, 1))

    def test_a_missing_rule_is_reported(self):
        problems = u3_escape_rule_problems(load_dru().replace(U3_ESCAPE_RULE, "renamed"))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("has no rule", problems[0])

    def test_a_widened_scope_is_reported(self):
        for old, new in [(" && B.insideArea('U3_escape')", ""),
                         ("A.insideArea('U3_escape') && ", ""),
                         ("A.Type == 'Track' && B.Type == 'Track' && ", ""),
                         ("B.Type == 'Track'", "B.Type != 'Zone'"),
                         ("A.Type == 'Track'", "A.Type == 'Track' || A.Type == 'Via'"),
                         ("B.insideArea('U3_escape')", "B.insideArea('U3_escape') || B.NetClass == 'MDI'"),
                         ("A.insideArea('U3_escape')", "A.intersectsCourtyard('J2')")]:
            problems = self.mutate(old, new)
            self.assertTrue(any("condition" in p for p in problems), (new, problems))

    def test_a_wrong_minimum_is_reported(self):
        for new in ("0.1mm", "0.15mm", "0.25mm", "0.3mm"):
            problems = self.mutate("(min 0.2mm)", f"(min {new})")
            self.assertEqual(len(problems), 1, (new, problems))
            self.assertIn("must be 0.2", problems[0])

    def test_a_missing_area_is_reported(self):
        pcb = PCB.read_text(encoding="utf-8").replace('(name "U3_escape")', '(name "other")')
        problems = u3_escape_rule_problems(pcb_text=pcb)
        self.assertTrue(any("no zone named" in p for p in problems), problems)

    def test_a_widened_area_is_reported(self):
        pcb = PCB.read_text(encoding="utf-8")
        cx, cy = _footprint_at(pcb, "U3")
        layers, keepout, pts = _rule_area(pcb, U3_ESCAPE_AREA)
        x0, y0 = pts[0]
        grown = pcb.replace(f"(xy {x0:g} {y0:g})", f"(xy {x0 - 2:g} {y0 - 2:g})", 1)
        self.assertNotEqual(grown, pcb)
        problems = u3_escape_rule_problems(pcb_text=grown)
        self.assertTrue(any("reaches" in p for p in problems), problems)

    def test_an_area_that_keeps_things_out_or_sits_on_other_layers_is_reported(self):
        pcb = PCB.read_text(encoding="utf-8")
        start = pcb.index('(name "U3_escape")')
        block_start = pcb.rindex("\n\t(zone\n", 0, start)
        block_end = pcb.index("\n\t)", start)
        block = pcb[block_start:block_end]
        for old, new, word in [("(tracks allowed)", "(tracks not_allowed)", "forbids"),
                               ('(layer "F.Cu")', '(layers "F.Cu" "B.Cu")', "F.Cu only")]:
            self.assertIn(old, block)
            problems = u3_escape_rule_problems(
                pcb_text=pcb[:block_start] + block.replace(old, new) + pcb[block_end:])
            self.assertTrue(any(word in p for p in problems), (new, problems))


class MdiPairsStayInTheirCableGroup(unittest.TestCase):
    """Ruling AJ, revised: moving an MDI net across the A/B - C/D boundary
    gives a board with no link at all (A/B carry 10/100 and auto-negotiation)."""

    @staticmethod
    def swapped(netlist, a, b):
        """Exchange the J2 pins of nets a and b."""
        nets = netlist["nets"]
        ja = next(e for e in nets[a] if e.startswith("J2."))
        jb = next(e for e in nets[b] if e.startswith("J2."))
        nets[a] = [jb if e == ja else e for e in nets[a]]
        nets[b] = [ja if e == jb else e for e in nets[b]]
        return netlist

    def test_the_committed_netlist_passes(self):
        self.assertEqual(mdi_group_problems(load_netlist()), [])

    def test_the_exchange_used_in_task_8_is_what_the_netlist_says(self):
        nets = load_netlist()["nets"]
        j2 = lambda net: next(e for e in nets[net] if e.startswith("J2."))
        self.assertEqual([j2(n) for n in ("MDI0_P", "MDI0_N", "MDI1_P", "MDI1_N")],
                         ["J2.1", "J2.2", "J2.3", "J2.4"])
        self.assertEqual([j2(n) for n in ("MDI3_N", "MDI3_P", "MDI2_N", "MDI2_P")],
                         ["J2.7", "J2.8", "J2.9", "J2.10"])

    def test_the_legal_freedoms_pass(self):
        for a, b in [("MDI2_P", "MDI3_P"), ("MDI2_N", "MDI3_N"),   # exchange C/D
                     ("MDI0_P", "MDI1_P"), ("MDI0_N", "MDI1_N"),   # exchange A/B
                     ("MDI2_P", "MDI2_N"), ("MDI0_P", "MDI0_N")]:  # polarity
            netlist = self.swapped(copy.deepcopy(load_netlist()), a, b)
            # an exchange of one net of each pair splits nothing only if both
            # nets of the pair move: do the second net as well
            if a.endswith("_P") and b.endswith("_P"):
                netlist = self.swapped(netlist, a[:-1] + "N", b[:-1] + "N")
            elif a.endswith("_N") and b.endswith("_N"):
                netlist = self.swapped(netlist, a[:-1] + "P", b[:-1] + "P")
            self.assertEqual(mdi_group_problems(netlist), [], (a, b))

    def test_a_net_moved_across_the_boundary_is_reported(self):
        for a, b in [("MDI1_P", "MDI2_P"), ("MDI0_N", "MDI3_N"),
                     ("MDI1_N", "MDI3_P")]:
            netlist = self.swapped(copy.deepcopy(load_netlist()), a, b)
            problems = mdi_group_problems(netlist)
            self.assertTrue(any("outside its group" in p for p in problems),
                            (a, b, problems))

    def test_a_whole_pair_moved_across_the_boundary_is_reported(self):
        netlist = copy.deepcopy(load_netlist())
        for x, y in [("MDI1_P", "MDI2_P"), ("MDI1_N", "MDI2_N")]:
            self.swapped(netlist, x, y)
        problems = mdi_group_problems(netlist)
        self.assertEqual(len([p for p in problems if "outside its group" in p]),
                         4, problems)

    def test_a_pair_split_over_two_cable_pairs_is_reported(self):
        netlist = self.swapped(copy.deepcopy(load_netlist()), "MDI2_P", "MDI3_P")
        problems = mdi_group_problems(netlist)
        self.assertTrue(any("different cable pairs" in p for p in problems),
                        problems)

    def test_an_unreadable_pin_table_is_reported(self):
        netlist = copy.deepcopy(load_netlist())
        netlist["components"]["J2"]["pins"][7]["note"] = "PHY side, pair 3"
        problems = mdi_group_problems(netlist)
        self.assertTrue(any("no 'cable J<n>'" in p for p in problems), problems)


class U3EscapeRuleStaysAtItsArea(unittest.TestCase):
    """Ruling BF: ruling AU's 0.2 mm is not carried out of U3's escape area by
    long segments, and where it reaches past the edge is listed."""

    def test_the_committed_board_passes(self):
        self.assertEqual(u3_area_edge_problems(), [])

    def test_a_segment_across_the_edge_is_reported(self):
        pcb = PCB.read_text(encoding="utf-8")
        _, _, pts = _rule_area(pcb, U3_ESCAPE_AREA)
        x0, y0 = min(p[0] for p in pts), min(p[1] for p in pts)
        seg = (f'\t(segment\n\t\t(start {x0 + 0.5:g} {y0 + 0.5:g})\n\t\t(end {x0 + 0.5:g} {y0 - 3:g})\n'
               '\t\t(width 0.2)\n\t\t(layer "F.Cu")\n\t\t(net "ETH_LED0")\n\t)\n')
        problems = u3_area_edge_problems(pcb[:pcb.rstrip().rindex(")")] + seg + ")\n")
        self.assertTrue(any("runs across the edge" in p for p in problems), problems)

    def test_a_segment_that_ends_on_the_edge_and_runs_on_is_reported(self):
        # the reviewer's case (ruling BQ): a segment that only touches the edge
        pcb = PCB.read_text(encoding="utf-8")
        _, _, pts = _rule_area(pcb, U3_ESCAPE_AREA)
        x0, y0 = min(p[0] for p in pts), min(p[1] for p in pts)
        seg = (f'\t(segment\n\t\t(start {x0 + 0.5:g} {y0:g})\n\t\t(end {x0 + 0.5:g} {y0 - 1.9:g})\n'
               '\t\t(width 0.15)\n\t\t(layer "F.Cu")\n\t\t(net "ETH_LED0")\n\t)\n')
        problems = u3_area_edge_problems(pcb[:pcb.rstrip().rindex(")")] + seg + ")\n")
        self.assertTrue(any("ruling BQ" in p and "ETH_LED0" in p for p in problems), problems)

    def test_an_unlisted_or_grown_overhang_is_reported(self):
        saved = dict(AU_OVERHANGS)
        try:
            AU_OVERHANGS.pop(("+1V0", "USB3_TX_P"))
            problems = u3_area_edge_problems()
            self.assertTrue(any("not in AU_OVERHANGS" in p and "USB3_TX_P" in p for p in problems), problems)
            AU_OVERHANGS[("+1V0", "USB3_TX_P")] = (0.26, 0.12)
            problems = u3_area_edge_problems()
            self.assertTrue(any("AU_OVERHANGS allows" in p for p in problems), problems)
        finally:
            AU_OVERHANGS.clear()
            AU_OVERHANGS.update(saved)


def run_gen_pcb_on_routed_board(extra_args=(), routed=True):
    """Run tools/gen_pcb.py against a copy of the committed board, stripped of
    its tracks and then given one track segment if `routed`. The guard has to act before pcbnew is imported,
    so this runs under the interpreter of the test suite, which has no pcbnew:
    without the guard the script gets as far as the import and fails there.
    Returns the CompletedProcess plus whether the target file was left as it
    was."""
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "raccoon-tap.kicad_pcb"
        # the board without its tracks first, so the test does not depend on
        # whether the committed board is routed
        text = re.sub(r"\n\t\((?:segment|arc)\n.*?\n\t\)", "", PCB.read_text(), flags=re.S)
        if routed:
            net = re.search(r'\(net\s+"([^"]+)"\)', text).group(1)
            segment = ('\t(segment\n\t\t(start 120 100)\n\t\t(end 121 100)\n'
                       '\t\t(width 0.2)\n\t\t(layer "F.Cu")\n'
                       f'\t\t(net "{net}")\n'
                       '\t\t(uuid "00000000-0000-0000-0000-000000000001")\n\t)\n')
            text = text[:text.rstrip().rindex(")")] + segment + ")\n"
        target.write_text(text)
        result = subprocess.run([sys.executable, str(GEN_PCB), "--out", str(target),
                                 *extra_args], capture_output=True, text=True)
        result.untouched = target.read_text() == text
        return result


ACCEPTED_FINDINGS = HARDWARE / "review" / "2026-11-03-routed" / "accepted-findings.md"


def _mid_sample(probe, net):
    """A point on a pair net's F.Cu track, in the middle of the samples."""
    samples = [s for s in probe["coupling"][net] if s[5] == "F.Cu"]
    return samples[len(samples) // 2][:2]


def _pad_at(probe, ref, num):
    return next(p["at"] for p in probe["pads"] if p["ref"] == ref and p["num"] == str(num))


class PairsKeepTheirIn1Reference(unittest.TestCase):
    """Ruling BJ, first property: ground under every pair, all along it."""

    @classmethod
    def setUpClass(cls):
        cls.probe = committed_probe("--in1")

    def test_every_pair_has_a_continuous_in1_ground_under_it(self):
        self.assertEqual(in1_continuity_problems(self.probe), [])

    def test_every_named_exception_is_in_use(self):
        # Per rule AND per listed position: a rule with two positions whose second one nothing
        # uses any more is a loophole kept for nothing, and a per-rule count would not see it.
        used = set()
        for net, entry in self.probe["in1"]["nets"].items():
            for gap in entry["gaps"]:
                if gap["hole"]:
                    rule = _exception_for(net, gap)
                    if rule is None:
                        used.add((None, None))
                    elif "at" not in rule:
                        used.add((rule["name"], None))
                    else:
                        for i, (x, y) in enumerate(rule["at"]):
                            if math.hypot(x - gap["hole"]["at"][0], y - gap["hole"]["at"][1]) <= 0.05:
                                used.add((rule["name"], i))
        expected = {(r["name"], i) for r in IN1_EXCEPTIONS
                    for i in (range(len(r["at"])) if "at" in r else (None,))}
        self.assertEqual(used, expected, "an exception position nothing uses is a loophole kept for nothing")

    def test_every_pair_was_walked_along_its_whole_length(self):
        for net in BOARD_PAIR_NETS:
            entry = self.probe["in1"]["nets"][net]
            self.assertGreater(entry["samples"], 3 * entry["layers"].get("F.Cu", 0) / IN1_SAMPLE_STEP * 0.9, net)

    def test_ruling_ar_flank_vias_are_in_the_pour_and_the_plane(self):
        flank = [v for v in self.probe["in1"]["ar"]["vias"] if 18.0 < v["at"][0] < 20.0]
        self.assertTrue(flank)
        self.assertTrue(all(v["in_bcu_pour"] and v["in_in1"] for v in flank))


class In1ContinuityCanFail(unittest.TestCase):
    """The check is only a guard if it fails on the defect it exists for. Each
    test plants one on a scratch copy of the committed board."""

    @classmethod
    def setUpClass(cls):
        cls.coupling = committed_probe("--coupling")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)

    def board(self, name, *steps):
        source = PCB
        for i, step in enumerate(steps):
            target = Path(self.tmp.name) / f"{name}-{i}.kicad_pcb"
            run = subprocess.run([str(kicad_python()), str(BOARD_MUTATE), str(source), str(target), *map(str, step)],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr[-1500:])
            source = target
        return source

    def test_a_gap_in_the_ground_under_any_pair_is_found(self):
        steps = []
        for net in BOARD_PAIR_NETS:
            x, y = _mid_sample(self.coupling, net)
            steps.append(("void-in1", round(x - 0.4, 2), round(y - 0.25, 2), round(x + 0.4, 2), round(y + 0.25, 2)))
        problems = in1_continuity_problems(run_probe(self.board("voids", *steps), "--in1"))
        for net in BOARD_PAIR_NETS:
            with self.subTest(net=net):
                self.assertTrue(any(m.startswith(net + ":") and "without In1 ground" in m for m in problems),
                                f"{net} lost its reference and nothing said so")

    def test_the_wider_gap_of_a_via_antipad_beside_a_superspeed_pair_is_found(self):
        # the ordinary way a pair loses its plane: a signal or supply via next to it
        # RX_P runs east-west near x 9.5 with RX_N to its north: a +3V3 via 0.52 mm
        # south of it touches no copper and still opens In1 under the pair
        x, y = next(s[:2] for s in self.coupling["coupling"]["USB3_RX_P"] if abs(s[0] - 9.5) < 0.03)
        problems = in1_continuity_problems(
            run_probe(self.board("antipad", ("via", "+3V3", round(x, 2), round(y + 0.52, 2), 0.6, 0.3)), "--in1"))
        self.assertTrue(any("USB3_RX" in m and "not an allowed exception" in m for m in problems), problems)

    def test_a_stub_via_of_its_own_net_mid_run_on_usb_2_0_is_found(self):
        # ruling BU: the own-via exception is by position, not by net. The task 10
        # review planted these two (D+ at 11.52, 17.08; D- at 10.93, 16.2) and the
        # first version passed them.
        for net, (x, y) in (("USB2_D_P", (11.52, 17.08)), ("USB2_D_N", (10.93, 16.2))):
            with self.subTest(net=net):
                problems = in1_continuity_problems(
                    run_probe(self.board("stub-" + net, ("via", net, x, y, 0.6, 0.3)), "--in1"))
                self.assertTrue(any(m.startswith(net + ":") and "not an allowed exception" in m
                                    for m in problems), problems)

    def test_the_d_minus_exception_covers_one_via_and_not_another(self):
        # D- runs north-south at x 9.6 between y 16.2 and 18.9; D+ is 1.2 mm to the east
        x, y = next(s[:2] for s in self.coupling["coupling"]["USB2_D_N"]
                    if s[5] == "F.Cu" and abs(s[0] - 9.6) < 0.03 and abs(s[1] - 17.5) < 0.03)
        problems = in1_continuity_problems(
            run_probe(self.board("partnervia", ("via", "USB2_D_P", round(x + 0.52, 2), round(y, 2), 0.6, 0.3)),
                      "--in1"))
        self.assertTrue(any(m.startswith("USB2_D_N:") and "not an allowed exception" in m for m in problems), problems)

    def test_the_j2_pin_exception_does_not_cover_a_stretch_beyond_the_pin(self):
        x, y = _pad_at(self.coupling, "J2", 10)       # MDI2_P's pin
        problems = in1_continuity_problems(
            run_probe(self.board("mdivoid", ("void-in1", x - 2.5, y - 2.5, x + 2.5, y + 2.5)), "--in1"))
        self.assertTrue(any(m.startswith("MDI2_P:") and "without In1 ground" in m for m in problems), problems)

    def test_ruling_ar_fails_without_a_flank_via(self):
        problems = in1_continuity_problems(
            run_probe(self.board("noflank", ("remove-via", 19.1, 18.49)), "--in1"))
        self.assertTrue(any("flank" in m and "north" in m for m in problems), problems)


class PairCouplingHoldsTheRulings(unittest.TestCase):
    """Ruling BJ, second property: each pair stays at its designed gap for what
    the rulings granted, and no longer apart than they allowed."""

    @classmethod
    def setUpClass(cls):
        cls.probe = committed_probe("--coupling")
        cls.summary = coupling_summary(cls.probe)

    def test_every_pair_is_as_coupled_as_the_rulings_granted(self):
        self.assertEqual(pair_coupling_problems(self.probe), [])

    def test_the_pair_gaps_are_the_ones_in_the_project(self):
        self.assertAlmostEqual(pair_gap_mm("USB3_RX_P"), 0.17)
        self.assertAlmostEqual(pair_gap_mm("MDI0_P"), 0.21)

    def test_the_figures_the_ledger_records_are_what_is_measured(self):
        # TX 65/60 %, TX_CONN 50 %, RX 56/54 % at the designed gap by route_pcb.py,
        # which does not count the partner's pads; with pads and vias counted
        # the same board reads a little more coupled
        def gap(net):
            return self.summary[net]["at_gap"] / self.summary[net]["length"]
        for net, least in (("USB3_TX_P", 0.60), ("USB3_TX_N", 0.55), ("USB3_TX_CONN_P", 0.45),
                           ("USB3_TX_CONN_N", 0.45), ("USB3_RX_P", 0.54), ("USB3_RX_N", 0.52)):
            self.assertGreaterEqual(gap(net), least, net)

    def test_every_region_is_in_use(self):
        for region in COUPLING_REGIONS:
            key = (region["name"], region["cap_mm"], region["basis"])
            used = {n for n, row in self.summary.items()
                    if re.fullmatch(region["nets"], n) and key in row["regions"]}
            self.assertTrue(used, f"{region['name']} for {region['nets']} holds nothing: remove it")

    def test_every_as_built_region_is_argued_in_the_accepted_findings(self):
        text = " ".join(ACCEPTED_FINDINGS.read_text(encoding="utf-8").split())
        for region in COUPLING_REGIONS:
            if region["kind"] == "ratchet":
                self.assertTrue(region["basis"].startswith(RATCHET), region)
                self.assertIn(region["name"], text,
                              f"{region['name']} is a ratchet and has no entry in {ACCEPTED_FINDINGS.name}")
                # the cap table in A6 is kept by hand: the figure itself has to appear in the text
                # (as 0.94, or 2.0 / 2, or in a "1.2 / 1.0" pair), not only the region's name
                cap = region["cap_mm"]
                spellings = {f"{cap:.2f}", f"{cap:.1f}", f"{cap:g}"}
                self.assertTrue(any(re.search(rf"(?<![\d.]){re.escape(t)}(?![\d])", text) for t in spellings),
                                f"{region['name']} ({region['nets']}): cap {cap} mm is not in {ACCEPTED_FINDINGS.name}")

    def test_every_cap_names_its_ruling_or_says_it_is_a_ratchet(self):
        for region in COUPLING_REGIONS:
            self.assertIn(region["kind"], ("granted", "ratchet"), region)
            if region["kind"] == "granted":
                self.assertRegex(region["basis"], r"^ruling [A-Z]{2}\b", region)
            else:
                self.assertTrue(region["basis"].startswith(RATCHET), region)

    def test_no_ratchet_cap_is_shared_by_two_nets(self):
        self.assertEqual(shared_ratchet_problems(), [])

    def test_the_per_net_ratchets_sit_close_above_their_net(self):
        # ruling BY: the cap is the net's own measurement plus a small margin
        for region in COUPLING_REGIONS:
            if region["kind"] != "ratchet" or not region["name"].startswith(("TX cap", "U8", "J3")):
                continue
            key = (region["name"], region["cap_mm"], region["basis"])
            held = self.summary[region["nets"]]["regions"][key]
            self.assertGreaterEqual(region["cap_mm"], held, region)
            self.assertLessEqual(region["cap_mm"] - held, 0.15, region)

    def test_the_floor_is_below_what_the_board_has(self):
        for net, row in self.summary.items():
            self.assertLess(coupled_floor(net), row["window"] / row["length"], net)


class SharedRatchetCapCanFail(unittest.TestCase):
    """The guard for ruling BY has to fire on the defect it is there for."""

    @staticmethod
    def _planted(kind, nets):
        return COUPLING_REGIONS + ({"name": "planted", "nets": nets, "box": (0, 1, 0, 1), "cap_mm": 1.0,
                                    "kind": kind, "basis": RATCHET},)

    def test_a_ratchet_for_both_legs_of_a_pair_is_refused(self):
        for nets in (r"USB3_TX_CONN_[PN]", r"USB3_RX_.", "USB3_RX_P|USB3_RX_N", r"MDI0_[PN]", r".*"):
            problems = shared_ratchet_problems(self._planted("ratchet", nets))
            self.assertEqual(len(problems), 1, (nets, problems))
            self.assertIn("planted", problems[0])

    def test_a_ratchet_that_matches_no_pair_net_is_refused(self):
        self.assertEqual(len(shared_ratchet_problems(self._planted("ratchet", "USB3_RX_X"))), 1)

    def test_a_granted_cap_may_span_nets(self):
        self.assertEqual(shared_ratchet_problems(self._planted("granted", r"USB3_TX_CONN_[PN]")), [])

    def test_the_shared_caps_ruling_by_split_are_refused(self):
        for nets in (r"USB3_TX(_CONN)?_[PN]", r"USB3_RX_[PN]", r"USB3_TX_CONN_[PN]"):
            self.assertTrue(shared_ratchet_problems(self._planted("ratchet", nets)), nets)


class TxConnNHasItsOwnCap(unittest.TestCase):
    """The defect ruling BY names, planted on the committed board's measurements: TX_CONN_N
    must be held to its own length in the U8 straddle, not to the pair-wide 8.0 mm."""

    def test_tx_conn_n_cannot_degrade_into_the_room_the_shared_cap_left(self):
        # the defect ruling BY names: N measures 6.68 mm in the straddle, under a pair-wide 8.0 it
        # could grow by 1.3 mm unseen. Add 1.0 mm of N's own out-of-window path to the straddle.
        probe = copy.deepcopy(committed_probe("--coupling"))
        net = "USB3_TX_CONN_N"
        straddle = next(smp for smp in probe["coupling"][net]
                        if _region_of(net, smp[0], smp[1], smp[5], probe["pads"]) is not None
                        and _region_of(net, smp[0], smp[1], smp[5], probe["pads"])["name"] == "U8 straddle")
        x, y, _, width, _, layer = straddle
        probe["coupling"][net].append((x, y, 1.0, width, 1.0, layer))   # a gap of 1 mm: far out of the window
        held = sum(v for (name, _, _), v in coupling_summary(probe)[net]["regions"].items()
                   if name == "U8 straddle")
        self.assertLess(held, 8.0, "the plant must stay under the old shared cap or it proves nothing")
        problems = [m for m in pair_coupling_problems(probe) if m.startswith(net + ":")]
        self.assertTrue(any("U8 straddle" in m and "more than its cap of 6.79" in m for m in problems), problems)


class PairCouplingCanFail(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)

    def problems_after(self, *step):
        board = mutate_board(self.tmp.name, *step)
        return pair_coupling_problems(run_probe(board, "--coupling"))

    def test_a_pair_that_runs_apart_for_most_of_its_length_is_found(self):
        # what task 9's first review found: RX 28 % coupled, about 0.28 mm
        # further apart than designed along 70 % of the pair
        problems = self.problems_after("shift", "USB3_RX_N", 0, 0.45, 7.5, 24.5)
        net = [m for m in problems if m.startswith("USB3_RX_N:")]
        self.assertTrue(any("below the floor" in m for m in net), net)
        self.assertTrue(any("no region" in m for m in net), net)

    def test_a_pair_that_stays_coupled_but_for_two_millimetres_in_no_region_is_found(self):
        problems = self.problems_after("shift", "USB3_RX_N", 0, -0.3, 7.5, 11.3)
        self.assertTrue(any(m.startswith("USB3_RX_N:") and "no region" in m for m in problems), problems)

    def test_a_region_cannot_grow_past_its_cap(self):
        # U8's straddle: AS granted about 5 mm, RX_P's own cap is 5.41; push RX_P further out of the window
        problems = self.problems_after("shift", "USB3_RX_P", 0, 0.5, 11.3, 13.6)
        self.assertTrue(any(m.startswith("USB3_RX_P:") and "U8 straddle" in m for m in problems), problems)

    def test_a_pair_pushed_into_its_partner_is_found_too(self):
        problems = self.problems_after("shift", "USB3_TX_CONN_P", 0, -0.12, 21.3, 25.0)
        self.assertTrue(any(m.startswith("USB3_TX_CONN_P:") for m in problems), problems)

    def test_the_floor_follows_from_the_caps(self):
        self.assertAlmostEqual(coupled_floor("USB3_RX_P"),
                               1 - (NECK_MAX_LENGTH_MM + 5.41 + 2.0 + UNREGIONED_SLACK_MM) / 23.1)


class BoardNamesItself(unittest.TestCase):
    """Task 10: the release gate and the baseline both found a board with no
    name and no revision on it; `amend_pcb.py silk_id` put them there."""

    def test_the_silkscreen_carries_the_name_and_the_revision(self):
        text = PCB.read_text()
        texts = re.findall(r'\(gr_text "([^"]+)"\s*\(at [^)]*\)\s*\(layer "F\.SilkS"\)', text)
        self.assertIn("RACCOON TAP", texts)
        revision = re.search(r'\(rev "([^"]+)"\)', SCHEMATIC.read_text()).group(1)
        self.assertIn(f"REV {revision}".upper(), [t.upper() for t in texts])

    def test_the_pcb_title_block_has_the_schematics_revision(self):
        revision = re.search(r'\(rev "([^"]+)"\)', SCHEMATIC.read_text()).group(1)
        block = re.search(r"\(title_block(.*?)\n\t\)", PCB.read_text(), re.S)
        self.assertIsNotNone(block, "the PCB has no title block")
        self.assertIn(f'(rev "{revision}")', block.group(1))


class RoutedBoardIsFrozen(unittest.TestCase):
    """From task 9 on the geometry lives in the board: gen_pcb.py builds a new
    board from nothing, so one run would delete every track."""

    def test_gen_pcb_refuses_to_overwrite_a_routed_board(self):
        result = run_gen_pcb_on_routed_board()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("geroutet", result.stderr)
        self.assertIn("--force", result.stderr)
        self.assertTrue(result.untouched)

    def test_the_refusal_is_the_guard_and_not_a_missing_pcbnew(self):
        result = run_gen_pcb_on_routed_board()
        self.assertNotIn("pcbnew", result.stderr)

    def test_force_is_the_deliberate_way_past_the_guard(self):
        result = run_gen_pcb_on_routed_board(["--force"])
        self.assertNotIn("geroutet", result.stderr)

    def test_an_unrouted_board_is_not_refused(self):
        result = run_gen_pcb_on_routed_board(routed=False)
        self.assertNotIn("geroutet", result.stderr)



# ---------------------------------------------------------------------------
# Ruling BJ: what KiCad's DRC cannot see on the routed board.
#
# Twice a real defect reached a review because no rule describes it: a pair
# that lost the continuous In1 ground plane that is its reference, and a pair
# that ran apart from its partner, at the wrong impedance, for most of its
# length. Both are measured here on the committed board, under KiCad's own
# Python (tests/board_probe.py), and the judgement is made in this file. The
# gate still needs `kicad-cli pcb drc` beside this: these checks compare
# geometry and net labels, so shorts and unconnected items stay the DRC's job
# (ruling P).
# ---------------------------------------------------------------------------

KIPY_DEFAULT = Path("/Applications/KiCad/KiCad.app/Contents/Frameworks/"
                    "Python.framework/Versions/3.9/bin/python3")
BOARD_PROBE = HARDWARE / "tests" / "board_probe.py"
BOARD_MUTATE = HARDWARE / "tests" / "board_mutate.py"

BOARD_PAIRS = (("USB3_TX_P", "USB3_TX_N"), ("USB3_TX_CONN_P", "USB3_TX_CONN_N"),
               ("USB3_RX_P", "USB3_RX_N"), ("USB2_D_P", "USB2_D_N"),
               ("MDI0_P", "MDI0_N"), ("MDI1_P", "MDI1_N"),
               ("MDI2_P", "MDI2_N"), ("MDI3_P", "MDI3_N"))
BOARD_PAIR_NETS = tuple(n for pair in BOARD_PAIRS for n in pair)


class ProbeUnavailable(RuntimeError):
    """KiCad's Python is not there. A guard that cannot run is not a guard
    that passed, so this is an error and never a skip."""


def kicad_python():
    import os
    path = Path(os.environ.get("KIPY") or KIPY_DEFAULT)
    if not path.exists():
        raise ProbeUnavailable(
            f"{path} does not exist: the In1 and coupling checks need KiCad's "
            f"Python (pcbnew). Set KIPY to it.")
    return path


def run_probe(board, *flags):
    result = subprocess.run([str(kicad_python()), str(BOARD_PROBE), "--board", str(board), *flags],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"board_probe.py failed ({result.returncode}):\n{result.stderr[-2000:]}")
    return json.loads(result.stdout)


def mutate_board(directory, mode, *args, source=PCB):
    """A copy of `source` in `directory` with a planted defect (board_mutate.py)."""
    target = Path(directory) / "mutated.kicad_pcb"
    result = subprocess.run([str(kicad_python()), str(BOARD_MUTATE), str(source), str(target),
                             mode, *map(str, args)], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"board_mutate.py {mode} failed:\n{result.stderr[-2000:]}")
    return target


_PROBE_CACHE = {}


def committed_probe(*flags):
    """The probe of the committed board, run once per flag set per process."""
    key = tuple(sorted(flags))
    if key not in _PROBE_CACHE:
        _PROBE_CACHE[key] = run_probe(PCB, *flags)
    return _PROBE_CACHE[key]


# --- In1 continuity -------------------------------------------------------

IN1_SAMPLE_STEP = 0.02     # mm along the track, on the centre line and both edges

# The places where a pair track has no In1 ground under it and that is known
# and ruled. Anything else, anywhere, is a failure. A gap is excused only if
# board_probe.py attributes it to a hole in In1 round a via or hole of the
# kind and net named here, and only for `max_run_mm` along one sampled line
# (a straight pass through the hole is at most its diameter).
#
#   own J2 pin   an MDI track ends on its own through-hole pin of the MagJack,
#                and In1 has to leave a hole round that pin;
#   own via      a USB 2.0 track changes layer (ruling AR) and In1 leaves a hole
#                round its own via. Only the four layer-change vias, by position
#                (ruling BU): an exception by net instead of by place is a gap, a
#                stub via mid-run would have passed;
#   D- over D+   the single exception between nets: where USB2_D_N passes the
#                antipad of USB2_D_P's layer-change via at (21.5, 19.15), half
#                its width has no ground for about 0.5 mm (task 9 re-review
#                M1; 480 Mbit/s, at the layer change itself).
IN1_EXCEPTIONS = (
    {"name": "own J2 pin", "nets": r"MDI[0-3]_[PN]", "hole": "pad", "whose": "own",
     "label": r"J2\.\d+", "max_run_mm": 1.3},
    {"name": "own layer-change via, D-", "nets": "USB2_D_N", "hole": "via", "whose": "own",
     "label": "via", "at": ((12.2, 16.2), (20.8, 18.75)), "max_run_mm": 1.3},
    {"name": "own layer-change via, D+", "nets": "USB2_D_P", "hole": "via", "whose": "own",
     "label": "via", "at": ((12.2, 17.1), (21.5, 19.15)), "max_run_mm": 1.3},
    {"name": "D- over the antipad of D+'s layer-change via", "nets": "USB2_D_N", "hole": "via",
     "whose": "partner", "label": "via", "at": ((21.5, 19.15),), "max_run_mm": 0.55},
)
# Ruling AR (revised): the one stretch of a pair that may leave F.Cu, USB 2.0
# only, across at most one In2 island boundary, flanked by GND vias that stand
# in the B.Cu pour and in the In1 plane.
B_CU_PAIR_NETS = ("USB2_D_P", "USB2_D_N")
AR_MAX_ISLAND_BOUNDARIES = 1
AR_FLANK_REACH_MM = 1.5


def _partner_net(net):
    return net[:-1] + ("N" if net.endswith("P") else "P")


def _exception_for(net, gap):
    hole = gap["hole"]
    whose = "own" if hole["net"] == net else "partner" if hole["net"] == _partner_net(net) else "other"
    for rule in IN1_EXCEPTIONS:
        if not re.fullmatch(rule["nets"], net) or rule["hole"] != hole["kind"] or rule["whose"] != whose:
            continue
        if not re.fullmatch(rule["label"], hole["label"]):
            continue
        if "at" in rule and not any(math.hypot(x - hole["at"][0], y - hole["at"][1]) <= 0.05
                                    for x, y in rule["at"]):
            continue
        return rule
    return None


def in1_continuity_problems(probe):
    """One message per reason a differential pair does not have a continuous
    ground plane on In1 under it (F.Cu tracks, centre line and both edges
    every IN1_SAMPLE_STEP), plus the ruling AR conditions for the pair stretch
    on B.Cu. `probe` is board_probe.py's output with --in1."""
    problems = []
    if sorted(probe["pairs"]) != sorted(BOARD_PAIR_NETS):
        problems.append(f"the board's pair nets are {sorted(probe['pairs'])}, not the expected "
                        f"{sorted(BOARD_PAIR_NETS)}: a pair the check does not know is not checked")
    in1 = probe["in1"]
    if in1["in1_gnd_zones"] != 1:
        problems.append(f"{in1['in1_gnd_zones']} GND zones on In1, expected exactly 1")
    if in1["in1_other_zones"]:
        problems.append(f"In1 carries zones of other nets {in1['in1_other_zones']}: the reference is "
                        f"not a plain ground plane")
    for net in BOARD_PAIR_NETS:
        entry = in1["nets"].get(net)
        if not entry:
            problems.append(f"{net}: no track on the board")
            continue
        on_f = entry["layers"].get("F.Cu", 0.0)
        if on_f <= 0:
            problems.append(f"{net}: nothing on F.Cu was sampled")
        elif entry["samples"] < 0.9 * 3 * on_f / IN1_SAMPLE_STEP:
            problems.append(f"{net}: only {entry['samples']} samples along {on_f:.1f} mm of F.Cu track, "
                            f"expected about {3 * on_f / IN1_SAMPLE_STEP:.0f}")
        for layer in entry["layers"]:
            if layer not in ("F.Cu", "B.Cu"):
                problems.append(f"{net}: pair track on {layer}")
            if layer == "B.Cu" and net not in B_CU_PAIR_NETS:
                problems.append(f"{net}: {entry['layers'][layer]:.1f} mm on B.Cu, where the plane next to "
                                f"it is In2 (power); only USB 2.0 may (ruling AR)")
        runs = {}
        unexplained = []
        for gap in entry["gaps"]:
            if gap["hole"] is None:
                unexplained.append(gap)
                continue
            rule = _exception_for(net, gap)
            if rule is None:
                h = gap["hole"]
                problems.append(f"{net}: no In1 ground at {tuple(gap['at'])}, inside the hole round "
                                f"{h['net']} {h['kind']} {h['label']} at {tuple(h['at'])}; that is not an "
                                f"allowed exception")
                continue
            key = (rule["name"], tuple(gap["hole"]["at"]), gap["side"])
            runs[key] = runs.get(key, 0) + 1
            if runs[key] * IN1_SAMPLE_STEP > rule["max_run_mm"]:
                problems.append(f"{net}: {rule['name']} at {tuple(gap['hole']['at'])} is "
                                f"{runs[key] * IN1_SAMPLE_STEP:.2f} mm along the track, more than the "
                                f"{rule['max_run_mm']} mm the exception allows")
        if unexplained:
            xs = [g["at"][0] for g in unexplained]
            ys = [g["at"][1] for g in unexplained]
            problems.append(f"{net}: {len(unexplained)} sampled points without In1 ground under them and "
                            f"no hole to explain it, x {min(xs):.2f}..{max(xs):.2f}, y {min(ys):.2f}..{max(ys):.2f}")
    problems += _ar_problems(in1["ar"])
    return sorted(set(problems))


def _ar_problems(ar):
    problems = []
    if not ar["in2"]:
        return ["no pair track on B.Cu was found: the USB 2.0 stretch of ruling AR is gone or unrecognised"]
    islands = {label for seq in ar["in2"].values() for label, _, _ in seq if label != "gap"}
    if len(islands) > AR_MAX_ISLAND_BOUNDARIES + 1:
        problems.append(f"the B.Cu pair stretch runs over {len(islands)} In2 islands {sorted(islands)}, "
                        f"more than {AR_MAX_ISLAND_BOUNDARIES} boundary (ruling AR)")
    window = sorted(x for seq in ar["in2"].values() for label, x, _ in seq
                    if label == "gap" and ar["bbox"][0] + 1.0 < x < ar["bbox"][2] - 1.0)
    if not window:
        return problems
    lo, hi = window[0], window[-1]
    ys = [y for seq in ar["in2"].values() for _, x, y in seq if lo - 0.5 <= x <= hi + 0.5]
    north = [v for v in ar["vias"] if lo - AR_FLANK_REACH_MM <= v["at"][0] <= hi + AR_FLANK_REACH_MM
             and v["at"][1] < min(ys)]
    south = [v for v in ar["vias"] if lo - AR_FLANK_REACH_MM <= v["at"][0] <= hi + AR_FLANK_REACH_MM
             and v["at"][1] > max(ys)]
    for side, vias in (("north", north), ("south", south)):
        good = [v for v in vias if v["in_bcu_pour"] and v["in_in1"]]
        if not good:
            problems.append(f"no GND via on the {side} side of the In2 gap crossing at x {lo:.2f}..{hi:.2f} "
                            f"that stands in both the B.Cu pour and the In1 plane (ruling AR flank)")
    return problems


# --- Pair coupling --------------------------------------------------------

COUPLING_STEP = 0.05
PROBE_FAR = 99.0
STACKUP_H_MM, STACKUP_ER, STACKUP_T_OZ = 0.1855, 4.74, 1.0
# Slack for the stretch of any pair net that is outside its impedance window
# and in no named region below: a corner, a step, the end of a neck.
UNREGIONED_SLACK_MM = 0.3

# Where a pair net may leave the impedance window and by how much. A sample is
# outside the window if the as-built differential impedance for its track width
# and its edge-to-edge gap to the partner's copper (track, pad or via, same
# layer) is more than 10 % from the target. Each region is a box in board
# coordinates (origin at the board's own origin) or a radius round the pads of
# the named parts; `cap_mm` is the most PATH length of that net the region may
# hold (path, not extent: the conductor length makes the discontinuity). Every
# region has a `kind` (ruling BW):
#   granted  a controller ruling gave this figure; `basis` names it
#            ("ruling XX ..."). The cap is that figure and nothing is added.
#   ratchet  no ruling gave this figure (or the cap is the ruling's figure plus
#            an allowance of the implementer's). The cap is the committed
#            board's length with a margin; it only stops the board getting
#            worse and is NOT verified against a requirement. `basis` starts
#            with RATCHET and the region is argued in
#            hardware/review/2026-11-03-routed/accepted-findings.md.
RATCHET = "as-built ratchet, not verified against a requirement"
_MDI_REGION = {"name": "J2 pin lead-in", "box": (33.5, 45.5, 11.0, 25.0), "layer": "F.Cu", "kind": "ratchet",
               "basis": RATCHET + "; rulings AM / AQ route it planar and quantify nothing"}
COUPLING_REGIONS = (
    # U3's pads: the neck, at most 1.0 mm from the pad centre (rulings AG, AI)
    {"name": "U3 neck", "nets": r"(USB3_(TX|RX)_[PN]|USB2_D_[PN]|MDI\d_[PN])", "near": (("U3",), NECK_MAX_LENGTH_MM),
     "cap_mm": NECK_MAX_LENGTH_MM, "kind": "granted", "basis": "ruling AG/AI (neck at most 1.0 mm from the pad centre)"},
    # Ruling BY: caps are per NET, not per pair. A cap shared by both legs is only as
    # tight as the longer one, so the shorter leg could degrade up to it unseen
    # (TX_CONN_N measures 6.68 mm under a pair-wide 8.0). Every ratchet below
    # therefore names one net and carries that net's own measured path length in
    # the region plus a margin of 0.1 mm, rounded up to 0.01 mm. 0.1 mm is twice
    # COUPLING_STEP, the resolution of the measurement, so sampling cannot trip it,
    # and small enough that a real change in the routing does. A split never
    # loosens a cap: where 0.1 mm over the measurement is more than the figure the
    # shared cap had (TX_CONN_N in the capacitor landing, RX in the J3 fan-out),
    # the old figure stays and the margin is the smaller one that leaves. The
    # lengths: hardware/review/2026-11-03-routed/accepted-findings.md, A6.
    # TX: the 45 degree fan-out to the two AC capacitors. Ruling BE and the
    # stackup note say about 1 mm; no ruling gives a cap.
    *({"name": "TX capacitor landing", "nets": net, "near": (("C22", "C23"), 1.6), "cap_mm": cap,
       "kind": "ratchet", "basis": RATCHET + "; ruling BE named a fan-out of about 1 mm, no cap"}
      for net, cap in (("USB3_TX_P", 0.94), ("USB3_TX_N", 1.26),
                       ("USB3_TX_CONN_P", 0.20), ("USB3_TX_CONN_N", 1.40))),
    # U8's straddle. Ruling AS: about 5 mm per pair, as extent; the path against
    # extent on top is the implementer's allowance, not granted.
    *({"name": "U8 straddle", "nets": net, "box": (12.0, 19.0, 0, 40), "layer": "F.Cu", "cap_mm": cap,
       "kind": "ratchet",
       "basis": RATCHET + "; ruling AS granted about 5 mm of extent, the allowance for path is not granted"}
      for net, cap in (("USB3_RX_P", 5.41), ("USB3_RX_N", 5.62))),
    # Ruling BV, as ruling CD reads it: 8.0 mm of PATH for USB3_TX_CONN_P's
    # straddle alone (not the pair). A granted concession under
    # reservation, not an engineering target: forced by U8's SOT-23-6 pad rows,
    # TX has no EMC iterations left. Verified by the SuperSpeed first-build check
    # (hardware/fab/fabrication-note.md); if the link proves marginal U8's
    # package is the first thing to change. BV's 8.0 mm is the figure for the leg
    # that needs it: TX_CONN_P, 7.995 mm. It stays exactly as granted and is not
    # re-derived. TX_CONN_N measures 6.68 mm and BV gave it nothing, so ruling BY
    # holds N to its own as-built ratchet below, not to the 8.0.
    {"name": "U8 straddle", "nets": "USB3_TX_CONN_P", "box": (12.0, 19.0, 0, 40), "layer": "F.Cu",
     "cap_mm": 8.0, "kind": "granted",
     "basis": "ruling BV (8.0 mm of path; granted concession, not an engineering target)"},
    {"name": "U8 straddle", "nets": "USB3_TX_CONN_N", "box": (12.0, 19.0, 0, 40), "layer": "F.Cu",
     "cap_mm": 6.79, "kind": "ratchet",
     "basis": RATCHET + "; ruling BV's 8.0 mm is for TX_CONN_P, ruling BY holds N to its own length"},
    # J3: its +5V pin sits between the RX pins and the pairs fan out to its 2 mm pitch
    *({"name": "J3 fan-out", "nets": net, "box": (4.5, 9.0, 0, 40), "layer": "F.Cu", "cap_mm": cap,
       "kind": "ratchet",
       "basis": RATCHET + "; ruling BN granted 1.5 mm, the 0.5 mm of path allowance is not granted"}
      for net, cap in (("USB3_RX_P", 2.0), ("USB3_RX_N", 2.0))),
    *({"name": "J3 fan-out", "nets": net, "box": (4.5, 9.0, 0, 40), "layer": "F.Cu", "cap_mm": cap,
       "kind": "ratchet",
       "basis": RATCHET + "; the 2.5 mm is the task 9 re-review's measurement, ruling BE gave no figure"}
      for net, cap in (("USB3_TX_CONN_P", 2.55), ("USB3_TX_CONN_N", 2.70))),
    # USB 2.0: the D+/D- crossover between J3 and U9 (task 8, the U9 channel)
    {"name": "USB 2.0 J3 to U9 crossover", "nets": "USB2_D_N", "box": (4.5, 12.6, 0, 40),
     "cap_mm": 11.0, "kind": "ratchet", "basis": RATCHET},
    {"name": "USB 2.0 J3 to U9 crossover", "nets": "USB2_D_P", "box": (4.5, 12.6, 0, 40),
     "cap_mm": 4.6, "kind": "ratchet", "basis": RATCHET},
    # USB 2.0: the skew meander on B.Cu that matches D+ to D- (EMC DP-001)
    {"name": "USB 2.0 skew meander", "nets": "USB2_D_P", "box": (14.5, 17.5, 0, 40), "layer": "B.Cu",
     "cap_mm": 5.0, "kind": "ratchet", "basis": RATCHET},
    # USB 2.0: the two layer changes at U3's end. Ruling AR allows the layer
    # change and quantifies no length.
    {"name": "USB 2.0 layer change at U3", "nets": "USB2_D_N", "box": (20.5, 23.6, 18.0, 20.0),
     "cap_mm": 1.2, "kind": "ratchet", "basis": RATCHET + "; ruling AR allows the layer change, not a length"},
    {"name": "USB 2.0 layer change at U3", "nets": "USB2_D_P", "box": (20.5, 23.6, 18.0, 20.0),
     "cap_mm": 1.0, "kind": "ratchet", "basis": RATCHET + "; ruling AR allows the layer change, not a length"},
    # MDI: the lead-in to J2's pin columns (rulings AM, AQ: planar, pins of one pair 2.5 mm apart)
    *({**_MDI_REGION, "nets": net, "cap_mm": cap} for net, cap in (
        ("MDI0_N", 5.5), ("MDI0_P", 4.5), ("MDI1_N", 4.2), ("MDI1_P", 3.1),
        ("MDI2_N", 7.0), ("MDI2_P", 5.0), ("MDI3_N", 4.3), ("MDI3_P", 2.3))),
)
def shared_ratchet_problems(regions=None):
    """Ruling BY: a ratchet cap is per net. One message per ratchet region whose
    `nets` pattern does not match exactly one pair net: a cap shared by both
    legs is only as tight as the longer one. Granted caps are a ruling's figure
    and may span nets."""
    problems = []
    for region in COUPLING_REGIONS if regions is None else regions:
        if region["kind"] != "ratchet":
            continue
        matched = [n for n in BOARD_PAIR_NETS if re.fullmatch(region["nets"], n)]
        if len(matched) != 1:
            problems.append(f"ratchet {region['name']!r} with nets {region['nets']!r} matches "
                            f"{len(matched)} pair nets {matched}, not exactly one (ruling BY)")
    return problems


# Each pair's length as committed, to turn the caps into a floor on the share
# of the pair that stays inside the window.
NOMINAL_LENGTH_MM = {
    "USB3_TX_P": 4.5, "USB3_TX_N": 4.6, "USB3_TX_CONN_P": 21.8, "USB3_TX_CONN_N": 22.2,
    "USB3_RX_P": 23.1, "USB3_RX_N": 24.1, "USB2_D_P": 21.4, "USB2_D_N": 24.8,
    "MDI0_P": 34.2, "MDI0_N": 34.4, "MDI1_P": 28.2, "MDI1_N": 28.4,
    "MDI2_P": 12.4, "MDI2_N": 14.5, "MDI3_P": 12.9, "MDI3_N": 15.1}
# Of the rest of the board: the share at the designed gap (+/- 0.03 mm) is
# smaller than the share inside the window by the length at 0.20 to 0.27 mm,
# which is inside it; this much of the pair's length may sit there.
BAND_ALLOWANCE = 0.05


def coupled_floor(net):
    """The least share of `net` that must be inside the impedance window:
    what is left after its regions' caps and the slack, over its length."""
    caps = sum(r["cap_mm"] for r in COUPLING_REGIONS if re.fullmatch(r["nets"], net))
    return 1.0 - (caps + UNREGIONED_SLACK_MM) / NOMINAL_LENGTH_MM[net]


def pair_target_ohm(net, targets=None):
    targets = targets or netlist_impedance_targets(load_netlist())
    return targets["MDI" if net.startswith("MDI") else "USB3"]


def pair_gap_mm(net):
    pro = load_pro()
    cls = "MDI" if net.startswith("MDI") else "USB3"
    return next(c["diff_pair_gap"] for c in pro["net_settings"]["classes"] if c["name"] == cls)


def _in_window(net, width, gap, target):
    z = as_built_zd(STACKUP_T_OZ, STACKUP_H_MM, width, max(gap, 0.0), STACKUP_ER)
    return abs(z - target) <= 0.1 * target


def _region_of(net, x, y, layer, pads):
    for region in COUPLING_REGIONS:
        if not re.fullmatch(region["nets"], net) or region.get("layer", layer) != layer:
            continue
        if "box" in region:
            x0, x1, y0, y1 = region["box"]
            if x0 <= x <= x1 and y0 <= y <= y1:
                return region
        else:
            refs, radius = region["near"]
            if any(math.hypot(x - p["at"][0], y - p["at"][1]) <= radius
                   for p in pads if p["ref"] in refs):
                return region
    return None


def coupling_summary(probe, targets=None):
    """Per pair net: length, length inside the impedance window, length at the
    designed gap +/- 0.03 mm, and the out-of-window length by region."""
    targets = targets or netlist_impedance_targets(load_netlist())
    out = {}
    for net in BOARD_PAIR_NETS:
        samples = probe["coupling"].get(net, [])
        target = pair_target_ohm(net, targets)
        gap = pair_gap_mm(net)
        row = {"length": 0.0, "window": 0.0, "at_gap": 0.0, "regions": {}, "unregioned": 0.0}
        for x, y, g, w, length, layer in samples:
            row["length"] += length
            if abs(g - gap) <= 0.03:
                row["at_gap"] += length
            if _in_window(net, w, g, target):
                row["window"] += length
                continue
            region = _region_of(net, x, y, layer, probe["pads"])
            if region is None:
                row["unregioned"] += length
            else:
                key = (region["name"], region["cap_mm"], region["basis"])
                row["regions"][key] = row["regions"].get(key, 0.0) + length
        out[net] = row
    return out


def pair_coupling_problems(probe, targets=None):
    """One message per reason a pair is less coupled than the rulings granted:
    a region over its cap, uncoupled length in no region, or a share of the
    pair inside the impedance window below the floor that the caps leave."""
    problems = []
    if sorted(probe["pairs"]) != sorted(BOARD_PAIR_NETS):
        problems.append(f"the board's pair nets are {sorted(probe['pairs'])}, not the expected "
                        f"{sorted(BOARD_PAIR_NETS)}")
    summary = coupling_summary(probe, targets)
    for net, row in summary.items():
        if row["length"] <= 0:
            problems.append(f"{net}: no track measured")
            continue
        for (name, cap, basis), length in row["regions"].items():
            if length > cap:
                problems.append(f"{net}: {length:.2f} mm outside the impedance window in {name!r}, "
                                f"more than its cap of {cap} mm ({basis})")
        if row["unregioned"] > UNREGIONED_SLACK_MM:
            problems.append(f"{net}: {row['unregioned']:.2f} mm outside the impedance window in no "
                            f"region any ruling grants (slack {UNREGIONED_SLACK_MM} mm)")
        share, floor = row["window"] / row["length"], coupled_floor(net)
        if share < floor:
            problems.append(f"{net}: {100 * share:.0f} % of its length inside the impedance window, "
                            f"below the floor of {100 * floor:.0f} % the granted regions leave")
        at_gap, floor_gap = row["at_gap"] / row["length"], floor - BAND_ALLOWANCE
        if at_gap < floor_gap:
            problems.append(f"{net}: {100 * at_gap:.0f} % of its length at the designed gap, below "
                            f"the floor of {100 * floor_gap:.0f} %")
    return problems


# ---------------------------------------------------------------------------
# Task 11, review focus 4: a gerber set must not come from a board other than
# the one in the repository, and not from a board that failed DRC.
#
# A stale set looks exactly like a valid one: same file names, same layers,
# plausible sizes. File times do not tell them apart either (git does not keep
# them, a re-saved but unchanged board is newer without being different), so
# the set carries a manifest written by tools/export_fab.py, which binds the
# files to the SHA-256 of the board, its rules file and its project file, and
# to the DRC report made from that same board. The check compares the manifest
# with the files on disk and the files with the manifest.
# ---------------------------------------------------------------------------

import hashlib
import os

FAB = HARDWARE / "fab"
GERBER_DIR = FAB / "gerber"
MANIFEST_NAME = "release-manifest.json"
DRC_REPORT_NAME = "raccoon-tap-drc.rpt"
EXPORT_FAB = HARDWARE / "tools" / "export_fab.py"
ASSEMBLED_REFS = ("U3", "Y1")

# What PCBWay needs to build and to assemble this board; the file name ends
# in one of these (kicad-cli's Protel extensions).
REQUIRED_GERBER_SUFFIXES = {
    "F_Cu.gtl": "top copper", "GND.g1": "In1 (GND)", "Power.g2": "In2 (power)",
    "B_Cu.gbl": "bottom copper", "F_Mask.gts": "top solder mask",
    "B_Mask.gbs": "bottom solder mask", "F_Silkscreen.gto": "top silkscreen",
    "B_Silkscreen.gbo": "bottom silkscreen", "F_Paste.gtp": "top paste (U3 and Y1 only)",
    "Edge_Cuts.gm1": "board outline",
    "PTH.drl": "plated drill file", "NPTH.drl": "non-plated drill file",
}


def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def drc_report_problems(text, board_name="raccoon-tap.kicad_pcb"):
    """Why a KiCad DRC report does not show a clean board: not for this board,
    not run with every severity, any error, any unconnected pad or footprint
    error, or a report that is not a report."""
    problems = []
    head = text.splitlines()[0] if text.strip() else ""
    if f"Drc report for {board_name}" not in head:
        problems.append(f"the DRC report is not for {board_name}: {head[:80]!r}")
    if "Report includes: Errors, Warnings" not in text:
        problems.append("the DRC report was not made with --severity-all (no 'Errors, Warnings' line)")
    if "** End of Report **" not in text:
        problems.append("the DRC report is cut off (no 'End of Report')")
    errors = len(re.findall(r";\s*error\s*$", text, re.M))
    if errors:
        problems.append(f"the DRC report has {errors} error(s)")
    sections = dict((k, int(n)) for n, k in
                    re.findall(r"\*\* Found (\d+) (DRC violations|unconnected pads|Footprint errors) \*\*", text))
    for needed in ("unconnected pads", "Footprint errors"):
        if needed not in sections:
            problems.append(f"the DRC report has no '{needed}' section")
        elif sections[needed]:
            problems.append(f"the DRC report has {sections[needed]} {needed}")
    return problems


def check_gerber_freshness(pcb=PCB, gerber_dir=GERBER_DIR, dru=DRU, pro=PRO):
    """One message per reason the gerber set in `gerber_dir` may not be sent
    to a fab: it does not exist, it was made from another board (or other DRC
    rules) than the ones given, a file was replaced after the export, a layer
    is missing or a stray file is there, or the DRC report beside it is not
    clean. An empty list means the set is the export of this board and the
    board passed DRC."""
    gerber_dir = Path(gerber_dir)
    manifest_path = gerber_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        return [f"no gerber set: {manifest_path} does not exist "
                f"(run hardware/tools/export_fab.py)"]
    problems = []
    manifest = json.loads(manifest_path.read_text())
    for label, path in (("board", pcb), ("rules", dru), ("project", pro)):
        recorded = manifest.get("inputs", {}).get(label)
        now = sha256_of(path)
        if recorded != now:
            problems.append(
                f"stale gerber set: it was exported from a {label} file with SHA-256 "
                f"{str(recorded)[:12]}, the file now is {now[:12]} ({Path(path).name})")
    files = manifest.get("files", {})
    on_disk = {p.name for p in gerber_dir.iterdir() if p.is_file()} - {MANIFEST_NAME}
    for name in sorted(on_disk - set(files)):
        problems.append(f"{name} is in the gerber folder but not in the manifest")
    for name, digest in sorted(files.items()):
        path = gerber_dir / name
        if not path.is_file():
            problems.append(f"{name} is in the manifest but missing")
        elif sha256_of(path) != digest:
            problems.append(f"{name} was changed after the export (SHA-256 differs from the manifest)")
    for suffix, what in REQUIRED_GERBER_SUFFIXES.items():
        if not any(n.endswith(suffix) for n in files):
            problems.append(f"no file for {what} (*{suffix})")
    report = gerber_dir / DRC_REPORT_NAME
    if DRC_REPORT_NAME not in files or not report.is_file():
        problems.append(f"no DRC report {DRC_REPORT_NAME} beside the set")
    else:
        problems += drc_report_problems(report.read_text(), Path(pcb).name)
    return problems


class GerberSetIsCurrent(unittest.TestCase):

    def test_gerbers_are_newer_than_the_pcb_and_drc_was_clean(self):
        self.assertEqual(check_gerber_freshness(), [])


def _copy_set(directory):
    """A scratch copy of the committed gerber set, for the tests that damage it."""
    target = Path(directory) / "gerber"
    shutil.copytree(GERBER_DIR, target)
    return target


class GerberFreshnessCanFail(unittest.TestCase):
    """The check above is only worth having if it fails on a stale or tainted
    set. Each test damages a copy of the committed set in one way (the board and
    the set in the repository are never touched) and demands a message that
    names that way; the control is the undamaged copy, which must pass."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.set = _copy_set(self.tmp.name)

    def problems(self, pcb=PCB):
        return check_gerber_freshness(pcb=pcb, gerber_dir=self.set)

    def rewrite_manifest(self, fn):
        path = self.set / MANIFEST_NAME
        manifest = json.loads(path.read_text())
        fn(manifest)
        path.write_text(json.dumps(manifest))

    def test_control_the_undamaged_copy_passes(self):
        self.assertEqual(self.problems(), [])

    def test_a_board_changed_after_the_export_makes_the_set_stale(self):
        board = Path(self.tmp.name) / "raccoon-tap.kicad_pcb"
        board.write_text(PCB.read_text() + "\n")     # one byte: a re-saved board with other content
        problems = self.problems(pcb=board)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("stale gerber set", problems[0])
        self.assertIn("board", problems[0])

    def test_changed_drc_rules_make_the_set_stale(self):
        rules = Path(self.tmp.name) / "r.kicad_dru"
        rules.write_text(DRU.read_text() + "\n")
        problems = check_gerber_freshness(gerber_dir=self.set, dru=rules)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("rules", problems[0])

    def test_an_error_in_the_drc_report_is_refused(self):
        report = self.set / DRC_REPORT_NAME
        text = report.read_text().replace("warning\n", "error\n", 1)
        report.write_text(text)
        self.rewrite_manifest(lambda m: m["files"].update({DRC_REPORT_NAME: sha256_of(report)}))
        problems = self.problems()
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("error", problems[0])

    def test_unconnected_pads_in_the_drc_report_are_refused(self):
        report = self.set / DRC_REPORT_NAME
        report.write_text(report.read_text().replace("Found 0 unconnected pads", "Found 3 unconnected pads"))
        self.rewrite_manifest(lambda m: m["files"].update({DRC_REPORT_NAME: sha256_of(report)}))
        self.assertEqual([m for m in self.problems() if "unconnected" in m][:1],
                         ["the DRC report has 3 unconnected pads"])

    def test_a_drc_report_of_another_board_is_refused(self):
        report = self.set / DRC_REPORT_NAME
        report.write_text(report.read_text().replace("raccoon-tap.kicad_pcb", "raccoon-hat.kicad_pcb", 1))
        self.rewrite_manifest(lambda m: m["files"].update({DRC_REPORT_NAME: sha256_of(report)}))
        self.assertTrue(any("not for raccoon-tap.kicad_pcb" in m for m in self.problems()))

    def test_a_missing_drc_report_is_refused(self):
        (self.set / DRC_REPORT_NAME).unlink()
        self.assertTrue(any(DRC_REPORT_NAME in m for m in self.problems()))

    def test_a_gerber_replaced_after_the_export_is_found(self):
        path = self.set / "raccoon-tap-F_Cu.gtl"
        path.write_text(path.read_text() + "G04 edited*\n")
        problems = self.problems()
        self.assertEqual(problems, ["raccoon-tap-F_Cu.gtl was changed after the export "
                                    "(SHA-256 differs from the manifest)"])

    def test_a_missing_layer_is_found(self):
        (self.set / "raccoon-tap-B_Mask.gbs").unlink()
        self.rewrite_manifest(lambda m: m["files"].pop("raccoon-tap-B_Mask.gbs"))
        self.assertEqual(self.problems(), ["no file for bottom solder mask (*B_Mask.gbs)"])

    def test_a_stray_file_from_an_earlier_export_is_found(self):
        (self.set / "raccoon-tap-F_Cu_old.gtl").write_text("G04 old*\n")
        self.assertEqual(self.problems(),
                         ["raccoon-tap-F_Cu_old.gtl is in the gerber folder but not in the manifest"])

    def test_no_set_at_all_is_refused(self):
        self.assertEqual(len(check_gerber_freshness(gerber_dir=Path(self.tmp.name) / "nothing")), 1)

    def test_file_times_are_not_what_decides(self):
        # a clone has arbitrary times; the check must neither need them nor be fooled by them
        later = PCB.stat().st_mtime + 1000
        for path in self.set.iterdir():
            os.utime(path, (later, later))
        self.assertEqual(self.problems(), [])
        board = Path(self.tmp.name) / "raccoon-tap.kicad_pcb"
        board.write_text(PCB.read_text() + "\n")
        os.utime(board, (later - 500, later - 500))   # board OLDER than the gerbers, yet different
        self.assertIn("stale gerber set", self.problems(pcb=board)[0])


def _normalised(path):
    """A gerber or drill file without the lines that carry the time of the export."""
    keep = []
    for line in Path(path).read_text().splitlines():
        if re.search(r"CreationDate|Created by KiCad|DRILL file|TF\.GenerationSoftware", line):
            continue
        keep.append(line)
    return "\n".join(keep)


def load_export_fab():
    import importlib.util
    spec = importlib.util.spec_from_file_location("export_fab", EXPORT_FAB)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GerberSetIsTheExportOfTheBoard(unittest.TestCase):
    """The manifest says which board the set came from; this exports the board
    again, now, and compares the content. It catches a manifest written by
    hand over files that were not made from this board."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.export = load_export_fab()
        cls.fresh = Path(cls.tmp.name) / "gerber"
        cls.manifest = cls.export.export_set(cls.fresh, drc_report_problems)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_gerber_and_drill_file_is_what_a_new_export_gives(self):
        committed = json.loads((GERBER_DIR / MANIFEST_NAME).read_text())
        compared = 0
        for name in committed["files"]:
            if name.endswith((".pdf", ".rpt", ".gbrjob")):
                continue          # time stamps inside, no geometry (the DRC verdict is below)
            self.assertEqual(_normalised(GERBER_DIR / name), _normalised(self.fresh / name), name)
            compared += 1
        self.assertGreaterEqual(compared, 11)
        self.assertEqual(set(committed["files"]), set(self.manifest["files"]))

    def test_the_new_drc_report_is_clean_and_so_is_the_committed_one(self):
        self.assertEqual(drc_report_problems((self.fresh / DRC_REPORT_NAME).read_text()), [])
        self.assertEqual(drc_report_problems((GERBER_DIR / DRC_REPORT_NAME).read_text()), [])

    def test_the_export_refuses_a_board_that_fails_drc(self):
        # a scratch board with a track laid across two pads of different nets
        mutated = Path(self.tmp.name) / "bad"
        mutated.mkdir()
        for name in ("raccoon-tap.kicad_pro", "raccoon-tap.kicad_dru"):
            shutil.copy(HARDWARE / "kicad" / name, mutated / name)
        text = PCB.read_text()
        short = ('\n\t(segment\n\t\t(start 124 103)\n\t\t(end 124 111)\n\t\t(width 0.2)\n'
                 '\t\t(layer "F.Cu")\n\t\t(net "GND")\n\t\t(uuid "00000000-0000-0000-0000-000000000011")\n\t)\n')
        (mutated / "raccoon-tap.kicad_pcb").write_text(text.rstrip()[:-1] + short + ")\n")
        target = Path(self.tmp.name) / "refused"
        with self.assertRaises(self.export.ExportFailed) as ctx:
            self.export.export_set(target, drc_report_problems, board=mutated / "raccoon-tap.kicad_pcb",
                                   dru=mutated / "raccoon-tap.kicad_dru", pro=mutated / "raccoon-tap.kicad_pro")
        self.assertIn("does not pass DRC", str(ctx.exception))
        self.assertEqual(sorted(p.name for p in target.glob("*.g*")), [])   # no gerber was written


def gerber_flashes(text):
    """[(x, y)] in mm of every flash (D03) in a gerber with the 4.6 coordinate format."""
    return [(int(x) / 1e6, int(y) / 1e6)
            for x, y in re.findall(r"^X(-?\d+)Y(-?\d+)D03\*", text, re.M)]


def gerber_pad_positions(text, ref):
    """{pad number: (x, y)} in mm of the first flash after each `%TO.P,<ref>,<pad>`
    attribute of a copper gerber."""
    out = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(rf"%TO\.P,{re.escape(ref)},([^,*]+)", line)
        if not m or m.group(1) in out:
            continue
        for follow in lines[i + 1:i + 8]:
            f = re.match(r"^X(-?\d+)Y(-?\d+)D03\*", follow)
            if f:
                out[m.group(1)] = (int(f.group(1)) / 1e6, int(f.group(2)) / 1e6)
                break
    return out


def footprint_block(pcb_text, ref):
    for block in re.split(r"\n\t\(footprint ", pcb_text)[1:]:
        if re.search(r'\(property "Reference" "%s"' % re.escape(ref), block):
            return block
    raise KeyError(ref)


def footprint_local_pad(block, number):
    """Position (x, y) of pad `number` in the footprint's own frame, KiCad's Y down."""
    m = re.search(r'\n\t\t\(pad "%s" \w+ \w+\s+\(at ([-0-9.]+) ([-0-9.]+)' % re.escape(number), block)
    return float(m.group(1)), float(m.group(2))


def footprint_silk_marker(block):
    """The pin-1 marking of a footprint in its own frame (Y down): the centre of
    the polygon on F.SilkS if there is one, else the corner where two silkscreen
    lines meet (the L-shaped mark of the crystal)."""
    for poly in re.findall(r"\n\t\t\(fp_poly\n(.*?)\n\t\t\)", block, re.S):
        if '(layer "F.SilkS")' in poly:
            pts = [(float(a), float(b)) for a, b in re.findall(r"\(xy ([-0-9.]+) ([-0-9.]+)\)", poly)]
            return (sum(p[0] for p in pts) / len(pts), sum(p[1] for p in pts) / len(pts))
    ends = []
    for line in re.findall(r"\n\t\t\(fp_line\n(.*?)\n\t\t\)", block, re.S):
        if '(layer "F.SilkS")' in line:
            a = re.search(r"\(start ([-0-9.]+) ([-0-9.]+)\)", line).groups()
            b = re.search(r"\(end ([-0-9.]+) ([-0-9.]+)\)", line).groups()
            ends += [tuple(map(float, a)), tuple(map(float, b))]
    shared = [p for p in set(ends) if ends.count(p) >= 2]
    if len(shared) != 1:
        raise ValueError(f"no single pin-1 marking found ({len(shared)} candidates)")
    return shared[0]


def _rotate_up(x, y, degrees):
    """Rotate (x, y), Y up, counter-clockwise by `degrees`."""
    a = math.radians(degrees)
    return x * math.cos(a) - y * math.sin(a), x * math.sin(a) + y * math.cos(a)


def cpl_pin1_problems(rows, pcb_text, copper_gerber_text, tolerance_deg=0.5):
    """For every CPL row: the rotation that carries the footprint's own pin-1
    position onto the pin-1 pad that the copper gerber really has, and the
    marking on the silkscreen next to that pad.

    The CPL rotation is KiCad's orientation, counter-clockwise, Y up, with the
    footprint in its library pose at 0 degrees (that is what the pad
    coordinates in the board file are: the library pose). So the angle from the
    centre to the pad-1 flash in the gerber, less the angle of the library pad 1,
    is the rotation the part has been given. The gerber is what the fab will
    see; the board-file angle is not used."""
    problems = []
    for row in rows:
        ref = row["Designator"]
        block = footprint_block(pcb_text, ref)
        centre = (float(row["Mid X"]), float(row["Mid Y"]))
        rotation = float(row["Rotation"])
        pads = gerber_pad_positions(copper_gerber_text, ref)
        if "1" not in pads:
            problems.append(f"{ref}: pad 1 is not in the copper gerber")
            continue
        lx, ly = footprint_local_pad(block, "1")
        library = (lx, -ly)
        actual = (pads["1"][0] - centre[0], pads["1"][1] - centre[1])
        derived = (math.degrees(math.atan2(actual[1], actual[0]))
                   - math.degrees(math.atan2(library[1], library[0]))) % 360
        if abs(((derived - rotation + 180) % 360) - 180) > tolerance_deg:
            problems.append(f"{ref}: the CPL says {rotation:g} degrees, the pin-1 pad in the "
                            f"gerber says {derived:g}")
        if abs(math.hypot(*actual) - math.hypot(*library)) > 0.01:
            problems.append(f"{ref}: the CPL centre is not the footprint centre (pad 1 is "
                            f"{math.hypot(*actual):.3f} mm from it in the gerber, "
                            f"{math.hypot(*library):.3f} mm in the library)")
        mx, my = footprint_silk_marker(block)
        rx, ry = _rotate_up(mx, -my, rotation)
        marker = (centre[0] + rx, centre[1] + ry)
        by_distance = sorted((math.dist(marker, pos), number) for number, pos in pads.items())
        if by_distance[0][1] != "1":
            problems.append(f"{ref}: the pin-1 marking lands next to pad {by_distance[0][1]}, not pad 1")
    return problems


def read_cpl(path=None):
    with open(path or FAB / "raccoon-tap-cpl.csv", newline="") as fh:
        return list(csv.DictReader(fh))


class CplRotationIsVerifiedAgainstPinOne(unittest.TestCase):
    """A QFN-40 turned the wrong way is a dead board. The rotation in the CPL
    is not taken from the placement table: it is derived from where the gerber
    has pad 1 and where the footprint's silkscreen marks pin 1."""

    def test_the_cpl_has_u3_and_y1_and_nothing_else_on_the_top_side(self):
        rows = read_cpl()
        self.assertEqual([r["Designator"] for r in rows], list(ASSEMBLED_REFS))
        self.assertEqual({r["Layer"] for r in rows}, {"Top"})
        self.assertEqual(list(rows[0]), ["Designator", "Val", "Package", "Mid X", "Mid Y", "Rotation", "Layer"])

    def test_rotation_and_pin_one_marking_agree_with_the_gerber(self):
        copper = (GERBER_DIR / "raccoon-tap-F_Cu.gtl").read_text()
        self.assertEqual(cpl_pin1_problems(read_cpl(), PCB.read_text(), copper), [])

    def test_u3_is_turned_180_degrees_pin_1_at_the_lower_right(self):
        u3 = {r["Designator"]: r for r in read_cpl()}["U3"]
        self.assertEqual(float(u3["Rotation"]) % 360, 180)
        pads = gerber_pad_positions((GERBER_DIR / "raccoon-tap-F_Cu.gtl").read_text(), "U3")
        cx, cy = float(u3["Mid X"]), float(u3["Mid Y"])
        self.assertGreater(pads["1"][0], cx)      # right of the centre
        self.assertLess(pads["1"][1], cy)         # below it (Y is up in the gerber)
        self.assertAlmostEqual(pads["1"][0] - cx, 2.4375, places=4)
        self.assertAlmostEqual(pads["1"][1] - cy, -1.8, places=4)

    def test_position_is_the_footprint_position_in_gerber_coordinates(self):
        text = PCB.read_text()
        for row in read_cpl():
            x, y = re.search(r"\n\t\t\(at ([-0-9.]+) ([-0-9.]+)", footprint_block(text, row["Designator"])).groups()
            self.assertEqual((float(row["Mid X"]), float(row["Mid Y"])), (float(x), -float(y)))

    def test_a_cpl_with_the_wrong_rotation_is_caught(self):
        copper = (GERBER_DIR / "raccoon-tap-F_Cu.gtl").read_text()
        for wrong in ("0", "90", "270"):
            rows = read_cpl()
            rows[0]["Rotation"] = wrong
            problems = cpl_pin1_problems(rows, PCB.read_text(), copper)
            self.assertTrue(any(m.startswith("U3: the CPL says") for m in problems), (wrong, problems))
            self.assertTrue(any("marking lands next to pad" in m for m in problems), (wrong, problems))

    def test_a_cpl_with_a_mirrored_y_is_caught(self):
        copper = (GERBER_DIR / "raccoon-tap-F_Cu.gtl").read_text()
        rows = read_cpl()
        rows[0]["Mid Y"] = str(-float(rows[0]["Mid Y"]))
        self.assertTrue(cpl_pin1_problems(rows, PCB.read_text(), copper))

    def test_y1_turned_180_degrees_would_be_harmless_but_90_is_not(self):
        # the ABM8 has no fixed pin-1 mark (its datasheet: the chamfer "could be located on
        # pin #1, 3, or 4"); pads 1 and 3 are the two crystal terminals and 2 and 4 are GND, so
        # a half turn swaps terminals with terminals; a quarter turn puts a terminal on GND
        text = PCB.read_text()
        block = footprint_block(text, "Y1")
        pads = {n: footprint_local_pad(block, n) for n in "1234"}
        nets = dict(re.findall(r'\(pad "([1-4])" smd roundrect.*?\(net "([^"]+)"\)', block, re.S))
        self.assertEqual(nets["2"], "GND")
        self.assertEqual(nets["4"], "GND")
        self.assertNotIn(nets["1"], ("GND",))
        self.assertNotIn(nets["3"], ("GND",))
        half = {n: (-x, -y) for n, (x, y) in pads.items()}
        self.assertEqual({half[n] == pads[m] for n, m in (("1", "3"), ("2", "4"))}, {True})
        quarter = {n: (-y, x) for n, (x, y) in pads.items()}
        self.assertNotEqual(quarter["1"], pads["3"])
        self.assertNotIn(quarter["1"], pads.values())


def gerber_component_openings(text):
    """({ref: flash count}, unattributed flash count) of a paste gerber. KiCad
    writes the component of every pad opening as a `%TO.C,<ref>*%` attribute
    that stays in force until `%TD*%`; that attribute is what the exported file
    itself says about whose opening it is, so no geometry is guessed."""
    counts, current, unattributed = {}, None, 0
    for line in text.splitlines():
        if line.startswith("%TO.C,"):
            current = line[len("%TO.C,"):].rstrip("*%")
            counts.setdefault(current, 0)
        elif line.startswith("%TD"):
            current = None
        elif re.match(r"^X-?\d+Y-?\d+D0[123]\*", line) or line.startswith("G36"):
            if current is None:
                unattributed += 1
            else:
                counts[current] += 1
    return counts, unattributed


class PasteIsOpenOnlyForTheAssembledParts(unittest.TestCase):
    """What the stencil opens is read from the exported F.Paste file itself: the
    only component attributes (`%TO.C`) in it are U3 and Y1, and no opening or
    region stands outside an attribute. (An earlier version tested a bounding
    box round the two parts; C7, C15 and R14 are 0.2 to 0.5 mm from that box,
    so a neighbour's opening could have been taken for U3's.)"""

    def paste(self):
        return (GERBER_DIR / "raccoon-tap-F_Paste.gtp").read_text()

    def test_the_only_components_in_the_paste_file_are_u3_and_y1(self):
        text = self.paste()
        self.assertEqual(sorted(re.findall(r"^%TO\.C,([^*,]+)\*%", text, re.M)),
                         sorted(ASSEMBLED_REFS))
        counts, unattributed = gerber_component_openings(text)
        self.assertEqual(sorted(counts), sorted(ASSEMBLED_REFS))
        self.assertEqual(unattributed, 0, "an opening that no component attribute covers")

    def test_u3_and_y1_have_their_openings(self):
        counts, _ = gerber_component_openings(self.paste())
        self.assertEqual(counts["Y1"], 4)           # four pads
        # 49 flashes: 40 pads plus the 9 openings of the exposed pad (pin 41). The count is of
        # every flash, region or draw line the file attributes to U3; the file has only D03
        # flashes, so an exact figure makes the test fail if a pad loses its opening, which
        # a lower bound of 40 would not.
        self.assertEqual(counts["U3"], 49)

    def test_the_full_paste_layer_of_the_board_would_not_pass(self):
        # the control: the board's own F.Paste has openings on other components, so the test
        # above can fail. The kicad-cli is resolved the way export_fab.py does (KICAD_CLI).
        cli = load_export_fab().KICAD_CLI
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([cli, "pcb", "export", "gerbers", "--layers", "F.Paste",
                            "--output", tmp, str(PCB)], check=True, capture_output=True)
            text = (Path(tmp) / "raccoon-tap-F_Paste.gtp").read_text()
        others = set(re.findall(r"^%TO\.C,([^*,]+)\*%", text, re.M)) - set(ASSEMBLED_REFS)
        self.assertGreater(len(others), 20, sorted(others))
        self.assertTrue({"C7", "C15", "R14"} <= others, sorted(others))

    def test_the_check_sees_a_neighbours_opening_and_an_unattributed_one(self):
        relabelled = self.paste().replace("%TO.C,U3*%", "%TO.C,C7*%", 1)
        self.assertEqual(sorted(gerber_component_openings(relabelled)[0]), ["C7", "Y1"])
        bare = self.paste().replace("%TO.C,Y1*%\n", "", 1)
        counts, unattributed = gerber_component_openings(bare)
        self.assertEqual((sorted(counts), unattributed), (["U3"], 4))

    def test_there_is_no_bottom_paste_layer_and_no_bottom_part_is_assembled(self):
        names = json.loads((GERBER_DIR / MANIFEST_NAME).read_text())["files"]
        self.assertFalse([n for n in names if n.endswith(("B_Paste.gbp",))])


ASSEMBLY_BOM = FAB / "raccoon-tap-assembly-bom.csv"
CPL_PATH = FAB / "raccoon-tap-cpl.csv"
ORDERING = FAB / "ORDERING.md"


U3_SOURCING = HARDWARE / "review" / "u3-sourcing.md"


def assembly_bom_rows(path=ASSEMBLY_BOM):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def generate_assembly_bom(netlist, directory):
    """Run the real gen_bom.py on `netlist` and return the assembly BOM text it
    writes, or the ValueError text as ('error', message)."""
    directory = Path(directory)
    source = directory / "netlist.yaml"
    source.write_text(yaml.safe_dump(netlist, sort_keys=False, width=10_000))
    out = directory / "assembly-bom.csv"
    result = subprocess.run([sys.executable, str(GEN_BOM), str(source), "--out",
                             str(directory / "bom.csv"), "--assembly-out", str(out)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        return "error", result.stderr
    return "ok", out.read_text()


def assembly_bom_is_current(path, netlist, scratch):
    """True when the file at `path` is exactly what gen_bom.py writes for `netlist`."""
    status, fresh = generate_assembly_bom(netlist, scratch)
    return status == "ok" and Path(path).read_text() == fresh


class AssemblyBomIsGeneratedFromTheNetlist(unittest.TestCase):
    """raccoon-tap-assembly-bom.csv is a derived artefact: gen_bom.py writes it
    from the `assembly:` mappings of netlist.yaml, as it writes bom.csv. A
    hand-edited copy differs from a fresh run and fails here."""

    @classmethod
    def setUpClass(cls):
        cls.netlist = load_netlist()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.status, cls.fresh = generate_assembly_bom(cls.netlist, cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_committed_file_is_what_the_generator_writes(self):
        self.assertEqual(self.status, "ok", self.fresh)
        self.assertTrue(assembly_bom_is_current(ASSEMBLY_BOM, self.netlist, self.tmp.name))

    def test_the_machine_placed_parts_are_those_the_netlist_marks(self):
        # ASSEMBLED_REFS is the expected answer (rulings Y and AC), written out on purpose:
        # the exporter derives its own list from the netlist (ExporterTakesTheAssembledPartsFromTheNetlist)
        marked = [ref for ref, c in self.netlist["components"].items() if c.get("assembly") is not None]
        self.assertEqual(sorted(marked), sorted(ASSEMBLED_REFS))
        self.assertEqual(sorted(load_export_fab().assembled_refs()), sorted(ASSEMBLED_REFS))

    def test_the_equality_check_itself_fails_on_a_hand_edited_copy(self):
        # the check behind test_the_committed_file_is_what_the_generator_writes, run on a scratch
        # copy of the committed file with one character of the LCSC number changed
        with tempfile.TemporaryDirectory() as tmp:
            edited = Path(tmp) / "edited.csv"
            text = ASSEMBLY_BOM.read_text()
            edited.write_text(text.replace("C2802072", "C2802073"))
            self.assertNotEqual(edited.read_text(), text, "the edit did not change anything")
            self.assertTrue(assembly_bom_is_current(ASSEMBLY_BOM, self.netlist, tmp))
            self.assertFalse(assembly_bom_is_current(edited, self.netlist, tmp))

    def test_the_generator_reads_the_netlist_not_a_stored_copy(self):
        changed = copy.deepcopy(self.netlist)
        changed["components"]["U3"]["assembly"]["distributor_pn"] = "C1"
        changed["components"]["U3"]["assembly"]["placement"] = "Pin 1 at the upper left."
        with tempfile.TemporaryDirectory() as tmp:
            status, text = generate_assembly_bom(changed, tmp)
        self.assertEqual(status, "ok")
        self.assertIn(",C1\n", text)
        self.assertIn("Pin 1 at the upper left.", text)
        self.assertNotIn("C2802072", text)

    def test_a_part_the_netlist_does_not_mark_is_not_in_it(self):
        changed = copy.deepcopy(self.netlist)
        del changed["components"]["Y1"]["assembly"]
        with tempfile.TemporaryDirectory() as tmp:
            status, text = generate_assembly_bom(changed, tmp)
        self.assertEqual(status, "ok")
        self.assertEqual([r["Reference Designator"] for r in csv.DictReader(text.splitlines())], ["U3"])

    def test_the_generator_refuses_a_marked_part_that_is_not_fitted_or_is_incomplete(self):
        dnp = copy.deepcopy(self.netlist)
        dnp["components"]["U3"]["populate"] = False
        incomplete = copy.deepcopy(self.netlist)
        del incomplete["components"]["Y1"]["assembly"]["distributor"]
        marked_c5 = copy.deepcopy(self.netlist)
        marked_c5["components"]["C5"]["assembly"] = {"description": "x", "placement": "x",
                                                     "distributor": "x", "distributor_pn": "x"}
        marked_c5["components"]["C5"].pop("mpn", None)
        for name, netlist in (("DNP", dnp), ("incomplete", incomplete), ("no mpn", marked_c5)):
            with tempfile.TemporaryDirectory() as tmp:
                status, text = generate_assembly_bom(netlist, tmp)
            self.assertEqual(status, "error", name)

    def test_no_assembly_bom_is_written_unless_asked_for(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, str(GEN_BOM), str(NETLIST), "--out", str(Path(tmp) / "bom.csv")],
                           check=True, capture_output=True)
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ["bom.csv"])


class ExporterTakesTheAssembledPartsFromTheNetlist(unittest.TestCase):
    """Which parts PCBWay places has one home: the `assembly:` marks of
    netlist.yaml. The CPL, the paste layer and the manifest of export_fab.py
    follow the marks. ASSEMBLED_REFS above is the expected answer for the real
    netlist; here a netlist whose marks differ from it (Y1 unmarked, R14 marked)
    shows that the exporter follows the netlist and not that tuple."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.export = load_export_fab()
        netlist = load_netlist()
        del netlist["components"]["Y1"]["assembly"]
        netlist["components"]["R14"]["assembly"] = {
            "description": "0R, 0402.", "placement": "No polarity.",
            "distributor": "DigiKey", "distributor_pn": ""}
        cls.netlist_path = Path(cls.tmp.name) / "netlist.yaml"
        cls.netlist_path.write_text(yaml.safe_dump(netlist, sort_keys=False, width=10_000))
        cls.expected = ("R14", "U3")
        assert cls.expected != tuple(sorted(ASSEMBLED_REFS))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def patched(self):
        from unittest import mock
        return mock.patch.object(self.export, "NETLIST", self.netlist_path)

    def test_assembled_refs_are_the_marked_components(self):
        self.assertEqual(self.export.assembled_refs(self.netlist_path), self.expected)
        with self.patched():
            self.assertEqual(self.export.assembled_refs(), self.expected)
        self.assertEqual(self.export.assembled_refs(), tuple(ASSEMBLED_REFS))     # the real netlist

    def test_the_cpl_follows_the_marks(self):
        with self.patched(), tempfile.TemporaryDirectory() as tmp:
            self.export.write_cpl(Path(tmp) / "cpl.csv")
            rows = read_cpl(Path(tmp) / "cpl.csv")
        self.assertEqual(sorted(r["Designator"] for r in rows), sorted(self.expected))

    def test_the_paste_layer_and_the_manifest_follow_the_marks(self):
        with self.patched():
            manifest = self.export.export_set(Path(self.tmp.name) / "set", drc_report_problems)
        self.assertEqual(sorted(manifest["paste_openings_only_for"]), sorted(self.expected))
        paste = (Path(self.tmp.name) / "set" / "raccoon-tap-F_Paste.gtp").read_text()
        self.assertEqual(sorted(re.findall(r"^%TO\.C,([^*,]+)\*%", paste, re.M)), sorted(self.expected))

    def test_a_netlist_that_marks_nothing_is_refused(self):
        netlist = load_netlist()
        for comp in netlist["components"].values():
            comp.pop("assembly", None)
        path = Path(self.tmp.name) / "none.yaml"
        path.write_text(yaml.safe_dump(netlist, sort_keys=False, width=10_000))
        with self.assertRaises(self.export.ExportFailed):
            self.export.assembled_refs(path)

    def test_the_committed_set_and_cpl_are_for_the_marked_parts(self):
        manifest = json.loads((GERBER_DIR / MANIFEST_NAME).read_text())
        self.assertEqual(manifest["paste_openings_only_for"], list(ASSEMBLED_REFS))
        self.assertEqual([r["Designator"] for r in read_cpl()], list(ASSEMBLED_REFS))


class AssemblyBomIsTheTwoMachinePlacedParts(unittest.TestCase):
    """The generated file checked against sources that are not the generator:
    the hand-solder BOM, the board, the CPL, the sourcing review."""

    def rows(self):
        return assembly_bom_rows()

    def by_ref(self):
        return {r["Reference Designator"]: r for r in self.rows()}

    def test_only_u3_and_y1_are_in_it(self):
        self.assertEqual([r["Reference Designator"] for r in self.rows()], list(ASSEMBLED_REFS))
        self.assertEqual([r["Quantity Per Part Number"] for r in self.rows()], ["1", "1"])
        self.assertEqual([r["Line#"] for r in self.rows()], ["1", "2"])

    def test_part_numbers_are_those_of_the_hand_solder_bom(self):
        main = {r["Reference"]: r for r in load_bom()}
        for row in self.rows():
            ref = row["Reference Designator"]
            self.assertEqual(row["Part Number"], main[ref]["Part Number"])
            self.assertEqual(row["Manufacturers Part Number"], main[ref]["Part Number"])
            self.assertEqual(row["Manufacturers Name"], main[ref]["Manufacturer"])

    def test_package_is_the_footprint_on_the_board_and_in_the_cpl(self):
        text = PCB.read_text()
        cpl = {r["Designator"]: r for r in read_cpl()}
        for ref, row in self.by_ref().items():
            names = re.findall(r'^\(footprint "([^"]+)"', footprint_block_header(text, ref), re.M)
            self.assertEqual([n.split(":")[-1] for n in names], [row["Package"]], ref)
            self.assertEqual(row["Package"], cpl[ref]["Package"], ref)

    def test_description_agrees_with_the_hand_solder_bom_and_the_footprint(self):
        main = {r["Reference"]: r for r in load_bom()}
        by_ref = self.by_ref()
        # U3: 40 pins on 0.4 mm pitch, 5x5 mm, exposed pad = pin 41
        u3 = by_ref["U3"]["Part Description"]
        footprint = by_ref["U3"]["Package"]
        self.assertIn("QFN-40", u3)
        self.assertIn("QFN-40", footprint)
        self.assertRegex(footprint, r"5x5mm_P0\.4mm")
        self.assertRegex(u3, r"5\s?x\s?5 mm")
        self.assertRegex(u3, r"0\.4 mm pitch")
        self.assertIn("pin 41", u3)
        self.assertIn('(pad "41" ', footprint_block(PCB.read_text(), "U3"))
        self.assertIn("pin 41", main["U3"]["Source"])
        # Y1: 25 MHz, CL 18 pF, 3225
        y1 = by_ref["Y1"]["Part Description"]
        self.assertIn("25 MHz", y1)
        self.assertIn("25MHz", main["Y1"]["Description"])
        self.assertIn("CL 18 pF", y1)
        self.assertIn("CL 18pF", main["Y1"]["Description"])
        self.assertIn("3225", y1)
        self.assertEqual(main["Y1"]["Package"], "3225")
        self.assertIn("3225", by_ref["Y1"]["Package"])

    def test_the_pin_1_text_agrees_with_the_gerber_and_the_cpl(self):
        by_ref = self.by_ref()
        u3 = by_ref["U3"]["Part Description"]
        self.assertRegex(u3, r"(?i)pin 1 at the lower right of the part as seen from the front")
        cpl = {r["Designator"]: r for r in read_cpl()}["U3"]
        pad1 = gerber_pad_positions((GERBER_DIR / "raccoon-tap-F_Cu.gtl").read_text(), "U3")["1"]
        self.assertGreater(pad1[0], float(cpl["Mid X"]))        # right
        self.assertLess(pad1[1], float(cpl["Mid Y"]))           # lower (Y is up in the gerber)
        self.assertEqual(float(cpl["Rotation"]) % 360, 180)
        # Y1: pads 1 and 3 are the crystal terminals, 2 and 4 ground; no fixed pin-1 mark
        y1 = by_ref["Y1"]["Part Description"]
        self.assertIn("Pads 1 and 3 are the terminals, 2 and 4 are ground", y1)
        self.assertIn("No fixed pin-1 mark", y1)
        block = footprint_block(PCB.read_text(), "Y1")
        nets = dict(re.findall(r'\(pad "([1-4])" smd roundrect.*?\(net "([^"]+)"\)', block, re.S))
        self.assertEqual((nets["2"], nets["4"]), ("GND", "GND"))
        self.assertNotIn("GND", (nets["1"], nets["3"]))

    def test_u3_names_lcsc_c2802072_and_y1_names_a_distributor(self):
        by_ref = self.by_ref()
        self.assertEqual(by_ref["U3"]["Distributors Part Number"], "C2802072")
        self.assertEqual(by_ref["U3"]["Distributor"], "LCSC")
        self.assertRegex(by_ref["U3"]["Distributors Part Number"], r"^C\d+$")
        self.assertTrue(by_ref["Y1"]["Distributor"])
        self.assertEqual(by_ref["Y1"]["Distributors Part Number"], "")      # none was verified

    def test_the_lcsc_number_is_the_one_in_the_sourcing_review_and_in_ordering(self):
        number = self.by_ref()["U3"]["Distributors Part Number"]
        review = U3_SOURCING.read_text()
        self.assertRegex(review, rf"LCSC\*?\*? `{number}`")
        self.assertRegex(review, r"RTL8153B")
        self.assertIn(number, ORDERING.read_text())
        self.assertIn(self.by_ref()["Y1"]["Manufacturers Part Number"], ORDERING.read_text())

    def test_no_hand_soldered_part_is_in_it(self):
        main = {r["Reference"] for r in load_bom()}
        self.assertTrue(set(ASSEMBLED_REFS) <= main)
        refs = {r["Reference Designator"] for r in self.rows()}
        self.assertEqual(refs, set(ASSEMBLED_REFS))


def footprint_block_header(pcb_text, ref):
    """The first line of the footprint block of `ref`, as it stands in the file."""
    return "(footprint " + footprint_block(pcb_text, ref).split("\n", 1)[0]


def board_vias(pcb_text):
    """[(size, drill, back_tented)] of every via of the board."""
    out = []
    for block in re.findall(r"\n\t\(via\n(.*?)\n\t\)", pcb_text, re.S):
        size = float(re.search(r"\(size ([0-9.]+)\)", block).group(1))
        drill = float(re.search(r"\(drill ([0-9.]+)\)", block).group(1))
        back = re.search(r"\(tenting\s+\(front (\w+)\)\s+\(back (\w+)\)", block)
        out.append((size, drill, back.group(2) if back else None))
    return out


class OrderingStatesEveryRuledRequirement(unittest.TestCase):
    """ORDERING.md is what a human reads before paying. Each ruled requirement
    is a row here; the numbers that come from the board are compared with the
    board, so the text cannot drift from the design."""

    @classmethod
    def setUpClass(cls):
        cls.text = ORDERING.read_text()
        cls.flat = re.sub(r"\s+", " ", cls.text)       # a sentence may wrap

    def assertStated(self, pattern, what):
        self.assertRegex(self.flat, pattern, f"ORDERING.md does not state: {what}")

    def test_partial_assembly_of_exactly_u3_and_y1(self):
        self.assertStated(r"(?i)partial assembly.{0,80}U3.{0,40}Y1", "partial assembly of U3 and Y1 (rulings Y, AC)")
        self.assertStated(r"(?i)every other (part|position)", "everything else is fitted by the operator")

    def test_three_via_sizes_match_the_board(self):
        vias = board_vias(PCB.read_text())
        sizes = {}
        for size, drill, _ in vias:
            sizes[(size, drill)] = sizes.get((size, drill), 0) + 1
        self.assertEqual(sorted(sizes), [(0.56, 0.3), (0.6, 0.3), (0.8, 0.4)])
        for (size, drill), count in sizes.items():
            self.assertStated(rf"\|\s*{size:g} / {drill:g}\s*\|\s*{count}\s*\|",
                              f"{count} vias of {size:g} / {drill:g} mm")
        self.assertStated(r"(?i)minimum", "that 0.56 / 0.30 mm is the board's minimum via (ruling BP)")

    def test_tented_vias_match_the_board(self):
        vias = board_vias(PCB.read_text())
        tented_back = [v for v in vias if v[2] == "yes"]
        self.assertEqual(len(tented_back), 10)       # U3's nine and U8 pin 2's
        self.assertStated(r"(?i)tented.{0,40}(back|bottom)", "vias tented from the back")
        self.assertStated(r"(?i)nine.{0,60}U3|U3.{0,60}nine|9.{0,40}U3", "U3's nine thermal vias")
        self.assertStated(r"U8.{0,40}pin 2", "U8 pin 2's via")

    def test_resin_filling_is_a_priced_option_not_a_decision(self):
        self.assertStated(r"(?i)resin", "resin-filled vias")
        self.assertStated(r"(?i)(not decided|operator decides|decision for the operator)", "that the operator decides (ruling BD)")
        self.assertStated(r"(?i)price", "that PCBWay's price for it is to be obtained")

    def test_bottom_side_hand_parts_are_named_and_the_job_is_not_double_sided_smt(self):
        for ref in ("C9", "C14", "C27"):
            self.assertStated(rf"\b{ref}\b", f"{ref} on the bottom side (ruling BL)")
        self.assertStated(r"(?i)not a double-sided", "that this is not double-sided SMT")
        bottom = re.findall(r'\(footprint "[^"]+"\n\t\t\(layer "B\.Cu"\)', PCB.read_text())
        self.assertEqual(len(bottom), 3)

    def test_surface_finish_is_enig_by_ruling_ca_everywhere_it_is_mentioned(self):
        row = next(l for l in self.text.splitlines() if l.startswith("| Surface finish"))
        self.assertRegex(row, r"\*\*ENIG\*\*.*ruling CA")
        self.assertStated(r"(?i)surface finish: ENIG \(ruling CA\)", "the finish decision, with its ruling")
        self.assertStated(r"(?i)QFN-40.{0,80}0\.4 mm pitch.{0,300}ENIG is flat|ENIG is\s+flat", "the ruling's reason: ENIG is flat at 0.4 mm pitch")
        self.assertStated(r"(?i)HASL.{0,40}uneven", "that HASL is uneven")
        job_row = next(l for l in self.text.splitlines() if "raccoon-tap-job.gbrjob" in l and l.startswith("|"))
        self.assertRegex(job_row, r"ENIG.*ruling CA")
        questions = self.text.split("## Questions for PCBWay", 1)[1]
        question_11 = questions.split("\n11. ", 1)[1].split("\n\n", 1)[0]
        self.assertRegex(re.sub(r"\s+", " ", question_11), r"ENIG.*ruling CA")
        decisions = re.sub(r"\s+", " ", self.text.split("* **Decisions** for the operator:", 1)[1].split("* **The first-build", 1)[0])
        self.assertNotRegex(decisions.split("The surface finish")[0], r"(?i)finish")
        self.assertRegex(decisions, r"(?i)surface finish is no longer one.{0,30}ENIG \(ruling CA\)")

    def test_ordering_no_longer_calls_the_finish_open(self):
        for stale in (r"recommended, not decided", r"Nobody has ruled", r"open decision for the operator",
                      r"(?i)surface finish is an open"):
            self.assertNotRegex(self.flat, stale)

    def test_cpl_format_is_declared_unverified_and_the_preview_is_a_gate(self):
        self.assertStated(r"(?i)CPL.s format is unverified against PCBWay", "that the CPL format, not only the rotation, is unverified")
        questions = self.text.split("## Questions for PCBWay", 1)[1]
        q10 = re.sub(r"\s+", " ", questions.split("\n10. ", 1)[1].split("\n11. ", 1)[0])
        for needed, what in ((r"hard gate", "a hard gate"), (r"before I pay", "before payment"),
                             (r"`Layer`.{0,20}`Top`", "the Layer value Top"), (r"`T`", "T / B"),
                             (r"without.{0,10}unit suffix|unit suffix", "the missing mm suffix"),
                             (r"negative", "the negative Mid Y"),
                             (r"Designator, Val, Package, Mid X, Mid Y, Rotation, Layer", "the column set"),
                             (r"rotation convention", "the rotation convention")):
            self.assertRegex(q10, rf"(?i){needed}", f"Question 10 does not state: {what}")
        self.assertStated(r"(?i)GATE: do not pay until you have seen PCBWay.s placement preview", "the gate before payment")
        self.assertStated(r"(?i)no payment before the operator has seen it", "the gate in the open items")
        header = CPL_PATH.read_text().splitlines()[0].split(",")
        self.assertIn(", ".join(header), self.flat)               # the column set stated is the file's
        self.assertEqual({r["Layer"] for r in read_cpl()}, {"Top"})
        self.assertTrue(float([r for r in read_cpl() if r["Designator"] == "U3"][0]["Mid Y"]) < 0)

    def test_the_narrow_via_is_flagged_as_possibly_out_of_process_in_the_table(self):
        row = next(l for l in self.text.splitlines() if l.startswith("| 0.56 / 0.3"))
        self.assertRegex(row, r"(?i)annular ring 0\.13 mm")
        self.assertRegex(row, r"(?i)may be below PCBWay.s published minimum")
        self.assertRegex(row, r"(?i)0\.15 mm")
        self.assertRegex(row, r"(?i)not confirmed")

    def test_controlled_impedance_with_targets_and_the_mask_pass_question_first(self):
        self.assertStated(r"90\s*(ohm|Ω)", "90 ohm differential")
        self.assertStated(r"100\s*(ohm|Ω)", "100 ohm differential")
        self.assertStated(r"(?i)stackup-note\.md", "the stackup note is attached")
        mask_passes = r"(?i)passes of (the )?solder\s+mask|mask\s+passes"
        questions = self.text.split("## Questions for PCBWay", 1)[1]
        first = questions.split("\n2. ", 1)[0]
        self.assertRegex(first, r"(?s)^.*\n1\. ")
        self.assertRegex(re.sub(r"\s+", " ", first), mask_passes)          # Question 1 asks it
        self.assertStated(r"(?i)two passes", "what two passes do to the tolerance")

    def test_u3_sourcing_names_lcsc_and_what_only_a_quote_can_answer(self):
        self.assertStated(r"C2802072", "LCSC C2802072")
        self.assertStated(r"(?i)Mouser.{0,60}DigiKey|DigiKey.{0,60}Mouser", "that Mouser and DigiKey list nothing")
        self.assertStated(r"(?i)consign", "the consignment fallback")
        self.assertStated(r"(?i)X-ray", "X-ray of the QFN")

    def test_ruling_u_wuerth_datasheet_is_an_open_item_for_the_human(self):
        self.assertStated(r"692112030100", "the Würth part number")
        self.assertStated(r"(?i)403", "HTTP 403")
        self.assertStated(r"(?i)by hand", "that the human downloads it")
        self.assertStated(r"(?i)USB 3\.0 (specification|Specification)", "the USB 3.0 specification as the citation")

    def test_archiving_decision_is_recorded_as_ruling_e(self):
        self.assertStated(r"(?i)ruling E", "ruling E")
        self.assertStated(r"(?i)versioned", "that the release set is versioned")

    def test_it_names_the_board_it_was_written_for(self):
        self.assertIn(sha256_of(PCB), self.text)
        self.assertEqual(json.loads((GERBER_DIR / MANIFEST_NAME).read_text())["inputs"]["board"],
                         sha256_of(PCB))

    def test_the_files_it_lists_exist(self):
        for name in re.findall(r"`((?:gerber/)?raccoon-tap[-\w.]*\.(?:gtl|g1|g2|gbl|gts|gbs|gto|gbo|gm1|drl|gtp|gbrjob|csv))`",
                               self.text):
            self.assertTrue((FAB / name).is_file() or (GERBER_DIR / name.split("/")[-1]).is_file(), name)

    def test_nothing_was_ordered(self):
        self.assertStated(r"(?i)nothing (has been|was) (ordered|uploaded)", "that nothing was ordered or uploaded")


class ReleaseSetIsVersioned(unittest.TestCase):
    """Ruling E: hardware/fab/gerber/ is covered by no ignore rule, on purpose."""

    def test_no_file_of_the_set_is_ignored_by_git(self):
        names = [GERBER_DIR / n for n in json.loads((GERBER_DIR / MANIFEST_NAME).read_text())["files"]]
        names += [GERBER_DIR / MANIFEST_NAME, FAB / "raccoon-tap-cpl.csv", ASSEMBLY_BOM, ORDERING]
        for path in names:
            result = subprocess.run(["git", "check-ignore", "-q", str(path)], cwd=HARDWARE,
                                    capture_output=True)
            self.assertEqual(result.returncode, 1, f"{path.name} is ignored by git (exit {result.returncode})")

    def test_control_the_old_gerber_folder_is_ignored(self):
        result = subprocess.run(["git", "check-ignore", "-q", "gerber/x.gbr"], cwd=HARDWARE,
                                capture_output=True)
        self.assertEqual(result.returncode, 0)


class U3ThermalIsNotLeftSilent(unittest.TestCase):
    """kicad-happy assessed only U4; task 10 computed U4 and U6 by hand. U3 is
    the most heavily loaded part, so the fabrication note carries its estimate
    and the measurement that decides it."""

    def test_the_fabrication_note_has_an_estimate_and_a_first_build_measurement(self):
        text = (FAB / "fabrication-note.md").read_text()
        self.assertRegex(text, r"(?m)^## U3 thermal")
        section = text.split("## U3 thermal", 1)[1].split("\n## ", 1)[0]
        self.assertRegex(section, r"125")                        # the datasheet's junction limit
        self.assertRegex(section, r"(?i)assum")                  # theta-JA is an assumption, said so
        self.assertRegex(section, r"(?i)first build|first-build")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
