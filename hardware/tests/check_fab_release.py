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


# RJ45 pins of the four cable pairs of 1000BASE-T (IEEE 802.3 clause 40) and the
# group each MDI pair of the RTL8153B belongs to ([RTL-DS] Table 4: MDI0 BI_DA,
# MDI1 BI_DB, MDI2 BI_DC, MDI3 BI_DD). A and B carry 10/100 and auto-negotiation.
CABLE_PAIRS = {"A": (1, 2), "B": (3, 6), "C": (4, 5), "D": (7, 8)}
MDI_GROUPS = {"MDI0": "AB", "MDI1": "AB", "MDI2": "CD", "MDI3": "CD"}


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


def run_gen_pcb_on_routed_board(extra_args=(), routed=True):
    """Run tools/gen_pcb.py against a copy of the committed board, given one
    track segment if `routed`. The guard has to act before pcbnew is imported,
    so this runs under the interpreter of the test suite, which has no pcbnew:
    without the guard the script gets as far as the import and fails there.
    Returns the CompletedProcess plus whether the target file was left as it
    was."""
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "raccoon-tap.kicad_pcb"
        text = PCB.read_text()
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


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
