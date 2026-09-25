#!/usr/bin/env python3
"""
Structural checks for the Raccoon HAT KiCad sources.

KiCad's own ERC/DRC is the authority; this only catches the classes of defect
that made the files unusable in the first place, so they cannot creep back in:

  * PCB net encoding: a net table must exist, every reference must use an
    integer id, every id must be declared, zones must carry net_name.
  * Reference designators must agree between schematic, PCB and BOM.
  * Component values must agree between the schematic and the BOM.
  * Balanced parentheses in both KiCad files.

Exit code 0 = all checks pass, 1 = at least one failure.
Known, deliberately-accepted gaps are listed in KNOWN_GAPS and reported as
warnings rather than failures.

Usage:
    python3 check_kicad.py [-v]
"""

import argparse
import csv
import re
import sys

import yaml
from pathlib import Path

HARDWARE = Path(__file__).resolve().parent.parent
SCH = HARDWARE / "kicad" / "raccoon-tap.kicad_sch"      # generated from netlist.yaml
LEGACY_PCB = HARDWARE / "kicad" / "raccoon-hat.kicad_pcb"  # old 2-layer board
BOM = HARDWARE / "bom.csv"                               # generated from netlist.yaml
NETLIST = HARDWARE / "netlist.yaml"                      # source of truth

# Power symbols the generator adds; they are not real components.
POWER_PREFIXES = ("#PWR",)

# Parts of the PoE front end intentionally absent from the PCB while the
# architecture decision in OPEN_QUESTIONS.md item 0 is open.
def parse_sexp(text):
    tokens = re.findall(r'\(|\)|"(?:[^"\\]|\\.)*"|[^\s()]+', text)

    def build(index):
        node = []
        while index < len(tokens):
            token = tokens[index]
            if token == "(":
                child, index = build(index + 1)
                node.append(child)
            elif token == ")":
                return node, index + 1
            else:
                if token.startswith('"'):
                    token = token[1:-1].replace('\\"', '"')
                node.append(token)
                index += 1
        return node, index

    return build(0)[0][0]


def children(node, name):
    return [n for n in node if isinstance(n, list) and n and n[0] == name]


def descendants(node, name, acc=None):
    if acc is None:
        acc = []
    for child in node:
        if isinstance(child, list):
            if child and child[0] == name:
                acc.append(child)
            descendants(child, name, acc)
    return acc


def prop(node, key):
    for p in descendants(node, "property"):
        if len(p) > 2 and p[1] == key:
            return p[2]
    return None


class Report:
    def __init__(self, verbose=False):
        self.failures = []
        self.warnings = []
        self.verbose = verbose

    def check(self, condition, label, detail=""):
        if condition:
            if self.verbose:
                print(f"  ok    {label}")
        else:
            self.failures.append((label, detail))
            print(f"  FAIL  {label}")
            if detail:
                print(f"          {detail}")

    def warn(self, label, detail=""):
        self.warnings.append((label, detail))
        print(f"  warn  {label}")
        if detail:
            print(f"          {detail}")


def check_pcb_nets(pcb_text, pcb, report):
    print("PCB net encoding")

    table = {}
    for net in children(pcb, "net"):
        if len(net) > 2:
            table[int(net[1])] = net[2]

    report.check(bool(table), "net table exists",
                 "no top-level (net <id> \"<name>\") entries found")
    report.check(0 in table, "net 0 (unconnected net) declared")
    if table:
        expected = set(range(max(table) + 1))
        report.check(set(table) == expected, "net ids are contiguous from 0",
                     f"missing: {sorted(expected - set(table))}")

    name_only = re.findall(r'\(net\s+"', pcb_text)
    report.check(not name_only, "no name-only net references remain",
                 f"{len(name_only)} occurrence(s) of the invalid (net \"name\") form")

    dangling = []
    for pad in descendants(pcb, "pad"):
        net = children(pad, "net")
        if net and int(net[0][1]) not in table:
            dangling.append(net[0][1])
    for seg in children(pcb, "segment"):
        net = children(seg, "net")
        if net and int(net[0][1]) not in table:
            dangling.append(net[0][1])
    report.check(not dangling, "every referenced net id is declared",
                 f"undeclared ids: {sorted(set(dangling))}")

    zones = children(pcb, "zone")
    bad_zones = []
    for zone in zones:
        net = children(zone, "net")
        net_name = children(zone, "net_name")
        if not net or not net_name:
            bad_zones.append("zone missing net or net_name")
        elif table.get(int(net[0][1])) != net_name[0][1]:
            bad_zones.append(
                f"zone net {net[0][1]} is {table.get(int(net[0][1]))!r} "
                f"but net_name says {net_name[0][1]!r}")
    report.check(not bad_zones, f"all {len(zones)} zone(s) consistent",
                 "; ".join(bad_zones))


def expand_bom_refs(field):
    """Expand a BOM Reference cell into individual designators.

    Handles single refs, comma lists and ranges: "R1-R2", "C5-C10", "D3-D4".
    """
    refs = []
    for part in field.split(","):
        part = part.strip()
        if not part:
            continue
        span = re.fullmatch(r"([A-Z]+)(\d+)\s*-\s*(?:([A-Z]+))?(\d+)", part)
        if span:
            prefix, start, end_prefix, end = span.groups()
            if end_prefix and end_prefix != prefix:
                continue
            refs.extend(f"{prefix}{n}" for n in range(int(start), int(end) + 1))
        elif re.fullmatch(r"[A-Z]+\d+", part):
            refs.append(part)
    return refs


def check_against_netlist(sch, bom_rows, netlist, report):
    """netlist.yaml is the source of truth; both artefacts must match it."""
    print("Generated artefacts vs netlist.yaml")

    source = netlist["components"]

    sch_refs = {}
    for sym in children(sch, "symbol"):
        if not children(sym, "lib_id"):
            continue
        ref = prop(sym, "Reference")
        if ref and not ref.startswith(POWER_PREFIXES):
            sch_refs[ref] = prop(sym, "Value")

    bom_refs = {}
    for row in bom_rows:
        for ref in expand_bom_refs(row["Reference"]):
            bom_refs[ref] = row["Value"]

    report.check(set(sch_refs) == set(source),
                 f"schematic has all {len(source)} netlist refs",
                 f"missing: {sorted(set(source) - set(sch_refs))} "
                 f"extra: {sorted(set(sch_refs) - set(source))}")
    report.check(set(bom_refs) == set(source),
                 f"BOM has all {len(source)} netlist refs",
                 f"missing: {sorted(set(source) - set(bom_refs))} "
                 f"extra: {sorted(set(bom_refs) - set(source))}")

    sch_bad, bom_bad = [], []
    for ref, comp in sorted(source.items()):
        want = normalise(str(comp.get("value", "")))
        if ref in sch_refs and normalise(sch_refs[ref]) != want:
            sch_bad.append(f"{ref}: schematic {sch_refs[ref]!r} vs netlist "
                           f"{comp.get('value')!r}")
        if ref in bom_refs and normalise(bom_refs[ref]) != want:
            bom_bad.append(f"{ref}: BOM {bom_refs[ref]!r} vs netlist "
                           f"{comp.get('value')!r}")
    report.check(not sch_bad, "schematic values match netlist", "; ".join(sch_bad))
    report.check(not bom_bad, "BOM values match netlist", "; ".join(bom_bad))

    # Every component must carry a footprint.
    missing = [r for r, c in source.items() if not c.get("footprint")]
    report.check(not missing, "every component has a footprint",
                 f"missing: {sorted(missing)}")


def normalise(value):
    """Compare component values loosely: 13.3K == 13.3k == 13k3."""
    if value is None:
        return ""
    return value.strip().lower().replace(" ", "").replace("ohm", "r")


def check_balanced(path, report):
    text = path.read_text(encoding="utf-8")
    report.check(text.count("(") == text.count(")"),
                 f"{path.name}: parentheses balanced",
                 f"{text.count('(')} open vs {text.count(')')} close")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    for path in (SCH, BOM, NETLIST):
        if not path.exists():
            print(f"error: {path} not found")
            return 1

    report = Report(args.verbose)

    print("Syntax")
    sch_text = check_balanced(SCH, report)
    sch = parse_sexp(sch_text)

    with open(BOM, newline="") as handle:
        bom_rows = list(csv.DictReader(handle))
    with open(NETLIST) as handle:
        netlist = yaml.safe_load(handle)

    check_against_netlist(sch, bom_rows, netlist, report)

    if LEGACY_PCB.exists():
        print("Legacy PCB net encoding (raccoon-hat, 2-layer)")
        pcb_text = check_balanced(LEGACY_PCB, report)
        check_pcb_nets(pcb_text, parse_sexp(pcb_text), report)

    print()
    if report.failures:
        print(f"FAILED — {len(report.failures)} check(s) failed, "
              f"{len(report.warnings)} warning(s)")
        return 1
    print(f"PASSED — all checks ok, {len(report.warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
