#!/usr/bin/env python3
"""
Structural checks for the Raccoon Tap KiCad sources.

KiCad's own ERC/DRC is the authority; this only catches the classes of defect
that made the files unusable in the first place, so they cannot creep back in:

  * PCB net encoding, in whichever format the file uses. KiCad 10 (the tap
    board): pads, vias, tracks and zones reference nets by name, there is no
    net table, and every name must exist in netlist.yaml. KiCad 9 (the archived
    hat board): a net table must exist, every reference must use an integer
    id, every id must be declared, zones must carry net_name.
  * PCB connectivity: for every net in netlist.yaml the set of pads carrying
    that net name must be exactly the netlist's endpoints. netlist.yaml is
    the authority; the PCB is what is being checked. This replaces the
    guarantee that used to come from regenerating the PCB from the netlist.
  * PCB fitting flags: a DNP part (populate: false) is marked DNP and left out
    of position files and BOM on its footprint; a bare board feature
    (bom: false) is left out of both; a part that is fitted is neither (U3 and
    Y1 are machine-placed from the position file).
  * Reference designators must agree between schematic, PCB and BOM.
  * Component values must agree between the schematic and the BOM.
  * Balanced parentheses in both KiCad files.

Exit code 0 = all checks pass, 1 = at least one failure. Every check is a
failure; there is no list of accepted gaps. (Report.warn exists and is counted
in the summary, but nothing calls it today.)

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
PCB = HARDWARE / "kicad" / "raccoon-tap.kicad_pcb"      # 4-layer board, KiCad 10
LEGACY_PCB = HARDWARE / "kicad" / "raccoon-hat.kicad_pcb"  # archived 2-layer board, KiCad 9 format; not checked
BOM = HARDWARE / "bom.csv"                               # generated from netlist.yaml
NETLIST = HARDWARE / "netlist.yaml"                      # source of truth

# Power symbols the generator adds; they are not real components.
POWER_PREFIXES = ("#PWR",)


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


def check_pcb_nets(pcb_text, pcb, report, netlist=None):
    """Check net encoding, detecting the file's format from its contents.

    A top-level (net <id> "<name>") table means KiCad 9; no table means KiCad
    10, which needs netlist (the parsed netlist.yaml) to validate names.
    """
    print("PCB net encoding")

    table = {}
    for net in children(pcb, "net"):
        if len(net) > 2:
            table[int(net[1])] = net[2]

    if table:
        check_pcb_nets_table(pcb_text, pcb, table, report)
    else:
        check_pcb_nets_named(pcb_text, pcb, netlist, report)


def net_id(net):
    """Integer id of a (net <id>) reference, None for a name-only one."""
    return int(net[1]) if len(net) > 1 and net[1].isdigit() else None


def check_pcb_nets_table(pcb_text, pcb, table, report):
    """KiCad 9: net table with contiguous integer ids, integer references."""
    report.check(0 in table, "net 0 (unconnected net) declared")
    expected = set(range(max(table) + 1))
    report.check(set(table) == expected, "net ids are contiguous from 0",
                 f"missing: {sorted(expected - set(table))}")

    name_only = re.findall(r'\(net\s+"', pcb_text)
    report.check(not name_only, "no name-only net references remain",
                 f"{len(name_only)} occurrence(s) of the invalid (net \"name\") form")

    dangling = []
    for pad in descendants(pcb, "pad"):
        net = children(pad, "net")
        if net and net_id(net[0]) not in table:
            dangling.append(net[0][1])
    for seg in children(pcb, "segment"):
        net = children(seg, "net")
        if net and net_id(net[0]) not in table:
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
        elif table.get(net_id(net[0])) != net_name[0][1]:
            bad_zones.append(
                f"zone net {net[0][1]} is {table.get(net_id(net[0]))!r} "
                f"but net_name says {net_name[0][1]!r}")
    report.check(not bad_zones, f"all {len(zones)} zone(s) consistent",
                 "; ".join(bad_zones))


def check_pcb_nets_named(pcb_text, pcb, netlist, report):
    """KiCad 10: no net table; every net reference is (net "NAME")."""
    report.check(netlist is not None, "netlist supplied to validate net names",
                 "a table-less (KiCad 10) board can only be checked against "
                 "netlist.yaml")
    known = set((netlist or {}).get("nets", {}))

    integer_refs = re.findall(r'\(net\s+[^"\s)][^)]*\)', pcb_text)
    report.check(not integer_refs, "no integer net references in a table-less board",
                 f"{len(integer_refs)} occurrence(s), e.g. {integer_refs[:3]}")

    unnamed, unknown = [], set()
    referenced = 0
    for kind in ("pad", "via", "segment", "arc"):
        for item in descendants(pcb, kind):
            for net in children(item, "net"):
                referenced += 1
                if len(net) != 2 or not net[1]:
                    unnamed.append(kind)
                elif net[1] not in known:
                    unknown.add(net[1])
    report.check(referenced > 0, "pads carry net references",
                 "no pad, via or track has a (net ...) at all")
    report.check(not unnamed, "every net reference carries a name",
                 f"{len(unnamed)} reference(s) without one, on: "
                 f"{sorted(set(unnamed))}")
    report.check(not unknown, "every referenced net name is in netlist.yaml",
                 f"unknown names: {sorted(unknown)}")

    # A rule area (keepout) has no net by design: it is a region, not copper.
    zones = [z for z in children(pcb, "zone") if not children(z, "keepout")]
    bad_zones = []
    for zone in zones:
        net = children(zone, "net")
        if len(net) != 1 or len(net[0]) != 2 or not net[0][1]:
            bad_zones.append("zone without a net name")
        elif net[0][1] not in known:
            bad_zones.append(f"zone net {net[0][1]!r} not in netlist.yaml")
    report.check(not bad_zones, f"all {len(zones)} zone(s) carry a netlist net name",
                 "; ".join(bad_zones))


def check_pcb_connectivity(pcb, netlist, report):
    """The set of pads carrying each net's name must equal netlist.yaml's.

    This compares pad net assignments, not copper. It catches a pad moved to
    the wrong net, a pad left off its net, a pad on a net the netlist does not
    know, a part missing from or added to the board, and a no_connect pin that
    got wired. It cannot see whether tracks physically join the pads, or a
    track that shorts two nets; KiCad's DRC is the authority for that.
    """
    print("PCB connectivity vs netlist.yaml")

    nets = netlist["nets"]
    expected = {}                 # net -> {(ref, pin)}
    claimed = {}                  # (ref, pin) -> net, to catch double claims
    double = []
    for name, endpoints in nets.items():
        expected[name] = set()
        for endpoint in endpoints or []:
            ref, _, pin = str(endpoint).rpartition(".")
            expected[name].add((ref, pin))
            if (ref, pin) in claimed and claimed[(ref, pin)] != name:
                double.append(f"{ref}.{pin} in {claimed[(ref, pin)]} and {name}")
            claimed[(ref, pin)] = name
    no_connect = {tuple(str(k).rpartition(".")[::2])
                  for k in netlist.get("no_connect", {})}
    report.check(not double, "netlist assigns each pin to one net only",
                 "; ".join(double))

    pcb_refs = []
    actual = {}                   # net -> {(ref, pin)}
    pad_nets = {}                 # (ref, pin) -> {net names on that pad}
    for fp in children(pcb, "footprint"):
        ref = prop(fp, "Reference")
        pcb_refs.append(ref)
        for pad in children(fp, "pad"):
            key = (ref, pad[1])
            net = children(pad, "net")
            if net and len(net[0]) == 2:
                actual.setdefault(net[0][1], set()).add(key)
                pad_nets.setdefault(key, set()).add(net[0][1])
            else:
                pad_nets.setdefault(key, set())

    source = set(netlist["components"])
    dupes = sorted({r for r in pcb_refs if pcb_refs.count(r) > 1})
    report.check(set(pcb_refs) == source and not dupes,
                 f"PCB has exactly the {len(source)} netlist components",
                 f"missing: {sorted(source - set(pcb_refs))} "
                 f"extra: {sorted(set(pcb_refs) - source)} "
                 f"duplicated: {dupes}")

    for name in nets:
        want, got = expected[name], actual.get(name, set())
        fmt = lambda pads: sorted(f"{r}.{p}" for r, p in pads)
        report.check(want == got, f"net {name}: PCB pads match netlist",
                     f"in netlist but not on this net in the PCB: {fmt(want - got)}; "
                     f"on this net in the PCB but not in the netlist: {fmt(got - want)}")

    stray = sorted(set(actual) - set(nets))
    report.check(not stray, "no PCB pad sits on a net the netlist lacks",
                 f"nets: {stray}")

    split = sorted(f"{r}.{p}" for (r, p), n in pad_nets.items() if len(n) > 1)
    report.check(not split, "no pad number carries two different nets",
                 f"pads: {split}")

    wired = sorted(f"{r}.{p}" for r, p in no_connect if pad_nets.get((r, p)))
    report.check(not wired, "no_connect pins have no net in the PCB",
                 f"wired: {wired}")

    accounted = set(claimed) | no_connect
    orphan = sorted(f"{r}.{p}" for (r, p) in pad_nets
                    if p and (r, p) not in accounted)
    report.check(not orphan, "every numbered PCB pad is in the netlist",
                 f"in neither nets nor no_connect: {orphan}")


def check_pcb_fitting(pcb, netlist, report):
    """The footprint flags must say what netlist.yaml says about fitting.

    A CPL exported from the PCB lists every footprint not flagged out of the
    position files. R12 exists so that it is NOT fitted (fitting it reverses
    the pin 20 decision), so its footprint must carry DNP and the exclusion;
    U3 and Y1 are placed by the assembler from the same file, so they must not
    carry it. netlist.yaml is the authority.
    """
    print("PCB fitting flags vs netlist.yaml")

    flags = {}
    for fp in children(pcb, "footprint"):
        found = set()
        for attr in children(fp, "attr"):
            found.update(a for a in attr[1:] if isinstance(a, str))
        flags[prop(fp, "Reference")] = found

    wrong = []
    for ref, comp in netlist["components"].items():
        if ref not in flags:
            continue                     # a missing part is the other check's job
        have = flags[ref]
        dnp = comp.get("populate", True) is False
        feature = comp.get("bom", True) is False
        if dnp:
            need = {"dnp", "exclude_from_pos_files", "exclude_from_bom"}
        elif feature:
            need = {"exclude_from_pos_files", "exclude_from_bom"}
        else:
            need = set()
        missing = need - have
        if missing:
            wrong.append(f"{ref}: lacks {sorted(missing)}")
        if not dnp and not feature:
            extra = have & {"dnp", "exclude_from_bom"}
            if "smd" in have:
                extra |= have & {"exclude_from_pos_files"}
            if extra:
                wrong.append(f"{ref}: is fitted but carries {sorted(extra)}")
    report.check(not wrong, "footprint DNP / position-file flags match the netlist",
                 "; ".join(wrong))


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
    # `bom: false` marks a board feature that is not a part (test pad, cut-open
    # solder jumper): on the schematic and the PCB, deliberately not in the BOM.
    in_bom = {ref for ref, comp in source.items()
              if comp.get("bom", True) is not False}
    report.check(set(bom_refs) == in_bom,
                 f"BOM has all {len(in_bom)} netlist refs that are parts",
                 f"missing: {sorted(in_bom - set(bom_refs))} "
                 f"extra: {sorted(set(bom_refs) - in_bom)}")

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

    for path in (SCH, PCB, BOM, NETLIST):
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

    pcb_text = check_balanced(PCB, report)
    pcb = parse_sexp(pcb_text)
    check_pcb_nets(pcb_text, pcb, report, netlist)
    check_pcb_connectivity(pcb, netlist, report)
    check_pcb_fitting(pcb, netlist, report)

    print()
    if report.failures:
        print(f"FAILED — {len(report.failures)} check(s) failed, "
              f"{len(report.warnings)} warning(s)")
        return 1
    print(f"PASSED — all checks ok, {len(report.warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
