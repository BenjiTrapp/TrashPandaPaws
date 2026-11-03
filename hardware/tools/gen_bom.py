#!/usr/bin/env python3
"""
Generate bom.csv from netlist.yaml.

The old BOM was maintained by hand and had drifted: wrong values, refs that
existed in no schematic, and parts the schematic did not have. Deriving it from
the netlist removes that whole class of mismatch by construction.

Identical parts are grouped into ranges (C7-C10 style) the way the previous BOM
did, so the diff stays readable.

DNP is explicit. A component with `populate: false` is never grouped with a
part that is fitted, and its row says so in four places that an assembler
cannot all miss: Populate = DNP, Quantity = 0, the "Part Number" cell is EMPTY
(a buyer working down that column cannot order it), and the part to use if it
is ever fitted is named in "Part If Fitted". DNP rows come last. A part PCBWay places (it carries an `assembly:` mapping) has
its Description start with "PLACED BY PCBWAY"; it stays in this file as the
record of the whole board. Parts with
`bom: false` (test pads, cut-open solder jumpers) are not parts and are left
out. Rules in tools/fitting.py.

The assembly BOM for PCBWay's partial assembly (fab/raccoon-tap-assembly-bom.csv)
is generated from the same netlist and never edited by hand: a component is
machine-placed exactly when it carries an `assembly:` mapping (description,
placement, distributor, distributor_pn). Pass --assembly-out to write it; the
file is not written otherwise, so a run into a scratch folder cannot touch the
committed one. tools/export_fab.py writes it together with the gerbers.

Usage:
    python3 gen_bom.py [--out bom.csv] [--assembly-out raccoon-tap-assembly-bom.csv] [netlist.yaml]
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fitting  # noqa: E402

HERE = Path(__file__).resolve().parent
DEFAULT_NETLIST = HERE.parent / "netlist.yaml"
DEFAULT_OUT = HERE.parent / "bom.csv"
DEFAULT_ASSEMBLY_OUT = HERE.parent / "fab" / "raccoon-tap-assembly-bom.csv"

FIELDS = ["Reference", "Quantity", "Populate", "Value", "Tolerance", "Package",
          "Manufacturer", "Part Number", "Part If Fitted", "Description",
          "Source"]

ASSEMBLY_FIELDS = ["Line#", "Quantity Per Part Number", "Reference Designator",
                   "Part Number", "Part Description", "Package", "Type",
                   "Manufacturers Name", "Manufacturers Part Number", "Distributor",
                   "Distributors Part Number"]
ASSEMBLY_KEYS = ("description", "placement", "distributor", "distributor_pn")


def ref_key(ref):
    """Sort R2 before R10."""
    match = re.match(r"([A-Z]+)(\d+)", ref)
    return (match.group(1), int(match.group(2))) if match else (ref, 0)


def collapse(refs):
    """R7,R8,R9 -> 'R7-R9'; non-contiguous stays comma separated."""
    groups = defaultdict(list)
    for ref in refs:
        prefix, number = ref_key(ref)
        groups[prefix].append(number)

    parts = []
    for prefix in sorted(groups):
        numbers = sorted(groups[prefix])
        run_start = previous = numbers[0]
        for number in numbers[1:] + [None]:
            if number == previous + 1:
                previous = number
                continue
            if run_start == previous:
                parts.append(f"{prefix}{run_start}")
            elif previous == run_start + 1:
                parts.append(f"{prefix}{run_start},{prefix}{previous}")
            else:
                parts.append(f"{prefix}{run_start}-{prefix}{previous}")
            run_start = previous = number
    return ",".join(parts)


def first_line(text):
    if not text:
        return ""
    return " ".join(str(text).split())


def build_rows(netlist):
    """BOM rows for `netlist`: fitted rows by reference, then the DNP rows."""
    components = netlist["components"]

    # Group by everything that makes two parts interchangeable. `populate` is
    # part of the key so a DNP part can never be folded into a fitted row.
    groups = defaultdict(list)
    for ref, comp in components.items():
        if not fitting.in_bom(ref, comp):
            continue
        key = (fitting.is_populated(ref, comp),
               str(comp.get("value", "")),
               str(comp.get("tolerance", "")),
               str(comp.get("package", "")),
               str(comp.get("manufacturer", "")),
               str(comp.get("mpn", "")),
               comp.get("assembly") is not None)
        groups[key].append(ref)

    rows = []
    for (populated, value, tolerance, package, manufacturer, mpn, assembled), refs in groups.items():
        refs.sort(key=ref_key)
        sample = components[refs[0]]
        # One description if they agree. If not, list the distinct ones (at
        # most three, then "and N more") so the cell never describes only the
        # first reference of a group.
        distinct = []
        for ref in refs:
            text = first_line(components[ref].get("description"))
            if text not in distinct:
                distinct.append(text)
        description = " | ".join(distinct[:3])
        if len(distinct) > 3:
            description += f" | and {len(distinct) - 3} more"
        if assembled:
            # A hand-solderer working down this file must not try to fit it
            description = "PLACED BY PCBWAY, not hand-soldered (assembly BOM). " + description
        rows.append({
            "Reference": collapse(refs),
            "Quantity": len(refs) if populated else 0,
            "Populate": "yes" if populated else "DNP",
            "Value": value,
            "Tolerance": tolerance,
            "Package": package,
            "Manufacturer": manufacturer,
            "Part Number": mpn if populated else "",
            "Part If Fitted": "" if populated else mpn,
            "Description": description,
            "Source": first_line(sample.get("source"))[:160],
        })

    rows.sort(key=lambda r: (r["Populate"] != "yes",
                             ref_key(r["Reference"].split(",")[0].split("-")[0])))
    return rows


def assembly_refs(netlist):
    """The references that PCBWay places: those with an `assembly:` mapping."""
    return sorted((ref for ref, comp in netlist["components"].items()
                   if comp.get("assembly") is not None), key=ref_key)


def build_assembly_rows(netlist):
    """Rows of the assembly BOM: one per machine-placed component, by reference.
    Every field comes from the netlist; a part that is not to be fitted, or that
    is not a BOM part, is refused rather than sent to the assembler."""
    components = netlist["components"]
    rows = []
    for number, ref in enumerate(assembly_refs(netlist), start=1):
        comp = components[ref]
        assembly = comp["assembly"]
        if not isinstance(assembly, dict):
            raise ValueError(f"{ref}: assembly must be a mapping of {', '.join(ASSEMBLY_KEYS)}")
        missing = [k for k in ASSEMBLY_KEYS if k not in assembly]
        if missing:
            raise ValueError(f"{ref}: assembly lacks {', '.join(missing)}")
        if not fitting.in_bom(ref, comp) or not fitting.is_populated(ref, comp):
            raise ValueError(f"{ref}: marked for machine assembly but not to be fitted")
        for key in ("mpn", "manufacturer", "footprint"):
            if not comp.get(key):
                raise ValueError(f"{ref}: assembled but has no {key}")
        text = " ".join(f"{assembly['description']} {assembly['placement']}".split())
        rows.append({
            "Line#": number,
            "Quantity Per Part Number": 1,
            "Reference Designator": ref,
            "Part Number": comp["mpn"],
            "Part Description": text,
            "Package": str(comp["footprint"]).split(":", 1)[-1],
            "Type": "Surface mount",
            "Manufacturers Name": comp["manufacturer"],
            "Manufacturers Part Number": comp["mpn"],
            "Distributor": first_line(assembly["distributor"]),
            "Distributors Part Number": first_line(assembly["distributor_pn"]),
        })
    return rows


def write_assembly_bom(netlist, path):
    rows = build_assembly_rows(netlist)
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ASSEMBLY_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return rows


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("netlist", nargs="?", default=str(DEFAULT_NETLIST))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--assembly-out", metavar="PATH",
                        help="also write the BOM for PCBWay's partial assembly "
                             f"(committed copy: {DEFAULT_ASSEMBLY_OUT})")
    args = parser.parse_args()

    with open(args.netlist) as handle:
        netlist = yaml.safe_load(handle)

    try:
        rows = build_rows(netlist)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    out = Path(args.out)
    with open(out, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    fitted = sum(r["Quantity"] for r in rows)
    dnp = [r["Reference"] for r in rows if r["Populate"] == "DNP"]
    if args.assembly_out:
        try:
            placed = write_assembly_bom(netlist, args.assembly_out)
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        print(f"Generated {args.assembly_out} ({', '.join(r['Reference Designator'] for r in placed)})")
    print(f"Generated {out}")
    print(f"  line items   {len(rows)}")
    print(f"  to be fitted {fitted}")
    print(f"  DNP          {', '.join(dnp) if dnp else 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
