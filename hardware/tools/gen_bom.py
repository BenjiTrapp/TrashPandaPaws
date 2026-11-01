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
is ever fitted is named in "Part If Fitted". DNP rows come last. Parts with
`bom: false` (test pads, cut-open solder jumpers) are not parts and are left
out. Rules in tools/fitting.py.

Usage:
    python3 gen_bom.py [--out bom.csv] [netlist.yaml]
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

FIELDS = ["Reference", "Quantity", "Populate", "Value", "Tolerance", "Package",
          "Manufacturer", "Part Number", "Part If Fitted", "Description",
          "Source"]


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
               str(comp.get("mpn", "")))
        groups[key].append(ref)

    rows = []
    for (populated, value, tolerance, package, manufacturer, mpn), refs in groups.items():
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


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("netlist", nargs="?", default=str(DEFAULT_NETLIST))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
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
    print(f"Generated {out}")
    print(f"  line items   {len(rows)}")
    print(f"  to be fitted {fitted}")
    print(f"  DNP          {', '.join(dnp) if dnp else 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
