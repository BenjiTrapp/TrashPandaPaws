#!/usr/bin/env python3
"""
Generate bom.csv from netlist.yaml.

The old BOM was maintained by hand and had drifted: wrong values, refs that
existed in no schematic, and parts the schematic did not have. Deriving it from
the netlist removes that whole class of mismatch by construction.

Identical parts are grouped into ranges (C7-C10 style) the way the previous BOM
did, so the diff stays readable.

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

HERE = Path(__file__).resolve().parent
DEFAULT_NETLIST = HERE.parent / "netlist.yaml"
DEFAULT_OUT = HERE.parent / "bom.csv"

FIELDS = ["Reference", "Quantity", "Value", "Tolerance", "Package",
          "Part Number", "Description", "Source"]


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


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("netlist", nargs="?", default=str(DEFAULT_NETLIST))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    with open(args.netlist) as handle:
        netlist = yaml.safe_load(handle)

    components = netlist["components"]

    # Group by everything that makes two parts interchangeable.
    groups = defaultdict(list)
    for ref, comp in components.items():
        key = (str(comp.get("value", "")),
               str(comp.get("tolerance", "")),
               str(comp.get("package", "")),
               str(comp.get("mpn", "")))
        groups[key].append(ref)

    rows = []
    for (value, tolerance, package, mpn), refs in groups.items():
        refs.sort(key=ref_key)
        sample = components[refs[0]]
        # Prefer a shared description; if they differ, say so generically.
        descriptions = {first_line(components[r].get("description")) for r in refs}
        description = (descriptions.pop() if len(descriptions) == 1
                       else first_line(sample.get("description")))
        rows.append({
            "Reference": collapse(refs),
            "Quantity": len(refs),
            "Value": value,
            "Tolerance": tolerance,
            "Package": package,
            "Part Number": mpn,
            "Description": description,
            "Source": first_line(sample.get("source"))[:160],
        })

    rows.sort(key=lambda r: ref_key(r["Reference"].split(",")[0].split("-")[0]))

    out = Path(args.out)
    with open(out, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {out}")
    print(f"  line items   {len(rows)}")
    print(f"  components   {sum(r['Quantity'] for r in rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
