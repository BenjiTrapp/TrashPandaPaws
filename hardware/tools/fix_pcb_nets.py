#!/usr/bin/env python3
"""
Repair the net encoding in raccoon-hat.kicad_pcb.

The board file was written with net *names* where KiCad's parser requires
integer net IDs, and it carries no net table at all. KiCad refuses to load it.

This script:
  1. collects every net name referenced in the file,
  2. emits a proper `(net <id> "<name>")` table, with net 0 as the unconnected
     net, inserted directly after the `(setup ...)` block,
  3. rewrites each reference into the form its parent element requires:
       pad     -> (net <id> "<name>")
       segment -> (net <id>)
       via     -> (net <id>)
       zone    -> (net <id>) followed by (net_name "<name>")
  4. renumbers R1..R8 to R3..R10 so the board agrees with design-guide.md
     and bom.csv, which both number the resistors R3..R10.

Idempotent: running it on an already-fixed file changes nothing.

Usage:
    python3 fix_pcb_nets.py [--check] [path/to/board.kicad_pcb]
"""

import argparse
import re
import sys
from pathlib import Path

DEFAULT_BOARD = Path(__file__).resolve().parent.parent / "kicad" / "raccoon-hat.kicad_pcb"

# The PCB numbers its resistors R1..R8. design-guide.md and bom.csv both use
# R3..R10 (R3=RCLASS, R4=RDET, R5/R6=SPI pull-ups, R7/R8=LED, R9/R10=FB divider).
# Shift by two so all three sources agree. Applied high-to-low to avoid collisions.
RESISTOR_RENUMBER = [(f"R{n}", f"R{n + 2}") for n in range(8, 0, -1)]

# Elements that may carry a net reference, and the form each one needs.
NET_STYLE_ID_AND_NAME = "pad"      # (net <id> "<name>")
NET_STYLE_ID_ONLY = "id"           # (net <id>)
NET_STYLE_ZONE = "zone"            # (net <id>) + (net_name "<name>")

CONTEXT_STYLES = {
    "pad": NET_STYLE_ID_AND_NAME,
    "segment": NET_STYLE_ID_ONLY,
    "via": NET_STYLE_ID_ONLY,
    "arc": NET_STYLE_ID_ONLY,
    "zone": NET_STYLE_ZONE,
}

NET_NAME_RE = re.compile(r'\(net\s+"((?:[^"\\]|\\.)*)"\s*\)')
NET_ID_RE = re.compile(r'\(net\s+(\d+)')
ELEMENT_RE = re.compile(r'\(\s*(pad|segment|via|arc|zone|footprint)\b')


def collect_net_names(text: str) -> list:
    """Return net names in first-appearance order, GND and power rails first."""
    seen = []
    for match in NET_NAME_RE.finditer(text):
        name = match.group(1)
        if name not in seen:
            seen.append(name)

    # Keep the table stable and readable: ground, then power rails, then the rest.
    def sort_key(name):
        if name == "GND":
            return (0, name)
        if name.startswith("+"):
            return (1, name)
        return (2, name)

    return sorted(seen, key=sort_key)


def build_net_table(names: list, indent: str = "\t") -> str:
    lines = [f'{indent}(net 0 "")']
    for index, name in enumerate(names, start=1):
        lines.append(f'{indent}(net {index} "{name}")')
    return "\n".join(lines)


def find_setup_end(text: str) -> int:
    """Return the offset just past the top-level (setup ...) block."""
    start = text.find("(setup")
    if start == -1:
        raise SystemExit("error: no (setup ...) block found — is this a .kicad_pcb?")
    depth = 0
    for offset in range(start, len(text)):
        char = text[offset]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return offset + 1
    raise SystemExit("error: (setup ...) block is not closed")


def current_context(text: str, position: int) -> str:
    """Identify the innermost pad/segment/via/arc/zone enclosing `position`."""
    context = None
    for match in ELEMENT_RE.finditer(text, 0, position):
        name = match.group(1)
        if name == "footprint":
            continue
        context = name
    return context


def rewrite_net_references(text: str, net_ids: dict) -> tuple:
    """Rewrite every (net "name") into the form its parent element requires."""
    out = []
    cursor = 0
    counts = {"pad": 0, "segment": 0, "via": 0, "arc": 0, "zone": 0, "unknown": 0}

    for match in NET_NAME_RE.finditer(text):
        name = match.group(1)
        net_id = net_ids[name]
        context = current_context(text, match.start())
        style = CONTEXT_STYLES.get(context)

        if style == NET_STYLE_ID_AND_NAME:
            replacement = f'(net {net_id} "{name}")'
        elif style == NET_STYLE_ID_ONLY:
            replacement = f"(net {net_id})"
        elif style == NET_STYLE_ZONE:
            # Zones need both the id and the name, on separate lines.
            line_start = text.rfind("\n", 0, match.start()) + 1
            indent = re.match(r"[\t ]*", text[line_start:match.start()]).group(0)
            replacement = f'(net {net_id})\n{indent}(net_name "{name}")'
        else:
            counts["unknown"] += 1
            replacement = f'(net {net_id} "{name}")'

        counts[context if context in counts else "unknown"] += 1
        out.append(text[cursor:match.start()])
        out.append(replacement)
        cursor = match.end()

    out.append(text[cursor:])
    return "".join(out), counts


def renumber_resistors(text: str) -> tuple:
    """Shift R1..R8 to R3..R10 so the PCB matches the guide and the BOM."""
    changed = []
    for old, new in RESISTOR_RENUMBER:
        # Only touch whole designators inside quoted strings, e.g. "R4" or "R4"
        pattern = re.compile(r'"' + re.escape(old) + r'"')
        text, hits = pattern.subn(f'"{new}"', text)
        if hits:
            changed.append((old, new, hits))
    return text, changed


def verify(text: str) -> list:
    """Post-conditions that must hold for KiCad to load the file."""
    problems = []

    table = dict(re.findall(r'\(net\s+(\d+)\s+"((?:[^"\\]|\\.)*)"\s*\)', text))
    if "0" not in table:
        problems.append("net 0 (unconnected net) is missing from the net table")

    leftover = NET_NAME_RE.findall(text)
    if leftover:
        problems.append(
            f"{len(leftover)} net reference(s) still use the name-only form, "
            f"e.g. {leftover[0]!r}")

    declared = set(table.keys())
    for match in NET_ID_RE.finditer(text):
        if match.group(1) not in declared:
            problems.append(f"net id {match.group(1)} is referenced but not declared")
            break

    zone_count = len(re.findall(r"\(\s*zone\b", text))
    net_name_count = len(re.findall(r"\(net_name\b", text))
    if zone_count != net_name_count:
        problems.append(
            f"{zone_count} zone(s) but {net_name_count} (net_name ...) field(s)")

    if text.count("(") != text.count(")"):
        problems.append(
            f"unbalanced parentheses: {text.count('(')} open, {text.count(')')} close")

    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("board", nargs="?", default=str(DEFAULT_BOARD))
    parser.add_argument("--check", action="store_true",
                        help="report what would change without writing")
    args = parser.parse_args()

    path = Path(args.board)
    if not path.exists():
        raise SystemExit(f"error: {path} not found")
    original = path.read_text(encoding="utf-8")

    already_has_table = bool(re.search(r'\(net\s+\d+\s+"', original))
    names = collect_net_names(original)

    if already_has_table and not names:
        print(f"{path.name}: already repaired, nothing to do")
        return 0

    if not names:
        raise SystemExit("error: no net references found at all — unexpected file")

    net_ids = {name: index for index, name in enumerate(names, start=1)}

    text, counts = rewrite_net_references(original, net_ids)
    insert_at = find_setup_end(text)
    text = text[:insert_at] + "\n" + build_net_table(names) + text[insert_at:]
    text, renumbered = renumber_resistors(text)

    problems = verify(text)

    print(f"Board:            {path}")
    print(f"Net names found:  {len(names)}")
    print(f"Net table:        net 0 (unconnected) + {len(names)} nets")
    print("References rewritten:")
    for context in ("pad", "segment", "via", "arc", "zone"):
        if counts.get(context):
            print(f"  {context:<10} {counts[context]:>4}  -> {CONTEXT_STYLES[context]}")
    if counts["unknown"]:
        print(f"  {'unknown':<10} {counts['unknown']:>4}  (fell back to id+name)")
    if renumbered:
        print("Resistors renumbered to match design-guide.md and bom.csv:")
        for old, new, hits in reversed(renumbered):
            print(f"  {old} -> {new}  ({hits} reference(s))")

    if problems:
        print("\nVERIFICATION FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nVerification passed:")
    print("  - net 0 present")
    print("  - no name-only net references remain")
    print("  - every referenced net id is declared")
    print("  - every zone has a net_name")
    print("  - parentheses balanced")

    if args.check:
        print("\n--check given, file not written")
        return 0

    path.write_text(text, encoding="utf-8")
    print(f"\nWritten: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
