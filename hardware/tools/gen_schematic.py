#!/usr/bin/env python3
"""
Generate kicad/raccoon-tap.kicad_sch from netlist.yaml.

Connectivity style: every pin gets a short wire stub and a net label. That is
netlist-exact and sidesteps having to solve a 2D routing problem to place wires
between arbitrary pin pairs. It is also how dense IC sheets are normally drawn.

Rails additionally get a power symbol so KiCad's ERC sees a driver, and pins
listed under no_connect get a no_connect marker.

All symbols are emitted into the file's own lib_symbols block, so the schematic
is self-contained and does not depend on installed KiCad libraries.

Run tests/check_netlist.py first - this script trusts the netlist.

Usage:
    python3 gen_schematic.py [--out path] [netlist.yaml]
"""

import argparse
import hashlib
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
DEFAULT_NETLIST = HERE.parent / "netlist.yaml"
DEFAULT_OUT = HERE.parent / "kicad" / "raccoon-tap.kicad_sch"
DEFAULT_SYMLIB = HERE.parent / "kicad" / "raccoon.kicad_sym"
LIB = "raccoon"

GRID = 1.27
PIN_LEN = 2.54
PIN_SPACING = 2.54
STUB = 2.54
SHEET_W, SHEET_H = 420.0, 297.0   # A3
MARGIN = 20.0


def uuid_for(*parts):
    """Deterministic UUID so regenerating the file produces a stable diff."""
    digest = hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()
    return (f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-"
            f"{digest[16:20]}-{digest[20:32]}")


def pin_sort_key(number):
    """Pin numbers are not always integers - USB shields use "SH"."""
    text = str(number)
    return (0, int(text), "") if text.isdigit() else (1, 0, text)


def snap(value):
    return round(round(value / GRID) * GRID, 4)


class Symbol:
    """A generated schematic symbol: rectangle with pins on left and right."""

    def __init__(self, ref, comp):
        self.ref = ref
        self.comp = comp
        self.value = str(comp.get("value", ref))
        self.footprint = comp.get("footprint", "")
        pins = comp.get("pins") or {}
        self.pins = {str(n): (p or {}) for n, p in pins.items()}
        self.bare = f"RACCOON_{ref}"
        self.name = f"{LIB}:{self.bare}"
        self._layout()

    def _layout(self):
        """Assign each pin a side and an offset inside the symbol body."""
        numbers = sorted(self.pins, key=pin_sort_key)
        count = len(numbers)
        self.placement = {}

        if count <= 2:
            # Passive: pin 1 left, pin 2 right, drawn horizontally.
            self.half_w = 2.54
            self.half_h = 1.27
            for index, number in enumerate(numbers):
                side = "L" if index == 0 else "R"
                self.placement[number] = (side, 0.0)
            return

        # IC: split down the middle, first half left, second half right.
        per_side = (count + 1) // 2
        self.half_w = 12.7
        self.half_h = snap(((per_side - 1) * PIN_SPACING) / 2 + PIN_SPACING)
        for index, number in enumerate(numbers):
            if index < per_side:
                side, slot = "L", index
            else:
                side, slot = "R", index - per_side
            top = (per_side - 1) * PIN_SPACING / 2
            self.placement[number] = (side, snap(top - slot * PIN_SPACING))

    def pin_offset(self, number):
        """Pin connection point relative to the symbol origin, library coords."""
        side, y = self.placement[number]
        x = -(self.half_w + PIN_LEN) if side == "L" else (self.half_w + PIN_LEN)
        return x, y

    def render(self):
        out = [f'\t\t(symbol "{self.name}"',
               '\t\t\t(pin_names (offset 0.508))',
               '\t\t\t(exclude_from_sim no) (in_bom yes) (on_board yes)',
               f'\t\t\t(property "Reference" "{self.ref}" (at 0 {self.half_h + 2.54} 0)',
               '\t\t\t\t(effects (font (size 1.27 1.27))))',
               f'\t\t\t(property "Value" "{self.value}" (at 0 {-self.half_h - 2.54} 0)',
               '\t\t\t\t(effects (font (size 1.27 1.27))))',
               f'\t\t\t(property "Footprint" "{self.footprint}" (at 0 0 0)',
               '\t\t\t\t(effects (font (size 1.27 1.27)) hide))',
               f'\t\t\t(symbol "{self.bare}_0_1"',
               f'\t\t\t\t(rectangle (start {-self.half_w} {-self.half_h}) '
               f'(end {self.half_w} {self.half_h})',
               '\t\t\t\t\t(stroke (width 0.254) (type default)) '
               '(fill (type background)))',
               '\t\t\t)',
               f'\t\t\t(symbol "{self.bare}_1_1"']
        for number in sorted(self.pins, key=pin_sort_key):
            info = self.pins[number]
            name = str(info.get("name", number))
            etype = info.get("type", "passive")
            side, y = self.placement[number]
            if side == "L":
                x, angle = -(self.half_w + PIN_LEN), 0
            else:
                x, angle = (self.half_w + PIN_LEN), 180
            out.append(
                f'\t\t\t\t(pin {etype} line (at {x} {y} {angle}) (length {PIN_LEN})'
                f' (name "{name}" (effects (font (size 1.016 1.016))))'
                f' (number "{number}" (effects (font (size 1.016 1.016)))))')
        out += ['\t\t\t)', '\t\t)']
        return out


POWER_SYMBOL = """\t\t(symbol "{lib}:RACCOON_PWR_{safe}"
\t\t\t(power) (pin_numbers hide) (pin_names (offset 0) hide)
\t\t\t(exclude_from_sim no) (in_bom no) (on_board yes)
\t\t\t(property "Reference" "#PWR" (at 0 -2.54 0)
\t\t\t\t(effects (font (size 1.27 1.27)) hide))
\t\t\t(property "Value" "{net}" (at 0 3.556 0)
\t\t\t\t(effects (font (size 1.27 1.27))))
\t\t\t(symbol "RACCOON_PWR_{safe}_0_1"
\t\t\t\t(polyline (pts (xy -0.762 1.27) (xy 0 2.032) (xy 0.762 1.27))
\t\t\t\t\t(stroke (width 0.254) (type default)) (fill (type none)))
\t\t\t)
\t\t\t(symbol "RACCOON_PWR_{safe}_1_1"
\t\t\t\t(pin power_out line (at 0 0 90) (length 1.27)
\t\t\t\t\t(name "{net}" (effects (font (size 1.27 1.27))))
\t\t\t\t\t(number "1" (effects (font (size 1.27 1.27)))))
\t\t\t)
\t\t)"""


def safe_name(net):
    return "".join(c if c.isalnum() else "_" for c in net)


def place(symbols, order):
    """Lay symbols out in columns, tallest first, inside the sheet margins."""
    positions = {}
    x = MARGIN + 30.0
    y = MARGIN + 20.0
    column_width = 0.0
    for ref in order:
        sym = symbols[ref]
        height = sym.half_h * 2 + 12.0
        if y + height > SHEET_H - MARGIN:
            x += column_width + 46.0
            y = MARGIN + 20.0
            column_width = 0.0
        positions[ref] = (snap(x), snap(y + sym.half_h))
        y += height
        column_width = max(column_width, sym.half_w * 2 + 24.0)
    return positions


def build(netlist, out_path):
    components = netlist["components"]
    nets = netlist["nets"]
    no_connect = netlist.get("no_connect") or {}
    rails = list(netlist.get("rails") or {})
    meta = netlist.get("meta") or {}

    symbols = {ref: Symbol(ref, comp) for ref, comp in components.items()}

    # Which net is each pin on?
    pin_net = {}
    for net, endpoints in nets.items():
        for endpoint in endpoints or []:
            pin_net[endpoint] = net

    # A rail only needs a power symbol if nothing on it is already a power
    # output. Adding one to a rail that a regulator or connector already drives
    # makes ERC report "power output connected to power output".
    def pin_type_of(endpoint):
        ref, _, number = endpoint.rpartition(".")
        pins = (components.get(ref) or {}).get("pins") or {}
        pin = pins.get(number)
        if pin is None and str(number).isdigit():
            pin = pins.get(int(number))
        return (pin or {}).get("type", "passive")

    undriven_rails = []
    for rail in rails:
        endpoints = nets.get(rail) or []
        if not any(pin_type_of(e) == "power_out" for e in endpoints):
            undriven_rails.append(rail)
    rails = undriven_rails

    # ICs first so they get the leftmost columns, then passives.
    order = sorted(components, key=lambda r: (len(components[r].get("pins") or {}) <= 2,
                                              r))
    positions = place(symbols, order)

    lines = ['(kicad_sch',
             '\t(version 20231120)',
             '\t(generator "raccoon-gen_schematic")',
             '\t(generator_version "8.0")',
             f'\t(uuid "{uuid_for("sheet", meta.get("revision"))}")',
             '\t(paper "A3")',
             '\t(title_block',
             f'\t\t(title "{meta.get("board", "Raccoon Tap")} — '
             f'USB 3.0 Gigabit Ethernet Tap")',
             f'\t\t(date "{meta.get("date", "")}")',
             f'\t\t(rev "{meta.get("revision", "")}")',
             '\t\t(company "TrashPandaPaws")',
             '\t\t(comment 1 "GENERATED from netlist.yaml by tools/gen_schematic.py '
             '— edit the netlist, not this file")',
             '\t\t(comment 2 "Power: Raspberry Pi PoE+ HAT. This board draws '
             '~1.5W from USB VBUS.")',
             '\t\t(comment 3 "NOT verified by KiCad ERC. Unrouted. '
             'See OPEN_QUESTIONS.md")',
             '\t\t(comment 4 "Authorized penetration testing use only")',
             '\t)',
             '\t(lib_symbols']

    for ref in order:
        lines += symbols[ref].render()
    for rail in rails:
        lines.append(POWER_SYMBOL.format(safe=safe_name(rail), net=rail, lib=LIB))
    lines.append('\t)')

    wires, labels, markers, instances = [], [], [], []

    for ref in order:
        sym = symbols[ref]
        ox, oy = positions[ref]
        instances += [
            f'\t(symbol (lib_id "{LIB}:RACCOON_{ref}") (at {ox} {oy} 0) (unit 1)',
            '\t\t(exclude_from_sim no) (in_bom yes) (on_board yes) (dnp no)',
            f'\t\t(uuid "{uuid_for("inst", ref)}")',
            f'\t\t(property "Reference" "{ref}" (at {ox} {oy - sym.half_h - 2.54} 0)',
            '\t\t\t(effects (font (size 1.27 1.27))))',
            f'\t\t(property "Value" "{sym.value}" '
            f'(at {ox} {oy + sym.half_h + 2.54} 0)',
            '\t\t\t(effects (font (size 1.27 1.27))))',
            f'\t\t(property "Footprint" "{sym.footprint}" (at {ox} {oy} 0)',
            '\t\t\t(effects (font (size 1.27 1.27)) hide))',
            f'\t\t(instances (project "raccoon-tap" '
            f'(path "/{uuid_for("sheet", meta.get("revision"))}" '
            f'(reference "{ref}") (unit 1))))',
            '\t)']

        for number in sorted(sym.pins, key=pin_sort_key):
            px, py = sym.pin_offset(number)
            ax, ay = snap(ox + px), snap(oy - py)
            outward = -STUB if px < 0 else STUB
            bx = snap(ax + outward)
            key = f"{ref}.{number}"

            if key in no_connect:
                markers.append(f'\t(no_connect (at {ax} {ay}) '
                               f'(uuid "{uuid_for("nc", key)}"))')
                continue

            net = pin_net.get(key)
            if net is None:
                continue

            wires += [f'\t(wire (pts (xy {ax} {ay}) (xy {bx} {ay}))',
                      '\t\t(stroke (width 0) (type default))',
                      f'\t\t(uuid "{uuid_for("wire", key)}"))']
            justify = "right" if px < 0 else "left"
            labels += [f'\t(label "{net}" (at {bx} {ay} 0)',
                       f'\t\t(effects (font (size 1.27 1.27)) '
                       f'(justify {justify} bottom))',
                       f'\t\t(uuid "{uuid_for("label", key)}"))']

    # One power symbol per rail, so ERC sees the net as driven.
    px = MARGIN + 10.0
    for rail in rails:
        py = snap(SHEET_H - MARGIN - 8.0)
        instances += [
            f'\t(symbol (lib_id "{LIB}:RACCOON_PWR_{safe_name(rail)}") '
            f'(at {snap(px)} {py} 0) (unit 1)',
            '\t\t(exclude_from_sim no) (in_bom no) (on_board yes) (dnp no)',
            f'\t\t(uuid "{uuid_for("pwr", rail)}")',
            f'\t\t(property "Reference" "#PWR{safe_name(rail)}" '
            f'(at {snap(px)} {py + 2.54} 0)',
            '\t\t\t(effects (font (size 1.27 1.27)) hide))',
            f'\t\t(instances (project "raccoon-tap" '
            f'(path "/{uuid_for("sheet", meta.get("revision"))}" '
            f'(reference "#PWR{safe_name(rail)}") (unit 1))))',
            '\t)']
        wires += [f'\t(wire (pts (xy {snap(px)} {py}) (xy {snap(px)} {snap(py + STUB)}))',
                  '\t\t(stroke (width 0) (type default))',
                  f'\t\t(uuid "{uuid_for("pwrwire", rail)}"))']
        labels += [f'\t(label "{rail}" (at {snap(px)} {snap(py + STUB)} 0)',
                   '\t\t(effects (font (size 1.27 1.27)) (justify left bottom))',
                   f'\t\t(uuid "{uuid_for("pwrlabel", rail)}"))']
        px += 22.0

    lines += wires + labels + markers + instances + [')', '']
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")

    # Also emit a real symbol library, so KiCad can resolve the lib_ids instead
    # of only finding the cached copies inside the schematic.
    lib = ['(kicad_symbol_lib',
           '\t(version 20231120)',
           '\t(generator "raccoon-gen_schematic")',
           '\t(generator_version "8.0")']
    for ref in order:
        for line in symbols[ref].render():
            lib.append(line.replace(f'"{LIB}:', '"', 1) if line.lstrip().startswith(
                f'(symbol "{LIB}:') else line)
    for rail in rails:
        block = POWER_SYMBOL.format(safe=safe_name(rail), net=rail, lib=LIB)
        lib.append(block.replace(f'"{LIB}:', '"', 1))
    lib += [')', '']
    symlib_path = DEFAULT_SYMLIB
    symlib_path.write_text("\n".join(lib), encoding="utf-8")

    return {"symbols": len(order), "rails": len(rails), "symlib": symlib_path.name,
            "wires": len(wires) // 3, "labels": len(labels) // 3,
            "no_connect": len(markers)}


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("netlist", nargs="?", default=str(DEFAULT_NETLIST))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    with open(args.netlist) as handle:
        netlist = yaml.safe_load(handle)

    stats = build(netlist, Path(args.out))
    print(f"Generated {args.out}")
    for key, value in stats.items():
        print(f"  {key:<12} {value}")
    print("\nNow verify with the real tool:")
    print("  kicad-cli sch erc --severity-all --exit-code-violations \\")
    print(f"    {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
