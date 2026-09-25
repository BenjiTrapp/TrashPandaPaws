#!/usr/bin/env python3
"""
Generate kicad/raccoon-tap.kicad_pcb from netlist.yaml using KiCad's own
pcbnew API, so the file is written by KiCad rather than hand-assembled.

What this does:
  * 4-layer stackup, F.Cu / In1.Cu (GND) / In2.Cu (power) / B.Cu
  * loads each footprint from its real library and places it
  * creates every net from the netlist and assigns it to the right pads
  * board outline
  * GND and power zones on the inner layers
  * thermal via array under U3's exposed pad
  * GND stitching vias around the board

What this deliberately does NOT do: route anything. The seven differential
pairs need KiCad's interactive differential-pair router with a human deciding
geometry and length matching. An autorouted result would be an unverifiable
artefact - see OPEN_QUESTIONS.md.

MUST be run with KiCad's bundled Python, which has the pcbnew bindings:

    /Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/\
Versions/3.9/bin/python3 tools/gen_pcb.py
"""

import argparse
import sys
from pathlib import Path

try:
    import pcbnew
except ImportError:
    sys.exit("error: pcbnew not importable - run this with KiCad's bundled Python")

HERE = Path(__file__).resolve().parent
HARDWARE = HERE.parent
DEFAULT_NETLIST = HARDWARE / "netlist.yaml"
DEFAULT_OUT = HARDWARE / "kicad" / "raccoon-tap.kicad_pcb"

KICAD_FP = Path("/Applications/KiCad/KiCad.app/Contents/SharedSupport/footprints")
PROJECT_FP = HARDWARE / "kicad" / "raccoon.pretty"

# Board outline. Without the GPIO header this no longer has to be a HAT, so it
# is sized to what the parts actually need rather than 65x56.
BOARD_W, BOARD_H = 58.0, 36.0
ORIGIN_X, ORIGIN_Y = 100.0, 80.0

# Placement follows the signal flow: USB plug on the left edge, PHY in the
# middle, MagJack on the right edge, power along the bottom.
# (x, y) in mm relative to the board's top-left corner, plus rotation.
PLACEMENT = {
    # Signal flow left to right: USB plug, PHY, MagJack.
    # J3 rotated 180 so the shell overhangs the LEFT edge while the pads stay
    # on the board. Footprint pads sit at local x=-10.85 and the courtyard runs
    # to +9.95, i.e. the shell extends away from the pads. After rotation the
    # pads land at origin+10.85, so the origin sits off-board.
    "J3":  (-5.85, 18.0, 180),
    "U3":  (27.0, 15.0, 0),     # RTL8153B
    "J2":  (48.0, 16.0, 180),   # gigabit MagJack, right edge
    # Crystal block, kept close to U3 but clear of it
    "Y1":  (27.0, 25.5, 0),
    "C19": (22.5, 25.5, 0),
    "C20": (31.5, 25.5, 0),
    "R11": (34.5, 25.5, 0),     # RSET
    "C21": (33.0, 28.5, 0),     # MagJack centre-tap bypass
    # 3.3V LDO, bottom left
    "U4":  (10.0, 31.0, 0),
    "C5":  (4.5, 31.0, 0),
    "C6":  (15.0, 31.0, 0),
    # 1.0V buck, top left
    "U6":  (10.0, 5.0, 0),
    "L2":  (16.0, 5.0, 0),
    "C3":  (5.0, 5.0, 0),   # buck CIN
    "C4":  (21.0, 5.0, 0),
    "R5":  (12.5, 9.5, 0),
    "R6":  (17.5, 9.5, 0),
    # USB input filtering
    "C1":  (27.0, 4.0, 0),
    "C2":  (32.0, 4.0, 0),
    # Decoupling ringed around U3, two rows clear of its courtyard
    "C7":  (20.0, 9.0, 0),  "C8":  (24.0, 9.0, 0),
    "C9":  (28.0, 9.0, 0),  "C10": (32.0, 9.0, 0),
    "C11": (36.0, 9.0, 0),
    "C12": (20.0, 21.0, 0), "C13": (24.0, 21.0, 0),
    "C14": (28.0, 21.0, 0), "C15": (32.0, 21.0, 0),
    "C16": (36.0, 21.0, 0), "C17": (36.0, 13.0, 90),
    "C18": (19.0, 15.0, 90),
    # LED series resistors, near the jack
    "R7":  (43.5, 31.0, 0), "R8": (48.5, 31.0, 0),
}



def mm(value):
    return pcbnew.FromMM(value)


def vec(x, y):
    return pcbnew.VECTOR2I(mm(x), mm(y))


def load_footprint(ref, fpid, report):
    """Load a footprint from its library. Accepts lib:name."""
    if ":" not in fpid:
        report.append(f"{ref}: footprint id {fpid!r} has no library prefix")
        return None
    libname, fpname = fpid.split(":", 1)
    for base in (PROJECT_FP.parent, KICAD_FP):
        libpath = base / f"{libname}.pretty"
        if libpath.is_dir():
            try:
                fp = pcbnew.FootprintLoad(str(libpath), fpname)
            except Exception as exc:
                report.append(f"{ref}: loading {fpid} raised {exc}")
                return None
            if fp:
                return fp
    report.append(f"{ref}: footprint {fpid} not found")
    return None


def add_outline(board):
    """Rounded rectangle board outline on Edge.Cuts."""
    corners = [(0, 0), (BOARD_W, 0), (BOARD_W, BOARD_H), (0, BOARD_H)]
    for index in range(4):
        x1, y1 = corners[index]
        x2, y2 = corners[(index + 1) % 4]
        shape = pcbnew.PCB_SHAPE(board)
        shape.SetShape(pcbnew.SHAPE_T_SEGMENT)
        shape.SetStart(vec(ORIGIN_X + x1, ORIGIN_Y + y1))
        shape.SetEnd(vec(ORIGIN_X + x2, ORIGIN_Y + y2))
        shape.SetLayer(pcbnew.Edge_Cuts)
        shape.SetWidth(mm(0.1))
        board.Add(shape)


def add_zone(board, layer, net, inset=0.3):
    """Full-board copper pour on one layer, tied to one net."""
    zone = pcbnew.ZONE(board)
    zone.SetLayer(layer)
    zone.SetNet(net)
    zone.SetAssignedPriority(0)
    outline = zone.Outline()
    outline.NewOutline()
    for x, y in ((inset, inset), (BOARD_W - inset, inset),
                 (BOARD_W - inset, BOARD_H - inset), (inset, BOARD_H - inset)):
        outline.Append(mm(ORIGIN_X + x), mm(ORIGIN_Y + y))
    zone.SetLocalClearance(mm(0.3))
    zone.SetMinThickness(mm(0.2))
    board.Add(zone)
    return zone


def add_via(board, x, y, net, diameter=0.6, drill=0.3):
    via = pcbnew.PCB_VIA(board)
    via.SetPosition(vec(ORIGIN_X + x, ORIGIN_Y + y))
    via.SetWidth(mm(diameter))
    via.SetDrill(mm(drill))
    via.SetViaType(pcbnew.VIATYPE_THROUGH)
    via.SetLayerPair(pcbnew.F_Cu, pcbnew.B_Cu)
    via.SetNet(net)
    board.Add(via)


def build(netlist, out_path):
    components = netlist["components"]
    nets = netlist["nets"]
    report = []

    board = pcbnew.NewBoard(str(out_path))
    board.SetCopperLayerCount(4)
    board.SetLayerName(pcbnew.In1_Cu, "GND")
    board.SetLayerName(pcbnew.In2_Cu, "Power")

    settings = board.GetDesignSettings()
    settings.SetBoardThickness(mm(1.6))

    # Create every net up front.
    net_objects = {}
    for name in nets:
        item = pcbnew.NETINFO_ITEM(board, name)
        board.Add(item)
        net_objects[name] = item

    # Which net does each pad belong to?
    pad_net = {}
    for name, endpoints in nets.items():
        for endpoint in endpoints or []:
            ref, _, pin = endpoint.rpartition(".")
            pad_net[(ref, pin)] = name

    placed = 0
    unplaced = []
    for ref, comp in components.items():
        fp = load_footprint(ref, comp.get("footprint", ""), report)
        if fp is None:
            continue
        fp.SetReference(ref)
        fp.SetValue(str(comp.get("value", "")))

        # On 0402-class parts the silkscreen reference does not fit between
        # neighbours; keep it on F.Fab only, which is normal for dense boards.
        # The value text is hidden everywhere - the BOM carries it.
        package = str(comp.get("package", ""))
        if package.startswith(("0402", "0603")):
            fp.Reference().SetLayer(pcbnew.F_Fab)
        fp.Value().SetVisible(False)

        if ref in PLACEMENT:
            x, y, rot = PLACEMENT[ref]
            fp.SetPosition(vec(ORIGIN_X + x, ORIGIN_Y + y))
            if rot:
                fp.SetOrientationDegrees(rot)
            placed += 1
        else:
            # Park unplaced parts off-board so they are obvious.
            fp.SetPosition(vec(ORIGIN_X - 25.0, ORIGIN_Y + 5.0 * len(unplaced)))
            unplaced.append(ref)

        board.Add(fp)

        for pad in fp.Pads():
            key = (ref, pad.GetNumber())
            name = pad_net.get(key)
            if name:
                pad.SetNet(net_objects[name])
            elif pad.GetNumber():
                report.append(f"{ref} pad {pad.GetNumber()}: no net "
                              f"(no_connect or unmapped)")

    add_outline(board)

    gnd = net_objects.get("GND")

    # Inner planes: In1 solid GND, In2 carries the power rails. The power pour
    # is left as one zone on +3V3; split it by hand for +5V and +1V0 islands.
    add_zone(board, pcbnew.In1_Cu, gnd)
    add_zone(board, pcbnew.In2_Cu, net_objects.get("+3V3", gnd))
    add_zone(board, pcbnew.B_Cu, gnd)

    # Thermal vias under U3's exposed pad. [RTL-DS] requires the pad to be
    # stitched to a plane; 3.6mm pad, 0.8mm grid gives a 4x4 array.
    u3 = board.FindFootprintByReference("U3")
    if u3:
        cx = pcbnew.ToMM(u3.GetPosition().x) - ORIGIN_X
        cy = pcbnew.ToMM(u3.GetPosition().y) - ORIGIN_Y
        # 3x3 on a 1.1mm grid fits inside the 3.6mm exposed pad while keeping
        # 0.6/0.3 vias, which hold a 0.15mm annular ring - the board minimum.
        for ix in range(3):
            for iy in range(3):
                add_via(board, cx + (ix - 1) * 1.1, cy + (iy - 1) * 1.1,
                        gnd, 0.6, 0.3)
    else:
        report.append("U3 not on the board, no thermal vias placed")

    # GND stitching around the perimeter.
    for i in range(1, int(BOARD_W / 5)):
        add_via(board, i * 5.0, 1.2, gnd)
        add_via(board, i * 5.0, BOARD_H - 1.2, gnd)
    for i in range(1, int(BOARD_H / 5)):
        add_via(board, 1.2, i * 5.0, gnd)
        add_via(board, BOARD_W - 1.2, i * 5.0, gnd)

    # Check courtyards for overlap before saving, so placement mistakes are
    # caught here rather than only by DRC.
    boxes = {}
    for fp in board.GetFootprints():
        box = fp.GetCourtyard(pcbnew.F_CrtYd).BBox()
        if box.GetWidth() == 0:
            box = fp.GetBoundingBox(False, False)
        boxes[fp.GetReference()] = box
    refs = sorted(boxes)
    for i, a in enumerate(refs):
        for b in refs[i + 1:]:
            if boxes[a].Intersects(boxes[b]):
                report.append(f"courtyard overlap: {a} <-> {b}")

    # Warn if any pad sits outside the board outline.
    for fp in board.GetFootprints():
        for pad in fp.Pads():
            px = pcbnew.ToMM(pad.GetPosition().x) - ORIGIN_X
            py = pcbnew.ToMM(pad.GetPosition().y) - ORIGIN_Y
            if not (0 <= px <= BOARD_W and 0 <= py <= BOARD_H):
                report.append(f"{fp.GetReference()} pad {pad.GetNumber()} is "
                              f"outside the outline at ({px:.2f}, {py:.2f})")

    pcbnew.SaveBoard(str(out_path), board)
    return {"placed": placed, "unplaced": unplaced,
            "nets": len(net_objects), "report": report}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("netlist", nargs="?", default=str(DEFAULT_NETLIST))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    sys.path.insert(0, str(HARDWARE))
    import yaml
    with open(args.netlist) as handle:
        netlist = yaml.safe_load(handle)

    stats = build(netlist, Path(args.out))
    print(f"Generated {args.out}")
    print(f"  nets created   {stats['nets']}")
    print(f"  placed         {stats['placed']}")
    if stats["unplaced"]:
        print(f"  UNPLACED       {stats['unplaced']} (parked off-board)")
    for line in stats["report"]:
        print(f"  note: {line}")
    print("\nNot routed. Verify with:")
    print(f"  kicad-cli pcb drc --severity-all {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
