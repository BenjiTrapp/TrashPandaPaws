#!/usr/bin/env python3
"""
Generate kicad/raccoon-tap.kicad_pcb from netlist.yaml using KiCad's own
pcbnew API, so the file is written by KiCad rather than hand-assembled.

What this does:
  * 4-layer stackup, F.Cu / In1.Cu (GND) / In2.Cu (power) / B.Cu
  * loads each footprint from its real library and places it
  * creates every net from the netlist and assigns it to the right pads
  * marks DNP parts DNP and keeps DNP parts and bare board features out of the
    position files (tools/fitting.py reads the same flags as the BOM and the
    schematic do)
  * board outline, two M2.5 mounting holes with a keepout, RJ45 cable-tie slots
  * GND planes on In1 and B.Cu, the power plane on In2 split into islands, and
    a GND copper patch under the 3.3 V regulator
  * thermal via array under U3's exposed pad, tented from the back
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
import math
import sys
from pathlib import Path

try:
    import pcbnew
except ImportError:
    sys.exit("error: pcbnew not importable - run this with KiCad's bundled Python")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fitting  # noqa: E402

HARDWARE = HERE.parent
DEFAULT_NETLIST = HARDWARE / "netlist.yaml"
DEFAULT_OUT = HARDWARE / "kicad" / "raccoon-tap.kicad_pcb"

KICAD_FP = Path("/Applications/KiCad/KiCad.app/Contents/SharedSupport/footprints")
PROJECT_FP = HARDWARE / "kicad" / "raccoon.pretty"

# Board outline. The 12 mm beyond the RJ45 jack's front face is the strain-relief
# tail: the cable boot lies on it and is tied down through the two slots, and
# the two M2.5 holes sit at its corners (spec 5.2 / 11.9). Before task 8 the
# board was 58 mm long and ended at the jack.
BOARD_W, BOARD_H = 70.0, 36.0
ORIGIN_X, ORIGIN_Y = 100.0, 80.0

# Anchors the placement is written against: mm from the board's top-left
# corner, x to the right, y down.
UX, UY = 24.0, 23.0           # U3 centre
JX, JY = 47.55, 18.0          # J2 origin; the jack's front face is at x = 57.9, the courtyard at 58.2

# Placement follows the signal flow: USB plug on the left edge, PHY in the
# middle, MagJack on the right edge, power along the bottom and top left.
# (x, y) in mm relative to the board's top-left corner, plus rotation.
#
# WHY U3 IS AT 180 DEGREES (task 8). At rotation 0 the MDI pins 1-10 are on
# U3's left edge, facing the USB plug, while J2 is 21 mm to the right: the four
# 100 ohm pairs would have had to wrap round the package and cross the
# SuperSpeed fan-out on the bottom edge. At 180 the MDI pins are on the right
# edge, facing J2 across an open corridor; the SuperSpeed and USB 2.0 pins
# (12-19) are on the top edge, the supply pins on the left, the crystal pins
# (35/36) on the bottom edge. The crystal block (Y1, C19, C20, R14) and the
# decoupling ring were moved with it.
#
# WHAT ROTATION DOES NOT FIX: the MDI pairs still arrive at J2 in the opposite
# order. U3's pins 1-10 and J2's pins 1-10 both run counter-clockwise round
# their package, so two parts that face each other present the pairs in
# reversed order (MDI3..0 against MDI0..3), for every rotation of both parts.
# Drawn as straight ratsnest lines the eight signal pins cross 28 times on one
# layer. The corridor between U3 and J2 is therefore kept clear on both signal
# layers; hardware/review/2026-10-31-placement/README.md has the measurement
# and the routing plan.
PLACEMENT = {
    # --- connectors --------------------------------------------------------
    # J3 rotated 180 so the shell overhangs the LEFT edge while the pads stay
    # on the board. Footprint pads sit at local x=-10.85 and the courtyard runs
    # to +9.95, i.e. the shell extends away from the pads. After rotation the
    # pads land at origin+10.85, so the origin sits off-board.
    "J3":  (-5.85, 18.0, 180),
    # J2 turned so the jack's opening faces the right-hand board edge: signal
    # pins on the left (x 38.7 and 41.2), LEDs at the front.
    "J2":  (JX, JY, 90),
    # --- PHY and what belongs to it ---------------------------------------
    "U3":  (UX, UY, 180),        # RTL8153B
    # Crystal block under the bottom edge, where pins 35/36 are. Y1 is the
    # extended-pad 3225 footprint (ruling AC): pads 2.1 x 1.8 mm reaching 0.9 mm
    # past the body, so an iron can reach them for rework.
    "Y1":  (24.0, 31.0, 0),
    "C19": (20.2, 32.1, 180),
    "C20": (28.2, 30.6, 0),
    "R14": (26.9, 28.1, 0),
    "R11": (30.2, 28.2, 0),      # RSET
    # --- USB side ----------------------------------------------------------
    "U9":  (9.6, 18.0, 0),       # USB 2.0 ESD, flow-through: D+ in at pin 1, out at pin 6, D- in at 3, out at 4
    "U8":  (18.6, 17.1, 270),    # SuperSpeed ESD, TX row north, 1.63 mm channel between the rows
    "C22": (24.95, 16.8, 90),    # TX AC coupling, P
    "C23": (26.0, 16.8, 90),     # TX AC coupling, N
    # --- decoupling ring round U3 -----------------------------------------
    # West edge (pins 21-30, supply pins): one column of 0402s, pad 1 towards U3.
    "C8":  (19.3, 20.35, 180),   # 2.2 uF 0603 on pin 20 (AVDD33 LDO output)
    "C17": (19.75, 21.75, 180),  # pin 22
    "C10": (19.75, 22.8, 180),   # pin 23
    "C18": (19.75, 23.85, 180),  # pins 21, 27
    "C11": (19.75, 24.9, 180),   # pins 26, 33
    "C16": (17.6, 21.75, 180),   # pins 14, 19; second column, there is no room beside them
    # North-east corner (pin 11, and the AVDD10 pin 8 on the east edge)
    "C7":  (27.7, 19.2, 90),
    "C13": (28.8, 19.2, 90),
    # South edge (pins 33-40), either side of the crystal channel
    "C15": (22.3, 26.75, 180),   # pin 34
    "C14": (25.65, 26.75, 0),    # pin 37
    "C9":  (27.65, 26.75, 0),    # pins 39, 40
    "C12": (29.6, 26.75, 0),     # AVDD10 pin 3 on the east edge
    # --- J2 side ------------------------------------------------------------
    "C21": (43.5, 17.4, 180),    # centre-tap bypass, on B.Cu under the jack, pad 1 1.3 mm from pin 5
    "C25": (41.8, 28.6, 0),      # shield to GND, by the jack's shield post
    "R13": (46.5, 28.6, 0),
    "R7":  (51.5, 28.0, 0),      # LED series resistors, by the LED pins
    "R8":  (50.0, 8.3, 0),
    # --- mounting ----------------------------------------------------------
    "H1":  (66.5, 3.5, 0),
    "H2":  (66.5, 32.5, 0),
    # --- input protection and load switch ---------------------------------
    "C1":  (8.3, 27.0, 180),
    "C2":  (8.3, 28.6, 180),
    "TP2": (8.3, 31.2, 0),
    "U7":  (12.0, 27.8, 0),
    "C26": (13.6, 31.4, 270),
    # --- 3.3 V LDO, bottom left --------------------------------------------
    "U4":  (17.1, 31.4, 0),
    "C5":  (16.5, 34.2, 0),
    "C6":  (17.4, 28.2, 180),
    "JP1": (10.9, 34.1, 0),
    # --- probe points along the bottom edge --------------------------------
    "TP4": (29.0, 33.8, 0),      # +3V3
    "TP1": (32.0, 33.8, 0),      # GND
    "TP6": (35.0, 33.8, 0),      # AVDD33_LDO (U3 pin 20)
    "TP7": (38.0, 33.8, 0),      # DVDD10_UPS (U3 pin 22)
    "TP3": (41.0, 33.8, 0),      # +5V_SW
    # --- 1.0 V buck, top middle, above U3 ---------------------------------
    # LX (U6 pin 1) leaves west into L2 and the output capacitor. The input
    # capacitor C3 sits 2.7 mm under the IN pin. R5/R6 are 4-5 mm south of LX
    # and L2, and the FB trace runs away from the switch node.
    "U6":  (30.0, 6.0, 0),
    "L2":  (25.2, 4.9, 180),
    "C4":  (20.4, 4.9, 180),
    "JP2": (20.5, 8.2, 0),
    "C3":  (31.4, 9.6, 180),
    "C24": (25.9, 7.5, 0),       # DNP feed-forward across R5
    "R5":  (25.9, 9.4, 0),
    "R6":  (28.6, 9.6, 90),
    "TP5": (35.5, 4.5, 0),       # +1V0
    # --- assembly fiducials (three, for PCBWay's pick-and-place) ------------
    "FID1": (2.5, 2.5, 0),
    "FID2": (2.5, 33.5, 0),
    "FID3": (68.0, 18.0, 0),
    # --- U3 pin 20 contingency ---------------------------------------------
    "R12": (15.6, 23.6, 90),     # DNP link U3.20 <-> +3V3
}

# Parts that sit on the bottom copper layer. C21 goes there because the jack's
# centre-tap pins (5 and 6) sit in the middle of the pin field, between the
# MDI pairs; the pins are through-hole, so a capacitor under the board reaches
# them without crossing a pair.
BOTTOM = {"C21"}

# M2.5 holes (spec 5.2): copper-free ring for the screw head and washer, round
# the plated pad of the hole. Tracks, vias and parts stay out; the GND pour may
# come in.
HOLE_KEEPOUT_R = (3.02, 3.9)

# RJ45 cable-tie slots, centres in mm. A tie goes down one slot, under the
# board and up the other, round the cable boot lying on the tail between them.
TIE_SLOTS = [(64.4, 13.5), (64.4, 22.5)]
TIE_SLOT_L, TIE_SLOT_W = 3.4, 1.6

# Copper patch on F.Cu under the 3.3 V regulator: GND, joined to U4 pin 2
# (the lead frame's main thermal path) without thermal relief.
U4_PATCH = [(13.0, 29.6), (21.2, 29.6), (21.2, 35.3), (13.0, 35.3)]
U4_PATCH_VIA_COUNT = 6

# In2 islands. +3V3 carries the corridor between U3 and J2 so that anything
# that has to hop to the bottom layer there still has a plane to look at.
ISLANDS = [
    ("+5V", [(6.4, 17.0), (11.8, 17.0), (11.8, 34.6), (6.4, 34.6)]),
    ("+5V_SW", [(12.4, 1.0), (18.8, 1.0), (18.8, 34.6), (12.4, 34.6)]),
    ("+5V_SW", [(29.6, 1.0), (36.4, 1.0), (36.4, 12.4), (29.6, 12.4)]),
    ("+1V0", [(19.4, 1.0), (29.0, 1.0), (29.0, 21.4), (19.4, 21.4)]),
    ("+3V3", [(19.4, 21.8), (29.4, 21.8), (29.4, 12.8), (58.0, 12.8),
              (58.0, 34.6), (19.4, 34.6)]),
    ("+3V3", [(44.0, 1.0), (58.0, 1.0), (58.0, 12.4), (44.0, 12.4)]),
]


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
    """Board outline on Edge.Cuts, plus the cable-tie slots."""
    corners = [(0, 0), (BOARD_W, 0), (BOARD_W, BOARD_H), (0, BOARD_H)]
    for index in range(4):
        x1, y1 = corners[index]
        x2, y2 = corners[(index + 1) % 4]
        add_edge_line(board, x1, y1, x2, y2)
    half = TIE_SLOT_W / 2
    reach = TIE_SLOT_L / 2 - half
    for cx, cy in TIE_SLOTS:
        add_edge_line(board, cx - reach, cy - half, cx + reach, cy - half)
        add_edge_line(board, cx - reach, cy + half, cx + reach, cy + half)
        add_edge_arc(board, (cx + reach, cy - half), (cx + reach + half, cy),
                     (cx + reach, cy + half))
        add_edge_arc(board, (cx - reach, cy + half), (cx - reach - half, cy),
                     (cx - reach, cy - half))


def add_edge_line(board, x1, y1, x2, y2):
    shape = pcbnew.PCB_SHAPE(board)
    shape.SetShape(pcbnew.SHAPE_T_SEGMENT)
    shape.SetStart(vec(ORIGIN_X + x1, ORIGIN_Y + y1))
    shape.SetEnd(vec(ORIGIN_X + x2, ORIGIN_Y + y2))
    shape.SetLayer(pcbnew.Edge_Cuts)
    shape.SetWidth(mm(0.1))
    board.Add(shape)


def add_edge_arc(board, start, mid, end):
    shape = pcbnew.PCB_SHAPE(board)
    shape.SetShape(pcbnew.SHAPE_T_ARC)
    shape.SetArcGeometry(vec(ORIGIN_X + start[0], ORIGIN_Y + start[1]),
                         vec(ORIGIN_X + mid[0], ORIGIN_Y + mid[1]),
                         vec(ORIGIN_X + end[0], ORIGIN_Y + end[1]))
    shape.SetLayer(pcbnew.Edge_Cuts)
    shape.SetWidth(mm(0.1))
    board.Add(shape)


def add_zone(board, layer, net, points=None, inset=0.3, direct_pads=False):
    """Copper pour on one layer, tied to one net. Without `points` it covers
    the whole board inside `inset`."""
    zone = pcbnew.ZONE(board)
    zone.SetLayer(layer)
    zone.SetNet(net)
    zone.SetAssignedPriority(0)
    if points is None:
        points = ((inset, inset), (BOARD_W - inset, inset),
                  (BOARD_W - inset, BOARD_H - inset), (inset, BOARD_H - inset))
    outline = zone.Outline()
    outline.NewOutline()
    for x, y in points:
        outline.Append(mm(ORIGIN_X + x), mm(ORIGIN_Y + y))
    zone.SetLocalClearance(mm(0.3))
    zone.SetMinThickness(mm(0.2))
    if direct_pads:
        zone.SetPadConnection(pcbnew.ZONE_CONNECTION_FULL)
    board.Add(zone)
    return zone


def add_hole_keepout(board, cx, cy):
    """Ring-shaped rule area round a mounting hole: no tracks, vias or parts.
    Drawn as four 90-degree sectors rather than one ring, so that no single
    rule area's bounding box takes in the hole's own centre (kicad-happy's
    KO-001 checks bounding boxes; KiCad's own DRC does not care)."""
    r_in, r_out = HOLE_KEEPOUT_R
    steps = 8
    for quarter in range(4):
        zone = pcbnew.ZONE(board)
        zone.SetIsRuleArea(True)
        zone.SetLayerSet(pcbnew.LSET.AllCuMask())
        zone.SetDoNotAllowTracks(True)
        zone.SetDoNotAllowVias(True)
        zone.SetDoNotAllowFootprints(True)
        zone.SetDoNotAllowPads(True)
        zone.SetDoNotAllowZoneFills(False)
        zone.SetZoneName("M2.5 screw head keepout")
        outline = zone.Outline()
        outline.NewOutline()
        start = math.radians(90 * quarter - 45)
        angles = [start + math.radians(90) * i / steps for i in range(steps + 1)]
        for angle in angles:
            outline.Append(mm(ORIGIN_X + cx + r_out * math.cos(angle)),
                           mm(ORIGIN_Y + cy + r_out * math.sin(angle)))
        for angle in reversed(angles):
            outline.Append(mm(ORIGIN_X + cx + r_in * math.cos(angle)),
                           mm(ORIGIN_Y + cy + r_in * math.sin(angle)))
        board.Add(zone)


def add_via(board, x, y, net, diameter=0.6, drill=0.3, tent_back=False):
    via = pcbnew.PCB_VIA(board)
    via.SetPosition(vec(ORIGIN_X + x, ORIGIN_Y + y))
    via.SetWidth(mm(diameter))
    via.SetDrill(mm(drill))
    via.SetViaType(pcbnew.VIATYPE_THROUGH)
    via.SetLayerPair(pcbnew.F_Cu, pcbnew.B_Cu)
    via.SetNet(net)
    if tent_back:
        via.SetBackTentingMode(pcbnew.TENTING_MODE_TENTED)
    board.Add(via)


def pad_gap(board, x, y, own_net):
    """Distance from (x, y) to the nearest pad edge of any net but `own_net`
    (every net if it is None), taking pads as their bounding rectangles."""
    best = 99.0
    for fp in board.GetFootprints():
        for pad in fp.Pads():
            if (own_net is not None and pad.GetNet() is not None
                    and pad.GetNet().GetNetname() == own_net.GetNetname()):
                continue
            box = pad.GetBoundingBox()
            x0 = pcbnew.ToMM(box.GetX()) - ORIGIN_X
            y0 = pcbnew.ToMM(box.GetY()) - ORIGIN_Y
            x1 = x0 + pcbnew.ToMM(box.GetWidth())
            y1 = y0 + pcbnew.ToMM(box.GetHeight())
            dx = max(x0 - x, 0.0, x - x1)
            dy = max(y0 - y, 0.0, y - y1)
            best = min(best, math.hypot(dx, dy))
    return best


def apply_fitting(fp, ref, comp):
    """DNP and position-file exclusion, from the same flags the BOM and the
    schematic read (tools/fitting.py)."""
    if not fitting.is_populated(ref, comp):
        # A DNP part: nothing is placed, nothing is bought, and an exported
        # position file must not list it.
        fp.SetDNP(True)
        fp.SetExcludedFromBOM(True)
        fp.SetExcludedFromPosFiles(True)
    if not fitting.in_bom(ref, comp):
        # A board feature (test pad, solder jumper, mounting hole): not a part.
        fp.SetExcludedFromBOM(True)
        fp.SetExcludedFromPosFiles(True)


def place(fp, x, y, rot):
    fp.SetPosition(vec(ORIGIN_X + x, ORIGIN_Y + y))
    if rot:
        fp.SetOrientationDegrees(rot)


def courtyard_box(fp):
    layer = pcbnew.B_CrtYd if fp.IsFlipped() else pcbnew.F_CrtYd
    box = fp.GetCourtyard(layer).BBox()
    if box.GetWidth() == 0:
        box = fp.GetBoundingBox(False, False)
    return box


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

        # On the small parts (passives, holes, fiducials) the silkscreen
        # reference does not fit between neighbours; keep it on F.Fab only,
        # which is normal for dense boards. ICs, connectors, test points and
        # jumpers keep theirs on the silkscreen. The value text is hidden
        # everywhere - the BOM carries it.
        package = str(comp.get("package", ""))
        if package.startswith(("0402", "0603")) or ref.startswith(("C", "R", "L", "H", "FID")):
            fp.Reference().SetLayer(pcbnew.F_Fab)
        fp.Value().SetVisible(False)

        if ref in PLACEMENT:
            x, y, rot = PLACEMENT[ref]
            place(fp, x, y, rot)
            placed += 1
        else:
            # Park unplaced parts off-board so they are obvious.
            fp.SetPosition(vec(ORIGIN_X - 25.0, ORIGIN_Y + 5.0 * len(unplaced)))
            unplaced.append(ref)

        apply_fitting(fp, ref, comp)
        board.Add(fp)
        if ref in BOTTOM:
            # Flip needs the footprint to be on a board already.
            fp.Flip(fp.GetPosition(), pcbnew.FLIP_DIRECTION_LEFT_RIGHT)

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

    # Inner planes: In1 is solid GND, the reference under every F.Cu pair.
    # In2 carries the rails as islands (ISLANDS); a net with no island has
    # none, so a part on it is wired on the surface layers. B.Cu has a GND pour.
    add_zone(board, pcbnew.In1_Cu, gnd)
    for name, points in ISLANDS:
        add_zone(board, pcbnew.In2_Cu, net_objects[name], points)
    add_zone(board, pcbnew.B_Cu, gnd)

    # GND copper under the 3.3 V regulator (0.36 W at the design current, see
    # netlist.yaml design_notes.rail_currents): a patch on F.Cu joined to pin 2
    # without thermal relief, with vias to In1 and B.Cu, the six nearest to the
    # pin that keep their distance from every other net's pad.
    add_zone(board, pcbnew.F_Cu, gnd, U4_PATCH, direct_pads=True)
    u4 = board.FindFootprintByReference("U4")
    if u4:
        pin2 = [p for p in u4.Pads() if p.GetNumber() == "2"][0]
        hx = pcbnew.ToMM(pin2.GetPosition().x) - ORIGIN_X
        hy = pcbnew.ToMM(pin2.GetPosition().y) - ORIGIN_Y
        xs = [p[0] for p in U4_PATCH]
        ys = [p[1] for p in U4_PATCH]
        candidates = []
        gx = min(xs) + 0.5
        while gx <= max(xs) - 0.5:
            gy = min(ys) + 0.5
            while gy <= max(ys) - 0.5:
                # 0.3 clearance + 0.3 via radius + 0.15 margin from every
                # other net's pad, and never inside or touching a GND pad
                # (a via in a hand-soldered pad draws the solder away).
                if (pad_gap(board, gx, gy, gnd) >= 0.3 + 0.3 + 0.15
                        and pad_gap(board, gx, gy, None) >= 0.3 + 0.15):
                    candidates.append((math.hypot(gx - hx, gy - hy), gx, gy))
                gy += 0.1
            gx += 0.1
        candidates.sort()
        chosen = []
        for _, gx, gy in candidates:
            if all(math.hypot(gx - cx_, gy - cy_) >= 1.0 for cx_, cy_ in chosen):
                chosen.append((gx, gy))
            if len(chosen) == U4_PATCH_VIA_COUNT:
                break
        for gx, gy in chosen:
            add_via(board, round(gx, 2), round(gy, 2), gnd)
        if len(chosen) < U4_PATCH_VIA_COUNT:
            report.append(f"U4 copper patch: only {len(chosen)} thermal vias fit")
    else:
        report.append("U4 not on the board, no copper patch vias placed")

    # Mounting holes: keepout round each one.
    for ref in ("H1", "H2"):
        if ref in PLACEMENT:
            add_hole_keepout(board, PLACEMENT[ref][0], PLACEMENT[ref][1])

    # Thermal vias under U3's exposed pad. [RTL-DS] requires the pad to be
    # stitched to a plane; 3x3 on a 1.1mm grid fits inside the 3.6mm exposed
    # pad while keeping 0.6/0.3 vias, which hold a 0.15mm annular ring - the
    # board minimum. Tented from the back so PCBWay's reflow does not draw
    # solder through them.
    u3 = board.FindFootprintByReference("U3")
    if u3:
        cx = pcbnew.ToMM(u3.GetPosition().x) - ORIGIN_X
        cy = pcbnew.ToMM(u3.GetPosition().y) - ORIGIN_Y
        for ix in range(3):
            for iy in range(3):
                add_via(board, cx + (ix - 1) * 1.1, cy + (iy - 1) * 1.1,
                        gnd, 0.6, 0.3, tent_back=True)
    else:
        report.append("U3 not on the board, no thermal vias placed")

    # GND stitching round the perimeter, skipping any spot that is too close to
    # a pad, a slot or a hole.
    def free(x, y):
        for fp in board.GetFootprints():
            for pad in fp.Pads():
                px = pcbnew.ToMM(pad.GetPosition().x) - ORIGIN_X
                py = pcbnew.ToMM(pad.GetPosition().y) - ORIGIN_Y
                sx = pcbnew.ToMM(pad.GetSize().x) / 2
                sy = pcbnew.ToMM(pad.GetSize().y) / 2
                reach = max(sx, sy) + 0.9
                if abs(x - px) < reach and abs(y - py) < reach:
                    return False
        for sx_, sy_ in TIE_SLOTS:
            if abs(x - sx_) < TIE_SLOT_L / 2 + 1.0 and abs(y - sy_) < 1.8:
                return False
        for ref in ("H1", "H2"):
            if ref in PLACEMENT and math.hypot(x - PLACEMENT[ref][0],
                                               y - PLACEMENT[ref][1]) < HOLE_KEEPOUT_R[1] + 0.5:
                return False
        return True

    stitches = []
    for i in range(1, int(BOARD_W / 5)):
        stitches += [(i * 5.0, 1.2), (i * 5.0, BOARD_H - 1.2)]
    for i in range(1, int(BOARD_H / 5)):
        stitches += [(1.2, i * 5.0), (BOARD_W - 1.2, i * 5.0)]
    for x, y in stitches:
        if free(x, y):
            add_via(board, x, y, gnd)

    # Check courtyards for overlap before saving, so placement mistakes are
    # caught here rather than only by DRC. A bottom-side part is compared with
    # the other bottom-side parts only.
    boxes = {}
    for fp in board.GetFootprints():
        boxes[fp.GetReference()] = (fp.IsFlipped(), courtyard_box(fp))
    refs = sorted(boxes)
    for i, a in enumerate(refs):
        for b in refs[i + 1:]:
            if boxes[a][0] == boxes[b][0] and boxes[a][1].Intersects(boxes[b][1]):
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
