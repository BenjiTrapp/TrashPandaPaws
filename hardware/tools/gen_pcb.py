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
  * board outline, two M2.5 mounting holes with a keepout
  * GND planes on In1 and B.Cu, the power plane on In2 split into islands, and
    a GND copper patch under the 3.3 V regulator
  * thermal via array under U3's exposed pad, tented from the back
  * GND stitching vias around the board

It places; it does not route. Routing is done by tools/route_pcb.py: the
pairs, the buck loop and U3's escapes as geometry written on purpose, the rest
connection by connection with tools/route_grid.py, all of it checked with
kicad-cli's DRC and kicad-happy's analyses (decision: docs/superpowers/specs/
2026-10-30-raccoon-tap-fab-release-design.md, section 6.3).

FROZEN ONCE ROUTED. This script builds the board from nothing (NewBoard), so
a run over a routed board deletes every track and via of the routing. It
therefore counts the track segments in the target file first and refuses,
with a non-zero exit, when there are any. `--force` is the deliberate way
past that refusal, for someone who means to throw the routing away. Once the
board is routed, geometry lives in the board and connectivity in
netlist.yaml: a net change goes into netlist.yaml and reaches the board via
the schematic (Update PCB from Schematic), never via this script.

SUPERSEDED (kept as the record of the earlier decision; section 6.3 of the
spec explains why it was reversed): "What this deliberately does NOT do:
route anything. The seven differential pairs need KiCad's interactive
differential-pair router with a human deciding geometry and length matching.
An autorouted result would be an unverifiable artefact - see
OPEN_QUESTIONS.md." The FreeRouting half of that objection still stands and
FreeRouting is not used; the "unverifiable" half no longer holds, because the
routed result is checked (DRC, kicad-happy skew, reference-plane and
decoupling checks) rather than trusted.

MUST be run with KiCad's bundled Python, which has the pcbnew bindings:

    /Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/\
Versions/3.9/bin/python3 tools/gen_pcb.py
"""

import argparse
import math
import re
import sys
from pathlib import Path

# Imported in main(), after the guard against overwriting a routed board, so
# that the guard works under any interpreter.
pcbnew = None

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fitting  # noqa: E402

HARDWARE = HERE.parent
DEFAULT_NETLIST = HARDWARE / "netlist.yaml"
DEFAULT_OUT = HARDWARE / "kicad" / "raccoon-tap.kicad_pcb"

KICAD_FP = Path("/Applications/KiCad/KiCad.app/Contents/SharedSupport/footprints")
PROJECT_FP = HARDWARE / "kicad" / "raccoon.pretty"

# Board outline. 58 x 36 mm, as before task 8: growth was released for the
# impedance geometry (spec 11.8), and nothing in the placement needed it. The
# jack's front face is 0.35 mm inside the edge.
BOARD_W, BOARD_H = 58.0, 36.0
ORIGIN_X, ORIGIN_Y = 100.0, 80.0

# Anchors the placement is written against: mm from the board's top-left
# corner, x to the right, y down.
UX, UY = 24.0, 23.0           # U3 centre
JX, JY = 47.3, 18.0           # J2 origin; the jack's front face is at x = 57.65, its courtyard at 57.94

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
# Drawn as straight ratsnest lines the eight signal pins cross 27 times (original netlist).
# Which pairs may be exchanged is limited (ruling AJ, revised): MDI0 and MDI1
# are the 10/100 pair, so only MDI0<->MDI1, MDI2<->MDI3 and P/N polarity are
# free; the two groups cannot trade places. Ruling AQ uses two of them: MDI2
# and MDI3 are exchanged and turned on J2 (pins 7 to 10 = MDI3_N, MDI3_P,
# MDI2_N, MDI2_P, still cable pairs C and D), which is in netlist.yaml and so
# in the pad nets generated here.
#
# THE PLANAR ROUTE THE PLACEMENT LEAVES ROOM FOR (ruling AM). J2's pins are
# through-hole, so a track can reach them from either face. The southern pairs
# (MDI0 and MDI1) go east past U3, under J2's pin 10 (strip y 24.7 to 27.5, x 31
# to 40), through the 2.7 mm gap between pin 9 and the shield pad SH1, up the
# 4 mm channel between the pin columns and the T-posts (x 41.7 to 45.7), and
# into the pins from the east: the outermost lane to the northernmost pins.
# F.Cu is kept free of parts along all of it, and C25 and R13 stay below
# y 29. MDI2 and MDI3 then come from the west without crossing. Zero vias in the
# MDI pairs; hardware/review/2026-10-31-placement/scratch_route_check.py lays
# all of it on a copy of the board and runs the DRC.
PLACEMENT = {
    # --- connectors --------------------------------------------------------
    # J3 rotated 180 so the shell overhangs the LEFT edge while the pads stay
    # on the board. Footprint pads sit at local x=-10.85 and the courtyard runs
    # to +9.95, i.e. the shell extends away from the pads. After rotation the
    # pads land at origin+10.85, so the origin sits off-board.
    "J3":  (-5.85, 18.0, 180),
    # J2 turned so the jack's opening faces the right-hand board edge: signal
    # pins on the left (x 38.4 and 40.9), LEDs at the front.
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
    "U9":  (9.6, 18.0, 0),       # USB 2.0 ESD. Pins 1/6 are one node and 3/4 another (DS4260): D+ in at 1, out at 6; D- in at 3, then north through the 0.95 mm channel between the pad columns (0.375 mm to each side), which puts it north of D+ with no via; pin 4 joined by a stub
    "U8":  (15.6, 17.1, 270),    # SuperSpeed ESD, 10.6 mm from the J3 pads (was 13.6); TX row north, 1.63 mm channel between the rows
    # 1.2 mm further north than task 8 put them (ruling AV): U3 pin 14 (+1V0)
    # leaves up the channel between the RX_N and TX_P escapes, and C22 closed
    # its end.
    "C22": (24.95, 15.6, 90),    # TX AC coupling, P
    "C23": (26.0, 15.6, 90),     # TX AC coupling, N
    # --- decoupling ring round U3 (re-placed under rulings AV / AY) ----------
    # Task 8's ring (a column of 0402s 0.64 mm from the west pads, a row 0.59 mm
    # under the south pads) walled in pins 23 / 26 / 27 / 32 / 33 / 38 with
    # pads of foreign supplies. Each cap now sits where its pin's escape ends,
    # with room for its own via; tools/route_pcb.py records the distances.
    "C16": (23.42, 16.75, 180),  # pin 14 (+1V0), at the end of its escape north up the RX_N / TX_P channel
    "C7":  (27.0, 19.0, 0),      # pin 11 (+3V3), north-east of the TX_N run
    "C13": (29.9, 21.35, 0),     # pin 8 (+1V0), in the pocket between MDI3 and MDI2
    "C12": (29.6, 24.4, 0),      # pin 3 (+1V0), in the pocket between MDI1 and MDI0
    "C8":  (19.2, 20.4, 180),    # pin 20 (AVDD33 LDO output, 2.2 uF 0603), west of pin 19's via
    "C17": (17.3, 22.43, 270),   # pin 22 (DVDD10), on its line west; pad 1 north
    "C10": (19.25, 22.65, 180),  # pins 23 / 26 (+3V3), west of their via
    "C18": (18.9, 24.2, 270),    # pin 27 (+5V_SW), on its line west to the +5V_SW island; pad 1 north
    "C15": (22.45, 27.95, 180),  # pin 34 (+1V0), under its via
    "C14": (32.6, 28.0, 0),      # pin 37 (+1V0); route_pcb.py stage "decoupling" moves it to B.Cu at pin 37's via (ruling BH)
    # Added after the board was routed (ruling BH): parked off the board here,
    # placed on B.Cu at pin 19's via by route_pcb.py stage "decoupling", so a
    # fresh run lays the routing round the parts where they were when it was
    # laid
    "C27": (-8.0, 40.0, 0),
    "C11": (19.2, 25.95, 180),   # pins 26 / 33 (+3V3), on the +3V3 plane south-west of U3
    "C9":  (19.2, 27.0, 180),    # pins 39 / 40 (+3V3), the same
    # --- J2 side ------------------------------------------------------------
    "C21": (34.4, 18.0, 180),    # centre-tap bypass, top side, in the 5 mm gap west of pin 6 (the MDI0/1 pairs come in from the east, MDI2/3 at y 19.9 and below); the jack's courtyard keeps it 3.3 mm from the pin
    "C25": (41.6, 29.9, 0),      # shield to GND, by the jack's shield post
    "R13": (46.3, 29.9, 0),
    "R7":  (51.3, 28.0, 0),      # LED series resistors, by the LED pins
    "R8":  (49.8, 8.3, 0),
    # --- mounting ----------------------------------------------------------
    "H1":  (54.5, 3.5, 0),
    "H2":  (54.5, 32.5, 0),
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
    "FID3": (47.0, 33.5, 0),
    # --- U3 pin 20 contingency ---------------------------------------------
    "R12": (15.6, 23.6, 90),     # DNP link U3.20 <-> +3V3
}

# Parts that sit on the bottom copper layer: none (a bottom-side part would mean
# double-sided assembly or hand soldering, and the bottom side has no fiducials).
BOTTOM = set()

# M2.5 holes (spec 5.2): copper-free ring for the screw head and washer, round
# the plated pad of the hole. Tracks, vias and parts stay out; the GND pour may
# come in.
HOLE_KEEPOUT_R = (3.02, 3.9)

# No cable-tie slots: the first round drew them 4.5 to 7.9 mm beyond the jack's
# front face, where the plug body still is, and nothing here shows that a tie
# would clear the latch of a tab-up jack. The board ends at the jack and the
# strain relief is the two screws, either side of the jack, 3.2 mm behind its
# front face (unproven without the J2 and plug drawings).

# GND vias for the USB 2.0 pair (ruling AR, revised). The pair leaves F.Cu at
# U9 (x 12.2), runs on B.Cu to U3 (x 21.5 and 22.4) and so crosses ONE boundary
# between In2 islands: the 0.6 mm gap at x 18.8 to 19.4 between +5V_SW and +1V0
# (it starts over the 11.8 to 12.4 gap beside the +5V_SW island, where its vias
# are, which is an end of the stretch and not a crossing). Return current has
# to get across that gap in the B.Cu GND pour beside the pair, so the pour is
# tied to In1 by a via on each side of the crossing, and at each end. The
# crossing's north via sits on the gap (x 19.1); the south one cannot, because
# C8 occupies the F.Cu south of it, so it is as near as the F.Cu copper lets it
# (1.5 mm west). The two end vias are the nearest places that keep 0.3 mm from
# the F.Cu routes of hardware/review/2026-10-31-placement/scratch_route_check.py.
USB2_RETURN_VIAS = [
    (19.1, 18.3),     # crossing, north of the pair (between RX_N and RX_P on F.Cu)
    (17.6, 20.6),     # crossing, south of the pair (west of C8)
    (12.1, 18.95),    # U9 end, south of the signal vias
]
# The U3-end GND via of task 8, (22.0, 17.3), is gone: ruling AZ released it
# with the USB 2.0 signal vias at U3, and tools/route_pcb.py places the vias
# of that end with the routing.

# Rule area round U3's escape (ruling AU), named for the DRC rule "track to
# track at the U3 escape" in raccoon-tap.kicad_dru: two escapes from
# neighbouring U3 pads are about 0.25 mm apart at the 0.40 mm pitch, which the
# Power class's 0.30 mm cannot allow. The square reaches 3.45 mm from U3's
# centre: the pads' outer ends are at 2.85 mm and a neck may run to 1.0 mm
# from a pad centre (3.44 mm). It restricts nothing by itself (no keepout).
U3_ESCAPE_AREA = "U3_escape"
U3_ESCAPE_HALF = 3.45

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
    ("+3V3", [(19.4, 21.8), (29.4, 21.8), (29.4, 12.8), (57.2, 12.8),
              (57.2, 34.6), (19.4, 34.6)]),
    ("+3V3", [(44.0, 1.0), (57.2, 1.0), (57.2, 12.4), (44.0, 12.4)]),
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
    """Board outline on Edge.Cuts."""
    corners = [(0, 0), (BOARD_W, 0), (BOARD_W, BOARD_H), (0, BOARD_H)]
    for index in range(4):
        x1, y1 = corners[index]
        x2, y2 = corners[(index + 1) % 4]
        add_edge_line(board, x1, y1, x2, y2)


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


def add_named_area(board, name, cx, cy, half):
    """Square rule area on F.Cu with no keepout of its own, for a DRC rule
    that scopes itself with insideArea()."""
    zone = pcbnew.ZONE(board)
    zone.SetIsRuleArea(True)
    zone.SetLayer(pcbnew.F_Cu)
    zone.SetDoNotAllowTracks(False)
    zone.SetDoNotAllowVias(False)
    zone.SetDoNotAllowFootprints(False)
    zone.SetDoNotAllowPads(False)
    zone.SetDoNotAllowZoneFills(False)
    zone.SetZoneName(name)
    outline = zone.Outline()
    outline.NewOutline()
    for dx, dy in ((-1, -1), (1, -1), (1, 1), (-1, 1)):
        outline.Append(mm(ORIGIN_X + cx + dx * half), mm(ORIGIN_Y + cy + dy * half))
    board.Add(zone)
    return zone


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
        add_named_area(board, U3_ESCAPE_AREA, cx, cy, U3_ESCAPE_HALF)
    else:
        report.append("U3 not on the board, no thermal vias placed")

    # GND stitching round the perimeter, skipping any spot that is too close to
    # a pad or a hole.
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
        for ref in ("H1", "H2"):
            if ref in PLACEMENT and math.hypot(x - PLACEMENT[ref][0],
                                               y - PLACEMENT[ref][1]) < HOLE_KEEPOUT_R[1] + 0.5:
                return False
        return True

    # GND vias for the USB 2.0 pair's stretch on B.Cu (ruling AR, revised).
    # Their places are fixed by the F.Cu copper they have to stay clear of; see
    # USB2_RETURN_VIAS.
    for x, y in USB2_RETURN_VIAS:
        add_via(board, x, y, gnd)

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


def routed_track_count(path):
    """Track segments and arcs in an existing board file (0 if there is none)."""
    path = Path(path)
    if not path.exists():
        return 0
    return len(re.findall(r"^\s*\((?:segment|arc)\b", path.read_text(), re.M))


def main():
    global pcbnew
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("netlist", nargs="?", default=str(DEFAULT_NETLIST))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--force", action="store_true",
                        help="overwrite a routed board, discarding its routing")
    args = parser.parse_args()

    tracks = routed_track_count(args.out)
    if tracks and not args.force:
        print(f"error: {args.out} ist geroutet ({tracks} Leiterbahnsegmente); "
              "gen_pcb.py baut das Board neu auf und wuerde das Routing vernichten. "
              f"The board is routed ({tracks} track segments) and this run would "
              "destroy the routing: change geometry in the board and connectivity "
              "in netlist.yaml. Pass --force only if you mean to throw the "
              "routing away.", file=sys.stderr)
        return 3
    try:
        import pcbnew as _pcbnew
    except ImportError:
        print("error: pcbnew not importable - run this with KiCad's bundled Python",
              file=sys.stderr)
        return 1
    pcbnew = _pcbnew

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
    print("\nNot routed (tools/route_pcb.py routes). Verify with:")
    print(f"  kicad-cli pcb drc --severity-all {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
