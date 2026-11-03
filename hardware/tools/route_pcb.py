#!/usr/bin/env python3
"""
Route kicad/raccoon-tap.kicad_pcb (task 9), programmatically. The differential
pairs, the buck loop and U3's escapes are coordinates written here on purpose;
the remaining supply and low-speed connections are searched one at a time by
tools/route_grid.py (not FreeRouting, nor any router that sees the board as a
whole). The result is checked by kicad-cli's DRC and kicad-happy's analyses.
Why routing is programmatic at all: docs/superpowers/specs/
2026-10-30-raccoon-tap-fab-release-design.md section 6.3.

Library:
  route_net(board, net, waypoints, width, layer)
      PCB_TRACK segments along `waypoints` (mm from the board's top-left
      corner). Refuses (RoutingError) a segment on In1.Cu, the solid GND plane
      every pair references, and a segment that would lie over a hole already
      cut into In1 when it belongs to a differential pair.
  route_pair(board, net_p, net_n, waypoints, layer)
      the two nets of a pair at a constant pitch along a centre line, at the
      geometry of hardware/fab/stackup-note.md; returns the length of each net
      laid and their difference.
  add_via(board, net, x, y)
      refuses a via whose clearance hole in In1 would cut under a pair track
      that is already laid (a via is the only thing that breaks In1).

The plan (STAGES) follows the order of the routing brief: SuperSpeed TX and
RX, MDI0 to MDI3, USB 2.0 (the pairs, coordinates written here), the buck's hot
loop, U3's supply and low-speed escapes (written here, rulings AU / AY), the
low-speed nets, the rails, every GND pad to a via, and last (ruling BA) no
open via in a pad of a hand-soldered part. The low-speed, rail and GND stages are
searched connection by connection on a 0.05 mm grid by tools/route_grid.py
round what is already laid, at the project's clearances; each call names the
connection, its width and where it may end. kicad-cli's DRC is the judge.
Stages added after the board was routed are applied to it in place by
tools/amend_pcb.py (the PCB is frozen; gen_pcb.py refuses a routed board).

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
    $KIPY hardware/tools/route_pcb.py --in <placed board> --out <board> [--stages a,b,...]

It routes a board that has no tracks; a board that already carries tracks is
refused, because it would be routed twice. After the stages it fills the
zones, saves, and prints the in-pair lengths, every via it placed, the In1
check under the pair tracks and the In2 islands under the USB 2.0 stretch.
"""

import argparse
import math
import sys
from pathlib import Path

import pcbnew

HERE = Path(__file__).resolve().parent
DEFAULT_PCB = HERE.parent / "kicad" / "raccoon-tap.kicad_pcb"

ORIGIN = (100.0, 80.0)          # gen_pcb.py ORIGIN_X, ORIGIN_Y

# Geometry (hardware/fab/stackup-note.md). Pitch = width + gap.
USB_W, USB_GAP = 0.20, 0.17
MDI_W, MDI_GAP = 0.18, 0.21
NECK_W = 0.15                    # at most 0.15 mm (rulings AG / AI)
NECK_LEN = 0.6                   # from the pad centre; the limit is 1.0 mm
IN1_CLEARANCE = 0.3              # zone clearance of the In1 pour (gen_pcb.add_zone)

PAIRS = [("USB3_TX_P", "USB3_TX_N"), ("USB3_TX_CONN_P", "USB3_TX_CONN_N"),
         ("USB3_RX_P", "USB3_RX_N"), ("USB2_D_P", "USB2_D_N"),
         ("MDI0_P", "MDI0_N"), ("MDI1_P", "MDI1_N"),
         ("MDI2_P", "MDI2_N"), ("MDI3_P", "MDI3_N")]
PAIR_NETS = {n for pair in PAIRS for n in pair}

# Ruling AR (revised): the one stretch of a pair that is allowed off F.Cu.
B_CU_EXCEPTION_NETS = {"USB2_D_P", "USB2_D_N"}


class RoutingError(Exception):
    pass


def mm(value):
    return pcbnew.FromMM(value)


def vec(x, y):
    return pcbnew.VECTOR2I(mm(ORIGIN[0] + x), mm(ORIGIN[1] + y))


def xy(v):
    return (pcbnew.ToMM(v.x) - ORIGIN[0], pcbnew.ToMM(v.y) - ORIGIN[1])


def seg_point_distance(a, b, p):
    ax, ay = a
    bx, by = b
    px, py = p
    dx, dy = bx - ax, by - ay
    length2 = dx * dx + dy * dy
    t = 0.0 if length2 == 0 else max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / length2))
    return math.hypot(ax + t * dx - px, ay + t * dy - py)


def partner(net):
    for p, n in PAIRS:
        if net in (p, n):
            return n if net == p else p
    return None


def in1_holes(board, net=None):
    """Every hole the In1 GND pour has to leave round an item of another net:
    (x, y, radius of the cleared area). Vias and holes not on GND; the items of
    `net` and of its pair partner are left out (a pair's own pad and via are
    where it leaves the layer)."""
    skip = {"GND", net, partner(net)}
    holes = []
    for item in board.GetTracks():
        if item.Type() == pcbnew.PCB_VIA_T and item.GetNetname() not in skip:
            x, y = xy(item.GetPosition())
            holes.append((x, y, pcbnew.ToMM(item.GetWidth(pcbnew.In1_Cu)) / 2 + IN1_CLEARANCE))
    for fp in board.GetFootprints():
        for pad in fp.Pads():
            if pad.HasHole() and pad.GetNetname() not in skip:
                x, y = xy(pad.GetPosition())
                size = pad.GetSize(pcbnew.In1_Cu) if pad.IsOnLayer(pcbnew.In1_Cu) else pad.GetDrillSize()
                r = max(pcbnew.ToMM(size.x), pcbnew.ToMM(size.y)) / 2
                holes.append((x, y, r + IN1_CLEARANCE))
    return holes


def route_net(board, net, waypoints, width, layer=pcbnew.F_Cu, exception=None):
    """Lay `net` along `waypoints` (mm, board coordinates) at `width` on
    `layer`. Returns the length laid (mm)."""
    if layer == pcbnew.In1_Cu:
        raise RoutingError(f"{net}: a track on In1.Cu would break the GND plane")
    item = board.FindNet(net)
    if item is None:
        raise RoutingError(f"{net}: no such net on the board")
    if net in PAIR_NETS and layer != pcbnew.F_Cu:
        if not (exception == "AR" and net in B_CU_EXCEPTION_NETS and layer == pcbnew.B_Cu):
            raise RoutingError(f"{net}: a pair off F.Cu has no In1 reference "
                               "(only USB 2.0 on B.Cu, ruling AR, is allowed)")
    if net in PAIR_NETS and layer == pcbnew.F_Cu:
        for a, b in zip(waypoints, waypoints[1:]):
            for hx, hy, r in in1_holes(board, net):
                if seg_point_distance(a, b, (hx, hy)) < r + width / 2:
                    raise RoutingError(f"{net}: segment {a}->{b} lies over a hole in In1 "
                                       f"at ({hx:.2f}, {hy:.2f})")
    length = 0.0
    for a, b in zip(waypoints, waypoints[1:]):
        if a == b:
            continue
        track = pcbnew.PCB_TRACK(board)
        track.SetLayer(layer)
        track.SetNet(item)
        track.SetStart(vec(*a))
        track.SetEnd(vec(*b))
        track.SetWidth(mm(width))
        board.Add(track)
        length += math.hypot(b[0] - a[0], b[1] - a[1])
    return length


def offset_line(points, d):
    """The polyline offset by d to the left of its direction of travel (north
    when travelling east), with mitred corners."""
    def unit(a, b):
        dx, dy = b[0] - a[0], b[1] - a[1]
        length = math.hypot(dx, dy)
        return dx / length, dy / length
    out = []
    for i, p in enumerate(points):
        if i == 0:
            u = unit(points[0], points[1])
            out.append((p[0] + u[1] * d, p[1] - u[0] * d))
        elif i == len(points) - 1:
            u = unit(points[-2], points[-1])
            out.append((p[0] + u[1] * d, p[1] - u[0] * d))
        else:
            u1, u2 = unit(points[i - 1], p), unit(p, points[i + 1])
            n1, n2 = (u1[1], -u1[0]), (u2[1], -u2[0])
            mx, my = n1[0] + n2[0], n1[1] + n2[1]
            length = math.hypot(mx, my)
            mx, my = mx / length, my / length
            k = d / (mx * n1[0] + my * n1[1])
            out.append((p[0] + mx * k, p[1] + my * k))
    return out


def route_pair(board, net_p, net_n, waypoints, layer=pcbnew.F_Cu, width=None, gap=None,
               p_left=True, head_p=(), head_n=(), tail_p=(), tail_n=(), exception=None):
    """Lay a differential pair along the centre line `waypoints` at a constant
    pitch (width + gap; the class geometry unless given). `head_*` are points
    before the coupled run (from the pad), `tail_*` after it (to the pad), for
    each net. Returns (length P, length N, |difference|)."""
    mdi = net_p.startswith("MDI")
    width = width if width is not None else (MDI_W if mdi else USB_W)
    gap = gap if gap is not None else (MDI_GAP if mdi else USB_GAP)
    half = (width + gap) / 2
    left = offset_line(waypoints, half)
    right = offset_line(waypoints, -half)
    p_line, n_line = (left, right) if p_left else (right, left)
    lp = route_net(board, net_p, list(head_p) + p_line + list(tail_p), width, layer, exception)
    ln = route_net(board, net_n, list(head_n) + n_line + list(tail_n), width, layer, exception)
    return lp, ln, abs(lp - ln)


def add_via(board, net, x, y, diameter=0.6, drill=0.3):
    if net != "GND":
        for track in board.GetTracks():
            if (track.Type() == pcbnew.PCB_TRACE_T and track.GetNetname() in PAIR_NETS
                    and track.GetLayer() == pcbnew.F_Cu
                    and track.GetNetname() not in (net, partner(net))):
                a, b = xy(track.GetStart()), xy(track.GetEnd())
                w = pcbnew.ToMM(track.GetWidth())
                if seg_point_distance(a, b, (x, y)) < diameter / 2 + IN1_CLEARANCE + w / 2:
                    raise RoutingError(f"via {net} at ({x}, {y}) would cut In1 under "
                                       f"{track.GetNetname()}")
    via = pcbnew.PCB_VIA(board)
    via.SetPosition(vec(x, y))
    via.SetWidth(mm(diameter))
    via.SetDrill(mm(drill))
    via.SetViaType(pcbnew.VIATYPE_THROUGH)
    via.SetLayerPair(pcbnew.F_Cu, pcbnew.B_Cu)
    via.SetNet(board.FindNet(net))
    board.Add(via)
    return via


class Pads:
    def __init__(self, board):
        self.pos = {}
        for fp in board.GetFootprints():
            for pad in fp.Pads():
                self.pos[(fp.GetReference(), pad.GetNumber())] = xy(pad.GetPosition())

    def __call__(self, ref, number):
        return self.pos[(ref, str(number))]


# ---------------------------------------------------------------------------
# The plan. Coordinates in mm from the board's top-left corner. The SuperSpeed,
# USB 2.0 and MDI geometry is the one hardware/review/2026-10-31-placement/
# scratch_route_check.py showed to clear the rules (task 8); the stages below
# lay it on the board itself.
# ---------------------------------------------------------------------------

F, B = pcbnew.F_Cu, pcbnew.B_Cu
PITCH = USB_W + USB_GAP          # 0.37
MPITCH = MDI_W + MDI_GAP         # 0.39


class Router:
    def __init__(self, board):
        self.board = board
        self.P = Pads(board)
        self.lengths = {}
        self.stubs = {}
        self.vias = []           # (net, x, y, why)

    def net(self, net, points, width, layer=F, exception=None, stub=False):
        """`stub`: a branch off the signal path (the tee into an ESD pad); it
        counts in the copper but not in the path from one end to the other."""
        length = route_net(self.board, net, points, width, layer, exception)
        self.lengths[net] = self.lengths.get(net, 0.0) + length
        if stub:
            self.stubs[net] = self.stubs.get(net, 0.0) + length
        return length

    def via(self, net, x, y, why, diameter=0.6, drill=0.3):
        add_via(self.board, net, x, y, diameter, drill)
        self.vias.append((net, x, y, why))

    def leave(self, net, pad, direction, then, width, length=NECK_LEN):
        """A track leaving a U3 pad: NECK_W wide for `length` from the pad
        centre (rulings AG / AI), then `width` along `then`."""
        x, y = pad
        end = (x + direction[0] * length, y + direction[1] * length)
        self.net(net, [pad, end], NECK_W)
        self.net(net, [end] + then, width)


# U3's north edge (rulings AV, AY, AZ). C22 / C23 sit 1.2 mm further north
# than task 8 had them, the TX_CONN pair leaves them at y 14.55 / 14.925, and
# the RX pair turns west at y 17.5 / 17.875 instead of 18.075 / 18.45. That
# leaves a band of 2.2 mm between RX_P and U3's pads for the USB 2.0 vias, pin
# 19's +1V0 via and pin 20's AVDD33 track, and a pocket between RX_N and the
# TX_CONN pair for pin 14's capacitor and via.
TX_CONN_Y_N = 14.55
RX_Y_N = 17.5
RX_Y_P = RX_Y_N + 0.375
# RX_P climbs to its horizontal on the line x + y = RX_P_DIAG, 1.0 mm from the
# crossing's north GND via (19.1, 18.3) measured square to the line (0.7 is
# the least that keeps 0.3 mm of copper). Stage "rx" (ruling BK) re-lays RX
# coupled and moves that via to (19.1, 18.49), south of both RX lines.
RX_P_DIAG = 38.4


def stage_usb3_tx(r):
    """TX: U3 -> C22 / C23 -> U8 (tee) -> J3. The pair opens to 1.05 mm at the
    capacitors (their courtyards) and round U8 (ruling AS)."""
    P = r.P
    u8 = {n: P("U8", n) for n in "123456"}
    y_c = (u8["2"][1] + u8["5"][1]) / 2
    y_ch = y_c - 0.40
    j5, j6 = P("J3", 5), P("J3", 6)
    p12, p13 = P("U3", 12), P("U3", 13)
    c22_1, c22_2, c23_1, c23_2 = P("C22", 1), P("C22", 2), P("C23", 1), P("C23", 2)
    x3, x1 = u8["3"][0], u8["1"][0]
    up = (0, -1)
    # TX_P in ONE straight segment from its neck into C22.1, leaning 0.1 mm east:
    # pin 14's +1V0 escape runs up beside it, also in one segment leaning 0.1
    # mm east, and both touch U3's escape area, so ruling AU's 0.2 mm holds
    # between them all the way while the escape clears RX_N's turn at y 17.5
    # by the Power class's 0.3 mm (see stage_supplies_u3).
    r.leave("USB3_TX_P", p13, up, [(p13[0] + 0.1, c22_1[1])], USB_W)
    r.leave("USB3_TX_N", p12, up, [(c23_1[0], c23_1[1] + 0.5), c23_1], USB_W)
    yn, yp = TX_CONN_Y_N, TX_CONN_Y_N + 0.375
    # N stays at yn until P's diagonal has dropped away, then steps to 14.8125
    r.net("USB3_TX_CONN_N", [c23_2, (c23_2[0], yn), (21.3, yn), (21.3 - (14.8125 - yn), 14.8125),
                             (8.3125, 14.8125), (7.5, j5[1]), (j5[0] + 0.9, j5[1])], USB_W)
    r.net("USB3_TX_CONN_N", [(x3, 14.8125), u8["3"]], USB_W, stub=True)
    r.net("USB3_TX_CONN_P", [c22_2, (c22_2[0], yp), (22.0, yp), (22.0 - (y_ch - yp), y_ch),
                             (x3 - 0.7375, y_ch), (x3 - 2.25, 15.1875),
                             (7.8125, 15.1875), (7.0, j6[1]), (j6[0] + 0.9, j6[1])], USB_W)
    r.net("USB3_TX_CONN_P", [(x1, y_ch), u8["1"]], USB_W, stub=True)


def stage_usb3_rx(r):
    """RX: J3 -> U8 (tee) -> U3. RX_N runs through U8's channel at y 17.5 and
    straight on to above pin 15; RX_P joins it at 0.375 mm east of the
    crossing's GND via."""
    P = r.P
    u8 = {n: P("U8", n) for n in "123456"}
    y_c = (u8["2"][1] + u8["5"][1]) / 2
    y_rn, y_rp = y_c + 0.40, 19.07
    assert abs(y_rn - RX_Y_N) < 1e-6, y_rn
    j8, j9 = P("J3", 8), P("J3", 9)
    p15, p16 = P("U3", 15), P("U3", 16)
    x3, x1 = u8["3"][0], u8["1"][0]
    r.net("USB3_RX_N", [(j8[0] + 0.9, j8[1]), (7.5, j8[1]), (8.3125, 20.8125),
                        (x3 - 3.3125, 20.8125), (x3, y_rn),
                        (p15[0], y_rn), (p15[0], p15[1] - NECK_LEN)], USB_W)
    r.net("USB3_RX_N", [(p15[0], p15[1] - NECK_LEN), p15], NECK_W)
    r.net("USB3_RX_N", [(x3, y_rn), (x3, u8["4"][1])], USB_W, stub=True)
    r.net("USB3_RX_P", [(j9[0] + 0.9, j9[1]), (7.0, j9[1]), (7.8125, 21.1875),
                        (x3 - 1.495, 21.1875), (x3 + 0.6225, y_rp), (RX_P_DIAG - y_rp, y_rp),
                        (RX_P_DIAG - RX_Y_P, RX_Y_P), (p16[0], RX_Y_P),
                        (p16[0], p16[1] - NECK_LEN)], USB_W)
    r.net("USB3_RX_P", [(p16[0], p16[1] - NECK_LEN), p16], NECK_W)
    r.net("USB3_RX_P", [(x1, y_rp), u8["6"]], USB_W, stub=True)


def mdi_wrap(r, nets, pads, centre, lane_x, pin_n, pin_p, necks=None):
    """One MDI pair round the south end of J2's pin field and up the channel
    east of the pin columns (ruling AM). N (the west line) leaves the lane at
    the row of pin_n, P at the row of pin_p."""
    net_n, net_p = nets
    pad_n, pad_p = pads
    top = min(pin_n[1], pin_p[1])
    line = centre + [(lane_x, top)]
    left = offset_line(line, MPITCH / 2)
    right = offset_line(line, -MPITCH / 2)
    cut = lambda poly, y: poly[:-1] + [(poly[-1][0], y)]
    necks = necks or {}
    ln, lp = necks.get(net_n, NECK_LEN), necks.get(net_p, NECK_LEN)
    r.net(net_n, [pad_n, (pad_n[0] + ln, pad_n[1])], NECK_W)
    r.net(net_p, [pad_p, (pad_p[0] + lp, pad_p[1])], NECK_W)
    ahead = lambda poly, x: [q for k, q in enumerate(poly) if k > 0 or q[0] > x]
    r.net(net_n, [(pad_n[0] + ln, pad_n[1])] + ahead(cut(left, pin_n[1]), pad_n[0] + ln) + [pin_n], MDI_W)
    r.net(net_p, [(pad_p[0] + lp, pad_p[1])] + ahead(cut(right, pin_p[1]), pad_p[0] + lp) + [pin_p], MDI_W)


# Round J2's south end the two pairs pass between pin 9 and SH1, and MDI1
# passes under pin 10. In1 is cleared 1.05 mm round each signal pin (0.75 pad
# + 0.3) and 1.6 mm round SH1 (1.3 + 0.3); task 8's scratch lanes crossed
# those holes by 0.03 to 0.06 mm (MDI0_P over SH1's, MDI1_N over pin 9's and
# pin 10's). The diagonals below sit on the axis from pin 9 to SH1 at 1.435 mm
# (MDI1) and 2.775 mm (MDI0) from pin 9, which leaves about 0.1 mm to each
# hole, and MDI1's run under pin 10 is at y 25.2 (0.15 mm to its hole).
def stage_mdi1(r):
    u4, u5 = r.P("U3", 4), r.P("U3", 5)
    x0 = u5[0] + NECK_LEN
    mdi_wrap(r, ("MDI1_N", "MDI1_P"), (u5, u4),
             [(x0, 23.4), (33.0, 23.4), (34.8, 25.2), (40.224, 25.2), (42.7, 22.724)],
             42.7, r.P("J2", 4), r.P("J2", 3))


# MDI0 drops from y 24.6 to 25.29 straight after its necks and MDI3 lifts from
# 21.4 to 20.1 (ruling AY): that opens a pocket between MDI1 and MDI0 for pin
# 3's +1V0 via and C12, and one between MDI3 and MDI2 for pin 8's via and C13.
# MDI3's N line then runs level with J2 pin 7 (y 19.905).
MDI0_Y = 25.35
MDI3_Y = 20.1
CORNER_NECK = 0.51


def stage_mdi0(r):
    u1, u2 = r.P("U3", 1), r.P("U3", 2)
    x0 = u2[0] + NECK_LEN
    d = MDI0_Y - 24.6
    k = 26.4 - MDI0_Y
    mdi_wrap(r, ("MDI0_N", "MDI0_P"), (u2, u1),
             [(u1[0] + CORNER_NECK, 24.6), (x0, 24.6), (x0 + d, MDI0_Y), (32.8 - k, MDI0_Y),
              (32.8, 26.4), (40.92, 26.4), (44.0, 23.32)],
             44.0, r.P("J2", 2), r.P("J2", 1), necks={"MDI0_P": CORNER_NECK})


def stage_mdi3(r):
    """MDI3 (north at U3) to J2 pins 7 (N) and 8 (P), from the west (ruling AQ)."""
    P = r.P
    x0 = P("U3", 10)[0] + NECK_LEN
    # the corner pin's neck (N, pin 10) stops at 0.51 mm, where its full width
    # has cleared pin 9's pad, so that P's turn north keeps 0.2 mm from it
    xn = P("U3", 10)[0] + CORNER_NECK
    r.net("MDI3_N", [P("U3", 10), (xn, P("U3", 10)[1])], NECK_W)
    r.net("MDI3_P", [P("U3", 9), (x0, P("U3", 9)[1])], NECK_W)
    d = 21.4 - MDI3_Y
    centre = [(xn - 0.1, 21.4), (x0, 21.4), (x0 + d, MDI3_Y), (36.6, MDI3_Y)]
    n_line = offset_line(centre, MPITCH / 2)
    p_line = offset_line(centre, -MPITCH / 2)
    j7, j8 = P("J2", 7), P("J2", 8)
    r.net("MDI3_N", [(xn, 21.2)] + n_line[1:] + [j7], MDI_W)
    r.net("MDI3_P", [(x0, 21.6)] + p_line[1:] + [(36.6 + j8[1] - p_line[-1][1], j8[1]), j8], MDI_W)


def stage_mdi2(r):
    P = r.P
    x0 = P("U3", 10)[0] + NECK_LEN
    for net, pin in (("MDI2_N", 7), ("MDI2_P", 6)):
        r.net(net, [P("U3", pin), (x0, P("U3", pin)[1])], NECK_W)
    r.net("MDI2_N", [(x0, 22.4), (36.5, 22.4), (36.6, 22.445), P("J2", 9)], MDI_W)
    r.net("MDI2_P", [(x0, 22.8), (34.0, 22.8), (34.915, 23.715), P("J2", 10)], MDI_W)


# The USB 2.0 pair (ruling AR, revised; the U3 end re-planned under AZ). It
# goes down at U9 (x 12.2) and comes up in the band between RX_P and U3's
# pads; D_N is the north track. On B.Cu it is coupled at the class pitch from
# x 20.25 west, at y 19.2 / 19.57 across the In2 gap at x 18.8 to 19.4,
# between the crossing's GND vias (19.1, 18.3) and (17.6, 20.6) (since rulings
# BI and BK at (19.1, 18.49) and (17.565, 20.6)).
USB2_VIA_U9 = {"USB2_D_N": (12.2, 16.2), "USB2_D_P": (12.2, 17.1)}
USB2_VIA_U3 = {"USB2_D_N": (20.8, 18.65), "USB2_D_P": (21.5, 19.0)}
USB2_FCU_Y = {"USB2_D_N": 18.33, "USB2_D_P": 18.7}     # their runs west from the pins
USB2_FCU_JOG = None       # {net: (y where it steps west, dx)}: none in the first layout
USB2_Y_N = 19.2
USB2_Y_P = USB2_Y_N + PITCH
# D+ runs 2.274 mm inside U9 (pins 1 and 6 are one node, pad centres 8.463 and
# 10.737), D- through U9's channel on copper; on the copper D- is longer.
# Two bumps on D+'s B.Cu run, south (away from D-), west of the crossing
# window x 18.3 to 19.9 and clear of its south GND via: each adds 2 x height.
USB2_U9_INTERNAL = 10.737 - 8.463
USB2_BUMPS = [(15.2, 15.7), (16.2, 16.7)]
USB2_BUMP_H = 0.93


def usb2_bcu():
    """Centre lines of the two B.Cu tracks, U9 end to U3 end."""
    (xn, yn), (xp, yp) = USB2_VIA_U9["USB2_D_N"], USB2_VIA_U9["USB2_D_P"]
    (un, vn), (up_, vp) = USB2_VIA_U3["USB2_D_N"], USB2_VIA_U3["USB2_D_P"]
    # from the U3 vias the pair leaves at y 19.0 / 19.37 (under the vias, clear
    # of pin 19's via) and steps down to 19.2 / 19.57 before the crossing
    yn3, yp3 = USB2_Y_N - 0.2, USB2_Y_P - 0.2
    xj = 19.95                                    # where D_N steps down
    n = [(xn, yn), (xn + USB2_Y_N - yn, USB2_Y_N), (xj - 0.2, USB2_Y_N), (xj, yn3),
         (un - (yn3 - vn), yn3), (un, vn)]
    c = (xn - yn) - PITCH * math.sqrt(2)          # D_P's 45-degree line: x - y = c
    k = (xj + yn3) + PITCH * math.sqrt(2)         # D_P's step: x + y = k
    bumps = []
    for a, b in USB2_BUMPS:
        bumps += [(a, USB2_Y_P), (a, USB2_Y_P + USB2_BUMP_H), (b, USB2_Y_P + USB2_BUMP_H), (b, USB2_Y_P)]
    p = [(xp, yp), (yp + c, yp), (USB2_Y_P + c, USB2_Y_P)] + bumps + [(k - USB2_Y_P, USB2_Y_P),
         (k - yp3, yp3), (up_ - (yp3 - vp), yp3), (up_, vp)]
    return {"USB2_D_N": n, "USB2_D_P": p}


USB2_BCU = usb2_bcu()


def stage_usb2(r, return_via=True):
    """D+/D-: J3 -> U9 (D- through the channel between U9's pad columns; pins
    3/4 and 1/6 are one node each, DS4260) -> four vias -> B.Cu under the TX
    and RX lanes -> U3."""
    P = r.P
    j2, j3 = P("J3", 2), P("J3", 3)
    u1, u3, u4, u6 = (P("U9", n) for n in (1, 3, 4, 6))
    vn9, vp9 = USB2_VIA_U9["USB2_D_N"], USB2_VIA_U9["USB2_D_P"]
    r.net("USB2_D_P", [(j3[0] + 0.9, j3[1]), (6.5, u1[1]), u1], USB_W)
    r.net("USB2_D_N", [(j2[0] + 0.9, j2[1]), (6.5, u3[1]), u3, (9.6, u3[1]),
                       (9.6, vn9[1]), vn9], USB_W)
    r.net("USB2_D_N", [(9.6, u3[1]), u4], USB_W, stub=True)
    r.net("USB2_D_P", [u6, vp9], USB_W)
    r.via("USB2_D_N", *vn9, "USB 2.0 to B.Cu, under the TX and RX lanes (U9 end)")
    r.via("USB2_D_P", *vp9, "USB 2.0 to B.Cu, under the TX and RX lanes (U9 end)")
    for net, pin in (("USB2_D_N", 17), ("USB2_D_P", 18)):
        pad = P("U3", pin)
        vx, vy = USB2_VIA_U3[net]
        y = USB2_FCU_Y[net]
        r.net(net, [pad, (pad[0], pad[1] - NECK_LEN)], NECK_W)
        if USB2_FCU_JOG:
            yj, dx = USB2_FCU_JOG[net]
            path = [(pad[0], pad[1] - NECK_LEN), (pad[0], yj), (pad[0] + dx, yj + dx), (pad[0] + dx, y)]
        else:
            path = [(pad[0], pad[1] - NECK_LEN), (pad[0], y)]
        r.net(net, split_at_area(path + [(vx + abs(vy - y), y), (vx, vy)]), USB_W)
        r.via(net, vx, vy, "USB 2.0 back to F.Cu at U3, in the band between RX_P and the pads")
    for net, path in USB2_BCU.items():
        r.net(net, path, USB_W, B, exception="AR")
    # the one free place within 1 mm of a USB 2.0 signal via (kicad-happy RP-001)
    if return_via:
        r.via("GND", 12.4, 18.0, "USB 2.0 return, 0.92 mm from D+'s via at U9")


# ---------------------------------------------------------------------------
# Supplies and low-speed nets: connections searched on a 0.05 mm grid by
# tools/route_grid.py round what is already laid, at the rules' clearances.
# Each call below names one connection, its width and where it may end.
# ---------------------------------------------------------------------------

import route_grid  # noqa: E402


class Grid:
    def __init__(self, r):
        self.r = r
        self.g = route_grid.Router(r.board, PAIR_NETS)
        self.failed = []

    def refresh(self):
        self.g.items = route_grid.collect(self.r.board, PAIR_NETS)

    def pad_item(self, ref, num):
        x, y = self.r.P(ref, num)
        for it in self.g.items:
            if it.kind == "pad" and it.dist(x, y) < -0.01 and abs(it.geom[1] - x) < 1e-3 and abs(it.geom[2] - y) < 1e-3:
                return it
        raise RoutingError(f"no pad {ref}.{num}")

    def connect(self, net, start, to=(), island=False, any_via=False, width=0.2, allow_b=True,
                why="", margin=3.0, via_cost=40.0, max_vias=2, points=(), copper=False, avoid=()):
        """start: (ref, pad) or (x, y[, layer]); to: list of (ref, pad)."""
        if isinstance(start[0], str):
            sx, sy = self.r.P(*start)
            starts = [(layer, sx, sy) for layer in sorted(self.pad_item(*start).layers)]
        else:
            sx, sy = start[0], start[1]
            starts = [(start[2] if len(start) > 2 else route_grid.F, sx, sy)]
        pads = [self.pad_item(*t) for t in to]
        # existing copper of the net counts as a goal unless it touches the start
        exclude = []
        if copper:
            for it in self.g.items:
                if it.net == net and it.kind in ("track", "via") and it.dist(sx, sy) < 0.05:
                    exclude.append(it)
        target = route_grid.Target(self.g, net, pads, island=island, any_via=any_via, points=points,
                                   copper=copper, exclude=exclude)
        xs = [sx] + [self.r.P(*t)[0] for t in to] + [p[1] for p in points]
        ys = [sy] + [self.r.P(*t)[1] for t in to] + [p[2] for p in points]
        box = (min(xs) - margin, min(ys) - margin, max(xs) + margin, max(ys) + margin)
        aim = None
        if to and not (island or any_via or copper):
            aim = self.r.P(*to[0])
        res = self.g.search(net, width, starts, target.hit, box, allow_b=allow_b,
                            via_cost=via_cost, max_vias=max_vias, aim=aim, avoid=avoid)
        if res is None:
            self.failed.append((net, start, to, why))
            print(f"  NOT ROUTED: {net} from {start} to {to or ('island' if island else 'via')} ({why})")
            return None
        path, how = res
        runs = route_grid.simplify(path)
        layers = {route_grid.F: F, route_grid.B: B}
        for k, (layer, pts) in enumerate(runs):
            if k > 0:
                x, y = pts[0]
                self.r.via(net, x, y, why or f"{net} layer change")
            if len(pts) > 1:
                route_net(self.r.board, net, pts, width, layers[layer])
        if how == "via":
            x, y = runs[-1][1][-1]
            self.r.via(net, x, y, why or f"{net} into its In2 island")
        self.refresh()
        return runs


def stage_supplies_u3(r):
    """U3's supply, GND and low-speed escapes (rulings AU, AY): every pin with
    a 0.15 mm escape, the supply pins to their own vias and capacitors."""
    P = r.P
    W = 0.15
    T = lambda net, pts, w=W: r.net(net, pts, w)
    V = lambda net, x, y, why: r.via(net, x, y, why)
    u = lambda n: P("U3", n)
    # GND pins 25 and 29 into the exposed pad
    for n in (25, 29):
        x, y = u(n)
        T("GND", [(x, y), (x + 0.75, y)])
    # -- north --------------------------------------------------------------
    # pin 14 up the channel between RX_N and TX_P, in one segment beside TX_P's
    x, y = u(14)
    T("+1V0", [(x, y), (x, y - NECK_LEN), (x + 0.1, 16.75)])
    T("+1V0", [(x + 0.0, 16.75), P("C16", 1)])
    T("+1V0", [P("C16", 1), (23.65, 15.85)])
    V("+1V0", 23.65, 15.85, "C16 / pin 14 into the +1V0 island")
    T("GND", [P("C16", 2), (22.6, 16.0)])
    V("GND", 22.6, 16.0, "C16's GND")
    # pin 19 west above pin 20's pad, to its via between the USB 2.0 vias and C8
    x, y = u(19)
    T("+1V0", [(x, y), (x, 19.85), (21.35, 19.85), (21.1, 20.1)])
    V("+1V0", 21.1, 20.1, "pin 19 into the +1V0 island")
    # pin 20 (AVDD33) west to C8, below pin 19's via
    x, y = u(20)
    T("AVDD33_LDO", [(x, 20.78), (P("C8", 1)[0], 20.78)])
    # pin 11 north-east to C7, then a via to B.Cu and over to the +3V3 plane east
    x, y = u(11)
    T("+3V3", [(x, y), (x + 0.05, 20.1), (26.25, 19.7), (P("C7", 1)[0] - 0.2, 19.7), P("C7", 1)])
    T("+3V3", [P("C7", 1), (P("C7", 1)[0], 18.2)])
    V("+3V3", P("C7", 1)[0], 18.2, "C7 / pin 11 to B.Cu (the plane under it is +1V0)")
    r.net("+3V3", [(P("C7", 1)[0], 18.2), (29.9, 18.2)], 0.3, B)
    V("+3V3", 29.9, 18.2, "C7 / pin 11 into the +3V3 plane east of x 29.4")
    T("GND", [P("C7", 2), (28.1, 19.0)])
    V("GND", 28.1, 19.0, "C7's GND")
    # -- east ---------------------------------------------------------------
    # pin 8 between MDI3 (lifted) and MDI2 to its via in the +1V0 island, C13 beside it
    x, y = u(8)
    T("+1V0", [(x, y), (27.3, y), (27.6, 21.9), (28.4, 21.9), (28.7, 21.6), (28.7, 21.1)])
    V("+1V0", 28.7, 21.1, "pin 8 into the +1V0 island")
    T("+1V0", [(28.7, 21.35), P("C13", 1)])
    T("GND", [P("C13", 2), (31.0, 21.35)])
    V("GND", 31.0, 21.35, "C13's GND")
    # pin 3 between MDI1 and MDI0 (dropped) to its via, C12 beside it; the via
    # is over the +3V3 plane, so B.Cu takes it to pin 8's via
    x, y = u(3)
    T("+1V0", [(x, y), (27.3, y), (27.6, 24.1), (28.0, 24.1), (28.3, 24.4)])
    V("+1V0", 28.3, 24.4, "pin 3 to B.Cu (the plane under it is +3V3)")
    T("+1V0", [(28.3, 24.4), P("C12", 1)])
    T("GND", [P("C12", 2), (30.9, 24.4)])
    V("GND", 30.9, 24.4, "C12's GND")
    r.net("+1V0", [(28.3, 24.4), (28.7, 24.0), (28.7, 21.1)], 0.3, B)
    # -- west ---------------------------------------------------------------
    # pin 21 (+5V_SW) west under C8 to its via in the +5V_SW island
    x, y = u(21)
    T("+5V_SW", [(x, y), (20.5, y), (20.4, 21.3), (16.7, 21.3), (16.4, 21.35)])
    V("+5V_SW", 16.4, 21.35, "pin 21 into the +5V_SW island")
    # pin 22 (DVDD10) west to C17, under pin 21's line
    x, y = u(22)
    T("DVDD10_UPS", [(x, y), (20.7, y), (20.4, 21.95), P("C17", 1)])
    # pins 23 and 26 (+3V3) joined at x 20.85, one via, C10 west of it
    for n in (23, 26):
        x, y = u(n)
        T("+3V3", [(x, y), (20.85, y)])
    T("+3V3", [(20.85, u(23)[1]), (20.85, u(26)[1])])
    T("+3V3", [(20.85, 22.65), (20.4, 22.65)])
    V("+3V3", 20.4, 22.65, "pins 23 / 26 / C10 into the +3V3 plane")
    T("+3V3", [(20.4, 22.65), P("C10", 1)])
    # C10's and C17's GND share one via between them
    T("GND", [P("C10", 2), (18.05, 22.75)], 0.3)
    T("GND", [P("C17", 2), (18.05, 22.75)], 0.3)
    V("GND", 18.05, 22.75, "C10 / C17 GND")
    # pin 27 (+5V_SW) west through C18 to its via
    x, y = u(27)
    T("+5V_SW", [(x, y), (P("C18", 1)[0], y), (17.9, 23.75)])
    V("+5V_SW", 17.9, 23.75, "pin 27 / C18 into the +5V_SW island")
    # pin 30 (ETH_LED1) west to its via
    x, y = u(30)
    T("ETH_LED1", [(x, y), (20.2, y), (20.2, 24.85)])
    V("ETH_LED1", 20.2, 24.85, "ETH_LED1 to B.Cu, towards J2")
    # -- south --------------------------------------------------------------
    # pin 32 (ETH_LED0) south-west to its via
    x, y = u(32)
    T("ETH_LED0", [(x, y), (x, 26.0), (22.45, 26.25), (21.75, 26.25), (21.35, 26.65)])
    V("ETH_LED0", 21.35, 26.65, "ETH_LED0 to B.Cu, towards J2 (east of the AW band)")
    # pin 33 (+3V3) leaning west, to its via
    x, y = u(33)
    T("+3V3", [(x, y), (x, 26.0), (22.9, 26.45), (22.9, 26.6), (22.2, 27.0)])
    V("+3V3", 22.2, 27.0, "pin 33 into the +3V3 plane")
    # pin 34 (+1V0) to its via over C15
    x, y = u(34)
    T("+1V0", [(x, y), (x, 26.0), (23.35, 26.45), (23.35, 26.95), (23.05, 27.3)])
    V("+1V0", 23.05, 27.3, "pin 34 / C15 to B.Cu (the plane under it is +3V3)")
    T("+1V0", [(23.05, 27.3), P("C15", 1)])
    # XTAL1 straight down the channel between Y1's pads
    x, y = u(35)
    T("XTAL1", [(x, y), (x, 27.8), (24.0, 28.0), (24.0, 31.6), (P("Y1", 1)[0], 31.6)])
    T("XTAL1", [P("Y1", 1), P("C19", 1)])
    # XTAL2 leaning west, then east under the others to R14
    x, y = u(36)
    T("XTAL2", [(x, y), (x, 26.0), (24.15, 26.45), (24.15, 27.45), (P("R14", 1)[0], 27.45), P("R14", 1)])
    T("XTAL2_Y1", [P("R14", 2), (P("R14", 2)[0], 29.2), (P("Y1", 3)[0] + 0.6, 29.2)])
    T("XTAL2_Y1", [P("R14", 2), (P("C20", 1)[0], 29.4), P("C20", 1)])
    # pin 37 (+1V0) down, then east under RSET to its via, C14 beside it
    x, y = u(37)
    T("+1V0", [(x, y), (x, 26.95), (26.8, 26.95), (27.1, 27.15)])
    V("+1V0", 27.1, 27.15, "pin 37 to B.Cu (the plane under it is +3V3)")
    # pin 38 (RSET) down to y 26.45, east, down into R11
    x, y = u(38)
    T("RSET", [(x, y), (x, 26.45), (P("R11", 1)[0], 26.45), P("R11", 1)])
    # -- south-west: the LDO, R12 and the caps on the +3V3 plane, laid before
    # the long low-speed runs take the space
    r.net("+3V3_REG", [P("U4", 5), (P("C6", 1)[0], 29.6), P("C6", 1)], 0.5)
    x, y = P("C6", 2)
    T("GND", [(x, y), (x, 29.1)], 0.3)
    V("GND", x, 29.1, "C6 GND")
    x, y = P("R12", 1)
    T("+3V3", [(x, y), (x, 25.3)], 0.3)
    V("+3V3", x, 25.3, "R12 (DNP link) +3V3 to B.Cu (the plane under it is +5V_SW)")
    r.net("+3V3", [(x, 25.3), (x, 25.95), (20.3, 25.95)], 0.2, B)
    V("+3V3", 20.3, 25.95, "R12 / C11 into the +3V3 plane")
    T("+3V3", [(20.3, 25.95), P("C11", 1)], 0.3)
    T("+3V3", [P("C11", 1), P("C9", 1)], 0.3)
    T("GND", [P("C18", 2), (18.0, 24.65)], 0.3)
    V("GND", 18.0, 24.65, "C18 GND")
    T("GND", [P("C11", 2), (18.0, 26.7), P("C9", 2)], 0.3)
    V("GND", 18.0, 26.7, "C11 / C9 GND")
    x, y = P("R11", 2)
    T("GND", [(x, y), (x, 29.35)], 0.3)
    V("GND", x, 29.35, "R11 (RSET) GND")
    x, y = P("C14", 2)
    T("GND", [(x, y), (x + 0.8, y)], 0.3)
    V("GND", x + 0.8, y, "C14 GND")
    # pins 39 and 40 (+3V3) joined under the pads, east to their via
    for n in (39, 40):
        x, y = u(n)
        T("+3V3", [(x, y), (x, 26.0)])
    T("+3V3", [(u(39)[0], 26.0), (26.6, 26.0), (26.9, 25.75)])
    V("+3V3", 26.9, 25.75, "pins 39 / 40 into the +3V3 plane")
    # the south +1V0 vias join pin 3's on B.Cu
    r.net("+1V0", [(23.05, 27.3), (23.6, 27.85), (26.4, 27.85), (27.1, 27.15)], 0.3, B)
    r.net("+1V0", [(27.1, 27.15), (28.3, 25.95), (28.3, 24.4)], 0.3, B)


def stage_buck(r):
    """U6's hot loop on F.Cu (netlist stackup.rules): C3 -> IN (pins 4 / 5) ->
    GND (pin 2) straight back under U6's body to C3, the switch node short and
    wide to L2, FB away from it to the south."""
    P = r.P
    u = lambda n: P("U6", n)
    # input: C3.1 up to pins 4 and 5
    r.net("+5V_SW", [P("C3", 1), (P("C3", 1)[0], 7.6), (31.75, 6.95), u(4)], 0.6)
    r.net("+5V_SW", [u(4), (31.6, 6.95), (31.6, 5.05), u(5)], 0.5)
    r.via("+5V_SW", 33.25, 9.6, "C3 / U6 IN into the +5V_SW island")
    r.net("+5V_SW", [P("C3", 1), (33.25, 9.6)], 0.6)
    # return: pin 2 east under the body (between the pad columns) and down to C3.2
    r.net("GND", [u(2), (30.0, 6.0), (30.0, 8.6), P("C3", 2)], 0.3)
    r.via("GND", 30.45, 10.95, "C3 / U6 GND to In1")
    r.net("GND", [P("C3", 2), (30.45, 10.95)], 0.5)
    # switch node
    r.net("SW_1V0", [u(1), (28.4, 4.95), (P("L2", 1)[0], 4.95)], 0.6)
    # output: L2.2 to C4.1, JP2.1, C24.1, R5.1
    r.net("+1V0_REG", [P("L2", 2), P("C4", 1)], 0.8)
    r.net("+1V0_REG", [P("C4", 1), (21.35, 5.8), (P("JP2", 1)[0], 7.3), P("JP2", 1)], 0.4)
    r.net("+1V0_REG", [P("L2", 2), (P("L2", 2)[0], 7.5), P("C24", 1)], 0.3)
    r.net("+1V0_REG", [P("C24", 1), (P("R5", 1)[0], 7.9), P("R5", 1)], 0.3)
    r.via("GND", 18.65, 4.9, "C4 (buck output) GND")
    r.net("GND", [P("C4", 2), (18.65, 4.9)], 0.5)
    # feedback, south of U6 and away from the switch node
    r.net("FB_1V0", [u(3), (27.6, 7.5), P("C24", 2)], 0.2)
    r.net("FB_1V0", [(27.6, 7.5), (27.6, 9.4), P("R5", 2)], 0.2)
    r.net("FB_1V0", [(27.6, 9.4), (27.6, 10.0), (28.2, 10.425), P("R6", 1)], 0.2)
    r.via("GND", 29.4, 8.775, "R6 (divider) GND")
    r.net("GND", [P("R6", 2), (29.4, 8.775), (30.0, 8.6)], 0.3)


def stage_supplies(r):
    """The rails between their parts and their In2 islands; widths by current
    (netlist.yaml design_notes.rail_currents: about 0.9 A on +5V / +5V_SW,
    0.3 A on +3V3, 0.35 A on +1V0)."""
    P = r.P
    g = Grid(r)
    # +5V: J3's VBUS pin sits between the RX pair's pads; a 0.8 mm via right at it
    j = P("J3", 1)
    r.net("+5V", [j, (6.5, j[1])], 0.6)
    r.via("+5V", 6.5, j[1], "VBUS from J3 into the +5V island", 0.8, 0.4)
    # U9's VBUS pin has D+ / D- pads either side and the USB 2.0 vias east of
    # it: its via sits at the pad's outer end, overlapping the pad
    x, y = P("U9", 5)
    r.via("+5V", x + 0.5, y, "U9 VBUS into the +5V island (no room off the pad)")
    for pad in (("U7", 1), ("U7", 3), ("C1", 1), ("C2", 1), ("TP2", 1)):
        g.connect("+5V", pad, island=True, width=0.5, allow_b=False, why=f"{pad[0]}.{pad[1]} into the +5V island")
    # +5V_SW: the two islands joined on F.Cu along the top edge
    r.via("+5V_SW", 17.9, 2.5, "+5V_SW island west to the buck's island")
    r.net("+5V_SW", [(17.9, 2.5), (30.3, 2.5)], 0.5)
    r.via("+5V_SW", 30.3, 2.5, "+5V_SW island west to the buck's island")
    for pad in (("U7", 6), ("U4", 1), ("U4", 3), ("C5", 1)):
        g.connect("+5V_SW", pad, island=True, width=0.5, allow_b=False, why=f"{pad[0]}.{pad[1]} into the +5V_SW island")
    g.connect("+5V_SW", ("TP3", 1), copper=True, island=True, width=0.3, margin=8.0, max_vias=3,
              points=[(None, 30.3, 2.5, 0.2)], why="TP3 to +5V_SW")
    # the two +3V3 islands (NE corner, and the main one) joined at x 55.5
    r.via("+3V3", 55.5, 11.9, "+3V3 NE island to the main +3V3 island")
    r.net("+3V3", [(55.5, 11.9), (55.5, 13.3)], 0.3)
    r.via("+3V3", 55.5, 13.3, "+3V3 NE island to the main +3V3 island")
    # +3V3_REG and +3V3
    g.connect("LS_CT", ("U7", 4), to=[("C26", 1)], width=0.2, allow_b=False, why="U7 soft start")
    g.connect("+3V3_REG", ("C6", 1), to=[("JP1", 1)], width=0.5, margin=5.0, why="C6 to JP1")
    g.connect("+3V3", ("JP1", 2), island=True, width=0.4, margin=12.0, max_vias=3,
              why="JP1 to the +3V3 plane")
    for pad in (("R7", 1), ("R8", 1), ("TP4", 1)):
        g.connect("+3V3", pad, island=True, width=0.3, allow_b=False, why=f"{pad[0]}.{pad[1]} into the +3V3 plane")
    # +1V0
    g.connect("+1V0", ("JP2", 2), island=True, width=0.5, allow_b=False, why="JP2 into the +1V0 island")
    g.connect("+1V0", ("TP5", 1), island=True, width=0.3, allow_b=False, margin=8.0, why="TP5 to the +1V0 island")
    g.connect("+1V0", ("C14", 1), copper=True, width=0.3, margin=6.0, why="C14 to pin 37's B.Cu link")
    return g


def stage_lowspeed(r):
    P = r.P
    g = Grid(r)
    # the shield posts are joined on B.Cu: on F.Cu the line would run beside the
    # MDI0 / MDI1 lanes up the channel east of J2's pins
    g.connect("SHIELD", ("J2", "SH2"), to=[("J2", "SH1")], width=0.3, margin=2.0,
              avoid=[(route_grid.F, 36.0, 9.0, 46.0, 27.0)], why="SHIELD posts")
    g.connect("SHIELD", ("J2", "SH1"), to=[("C25", 1)], width=0.3, allow_b=False, why="SHIELD to C25")
    g.connect("SHIELD", ("J2", "SH1"), to=[("R13", 1)], width=0.3, allow_b=False, why="SHIELD to R13")
    g.connect("MDI_CT", ("J2", "6"), to=[("C21", 1)], width=0.3, allow_b=False, why="MDI_CT to C21")
    g.connect("MDI_CT", ("J2", "5"), to=[("J2", "6")], width=0.3, allow_b=False, why="MDI_CT pins")
    g.connect("DVDD10_UPS", ("C17", 1), to=[("TP7", 1)], width=0.2, margin=12.0, max_vias=3, why="DVDD10 to TP7")
    g.connect("AVDD33_LDO", ("C8", 1), to=[("R12", 2)], width=0.2, allow_b=False, margin=4.0, why="AVDD33 to R12")
    g.connect("AVDD33_LDO", ("R12", 2), to=[("TP6", 1)], width=0.2, margin=12.0, max_vias=3, why="AVDD33 to TP6")
    # the LED lines keep off F.Cu in J2's MDI pin field and the MDI corridor
    # west of it (x 26.9 to 42.5, y 11 to 27.5): they cross under it on B.Cu
    mdi_field = [(route_grid.F, 26.9, 11.0, 42.5, 27.5)]
    g.connect("ETH_LED1", (20.2, 24.85, route_grid.B), to=[("J2", "12")], width=0.2, margin=12.0, max_vias=3,
              avoid=mdi_field, why="LED1 to J2")
    g.connect("ETH_LED0", (21.35, 26.65, route_grid.B), to=[("J2", "14")], width=0.2, margin=12.0, max_vias=3,
              avoid=mdi_field, why="LED0 to J2")
    g.connect("LED_G_A", ("R8", 2), to=[("J2", "11")], width=0.2, margin=4.0, why="LED_G_A")
    g.connect("LED_Y_A", ("R7", 2), to=[("J2", "13")], width=0.2, margin=4.0, why="LED_Y_A")
    return g


GND_PADS = [("C1", 2), ("C2", 2), ("C8", 2),
            ("C15", 2), ("C20", 2), ("C21", 2), ("C25", 2),
            ("R13", 2), ("R11", 2), ("U7", 2), ("U8", 2), ("U9", 2), ("J3", 4), ("J3", 7),
            ("TP1", 1), ("Y1", 2), ("Y1", 4)]


def stage_gnd(r):
    """Every GND pad on F.Cu outside the U4 patch to its own via (In1, B.Cu)."""
    g = Grid(r)
    # U8's GND pin sits between the TX pair's pads with a TX line either side
    # (ruling AS): the only place for its via is in the pad
    x, y = r.P("U8", 2)
    r.via("GND", x, y, "U8 GND, in the pad: the TX lines pass on both sides")
    g.refresh()
    for pad in GND_PADS:
        if pad == ("U8", 2):
            continue
        g.connect("GND", pad, any_via=True, copper=True, width=0.3, allow_b=False, margin=2.5,
                  why=f"{pad[0]}.{pad[1]} GND")
    return g


# Ruling BA: no open via in or touching a pad of a hand-soldered part (all but
# U3 and Y1, which PCBWay reflows). The stages above laid three such vias; this
# last stage takes each out of its pad where the copper allows, and tents from
# the back (as under U3's pad) the one that cannot move. It is also what
# tools/amend_pcb.py applies to the routed board.
PAD_VIAS = [
    ("+5V", ("U9", 5), "island"),       # partly in U9's VBUS pad
    ("GND", ("U8", 2), "via"),          # fully in U8's GND pad
    ("GND", ("C4", 2), "via"),          # touching C4's GND pad
]


def _vias_in_pad(board, net, ref, pad):
    P = Pads(board)
    fp = board.FindFootprintByReference(ref)
    p = next(q for q in fp.Pads() if q.GetNumber() == str(pad))
    found = []
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_VIA_T and t.GetNetname() == net:
            x, y = xy(t.GetPosition())
            r = pcbnew.ToMM(t.GetWidth(pcbnew.F_Cu)) / 2
            bb = p.GetBoundingBox()
            (x0, y0), (x1, y1) = xy(bb.GetOrigin()), xy(bb.GetEnd())
            dx = max(x0 - x, 0, x - x1)
            dy = max(y0 - y, 0, y - y1)
            if math.hypot(dx, dy) <= r + 0.001:
                found.append(t)
    return found


def stage_pad_vias(r):
    board = r.board
    report = []
    for net, (ref, pad), kind in PAD_VIAS:
        old = _vias_in_pad(board, net, ref, pad)
        if not old:
            report.append((ref, pad, "no via in or at the pad"))
            continue
        # tracks that ended on the old via end on the pad's side anyway: the
        # only ones laid are C4.2's stub, which the new connection replaces
        gone = [xy(v.GetPosition()) for v in old]
        for v in old:
            vx, vy = xy(v.GetPosition())
            for t in list(board.GetTracks()):
                if t.Type() == pcbnew.PCB_TRACE_T and t.GetNetname() == net:
                    a, b = xy(t.GetStart()), xy(t.GetEnd())
                    if math.hypot(a[0] - vx, a[1] - vy) < 0.01 or math.hypot(b[0] - vx, b[1] - vy) < 0.01:
                        board.Delete(t)
            board.Delete(v)
        r.vias = [q for q in r.vias if not any(
            abs(q[1] - gx) < 0.01 and abs(q[2] - gy) < 0.01 for gx, gy in gone)]
        if (ref, pad) == ("U9", 5):
            # The pad's only open side is east, where the USB 2.0 return via
            # of stage_usb2 sat 0.65 mm off: that via steps 0.46 mm further
            # out (1.35 mm from D+'s via instead of 0.92), and VBUS's via takes
            # the place just past the pad's end, inside the +5V island.
            for t in list(board.GetTracks()):
                if t.Type() == pcbnew.PCB_VIA_T and t.GetNetname() == "GND":
                    vx, vy = xy(t.GetPosition())
                    if abs(vx - 12.4) < 0.01 and abs(vy - 18.0) < 0.01:
                        board.Delete(t)
            r.vias = [q for q in r.vias if not (q[0] == "GND" and abs(q[1] - 12.4) < 0.01 and abs(q[2] - 18.0) < 0.01)]
            r.via("GND", 12.7, 18.35, "USB 2.0 return near U9's vias, 1.35 mm from D+'s (ruling BA moved it)")
            x, y = r.P(ref, pad)
            route_net(board, net, [(x, y), (11.75, y)], 0.3)
            r.via(net, 11.75, y, "U9 VBUS into the +5V island, just past the pad's end (ruling BA)")
            report.append((ref, pad, "moved off the pad (just past its east end)"))
            continue
        g = Grid(r)
        res = g.connect(net, (ref, pad), island=(kind == "island"), any_via=(kind == "via"),
                        copper=(kind == "via"), width=0.3 if net != "+5V" else 0.3, allow_b=False,
                        margin=2.5, why=f"{ref}.{pad} {net}, via out of the pad (ruling BA)")
        if res is None:
            x, y = r.P(ref, pad)
            via = add_via(board, net, x, y)
            via.SetBackTentingMode(pcbnew.TENTING_MODE_TENTED)
            r.vias.append((net, x, y, f"{ref}.{pad} {net} in the pad, tented from the back (ruling BA)"))
            report.append((ref, pad, "in the pad, tented from the back: no room off the pad"))
        else:
            report.append((ref, pad, "moved off the pad"))
    r.pad_vias = report


# ---------------------------------------------------------------------------
# Review 1 (rulings BE, BF, BG, BH, BI). The board was routed and committed
# before these; each is a late stage that rips exactly what it replaces and
# lays it again, so that a fresh gen_pcb.py + route_pcb.py run still gives the
# committed copper, and tools/amend_pcb.py applies the same stages in place.
# ---------------------------------------------------------------------------

U3_AREA = (20.55, 19.55, 27.45, 26.45)       # the "U3_escape" rule area (gen_pcb.py)


def split_at_area(points, area=U3_AREA):
    """Insert the points where a polyline crosses the edge of U3's escape area,
    so that no segment is both inside and outside it: ruling AU's 0.2 mm then
    applies only to the part that is in the area (ruling BF). KiCad's
    insideArea() is true when any copper of a segment touches the area, so the
    segment beyond the cut still carries AU, but only where its round end
    reaches into the area: at most half its width past the edge. au_overhangs()
    measures what lies there."""
    def inside(q):
        return area[0] <= q[0] <= area[2] and area[1] <= q[1] <= area[3]
    out = [points[0]]
    for a, b in zip(points, points[1:]):
        if inside(a) != inside(b):
            lo, hi = 0.0, 1.0
            for _ in range(40):
                m = (lo + hi) / 2
                q = (a[0] + (b[0] - a[0]) * m, a[1] + (b[1] - a[1]) * m)
                if inside(q) == inside(a):
                    lo = m
                else:
                    hi = m
            q = (round(a[0] + (b[0] - a[0]) * hi, 4), round(a[1] + (b[1] - a[1]) * hi, 4))
            if math.hypot(q[0] - out[-1][0], q[1] - out[-1][1]) > 0.001 and \
                    math.hypot(q[0] - b[0], q[1] - b[1]) > 0.001:
                out.append(q)
        out.append(b)
    return out


def au_overhangs(board, step=0.01):
    """Ruling BF: where ruling AU's 0.2 mm is used outside U3's escape area.
    For every pair of F.Cu tracks of different nets that both touch the area
    and come nearer than the class clearance (0.3 mm if either is a supply or
    GND, else 0.2), the copper of the pair outside the area that is that near:
    {(net a, net b): (least gap mm, how far past the area edge it reaches mm)}."""
    A = U3_AREA
    tr = []
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_TRACE_T and t.GetLayer() == pcbnew.F_Cu:
            a, b, w = xy(t.GetStart()), xy(t.GetEnd()), pcbnew.ToMM(t.GetWidth())
            dx = max(A[0] - max(a[0], b[0]), 0, min(a[0], b[0]) - A[2])
            dy = max(A[1] - max(a[1], b[1]), 0, min(a[1], b[1]) - A[3])
            if math.hypot(dx, dy) <= w / 2:          # bounding box: good enough for straight escapes
                tr.append((t.GetNetname(), a, b, w))

    def outside_by(q):
        return math.hypot(max(A[0] - q[0], 0, q[0] - A[2]), max(A[1] - q[1], 0, q[1] - A[3]))
    out = {}
    for na, a, b, wa in tr:
        length = math.hypot(b[0] - a[0], b[1] - a[1])
        k = max(1, int(length / step))
        for i in range(k + 1):
            q = (a[0] + (b[0] - a[0]) * i / k, a[1] + (b[1] - a[1]) * i / k)
            o = outside_by(q)
            if o <= 0:
                continue
            for nb, c, d, wb in tr:
                if nb == na or nb == partner(na):
                    continue
                cls = 0.3 if na in route_grid.POWER or nb in route_grid.POWER else 0.2
                g = seg_point_distance(c, d, q) - wa / 2 - wb / 2
                if g < cls - 1e-4:
                    key = tuple(sorted((na, nb)))
                    best = out.get(key, (9.0, 0.0))
                    out[key] = (round(min(best[0], g), 3), round(max(best[1], o), 3))
    return out


def rip(board, net, keep=lambda a, b, layer: False, vias=True):
    """Remove every track of `net` (except those `keep` says to keep) and, if
    `vias`, every via of it. Returns the number of items removed."""
    n = 0
    for t in list(board.GetTracks()):
        if t.GetNetname() != net:
            continue
        if t.Type() == pcbnew.PCB_VIA_T:
            if vias:
                board.Delete(t)
                n += 1
        elif not keep(xy(t.GetStart()), xy(t.GetEnd()), t.GetLayer()):
            board.Delete(t)
            n += 1
    return n


def rip_from_pad(board, ref, pad):
    """Remove the copper that hangs off one pad only: follow tracks and vias of
    the pad's net from the pad until a junction (a point shared by more than
    two items) or another pad. Returns the items removed."""
    fp = board.FindFootprintByReference(ref)
    p = next(q for q in fp.Pads() if q.GetNumber() == str(pad))
    net = p.GetNetname()
    start = xy(p.GetPosition())
    other_pads = [xy(q.GetPosition()) for f in board.GetFootprints() for q in f.Pads()
                  if q.GetNetname() == net and not (f.GetReference() == ref and q.GetNumber() == str(pad))]
    items = [t for t in board.GetTracks() if t.GetNetname() == net]

    def ends(t):
        if t.Type() == pcbnew.PCB_VIA_T:
            q = xy(t.GetPosition())
            return [q, q]
        return [xy(t.GetStart()), xy(t.GetEnd())]

    def near(a, b, d=0.01):
        return math.hypot(a[0] - b[0], a[1] - b[1]) < d

    def in_pad(q):
        return p.HitTest(vec(*q))
    removed, frontier, seen = [], [start], set()
    while frontier:
        q = frontier.pop()
        tracks_at = [t for t in items if t.Type() != pcbnew.PCB_VIA_T and
                     any((near(e, q) or (q == start and in_pad(e))) for e in ends(t))]
        vias_at = [t for t in items if t.Type() == pcbnew.PCB_VIA_T and near(ends(t)[0], q)]
        if q != start and (len(tracks_at) > 2 or any(near(q, o, 0.3) for o in other_pads)):
            continue                       # a junction or another pad: stop here
        for t in vias_at + tracks_at:
            if id(t) in seen:
                continue
            seen.add(id(t))
            removed.append(t)
            for e in ends(t):
                if not near(e, q):
                    frontier.append(e)
    n = len(removed)
    for t in removed:
        board.Delete(t)
    return n


def stage_coupling(r):
    """Rulings BE / BF / BG. The SuperSpeed TX pair, U3 to the caps, now
    coupled at the class gap with route_pair, shifted 0.215 mm east right
    after its necks and fanned out at 45 degrees about 1 mm before C23; TX_CONN
    coupled from the caps to just east of U8 pin 1, where P drops into U8's
    channel (ruling AS); pin 14's escape keeps 0.3 mm from RX_N and TX_P
    outside the escape area except within 0.2 mm of its edge (the named
    exception of ruling BF, AU_OVERHANGS in tests/check_fab_release.py);
    USB 2.0's run west from U3 is moved south and steps 0.2 mm west above
    pin 19, so D- keeps 0.3 mm or more from RX_P outside the escape area but
    for the last 0.25 mm before it."""
    board, P = r.board, r.P
    for net in ("USB3_TX_P", "USB3_TX_N", "USB3_TX_CONN_P", "USB3_TX_CONN_N", "USB2_D_P", "USB2_D_N"):
        rip(board, net)
    # pin 14's old escape: everything of +1V0 between its pad and C16.1
    in_channel = lambda q: 24.55 <= q[0] <= 24.75 and 16.7 <= q[1] <= 20.6
    rip(board, "+1V0", vias=False, keep=lambda a, b, layer: not (in_channel(a) or in_channel(b)))
    for k in list(r.lengths):
        if k.startswith(("USB3_TX", "USB2")):
            r.lengths.pop(k)
            r.stubs.pop(k, None)
    r.vias = [v for v in r.vias if not v[0].startswith("USB2_D")]
    T = lambda net, pts, w, layer=F: r.net(net, split_at_area(pts), w, layer, exception="AR" if layer == B else None)

    # -- TX, U3 to C22 / C23 ----------------------------------------------------
    p12, p13 = P("U3", 12), P("U3", 13)
    c22_1, c23_1 = P("C22", 1), P("C23", 1)
    yn = p12[1] - NECK_LEN
    T("USB3_TX_P", [p13, (p13[0], yn)], NECK_W)
    T("USB3_TX_N", [p12, (p12[0], yn)], NECK_W)
    xc = 25.4                     # the pair's centre after the 0.2 mm shift east
    y_fan = c23_1[1] + 1.25       # N leaves at 45 degrees about 1 mm before C23
    x0 = (p12[0] + p13[0]) / 2
    centre = [(x0, yn), (x0, yn - 0.1), (xc, yn - 0.1 - (xc - x0)), (xc, y_fan)]
    lp, ln, _ = route_pair(board, "USB3_TX_P", "USB3_TX_N", split_at_area(centre), p_left=True,
                           head_p=[(p13[0], yn)], head_n=[(p12[0], yn)],
                           tail_p=[(xc - PITCH / 2, c22_1[1] + 0.12)],
                           tail_n=[(c23_1[0], y_fan - (c23_1[0] - xc - PITCH / 2)), (c23_1[0], c23_1[1] + 0.12)])
    r.lengths["USB3_TX_P"] = r.lengths.get("USB3_TX_P", 0) + lp
    r.lengths["USB3_TX_N"] = r.lengths.get("USB3_TX_N", 0) + ln

    # -- pin 14 (+1V0): up the channel, 0.3 mm from RX_N and TX_P outside the area
    x, y = P("U3", 14)
    T("+1V0", [(x, y), (x, 19.6), (x + 0.1, 19.5), (x + 0.1, 16.75), P("C16", 1)], 0.15)

    # -- TX_CONN, C22 / C23 to J3, U8 as a tee -----------------------------------
    u8 = {n: P("U8", n) for n in "123456"}
    y_ch = (u8["2"][1] + u8["5"][1]) / 2 - 0.40
    j5, j6 = P("J3", 5), P("J3", 6)
    c22_2, c23_2 = P("C22", 2), P("C23", 2)
    x3, x1 = u8["3"][0], u8["1"][0]
    yc0 = TX_CONN_Y_N + PITCH / 2              # the pair's centre leaving the caps
    yc1 = 15.0                                 # and from x 21 west
    x_drop = 18.6                              # P leaves N here, 1.6 mm east of U8 pin 1
    centre = [(c22_2[0], yc0), (21.3, yc0), (21.3 - (yc1 - yc0), yc1), (x_drop, yc1)]
    # travelling west, N (north) is on the right
    lp, ln, _ = route_pair(board, "USB3_TX_CONN_P", "USB3_TX_CONN_N", centre, p_left=True,
                           head_p=[c22_2], head_n=[c23_2, (c23_2[0], TX_CONN_Y_N)],
                           tail_p=[(x_drop - (y_ch - yc1 - PITCH / 2), y_ch), (x3 - 0.7375, y_ch),
                                   (x3 - 2.25, 15.1875), (7.8125, 15.1875), (7.0, j6[1]), (j6[0] + 0.9, j6[1])],
                           tail_n=[(8.3125, yc1 - PITCH / 2), (7.5, j5[1]), (j5[0] + 0.9, j5[1])])
    r.lengths["USB3_TX_CONN_P"] = r.lengths.get("USB3_TX_CONN_P", 0) + lp
    r.lengths["USB3_TX_CONN_N"] = r.lengths.get("USB3_TX_CONN_N", 0) + ln
    r.net("USB3_TX_CONN_N", [(x3, yc1 - PITCH / 2), u8["3"]], USB_W, stub=True)
    r.net("USB3_TX_CONN_P", [(x1, y_ch), u8["1"]], USB_W, stub=True)

    # -- USB 2.0 (ruling BG): the run west from U3 moved south, vias re-placed
    global USB2_VIA_U3, USB2_FCU_Y, USB2_BCU, USB2_FCU_JOG
    USB2_VIA_U3 = {"USB2_D_N": (20.8, 18.75), "USB2_D_P": (21.5, 19.15)}
    USB2_FCU_Y = {"USB2_D_N": 18.55, "USB2_D_P": 18.92}
    # the pair steps 0.2 mm west just above pin 19's run: D- then keeps
    # 0.4 mm from RX_P instead of the 0.2 the adjacent pins leave
    # (D- steps 0.15 mm later than D+, so the two 45-degree steps keep the pair's pitch)
    USB2_FCU_JOG = {"USB2_D_P": (19.45, -0.2), "USB2_D_N": (19.3, -0.2)}
    USB2_BCU = usb2_bcu()
    stage_usb2(r, return_via=False)


def stage_split_area(r):
    """Ruling BF: every F.Cu track that crosses the edge of U3's escape area is
    cut into two segments there (the copper is unchanged), so that ruling
    AU's 0.2 mm holds only for the part inside the area and the DRC checks the
    part outside at the class clearance. Returns the number of tracks cut."""
    board = r.board
    cut = 0
    for t in list(board.GetTracks()):
        if t.Type() != pcbnew.PCB_TRACE_T or t.GetLayer() != pcbnew.F_Cu:
            continue
        a, b = xy(t.GetStart()), xy(t.GetEnd())
        net, w = t.GetNetname(), pcbnew.ToMM(t.GetWidth())
        pts = split_at_area([a, b])
        if len(pts) == 2:
            continue
        board.Delete(t)
        route_net(board, net, pts, w, pcbnew.F_Cu)
        cut += 1
    r.area_cuts = cut
    return cut


def _place_on_bottom(board, ref, pad1_at, toward):
    """Put footprint `ref` on B.Cu with pad 1 at `pad1_at` and pad 2 in the
    direction `toward` (a unit vector) from it. Creates the footprint from netlist.yaml if the
    board does not have it yet (a part added after the board was routed)."""
    fp = board.FindFootprintByReference(ref)
    if fp is None:
        sys.path.insert(0, str(HERE))
        import yaml
        import gen_pcb
        gen_pcb.pcbnew = pcbnew
        netlist = yaml.safe_load((HERE.parent / "netlist.yaml").read_text())
        comp = netlist["components"][ref]
        fp = gen_pcb.load_footprint(ref, comp["footprint"], [])
        fp.SetReference(ref)
        fp.SetValue(str(comp.get("value", "")))
        fp.Reference().SetLayer(pcbnew.F_Fab)
        fp.Value().SetVisible(False)
        gen_pcb.apply_fitting(fp, ref, comp)
        board.Add(fp)
        for pad in fp.Pads():
            for name, ends in netlist["nets"].items():
                if f"{ref}.{pad.GetNumber()}" in (ends or []):
                    pad.SetNet(board.FindNet(name))
    if not fp.IsFlipped():
        fp.Flip(fp.GetPosition(), pcbnew.FLIP_DIRECTION_LEFT_RIGHT)
    for rot in (0, 90, 180, 270):
        fp.SetOrientationDegrees(rot)
        fp.SetPosition(vec(*pad1_at))
        p1 = next(q for q in fp.Pads() if q.GetNumber() == "1")
        p2 = next(q for q in fp.Pads() if q.GetNumber() == "2")
        (ax, ay), (bx, by) = xy(p1.GetPosition()), xy(p2.GetPosition())
        if (bx - ax) * toward[0] + (by - ay) * toward[1] > 0.5:
            break
    off = (pad1_at[0] - xy(p1.GetPosition())[0], pad1_at[1] - xy(p1.GetPosition())[1])
    pos = xy(fp.GetPosition())
    fp.SetPosition(vec(pos[0] + off[0], pos[1] + off[1]))
    return fp


# Ruling BH: the capacitors that sit on B.Cu directly at their pin's via, GND
# pad on the B.Cu pour. Pad 1 starts 0.1 mm clear of the via (ruling BI).
# C27 hangs south of pin 19's via, clear of ETH_LED1's B.Cu run east of it,
# with 0.65 mm of pour left between it and the USB 2.0 pair (ruling AW).
B_CU_CAPS = [("C14", (27.1, 27.15), (1, 0), "U3 pin 37 (+1V0)"),
             ("C27", (21.1, 20.1), (0, 1), "U3 pin 19 (+1V0)")]


def stage_decoupling(r):
    board = r.board
    if board.FindFootprintByReference("C14") and not board.FindFootprintByReference("C14").IsFlipped():
        rip_from_pad(board, "C14", 1)
        rip_from_pad(board, "C14", 2)
        r.vias = [v for v in r.vias if "C14" not in v[3]]
    for ref, (vx, vy), (ux, uy), why in B_CU_CAPS:
        reach = 0.3 + 0.1 + 0.28 + (0.22 if uy else 0)     # via r + 0.1 + half the pad (+ room for the pour)
        pad1 = (round(vx + ux * reach, 3), round(vy + uy * reach, 3))
        _place_on_bottom(board, ref, pad1, (ux, uy))
        r.net("+1V0", [(vx, vy), pad1], 0.3, B)
    r.P = Pads(board)


# Ruling BI: least copper gap from a via to a pad of a hand-soldered part (all
# but U3 and Y1, which PCBWay reflows); under a fab's 0.1 mm mask dam less is a
# via in the pad again. The one via left inside a pad (U8 pin 2, ruling BA,
# tented from the back) is the listed exception.
PAD_VIA_GAP = 0.1
PAD_VIA_EXCEPTIONS = [("U8", "2")]
REFLOWED = ("U3", "Y1")


def pad_via_gaps(board):
    """[(via net, (x, y), ref, pad, gap mm)] for every via closer than
    PAD_VIA_GAP to a pad of a hand-soldered part (bounding boxes)."""
    hits = []
    pads = [(fp.GetReference(), p) for fp in board.GetFootprints() if fp.GetReference() not in REFLOWED
            for p in fp.Pads()]
    for v in board.GetTracks():
        if v.Type() != pcbnew.PCB_VIA_T:
            continue
        x, y = xy(v.GetPosition())
        rv = pcbnew.ToMM(v.GetWidth(pcbnew.F_Cu)) / 2
        for ref, p in pads:
            bb = p.GetBoundingBox()
            (x0, y0), (x1, y1) = xy(bb.GetOrigin()), xy(bb.GetEnd())
            dx, dy = max(x0 - x, 0, x - x1), max(y0 - y, 0, y - y1)
            gap = math.hypot(dx, dy) - rv
            if p.GetShape() == pcbnew.PAD_SHAPE_CIRCLE:
                cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
                gap = math.hypot(x - cx, y - cy) - (x1 - x0) / 2 - rv
                dx, dy = abs(x - cx), abs(y - cy)
            if gap < PAD_VIA_GAP - 1e-6 and (ref, p.GetNumber()) not in PAD_VIA_EXCEPTIONS:
                hits.append((v.GetNetname(), (round(x, 3), round(y, 3)), ref, p.GetNumber(), round(gap, 3),
                             ((x0 + x1) / 2, (y0 + y1) / 2), (dx, dy)))
    return hits


def _move_footprint(board, ref, dx, dy):
    """Shift a footprint and the ends of tracks that sit in its pads."""
    fp = board.FindFootprintByReference(ref)
    inside = []
    for p in fp.Pads():
        for t in board.GetTracks():
            if t.Type() == pcbnew.PCB_TRACE_T and t.GetNetname() == p.GetNetname():
                for which in ("start", "end"):
                    q = t.GetStart() if which == "start" else t.GetEnd()
                    if p.HitTest(q):
                        inside.append((t, which))
    pos = xy(fp.GetPosition())
    fp.SetPosition(vec(pos[0] + dx, pos[1] + dy))
    for t, which in inside:
        q = xy(t.GetStart() if which == "start" else t.GetEnd())
        (t.SetStart if which == "start" else t.SetEnd)(vec(q[0] + dx, q[1] + dy))


# Where moving the via would run it into its neighbours, the part moves instead.
VIA_GAP_MOVE_PART = {("+1V0", "C15", "1"): (0.0, 0.07)}   # pin 34's via; V33 sits north of it


def stage_via_gaps(r):
    """Move every via that comes within PAD_VIA_GAP of a hand-soldered pad
    straight away from that pad until it is PAD_VIA_GAP + 0.01 clear, taking
    the ends of its own net's tracks along (or, in VIA_GAP_MOVE_PART, move the
    part away from the via)."""
    board = r.board
    moved = []
    for net, (x, y), ref, pad, gap, centre, d in pad_via_gaps(board):
        if (net, ref, pad) in VIA_GAP_MOVE_PART:
            dx, dy = VIA_GAP_MOVE_PART[(net, ref, pad)]
            _move_footprint(board, ref, dx, dy)
            moved.append((net, (x, y), (x, y), ref, pad, gap))
    for _ in range(3):
        hits = pad_via_gaps(board)
        if not hits:
            break
        for net, (x, y), ref, pad, gap, centre, (dx, dy) in hits:
            v = next(t for t in board.GetTracks() if t.Type() == pcbnew.PCB_VIA_T and t.GetNetname() == net
                     and abs(xy(t.GetPosition())[0] - x) < 1e-3 and abs(xy(t.GetPosition())[1] - y) < 1e-3)
            if dx == 0 and dy == 0:
                ux, uy = x - centre[0], y - centre[1]
            else:
                ux, uy = (dx if x > centre[0] else -dx), (dy if y > centre[1] else -dy)
            norm = math.hypot(ux, uy) or 1.0
            step = PAD_VIA_GAP + 0.01 - gap
            nx, ny = round(x + ux / norm * step, 3), round(y + uy / norm * step, 3)
            for t in board.GetTracks():
                if t.Type() == pcbnew.PCB_TRACE_T and t.GetNetname() == net:
                    if math.hypot(xy(t.GetStart())[0] - x, xy(t.GetStart())[1] - y) < 1e-3:
                        t.SetStart(vec(nx, ny))
                    if math.hypot(xy(t.GetEnd())[0] - x, xy(t.GetEnd())[1] - y) < 1e-3:
                        t.SetEnd(vec(nx, ny))
            v.SetPosition(vec(nx, ny))
            r.vias = [(q[0], nx, ny, q[3]) if q[0] == net and abs(q[1] - x) < 1e-3 and abs(q[2] - y) < 1e-3
                      else q for q in r.vias]
            moved.append((net, (x, y), (nx, ny), ref, pad, gap))
    r.via_moves = moved
    return moved


ANTIPAD_SPARE = 0.1       # review 1: In1's hole round a via keeps this much from any pair track edge


def antipad_margins(board):
    """[(via, margin mm, nearest pair net)] for every non-GND via: the gap from
    the edge of the hole In1 leaves round it to the nearest F.Cu pair track
    of another net."""
    tr = [(t.GetNetname(), xy(t.GetStart()), xy(t.GetEnd()), pcbnew.ToMM(t.GetWidth())) for t in board.GetTracks()
          if t.Type() == pcbnew.PCB_TRACE_T and t.GetLayer() == pcbnew.F_Cu and t.GetNetname() in PAIR_NETS]
    out = []
    for v in board.GetTracks():
        if v.Type() != pcbnew.PCB_VIA_T or v.GetNetname() == "GND":
            continue
        x, y = xy(v.GetPosition())
        hole = pcbnew.ToMM(v.GetWidth(pcbnew.F_Cu)) / 2 + IN1_CLEARANCE
        skip = (v.GetNetname(), partner(v.GetNetname()))
        m = min(((seg_point_distance(a, c, (x, y)) - w / 2 - hole, n) for n, a, c, w in tr if n not in skip),
                default=(9.0, None))
        out.append((v, m[0], m[1]))
    return out


def stage_antipads(r):
    """Nudge every non-GND via whose In1 hole comes within ANTIPAD_SPARE of a
    pair track, along the direction that raises its least margin, by no more
    than it needs; in a pocket between two pairs it ends in the middle."""
    board = r.board
    tr = [(t.GetNetname(), xy(t.GetStart()), xy(t.GetEnd()), pcbnew.ToMM(t.GetWidth())) for t in board.GetTracks()
          if t.Type() == pcbnew.PCB_TRACE_T and t.GetLayer() == pcbnew.F_Cu and t.GetNetname() in PAIR_NETS]
    moves = []
    gr = route_grid.Router(board, PAIR_NETS)
    for v, m, near_net in antipad_margins(board):
        if m >= ANTIPAD_SPARE:
            continue
        x, y = xy(v.GetPosition())
        net = v.GetNetname()
        hole = pcbnew.ToMM(v.GetWidth(pcbnew.F_Cu)) / 2 + IN1_CLEARANCE
        skip = (net, partner(net))

        rv = pcbnew.ToMM(v.GetWidth(pcbnew.F_Cu)) / 2
        others = [it for it in gr.items if it.net != net and it.kind != "hole"]

        def copper_ok(px, py):
            # the class clearance (and 0.25 hole to hole) to everything of other nets
            for it in others:
                c = 0.3 if net in route_grid.POWER or (it.net or "") in route_grid.POWER else 0.2
                if it.dist(px, py) - rv < c - 1e-6:
                    return False
            return True

        def margin(px, py):
            if not copper_ok(px, py):
                return -9.0
            return min(seg_point_distance(a, c, (px, py)) - w / 2 - hole for n, a, c, w in tr if n not in skip)
        best = (m, x, y)
        for k in range(16):
            ang = math.pi * k / 8
            for step in [i * 0.005 for i in range(1, 25)]:
                px, py = x + math.cos(ang) * step, y + math.sin(ang) * step
                mm_ = margin(px, py)
                if mm_ > best[0] + 1e-6 and (best[0] < ANTIPAD_SPARE or step < math.hypot(best[1] - x, best[2] - y)):
                    best = (min(mm_, ANTIPAD_SPARE + 0.005), round(px, 3), round(py, 3))
                if mm_ >= ANTIPAD_SPARE + 0.005:
                    break
        _, nx, ny = best
        for t in board.GetTracks():
            if t.Type() == pcbnew.PCB_TRACE_T and t.GetNetname() == net:
                if math.hypot(xy(t.GetStart())[0] - x, xy(t.GetStart())[1] - y) < 1e-3:
                    t.SetStart(vec(nx, ny))
                if math.hypot(xy(t.GetEnd())[0] - x, xy(t.GetEnd())[1] - y) < 1e-3:
                    t.SetEnd(vec(nx, ny))
        v.SetPosition(vec(nx, ny))
        r.vias = [(q[0], nx, ny, q[3]) if q[0] == net and abs(q[1] - x) < 1e-3 and abs(q[2] - y) < 1e-3
                  else q for q in r.vias]
        moves.append((net, (x, y), (nx, ny), round(m, 3), round(margin(nx, ny), 3), near_net))
    r.antipad_moves = moves
    return moves


# Ruling BK: the AR flank via north of the USB 2.0 crossing stood between
# RX_N and RX_P. It moves 0.19 mm south, into the band between RX_P (F.Cu)
# and USB2_D_N (B.Cu), and RX is laid coupled with route_pair from J3's fan
# out to U8 and again from U8's pad 6 to U3. RX_N runs 0.095 mm further north
# than before from U8's channel to x 21, so that the via keeps 0.3 mm from
# RX_P on F.Cu and from D- on B.Cu.
AR_FLANK_NORTH_OLD, AR_FLANK_NORTH = (19.1, 18.3), (19.1, 18.49)
RX_Y_N_CH = 17.405           # RX_N in U8's channel and on to x 21


def stage_rx(r):
    board, P = r.board, r.P
    for net in ("USB3_RX_P", "USB3_RX_N"):
        rip(board, net)
        r.lengths.pop(net, None)
        r.stubs.pop(net, None)
    via = next(t for t in board.GetTracks() if t.Type() == pcbnew.PCB_VIA_T and t.GetNetname() == "GND"
               and math.hypot(xy(t.GetPosition())[0] - AR_FLANK_NORTH_OLD[0],
                              xy(t.GetPosition())[1] - AR_FLANK_NORTH_OLD[1]) < 1e-3)
    via.SetPosition(vec(*AR_FLANK_NORTH))
    r.vias.append(("GND", *AR_FLANK_NORTH, "AR crossing, north of the USB 2.0 pair (moved, ruling BK)"))

    half = PITCH / 2
    d = half / math.sqrt(2)                     # a 45-degree line's offset, per axis
    j8, j9 = P("J3", 8), P("J3", 9)
    u4, u6 = P("U8", 4), P("U8", 6)
    p15, p16 = P("U3", 15), P("U3", 16)
    y_p_u8 = 19.07                              # P under U8's south pad row (ruling AS)
    yc_w = 21.0                                 # the pair's centre from J3's fan out
    k_n = u4[0] + RX_Y_N_CH                     # N's climb to the channel: x + y = k_n
    k_c = k_n + 2 * d                           # the pair's centre on that climb
    x_up = k_c - yc_w                           # where the centre starts to climb
    k_p = k_c + 2 * d
    x_pj = k_p - y_p_u8                         # where P reaches its level under U8
    # out of J3's fan as soon as both lines clear J3 pin 1's +5V via and its In1 hole
    v5 = (6.5, 21.0)
    x_j = v5[0] + 1.1                           # both 45-degree legs pass the via 0.91 mm off: its In1 hole 0.11 clear
    centre = [(x_j, yc_w), (x_up, yc_w), (x_pj - d, y_p_u8 - d)]
    lp, ln, _ = route_pair(board, "USB3_RX_P", "USB3_RX_N", centre, p_left=False,
                           head_p=[(j9[0] + 0.9, j9[1]), (x_j - (j9[1] - yc_w - half), j9[1])],
                           head_n=[(j8[0] + 0.9, j8[1]), (x_j - (yc_w - half - j8[1]), j8[1])],
                           tail_p=[(u6[0], y_p_u8)], tail_n=[(u4[0], RX_Y_N_CH)])
    r.lengths["USB3_RX_P"] = r.lengths.get("USB3_RX_P", 0) + lp
    r.lengths["USB3_RX_N"] = r.lengths.get("USB3_RX_N", 0) + ln
    r.net("USB3_RX_N", [(u4[0], RX_Y_N_CH), u4], USB_W, stub=True)
    r.net("USB3_RX_P", [(u6[0], y_p_u8), u6], USB_W, stub=True)

    # east of U8: P climbs from its pad at 45 degrees to N's side
    y_pe = RX_Y_N_CH + PITCH
    x_pe = u6[0] + (y_p_u8 - y_pe)
    yc_e = RX_Y_N + half                       # east of x 21 at the first layout's height (C16's pads)
    x_step = 21.0
    centre = [(x_pe, RX_Y_N_CH + half), (x_step, RX_Y_N_CH + half),
              (x_step + (yc_e - RX_Y_N_CH - half), yc_e), (p16[0] - 0.2, yc_e)]
    yp_e = yc_e + half
    lp, ln, _ = route_pair(board, "USB3_RX_P", "USB3_RX_N", centre, p_left=False,
                           head_p=[(u6[0], y_p_u8)], head_n=[(u4[0], RX_Y_N_CH)],
                           tail_p=[(p16[0], yp_e), (p16[0], U3_AREA[1]), (p16[0], p16[1] - NECK_LEN)],
                           tail_n=[(p15[0], RX_Y_N), (p15[0], U3_AREA[1]), (p15[0], p15[1] - NECK_LEN)])
    r.lengths["USB3_RX_P"] += lp
    r.lengths["USB3_RX_N"] += ln
    r.net("USB3_RX_P", [(p16[0], p16[1] - NECK_LEN), p16], NECK_W)
    r.net("USB3_RX_N", [(p15[0], p15[1] - NECK_LEN), p15], NECK_W)


def move_via(r, net, old, new, diameter=None):
    """Move the via of `net` at `old` to `new` (and set its diameter), taking
    the ends of its own net's tracks along."""
    board = r.board
    v = next(t for t in board.GetTracks() if t.Type() == pcbnew.PCB_VIA_T and t.GetNetname() == net
             and math.hypot(xy(t.GetPosition())[0] - old[0], xy(t.GetPosition())[1] - old[1]) < 1e-3)
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_TRACE_T and t.GetNetname() == net:
            if math.hypot(xy(t.GetStart())[0] - old[0], xy(t.GetStart())[1] - old[1]) < 1e-3:
                t.SetStart(vec(*new))
            if math.hypot(xy(t.GetEnd())[0] - old[0], xy(t.GetEnd())[1] - old[1]) < 1e-3:
                t.SetEnd(vec(*new))
    v.SetPosition(vec(*new))
    if diameter:
        v.SetWidth(mm(diameter))
    r.vias = [(q[0], new[0], new[1], q[3]) if q[0] == net and abs(q[1] - old[0]) < 1e-3 and abs(q[2] - old[1]) < 1e-3
              else q for q in r.vias]
    return v


def rip_tracks_at(board, net, point):
    """Remove the tracks of `net` that end at `point`."""
    for t in list(board.GetTracks()):
        if t.Type() == pcbnew.PCB_TRACE_T and t.GetNetname() == net and any(
                math.hypot(q[0] - point[0], q[1] - point[1]) < 1e-3 for q in (xy(t.GetStart()), xy(t.GetEnd()))):
            board.Delete(t)


# Ruling BK: C9 (pins 39 / 40, +3V3) sat 5.93 mm away on C11's pads. It goes
# to B.Cu directly at the pins' via, west of it under U3's south edge, GND pad
# on the B.Cu pour; R11 and R14 are on F.Cu and do not stand in the way.
C9_VIA = (26.79, 25.75)


def stage_c9(r):
    board = r.board
    fp = board.FindFootprintByReference("C9")
    if not fp.IsFlipped():
        rip_tracks_at(board, "+3V3", r.P("C9", 1))         # from C11.1
        rip_tracks_at(board, "GND", r.P("C9", 2))          # from C11 / C9's GND via, which C11 keeps
    vx, vy = C9_VIA
    assert any(t.Type() == pcbnew.PCB_VIA_T and t.GetNetname() == "+3V3" and
               math.hypot(xy(t.GetPosition())[0] - vx, xy(t.GetPosition())[1] - vy) < 1e-3
               for t in board.GetTracks()), "pins 39 / 40's +3V3 via moved"
    pad1 = (round(vx - 0.69, 3), vy)          # via r + 0.11 + half the pad (ruling BI)
    _place_on_bottom(board, "C9", pad1, (-1, 0))
    r.net("+3V3", [(vx, vy), pad1], 0.3, B)
    r.P = Pads(board)


# Review 1: pin 3's +1V0 via sits between MDI1_P (y 23.595) and MDI0_N
# (y 25.155), 1.56 mm apart, one track width short of room for a 0.6 mm via
# and In1's hole round it with 0.1 mm to spare on both sides. It becomes the
# board's one 0.56 / 0.3 mm via (0.13 mm ring, the board's minimum) centred
# between the two: 0.11 mm on each side.
PIN3_VIA_OLD, PIN3_VIA, PIN3_VIA_D = (28.31, 24.377), (28.31, 24.375), 0.56


def stage_pin3_via(r):
    move_via(r, "+1V0", PIN3_VIA_OLD, PIN3_VIA, PIN3_VIA_D)


STAGES = [
    ("usb3_tx", stage_usb3_tx),
    ("usb3_rx", stage_usb3_rx),
    ("mdi0", stage_mdi0),
    ("mdi1", stage_mdi1),
    ("mdi2", stage_mdi2),
    ("mdi3", stage_mdi3),
    ("usb2", stage_usb2),
    ("buck", stage_buck),
    ("supplies_u3", stage_supplies_u3),
    ("lowspeed", stage_lowspeed),
    ("supplies", stage_supplies),
    ("gnd", stage_gnd),
    ("pad_vias", stage_pad_vias),
    ("coupling", stage_coupling),
    ("decoupling", stage_decoupling),
    ("via_gaps", stage_via_gaps),
    ("antipads", stage_antipads),
    ("split_area", stage_split_area),
    ("rx", stage_rx),
    ("c9", stage_c9),
    ("pin3_via", stage_pin3_via),
]


def track_count(board):
    return sum(1 for t in board.GetTracks() if t.Type() in (pcbnew.PCB_TRACE_T, pcbnew.PCB_ARC_T))


def reference_gaps(board, step=0.05):
    """After the zones are filled: every point along both edges of every F.Cu
    pair track that has no In1 GND copper under it. Points inside the hole In1
    leaves round the track's own pin (or its partner's) are where the pair
    leaves the layer and are not counted. Returns {net: [(x, y), ...]}."""
    gnd = board.FindNet("GND").GetNetCode()
    in1 = next(z for z in board.Zones() if z.GetLayer() == pcbnew.In1_Cu
               and z.GetNetCode() == gnd and not z.GetIsRuleArea())
    polys = in1.GetFilledPolysList(pcbnew.In1_Cu)
    own = {}
    for fp in board.GetFootprints():
        for pad in fp.Pads():
            if pad.HasHole():
                x, y = xy(pad.GetPosition())
                r = pcbnew.ToMM(max(pad.GetSize(pcbnew.In1_Cu).x, pad.GetSize(pcbnew.In1_Cu).y)) / 2
                own.setdefault(pad.GetNetname(), []).append((x, y, r + IN1_CLEARANCE + 0.05))
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_VIA_T:
            x, y = xy(t.GetPosition())
            own.setdefault(t.GetNetname(), []).append((x, y, 0.3 + IN1_CLEARANCE + 0.05))
    gaps = {}
    for t in board.GetTracks():
        net = t.GetNetname()
        if t.Type() != pcbnew.PCB_TRACE_T or t.GetLayer() != pcbnew.F_Cu or net not in PAIR_NETS:
            continue
        (ax, ay), (bx, by) = xy(t.GetStart()), xy(t.GetEnd())
        length = math.hypot(bx - ax, by - ay)
        if length == 0:
            continue
        ux, uy = (bx - ax) / length, (by - ay) / length
        half = pcbnew.ToMM(t.GetWidth()) / 2
        exempt = own.get(net, []) + own.get(partner(net), [])
        for k in range(int(length / step) + 1):
            cx, cy = ax + ux * k * step, ay + uy * k * step
            for side in (-1, 1):
                px, py = cx - uy * half * side, cy + ux * half * side
                if any(math.hypot(px - hx, py - hy) < hr for hx, hy, hr in exempt):
                    continue
                if not polys.Contains(vec(px, py)):
                    gaps.setdefault(net, []).append((round(px, 2), round(py, 2)))
    return gaps


CROSSING_X = (18.8, 19.4)        # the In2 gap the USB 2.0 stretch crosses
AR_FLANK_VIAS = [(19.1, 18.49), (17.565, 20.6)]   # north one moved by ruling BK, south by BI


def ar_return(board):
    """Ruling AR (revised) / AW, after the zones are filled: the B.Cu GND pour
    beside the USB 2.0 pair, sampled 0.6 mm from the centre line of the outer
    track on each side (0.3 mm clearance + half a track + 0.2 mm into the
    pour) from x 12.9 to 21.0; the crossing window (x 18.3 to 19.9) must be
    fully covered, and both crossing vias must sit in that pour. Also every
    other B.Cu track in the band x 17 to 21: it must run east-west, and leave
    at least 0.5 mm of pour on the pair's side. Returns (problems, lines)."""
    gnd = board.FindNet("GND").GetNetCode()
    pour = next(z for z in board.Zones() if z.GetLayer() == pcbnew.B_Cu
                and not z.GetIsRuleArea() and z.GetNetCode() == gnd)
    polys = pour.GetFilledPolysList(pcbnew.B_Cu)

    def poly_at(x, y):
        for i in range(polys.OutlineCount()):
            if polys.Outline(i).PointInside(vec(x, y)):
                return i
        return None
    total = covered = wt = wc = 0
    used, missing = set(), []
    for net, d in (("USB2_D_N", 0.6), ("USB2_D_P", -0.6)):
        pts = USB2_BCU[net]
        # D_N is the north track: travelling U9 -> U3 (east), left is north
        off = offset_line(pts, 0.6) if net == "USB2_D_N" else offset_line(pts, -0.6)
        for a, b in zip(off, off[1:]):
            n = max(1, int(math.hypot(b[0] - a[0], b[1] - a[1]) / 0.1))
            for k in range(n + 1):
                x = a[0] + (b[0] - a[0]) * k / n
                y = a[1] + (b[1] - a[1]) * k / n
                if x < 12.9 or x > 20.0:
                    continue
                total += 1
                i = poly_at(x, y)
                covered += i is not None
                if i is None:
                    missing.append((round(x, 2), round(y, 2)))
                else:
                    used.add(i)
                if CROSSING_X[0] - 0.5 <= x <= CROSSING_X[1] + 0.5:
                    wt += 1
                    wc += i is not None
    problems, lines = [], []
    lines.append(f"B.Cu GND pour beside the USB 2.0 pair (0.6 mm from each outer track, x 12.9 to 20.0): "
                 f"{covered} of {total} samples; crossing window x 18.3 to 19.9: {wc} of {wt}")
    if missing:
        lines.append(f"  not in the pour: {missing[:10]}")
    if wc != wt or not wt:
        problems.append("the pour does not run beside the pair across the crossing")
    for vx, vy in AR_FLANK_VIAS:
        ring = {poly_at(vx + 0.55 * math.cos(t * math.pi / 4), vy + 0.55 * math.sin(t * math.pi / 4)) for t in range(8)}
        ring.discard(None)
        ok = bool(ring & used)
        lines.append(f"  crossing via ({vx}, {vy}) in that pour: {ok}")
        if not ok:
            problems.append(f"crossing via ({vx}, {vy}) is not on the pour beside the pair")
    band = []
    for t in board.GetTracks():
        if t.Type() != pcbnew.PCB_TRACE_T or t.GetLayer() != pcbnew.B_Cu or t.GetNetname() in B_CU_EXCEPTION_NETS:
            continue
        (ax, ay), (bx, by) = xy(t.GetStart()), xy(t.GetEnd())
        if max(ax, bx) < 17.0 or min(ax, bx) > 21.0:
            continue
        w = pcbnew.ToMM(t.GetWidth())
        gap = min(abs(ay - 19.2), abs(ay - 19.57)) - 0.1 - w / 2 - 0.3 - 0.3
        horizontal = abs(ay - by) < 1e-6
        band.append((t.GetNetname(), round(ay, 2), horizontal, round(gap, 2)))
        if not horizontal or gap < 0.5:
            problems.append(f"B.Cu {t.GetNetname()} in the AW band at y {ay:.2f}: "
                            f"{'not east-west' if not horizontal else f'only {gap:.2f} mm of pour'}")
    lines.append(f"other B.Cu tracks in the band x 17 to 21 (net, y, east-west, pour left beside the pair mm): "
                 + (", ".join(map(str, band)) or "none"))
    return problems, lines


# Which U3 pins each decoupling capacitor is for (gen_pcb.py PLACEMENT).
DECOUPLING = {"C7": (11,), "C8": (20,), "C9": (39, 40), "C10": (23, 26), "C11": (26, 33),
              "C12": (3,), "C13": (8,), "C14": (37,), "C15": (34,), "C16": (14,),
              "C17": (22,), "C18": (21, 27), "C27": (19,)}


def decoupling_distances(board):
    P = Pads(board)
    rows = []
    for ref, pins in DECOUPLING.items():
        cx, cy = P(ref, 1)
        d = min(math.hypot(cx - P("U3", n)[0], cy - P("U3", n)[1]) for n in pins)
        rows.append((ref, pins, round(d, 2)))
    return rows


COUPLING_TOL = 0.03      # mm either side of the pair gap counted as "at the designed gap"


def coupling(board, step=0.05):
    """Ruling BE: how much of each pair runs at its designed gap. For every
    track of each net, sampled every `step`, the edge gap to the nearest track
    of its partner on the same layer. Returns {pair: (total mm, mm at the
    gap +/- COUPLING_TOL, mm at 0.6 mm or more apart)} per net."""
    tracks = {}
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_TRACE_T and t.GetNetname() in PAIR_NETS:
            tracks.setdefault(t.GetNetname(), []).append(
                (t.GetLayer(), xy(t.GetStart()), xy(t.GetEnd()), pcbnew.ToMM(t.GetWidth())))
    out = {}
    for p, n in PAIRS:
        gap = MDI_GAP if p.startswith("MDI") else USB_GAP
        for net, other in ((p, n), (n, p)):
            total = at = far = 0.0
            for layer, a, b, w in tracks.get(net, []):
                length = math.hypot(b[0] - a[0], b[1] - a[1])
                k = max(1, int(round(length / step)))
                for i in range(k):
                    t_ = (i + 0.5) / k
                    q = (a[0] + (b[0] - a[0]) * t_, a[1] + (b[1] - a[1]) * t_)
                    best = 99.0
                    for l2, c, d, w2 in tracks.get(other, []):
                        if l2 == layer:
                            best = min(best, seg_point_distance(c, d, q) - w2 / 2 - w / 2)
                    total += length / k
                    if abs(best - gap) <= COUPLING_TOL:
                        at += length / k
                    elif best >= 0.6:
                        far += length / k
            out[net] = (total, at, far)
    return out


def in2_under(board, points, step=0.05):
    """The In2 island under a polyline, as [(net, from x)], and the number of
    island-to-island boundaries it crosses (ruling AR counts these)."""
    islands = [z for z in board.Zones() if z.GetLayer() == pcbnew.In2_Cu and not z.GetIsRuleArea()]
    seq = []
    for a, b in zip(points, points[1:]):
        length = math.hypot(b[0] - a[0], b[1] - a[1])
        for k in range(int(length / step) + 1):
            x = a[0] + (b[0] - a[0]) * k * step / length
            y = a[1] + (b[1] - a[1]) * k * step / length
            label = next((z.GetNetname() + "@%.1f" % (pcbnew.ToMM(z.GetBoundingBox().GetLeft()) - ORIGIN[0])
                          for z in islands if z.Outline().Contains(vec(x, y))), "gap")
            if not seq or seq[-1][0] != label:
                seq.append((label, round(x, 2)))
    names = [s for s, _ in seq]
    solid = [s for s in names if s != "gap"]
    boundaries = sum(1 for a, c in zip(solid, solid[1:]) if a != c)
    return seq, boundaries


def route(board, stages):
    r = Router(board)
    names = [name for name, _ in STAGES]
    for name in stages:
        if name not in names:
            raise RoutingError(f"unknown stage {name!r}; stages: {', '.join(names)}")
    for name, work in STAGES:
        if name in stages:
            work(r)
    return r


def report(r, out=sys.stdout):
    """In-pair lengths: 'copper' is all the copper of the net (what kicad-happy
    measures), 'path' leaves out the tee stubs into the ESD pads, i.e. the
    signal's way from one end to the other."""
    def both(nets):
        copper = sum(r.lengths.get(n, 0) for n in nets)
        return copper, copper - sum(r.stubs.get(n, 0) for n in nets)
    rows = [("USB3_TX, U3 to J3", ("USB3_TX_P", "USB3_TX_CONN_P"), ("USB3_TX_N", "USB3_TX_CONN_N"))]
    rows += [(p[:-2], (p,), (n,)) for p, n in PAIRS]
    print("in-pair lengths (mm):          copper P / N / diff     path P / N / diff", file=out)
    for name, ps, ns in rows:
        (cp, pp), (cn, pn) = both(ps), both(ns)
        if cp or cn:
            print(f"  {name:22s}  {cp:7.3f} {cn:7.3f} {abs(cp - cn):6.3f}   "
                  f"{pp:7.3f} {pn:7.3f} {abs(pp - pn):6.3f}", file=out)
    if "USB2_D_P" in r.lengths:
        dp = r.lengths["USB2_D_P"] - r.stubs.get("USB2_D_P", 0) + USB2_U9_INTERNAL
        dn = r.lengths["USB2_D_N"] - r.stubs.get("USB2_D_N", 0)
        print(f"  USB2_D electrical (D+ through U9 pins 1 to 6, {USB2_U9_INTERNAL:.3f} mm): "
              f"P {dp:.3f}  N {dn:.3f}  diff {abs(dp - dn):.3f}", file=out)
    print(f"vias placed: {len(r.vias)}", file=out)
    for net, x, y, why in r.vias:
        print(f"  {net:12s} ({x:6.2f}, {y:6.2f})  {why}", file=out)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--in", dest="src", default=str(DEFAULT_PCB))
    parser.add_argument("--out", required=True)
    parser.add_argument("--stages", default=",".join(n for n, _ in STAGES))
    args = parser.parse_args()
    board = pcbnew.LoadBoard(args.src)
    if track_count(board):
        print(f"error: {args.src} already carries {track_count(board)} tracks; "
              "it is routed and would be routed twice", file=sys.stderr)
        return 2
    try:
        r = route(board, [s for s in args.stages.split(",") if s])
    except RoutingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    pcbnew.ZONE_FILLER(board).Fill(board.Zones())
    out = args.out
    pcbnew.SaveBoard(out, board)
    print(f"routed {out}: stages {args.stages}")
    report(r)
    gaps = reference_gaps(board)
    print("In1 under the F.Cu pair tracks (0.05 mm steps along both edges): "
          + ("no gap" if not gaps else "; ".join(f"{n}: {len(v)} points, first {v[0]}"
                                                for n, v in sorted(gaps.items()))))
    status = 1 if gaps else 0
    lens = {}
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_TRACE_T and t.GetNetname() in PAIR_NETS:
            (ax, ay), (bx, by) = xy(t.GetStart()), xy(t.GetEnd())
            lens[t.GetNetname()] = lens.get(t.GetNetname(), 0) + math.hypot(bx - ax, by - ay)
    tx_p = lens.get("USB3_TX_P", 0) + lens.get("USB3_TX_CONN_P", 0)
    tx_n = lens.get("USB3_TX_N", 0) + lens.get("USB3_TX_CONN_N", 0)
    print("pair copper lengths measured on the board (mm, P / N / diff): "
          f"USB3 TX U3-J3 {tx_p:.3f} / {tx_n:.3f} / {abs(tx_p - tx_n):.3f}; "
          + "; ".join(f"{p[:-2]} {lens.get(p, 0):.3f} / {lens.get(n, 0):.3f} / {abs(lens.get(p, 0) - lens.get(n, 0)):.3f}"
                      for p, n in PAIRS if p.startswith(("USB3_RX", "MDI", "USB2"))))
    print(f"coupling (edge gap within {COUPLING_TOL} mm of the pair gap), per net: total / at the gap / 0.6 mm or more apart, mm")
    for net, (tot, at, far) in coupling(board).items():
        print(f"  {net:15s} {tot:7.2f} {at:7.2f} ({100 * at / tot if tot else 0:4.0f} %) {far:7.2f}")
    if any(t.GetNetname() in B_CU_EXCEPTION_NETS and t.GetLayer() == B for t in board.GetTracks()):
        for net in ("USB2_D_N", "USB2_D_P"):
            seq, n = in2_under(board, USB2_BCU[net])
            print(f"In2 under {net} on B.Cu: {n} island boundary crossed; "
                  + " -> ".join(f"{a} from x {b}" for a, b in seq))
            status |= 0 if n == 1 else 1
        problems, lines = ar_return(board)
        for line in lines:
            print(line)
        for p in problems:
            print("PROBLEM:", p)
        status |= 1 if problems else 0
    for ref, pad, what in getattr(r, "pad_vias", []):
        print(f"ruling BA: {ref}.{pad}: {what}")
    for net, a, b, ref, pad, gap in getattr(r, "via_moves", []):
        print(f"ruling BI: {net} via {a} -> {b} ({gap} mm from {ref}.{pad})")
    for net, a, b, m0, m1, near_net in getattr(r, "antipad_moves", []):
        print(f"In1 hole: {net} via {a} -> {b}, margin to {near_net} {m0} -> {m1} mm")
    left = pad_via_gaps(board)
    print(f"ruling BI: vias closer than {PAD_VIA_GAP} mm to a hand-soldered pad: {len(left)} {[h[:5] for h in left]}")
    status |= 1 if left else 0
    if "supplies_u3" in args.stages:
        print("decoupling, cap pad 1 to the nearest pad centre of its U3 pin(s), mm:")
        for ref, pins, d in decoupling_distances(board):
            print(f"  {ref:4s} pins {','.join(map(str, pins)):6s} {d}")
    return status


if __name__ == "__main__":
    sys.exit(main())
