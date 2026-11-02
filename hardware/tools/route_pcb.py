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
low-speed nets, the rails, and every GND pad to a via. The last three are
searched connection by connection on a 0.05 mm grid by tools/route_grid.py
round what is already laid, at the project's clearances; each call names the
connection, its width and where it may end. kicad-cli's DRC is the judge.

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
# the least that keeps 0.3 mm of copper).
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
# between the crossing's GND vias (19.1, 18.3) and (17.6, 20.6).
USB2_VIA_U9 = {"USB2_D_N": (12.2, 16.2), "USB2_D_P": (12.2, 17.1)}
USB2_VIA_U3 = {"USB2_D_N": (20.8, 18.65), "USB2_D_P": (21.5, 19.0)}
USB2_FCU_Y = {"USB2_D_N": 18.33, "USB2_D_P": 18.7}     # their runs west from the pins
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


def stage_usb2(r):
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
        r.net(net, [(pad[0], pad[1] - NECK_LEN), (pad[0], y), (vx + abs(vy - y), y), (vx, vy)], USB_W)
        r.via(net, vx, vy, "USB 2.0 back to F.Cu at U3, in the band between RX_P and the pads")
    for net, path in USB2_BCU.items():
        r.net(net, path, USB_W, B, exception="AR")
    # the one free place within 1 mm of a USB 2.0 signal via (kicad-happy RP-001)
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
AR_FLANK_VIAS = [(19.1, 18.3), (17.6, 20.6)]


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
        off = offset_line(pts, d if net == "USB2_D_P" else d)
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
              "C17": (22,), "C18": (21, 27)}


def decoupling_distances(board):
    P = Pads(board)
    rows = []
    for ref, pins in DECOUPLING.items():
        cx, cy = P(ref, 1)
        d = min(math.hypot(cx - P("U3", n)[0], cy - P("U3", n)[1]) for n in pins)
        rows.append((ref, pins, round(d, 2)))
    return rows


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
    if "supplies_u3" in args.stages:
        print("decoupling, cap pad 1 to the nearest pad centre of its U3 pin(s), mm:")
        for ref, pins, d in decoupling_distances(board):
            print(f"  {ref:4s} pins {','.join(map(str, pins)):6s} {d}")
    return status


if __name__ == "__main__":
    sys.exit(main())
