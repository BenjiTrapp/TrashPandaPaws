#!/usr/bin/env python3
"""
Route kicad/raccoon-tap.kicad_pcb (task 9). Programmatic, targeted geometry,
not an autorouter: every track below is a coordinate written here on purpose,
and the result is checked by kicad-cli's DRC and kicad-happy's EMC analysis.
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

The plan (STAGES) follows the order of the routing brief. What exists is the
differential pairs: SuperSpeed TX and RX, MDI0 to MDI3, USB 2.0. They lay at
0 DRC errors with no gap in In1 under any F.Cu pair track. The stages after
them (the buck loop, supplies, low-speed nets, stitching) are not written:
U3's supply and GND pins cannot leave their pads within the rules in force,
and pin 14 cannot leave at all with the parts where they are; see
hardware/review/2026-11-02-routing/u3_supply_escape_probe.py. Until that is
ruled on, nothing here is meant to be written to the repository's board.

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
    r.leave("USB3_TX_P", p13, up, [c22_1], USB_W)
    r.leave("USB3_TX_N", p12, up, [(c23_1[0], c23_1[1] + 0.5), c23_1], USB_W)
    yn, yp = 15.2, 15.2 + 0.375
    r.net("USB3_TX_CONN_N", [c23_2, (c23_2[0], yn), (22.0, yn), (21.4, 14.8125),
                             (8.3125, 14.8125), (7.5, j5[1]), (j5[0] + 0.9, j5[1])], USB_W)
    r.net("USB3_TX_CONN_N", [(x3, 14.8125), u8["3"]], USB_W, stub=True)
    r.net("USB3_TX_CONN_P", [c22_2, (c22_2[0], yp), (22.0, yp), (20.9, y_ch),
                             (x3 - 0.7375, y_ch), (x3 - 2.25, 15.1875),
                             (7.8125, 15.1875), (7.0, j6[1]), (j6[0] + 0.9, j6[1])], USB_W)
    r.net("USB3_TX_CONN_P", [(x1, y_ch), u8["1"]], USB_W, stub=True)


def stage_usb3_rx(r):
    """RX: J3 -> U8 (tee) -> U3, the P line turning 0.155 mm after the N line
    on the 45-degree runs."""
    P = r.P
    u8 = {n: P("U8", n) for n in "123456"}
    y_c = (u8["2"][1] + u8["5"][1]) / 2
    y_rn, y_rp = y_c + 0.40, 19.07
    j8, j9 = P("J3", 8), P("J3", 9)
    p15, p16 = P("U3", 15), P("U3", 16)
    x3, x1 = u8["3"][0], u8["1"][0]
    r.net("USB3_RX_N", [(j8[0] + 0.9, j8[1]), (7.5, j8[1]), (8.3125, 20.8125),
                        (x3 - 3.3125, 20.8125), (x3, y_rn), (21.0, y_rn),
                        (21.575, 18.075), (p15[0], 18.075), (p15[0], p15[1] - NECK_LEN)], USB_W)
    r.net("USB3_RX_N", [(p15[0], p15[1] - NECK_LEN), p15], NECK_W)
    r.net("USB3_RX_N", [(x3, y_rn), (x3, u8["4"][1])], USB_W, stub=True)
    r.net("USB3_RX_P", [(j9[0] + 0.9, j9[1]), (7.0, j9[1]), (7.8125, 21.1875),
                        (x3 - 1.495, 21.1875), (x3 + 0.6225, y_rp), (19.6, y_rp),
                        (20.22, 18.45), (p16[0], 18.45), (p16[0], p16[1] - NECK_LEN)], USB_W)
    r.net("USB3_RX_P", [(p16[0], p16[1] - NECK_LEN), p16], NECK_W)
    r.net("USB3_RX_P", [(x1, y_rp), u8["6"]], USB_W, stub=True)


def mdi_wrap(r, nets, pads, centre, lane_x, pin_n, pin_p):
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
    for net, pad in ((net_n, pad_n), (net_p, pad_p)):
        r.net(net, [pad, (pad[0] + NECK_LEN, pad[1])], NECK_W)
    r.net(net_n, [(pad_n[0] + NECK_LEN, pad_n[1])] + cut(left, pin_n[1]) + [pin_n], MDI_W)
    r.net(net_p, [(pad_p[0] + NECK_LEN, pad_p[1])] + cut(right, pin_p[1]) + [pin_p], MDI_W)


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


def stage_mdi0(r):
    u1, u2 = r.P("U3", 1), r.P("U3", 2)
    x0 = u2[0] + NECK_LEN
    mdi_wrap(r, ("MDI0_N", "MDI0_P"), (u2, u1),
             [(x0, 24.6), (31.0, 24.6), (32.8, 26.4), (40.92, 26.4), (44.0, 23.32)],
             44.0, r.P("J2", 2), r.P("J2", 1))


def stage_mdi3(r):
    """MDI3 (north at U3) to J2 pins 7 (N) and 8 (P), from the west (ruling AQ)."""
    P = r.P
    x0 = P("U3", 10)[0] + NECK_LEN
    for net, pin in (("MDI3_N", 10), ("MDI3_P", 9)):
        r.net(net, [P("U3", pin), (x0, P("U3", pin)[1])], NECK_W)
    r.net("MDI3_N", [(x0, 21.2), (35.5, 21.2), (36.8, 19.905), P("J2", 7)], MDI_W)
    r.net("MDI3_P", [(x0, 21.6), (36.6, 21.6), (37.0, 21.175), P("J2", 8)], MDI_W)


def stage_mdi2(r):
    P = r.P
    x0 = P("U3", 10)[0] + NECK_LEN
    for net, pin in (("MDI2_N", 7), ("MDI2_P", 6)):
        r.net(net, [P("U3", pin), (x0, P("U3", pin)[1])], NECK_W)
    r.net("MDI2_N", [(x0, 22.4), (36.5, 22.4), (36.6, 22.445), P("J2", 9)], MDI_W)
    r.net("MDI2_P", [(x0, 22.8), (34.0, 22.8), (34.915, 23.715), P("J2", 10)], MDI_W)


# The USB 2.0 pair on B.Cu between its vias at U9 (x 12.2) and U3 (ruling AR,
# revised); D_N is the north track. Task 8's scratch stretch ran the two
# tracks 0.65 mm apart; here they are coupled at the class pitch (0.37 mm)
# from the U9 end to x 21.3, and part only over the last 1.2 mm, where the U3
# vias are.
#
# The U3-end vias: task 8 had D_N's at (22.4, 19.1), whose 0.6 mm hole in In1
# reaches y 18.5, 0.05 mm under RX_P (y 18.45, edge 18.55). It is at y 19.2
# here (0.05 mm to spare), and D_P's run above pins 19 / 20 moves to y 19.8 to
# keep the coupled-pair 0.17 mm from it.
USB2_VIA_U9 = {"USB2_D_N": (12.2, 16.2), "USB2_D_P": (12.2, 17.1)}
USB2_VIA_U3 = {"USB2_D_N": (22.4, 19.2), "USB2_D_P": (21.5, 19.8)}
USB2_Y_N = 19.2                      # B.Cu horizontal of D_N
USB2_Y_P = USB2_Y_N + PITCH          # coupled


def usb2_bcu():
    """Centre lines of the two B.Cu tracks, west to east."""
    (xn, yn), (xp, yp) = USB2_VIA_U9["USB2_D_N"], USB2_VIA_U9["USB2_D_P"]
    # D_N: 45 degrees down from its via to its horizontal
    n = [(xn, yn), (xn + USB2_Y_N - yn, USB2_Y_N), USB2_VIA_U3["USB2_D_N"]]
    # D_P: the parallel line PITCH to the south-west; x - y = c
    c = (xn - yn) - PITCH * math.sqrt(2)
    start = (yp + c, yp)                         # on that line, level with its via
    corner = (USB2_Y_P + c, USB2_Y_P)
    ex, ey = USB2_VIA_U3["USB2_D_P"]
    p = [(xp, yp), start, corner, (ex - (ey - USB2_Y_P), USB2_Y_P), (ex, ey)]
    return {"USB2_D_N": n, "USB2_D_P": p}


USB2_BCU = usb2_bcu()


def stage_usb2(r):
    """D+/D-: J3 -> U9 (D- through the channel between U9's pad columns; pins
    3/4 and 1/6 are one node each, DS4260) -> four vias -> B.Cu under the TX
    and RX lanes -> U3."""
    P = r.P
    j2, j3 = P("J3", 2), P("J3", 3)
    u1, u3, u4, u6 = (P("U9", n) for n in (1, 3, 4, 6))
    p17, p18 = P("U3", 17), P("U3", 18)
    vn9, vp9 = USB2_VIA_U9["USB2_D_N"], USB2_VIA_U9["USB2_D_P"]
    vn3, vp3 = USB2_VIA_U3["USB2_D_N"], USB2_VIA_U3["USB2_D_P"]
    r.net("USB2_D_P", [(j3[0] + 0.9, j3[1]), (6.5, u1[1]), u1], USB_W)
    r.net("USB2_D_N", [(j2[0] + 0.9, j2[1]), (6.5, u3[1]), u3, (9.6, u3[1]),
                       (9.6, vn9[1]), vn9], USB_W)
    r.net("USB2_D_N", [(9.6, u3[1]), u4], USB_W, stub=True)
    r.net("USB2_D_P", [u6, vp9], USB_W)
    r.via("USB2_D_N", *vn9, "USB 2.0 to B.Cu, under the TX and RX lanes (U9 end)")
    r.via("USB2_D_P", *vp9, "USB 2.0 to B.Cu, under the TX and RX lanes (U9 end)")
    r.net("USB2_D_P", [p18, (p18[0], p18[1] - NECK_LEN)], NECK_W)
    r.net("USB2_D_P", [(p18[0], p18[1] - NECK_LEN), (p18[0], vp3[1]), vp3], USB_W)
    r.net("USB2_D_N", [p17, (p17[0], p17[1] - NECK_LEN)], NECK_W)
    r.net("USB2_D_N", [(p17[0], p17[1] - NECK_LEN), (p17[0], vn3[1]), vn3], USB_W)
    r.via("USB2_D_P", *vp3, "USB 2.0 back to F.Cu at U3")
    r.via("USB2_D_N", *vn3, "USB 2.0 back to F.Cu at U3")
    for net, path in USB2_BCU.items():
        r.net(net, path, USB_W, B, exception="AR")


STAGES = [
    ("usb3_tx", stage_usb3_tx),
    ("usb3_rx", stage_usb3_rx),
    ("mdi0", stage_mdi0),
    ("mdi1", stage_mdi1),
    ("mdi2", stage_mdi2),
    ("mdi3", stage_mdi3),
    ("usb2", stage_usb2),
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
    if any(t.GetNetname() in B_CU_EXCEPTION_NETS and t.GetLayer() == B for t in board.GetTracks()):
        for net in ("USB2_D_N", "USB2_D_P"):
            seq, n = in2_under(board, USB2_BCU[net])
            print(f"In2 under {net} on B.Cu: {n} island boundary crossed; "
                  + " -> ".join(f"{a} from x {b}" for a, b in seq))
    return 0


if __name__ == "__main__":
    sys.exit(main())
