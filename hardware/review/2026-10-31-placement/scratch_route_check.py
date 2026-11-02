#!/usr/bin/env python3
"""Clearance evidence for the placement: can the SuperSpeed lanes, the USB 2.0
pair and the MDI pairs be laid out on the placed board at the geometry of
hardware/fab/stackup-note.md, and does the new U3 rule do what it says?

WHAT THIS SHOWS AND WHAT IT DOES NOT. It copies the project (board,
.kicad_pro, .kicad_dru) to a temporary directory, lays the traces below on the
copy with pcbnew, runs kicad-cli's DRC and prints what KiCad reports. The
repository's board is never written. A clean run means the copper clears its
neighbours at the rules in force. It says nothing about impedance, crosstalk or
return paths: the SuperSpeed pairs are open (1.5 to 2 mm apart) for about 5 mm
round U8, and TX_P and RX_N run 0.8 mm apart, centre to centre, through its
channel. The traces are a feasibility demonstration, not the routing; task 9
routes.

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
    $KIPY hardware/review/2026-10-31-placement/scratch_route_check.py [neck_mm]

Geometry: USB3 and USB 2.0 0.20 mm wide at a 0.375 mm pitch (gap 0.175), MDI
0.18 mm at 0.39 mm, a 0.15 mm neck for the first `neck_mm` (default 0.6, the
note allows 1.0) from the centre of every U3 pad.

Runs, each on a fresh copy:
  board    the board as committed: SuperSpeed + USB 2.0, the MDI0 / MDI1 pairs
           round the south end of J2's pin field (ruling AM), the MDI2 / MDI3
           pairs from the west. J2's pins 7 to 10 carry MDI3_N, MDI3_P,
           MDI2_N, MDI2_P (ruling AQ, variant X: the two pairs exchanged and
           turned, inside cable pairs C/D), so nothing crosses and there are no
           vias in the MDI pairs.
  return   the USB 2.0 pair's stretch on B.Cu (ruling AR, revised): counts the
           In2 island boundaries under it, samples the B.Cu GND pour beside it
           across the crossing and checks the GND vias that flank the crossing
           are on that pour; two controls (no flank vias; pour cut) must fail.
  rule     the escapes of every U3 signal pad, with and without the
           "track to U3 pad on fine-pitch parts" rule, and three controls that
           must still be reported.
It also prints the MDI net -> J2 pin -> RJ45 pin -> cable pair table of the
board and fails if an MDI net leaves its group of cable pairs (MDI0 and MDI1
on A/B, MDI2 and MDI3 on C/D).
Exit status 0 when every run and control behaves as stated.
"""

import itertools
import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pcbnew

KICAD = Path(__file__).resolve().parents[2] / "kicad"
KICAD_CLI = "/opt/homebrew/bin/kicad-cli"
ORIGIN = (100.0, 80.0)          # gen_pcb.py ORIGIN_X, ORIGIN_Y
NECK_LEN = float(sys.argv[1]) if len(sys.argv) > 1 else 0.6
RULE_NAME = "track to U3 pad on fine-pitch parts"

W, NECK, PITCH = 0.20, 0.15, 0.375      # USB3 / USB 2.0
MW, MPITCH = 0.18, 0.39                 # MDI


# The USB 2.0 pair on B.Cu between its vias at U9 (x 12.2) and at U3, west to
# east, centre lines. D_N is the north track of the pair.
USB2_BCU = {"USB2_D_N": [(12.2, 16.2), (15.1, 19.1), (22.4, 19.1)],
            "USB2_D_P": [(12.2, 17.1), (14.85, 19.75), (21.5, 19.75)]}
# The x range of the crossing of the In2 island gap between +5V_SW and +1V0
CROSSING_X = (18.8, 19.4)


def mm(value):
    return pcbnew.FromMM(value)


def vec(x, y):
    return pcbnew.VECTOR2I(mm(ORIGIN[0] + x), mm(ORIGIN[1] + y))


class Scratch:
    def __init__(self, tmp, drop_rule=False, board=None):
        self.tmp = Path(tmp)
        self.drop_rule = drop_rule
        shutil.copy(board or KICAD / "raccoon-tap.kicad_pcb",
                    self.tmp / "raccoon-tap.kicad_pcb")
        self.board = pcbnew.LoadBoard(str(self.tmp / "raccoon-tap.kicad_pcb"))
        self.pad = {}
        for fp in self.board.GetFootprints():
            for pad in fp.Pads():
                self.pad[(fp.GetReference(), pad.GetNumber())] = (
                    pcbnew.ToMM(pad.GetPosition().x) - ORIGIN[0],
                    pcbnew.ToMM(pad.GetPosition().y) - ORIGIN[1])

    def P(self, ref, number):
        return self.pad[(ref, number)]

    def set_net(self, ref, number, net):
        fp = self.board.FindFootprintByReference(ref)
        for pad in fp.Pads():
            if pad.GetNumber() == number:
                pad.SetNet(self.board.FindNet(net))

    def trace(self, net, points, width, layer=pcbnew.F_Cu):
        item = self.board.FindNet(net)
        assert item is not None, net
        for a, b in zip(points, points[1:]):
            track = pcbnew.PCB_TRACK(self.board)
            track.SetLayer(layer)
            track.SetNet(item)
            track.SetStart(vec(*a))
            track.SetEnd(vec(*b))
            track.SetWidth(mm(width))
            self.board.Add(track)

    def via(self, net, x, y, diameter=0.6, drill=0.3):
        via = pcbnew.PCB_VIA(self.board)
        via.SetPosition(vec(x, y))
        via.SetWidth(mm(diameter))
        via.SetDrill(mm(drill))
        via.SetViaType(pcbnew.VIATYPE_THROUGH)
        via.SetLayerPair(pcbnew.F_Cu, pcbnew.B_Cu)
        via.SetNet(self.board.FindNet(net))
        self.board.Add(via)

    def leave(self, net, pad, direction, then, width, neck=NECK, length=None):
        """A track leaving a U3 pad: `neck` wide for `length` from the pad
        centre, then `width` along `then`."""
        length = NECK_LEN if length is None else length
        x, y = pad
        end = (x + direction[0] * length, y + direction[1] * length)
        self.trace(net, [pad, end], neck)
        self.trace(net, [end] + then, width)

    def drc(self):
        pcbnew.SaveBoard(str(self.tmp / "raccoon-tap.kicad_pcb"), self.board)
        shutil.copy(KICAD / "raccoon-tap.kicad_pro", self.tmp)
        rules = (KICAD / "raccoon-tap.kicad_dru").read_text()
        if self.drop_rule:
            rules = re.sub(r'\(rule "%s".*?\n\t\(constraint[^\n]*\)\)\n' % RULE_NAME,
                           "", rules, flags=re.S)
            assert RULE_NAME not in rules
        (self.tmp / "raccoon-tap.kicad_dru").write_text(rules)
        out = self.tmp / "drc.json"
        subprocess.run([KICAD_CLI, "pcb", "drc", "--severity-all", "--format",
                        "json", "--output", str(out),
                        str(self.tmp / "raccoon-tap.kicad_pcb")],
                       check=True, capture_output=True)
        data = json.loads(out.read_text())
        self.unconnected = data["unconnected_items"]
        return [v for v in data["violations"] if v["severity"] == "error"]


def describe(violation):
    where = violation["items"][0]["pos"]
    return (f"{violation['description']}: "
            + "; ".join(i["description"] for i in violation["items"])
            + f" at ({where['x'] - ORIGIN[0]:.2f}, {where['y'] - ORIGIN[1]:.2f})")


def left_offset(points, d):
    """The polyline offset by d to the left of its direction of travel (north,
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


# ---- the order of the MDI pairs, and the cable pair each one reaches --------

def crossing(a, b, c, d):
    def o(p, q, r):
        return (q[0] - p[0]) * (r[1] - p[1]) - (q[1] - p[1]) * (r[0] - p[0])
    return o(a, b, c) * o(a, b, d) < 0 and o(c, d, a) * o(c, d, b) < 0


CABLE_PAIRS = {"A": (1, 2), "B": (3, 6), "C": (4, 5), "D": (7, 8)}
GROUPS = {"MDI0": "AB", "MDI1": "AB", "MDI2": "CD", "MDI3": "CD"}


def mdi_order(s):
    """Straight lines from U3's eight MDI signal pads to J2 pins: (a) with the
    original netlist (U3 pin n to J2 pin n), (b) as the board now has it,
    (c) the best any legal re-assignment can do (ruling AJ, revised: MDI0 with
    MDI1 and MDI2 with MDI3 may exchange, P/N polarity may turn, nothing else),
    (d) with J2 on the bottom side. Also the cable-pair table of the board."""
    import yaml
    netlist = yaml.safe_load((KICAD.parent / "netlist.yaml").read_text())
    note = {str(p): (i or {}).get("note", "") for p, i in
            netlist["components"]["J2"]["pins"].items()}
    rj45 = {p: int(re.search(r"cable J(\d)", n).group(1))
            for p, n in note.items() if "cable J" in n}
    pair_of = {pin: k for k, v in CABLE_PAIRS.items() for pin in v}

    u3 = {n: s.P("U3", n) for n in map(str, (1, 2, 4, 5, 6, 7, 9, 10))}
    j2 = s.board.FindFootprintByReference("J2")

    def j2_pads():
        return {p.GetNumber(): (pcbnew.ToMM(p.GetPosition().x) - ORIGIN[0],
                                pcbnew.ToMM(p.GetPosition().y) - ORIGIN[1])
                for p in j2.Pads()}

    def count(pairs_map, pin_pos):
        lines = [(u3[a], pin_pos[b]) for a, b in pairs_map]
        return sum(crossing(*x, *y) for x, y in itertools.combinations(lines, 2))

    pins = j2_pads()
    original = count([(str(n), str(n)) for n in (1, 2, 4, 5, 6, 7, 9, 10)], pins)
    # the board as it is: the J2 pin of each net
    by_net = {}
    for fp in s.board.GetFootprints():
        for pad in fp.Pads():
            if re.fullmatch(r"MDI[0-3]_[PN]", pad.GetNetname()):
                by_net.setdefault(pad.GetNetname(), {})[fp.GetReference()] = pad.GetNumber()
    built = count([(v["U3"], v["J2"]) for v in by_net.values()], pins)
    table, bad = [], []
    for net in sorted(by_net):
        pin = by_net[net]["J2"]
        cable = pair_of.get(rj45[pin])
        table.append(f"{net} -> J2.{pin} -> RJ45 {rj45[pin]} -> pair {cable}")
        if cable not in GROUPS[net[:4]]:
            bad.append(net)
    u3_pairs = {0: ("1", "2"), 1: ("4", "5"), 2: ("6", "7"), 3: ("9", "10")}
    j2_pairs = {"A": ("1", "2"), "B": ("3", "4"), "C": ("7", "8"), "D": ("9", "10")}
    best = None
    for ab, cd in itertools.product(itertools.permutations("AB"),
                                    itertools.permutations("CD")):
        target = dict(zip((0, 1), ab)); target.update(dict(zip((2, 3), cd)))
        for flips in itertools.product((0, 1), repeat=4):
            m = []
            for k in range(4):
                ju = j2_pairs[target[k]]
                if flips[k]:
                    ju = ju[::-1]
                m += [(u3_pairs[k][0], ju[0]), (u3_pairs[k][1], ju[1])]
            c = count(m, pins)
            best = c if best is None else min(best, c)
    j2.Flip(j2.GetPosition(), pcbnew.FLIP_DIRECTION_LEFT_RIGHT)
    j2.SetOrientationDegrees(270)
    mirrored = count([(str(n), str(n)) for n in (1, 2, 4, 5, 6, 7, 9, 10)], j2_pads())
    return original, built, best, mirrored, table, bad


# ---- SuperSpeed and USB 2.0 -------------------------------------------------

def lay_usb(s):
    """TX: U3 -> C22/C23 -> U8 -> J3. RX: J3 -> U8 -> U3. D+/D-: J3 -> U9, the
    D- line through the channel between U9's pad columns (DS4260: pins 3 and 4
    are one node), to the bottom layer and back up at U3. A 45-degree run of a
    pair puts its two lines 0.375 x sqrt 2 apart along y, which is why the RX
    pair's P line turns 0.155 mm after its N line."""
    P = s.P
    pad = {n: P("U8", n) for n in "123456"}
    y_c = (pad["2"][1] + pad["5"][1]) / 2        # centre of the channel
    y_ch, y_rn, y_rp = y_c - 0.40, y_c + 0.40, 19.07
    j2, j3, j5, j6, j8, j9 = (P("J3", n) for n in ("2", "3", "5", "6", "8", "9"))
    p12, p13, p15, p16, p17, p18 = (P("U3", n) for n in ("12", "13", "15", "16", "17", "18"))
    c22_1, c22_2, c23_1, c23_2 = P("C22", "1"), P("C22", "2"), P("C23", "1"), P("C23", "2")
    x3, x1 = pad["3"][0], pad["1"][0]
    up = (0, -1)

    # TX: necks, then the pair opens to 1.05 mm at the caps
    s.leave("USB3_TX_P", p13, up, [c22_1], W)
    s.leave("USB3_TX_N", p12, up, [(c23_1[0], c23_1[1] + 0.5), c23_1], W)
    yn, yp = 15.2, 15.2 + PITCH
    s.trace("USB3_TX_CONN_N", [c23_2, (c23_2[0], yn), (22.0, yn), (21.4, 14.8125),
                               (8.3125, 14.8125), (7.5, j5[1]), (j5[0] + 0.9, j5[1])], W)
    s.trace("USB3_TX_CONN_N", [(x3, 14.8125), pad["3"]], W)
    s.trace("USB3_TX_CONN_P", [c22_2, (c22_2[0], yp), (22.0, yp), (20.9, y_ch),
                               (x3 - 0.7375, y_ch), (x3 - 2.25, 15.1875),
                               (7.8125, 15.1875), (7.0, j6[1]), (j6[0] + 0.9, j6[1])], W)
    s.trace("USB3_TX_CONN_P", [(x1, y_ch), pad["1"]], W)
    # RX
    s.trace("USB3_RX_N", [(j8[0] + 0.9, j8[1]), (7.5, j8[1]), (8.3125, 20.8125),
                          (x3 - 3.3125, 20.8125), (x3, y_rn), (21.0, y_rn),
                          (21.575, 18.075), (p15[0], 18.075), (p15[0], p15[1] - NECK_LEN)], W)
    s.trace("USB3_RX_N", [(p15[0], p15[1] - NECK_LEN), p15], NECK)
    s.trace("USB3_RX_N", [(x3, y_rn), (x3, pad["4"][1])], W)
    s.trace("USB3_RX_P", [(j9[0] + 0.9, j9[1]), (7.0, j9[1]), (7.8125, 21.1875),
                          (x3 - 1.495, 21.1875), (x3 + 0.6225, y_rp), (19.6, y_rp),
                          (20.22, 18.45), (p16[0], 18.45), (p16[0], p16[1] - NECK_LEN)], W)
    s.trace("USB3_RX_P", [(p16[0], p16[1] - NECK_LEN), p16], NECK)
    s.trace("USB3_RX_P", [(x1, y_rp), pad["6"]], W)
    # USB 2.0 at J3 and U9: D+ in at pin 1 and out at 6; D- in at 3, through
    # the channel between the columns, north of D+, out at the top; pin 4 joined
    u1, u2, u3, u4, u5, u6 = (P("U9", n) for n in "123456")
    s.trace("USB2_D_P", [(j3[0] + 0.9, j3[1]), (6.5, u1[1]), u1], W)
    s.trace("USB2_D_N", [(j2[0] + 0.9, j2[1]), (6.5, u3[1]), u3, (9.6, u3[1]),
                         (9.6, 16.2), (12.2, 16.2)], W)
    s.trace("USB2_D_N", [(9.6, u3[1]), u4], W)
    s.trace("USB2_D_P", [u6, (12.2, 17.1)], W)
    s.trace("GND", [(P("J3", "7")[0] + 0.9, P("J3", "7")[1]), u2], 0.3)
    s.via("+5V", 11.9, 18.0)
    s.trace("+5V", [u5, (11.9, 18.0)], 0.3)
    s.via("USB2_D_N", 12.2, 16.2)
    s.via("USB2_D_P", 12.2, 17.1)
    # the D pair under the RX lanes, on the bottom layer, up again at U3
    s.trace("USB2_D_P", [p18, (p18[0], p18[1] - NECK_LEN)], NECK)
    s.trace("USB2_D_P", [(p18[0], p18[1] - NECK_LEN), (p18[0], 19.75), (21.5, 19.75)], W)
    s.trace("USB2_D_N", [p17, (p17[0], p17[1] - NECK_LEN)], NECK)
    s.trace("USB2_D_N", [(p17[0], p17[1] - NECK_LEN), (p17[0], 19.1), (22.4, 19.1)], W)
    s.via("USB2_D_P", 21.5, 19.75)
    s.via("USB2_D_N", 22.4, 19.1)
    for net, path in USB2_BCU.items():
        s.trace(net, path, W, pcbnew.B_Cu)
    return {"U8 channel centre y": round(y_c, 2), "TX_P line": round(y_ch, 2),
            "RX_N line": round(y_rn, 2)}


# ---- MDI --------------------------------------------------------------------

def wrap(s, nets, pads, centre, lane_x, pin_n, pin_p):
    """One MDI pair round the south end of J2's pin field and up the channel
    east of the pin columns. `centre` is the pair's centre line up to the foot
    of the lane at x = lane_x; N (the west line) leaves the lane at the row of
    pin_n (a west-column pin, reached from the east through the gap between two
    east-column pins), P at the row of pin_p (an east-column pin)."""
    net_n, net_p = nets
    pad_n, pad_p = pads
    top = min(pin_n[1], pin_p[1])
    line = centre + [(lane_x, top)]
    left = left_offset(line, MPITCH / 2)
    right = left_offset(line, -MPITCH / 2)
    cut = lambda poly, y: poly[:-1] + [(poly[-1][0], y)]
    for net, pad in ((net_n, pad_n), (net_p, pad_p)):
        s.trace(net, [pad, (pad[0] + NECK_LEN, pad[1])], NECK)
    s.trace(net_n, [(pad_n[0] + NECK_LEN, pad_n[1])] + cut(left, pin_n[1]) + [pin_n], MW)
    s.trace(net_p, [(pad_p[0] + NECK_LEN, pad_p[1])] + cut(right, pin_p[1]) + [pin_p], MW)


def lay_mdi(s):
    u = {n: s.P("U3", n) for n in ("1", "2", "4", "5", "6", "7", "9", "10")}
    j = {str(n): s.P("J2", str(n)) for n in range(1, 11)}
    x0 = u["5"][0] + NECK_LEN
    # MDI1 and MDI0 round the south end, the inner pair first
    wrap(s, ("MDI1_N", "MDI1_P"), (u["5"], u["4"]),
         [(x0, 23.4), (33.0, 23.4), (34.6, 25.0), (40.2, 25.0), (42.7, 22.5)],
         42.7, j["4"], j["3"])
    wrap(s, ("MDI0_N", "MDI0_P"), (u["2"], u["1"]),
         [(x0, 24.6), (31.0, 24.6), (32.6, 26.2), (41.3, 26.2), (44.0, 23.5)],
         44.0, j["2"], j["1"])
    # MDI3 (north at U3) to J2 pins 7 (N) and 8 (P), MDI2 to pins 9 (N) and 10
    # (P), straight from the west: the nets are where the netlist puts them
    x0d = u["10"][0] + NECK_LEN
    for net, pin in (("MDI3_N", "10"), ("MDI3_P", "9"), ("MDI2_N", "7"), ("MDI2_P", "6")):
        s.trace(net, [u[pin], (x0d, u[pin][1])], NECK)
    s.trace("MDI3_N", [(x0d, 21.2), (35.5, 21.2), (36.8, 19.905), j["7"]], MW)
    s.trace("MDI3_P", [(x0d, 21.6), (36.6, 21.6), (37.0, 21.175), j["8"]], MW)
    s.trace("MDI2_N", [(x0d, 22.4), (36.5, 22.4), (36.6, 22.445), j["9"]], MW)
    s.trace("MDI2_P", [(x0d, 22.8), (34.0, 22.8), (34.915, 23.715), j["10"]], MW)


def lay_escapes(s):
    """Every U3 signal pad leaves with the neck and runs on (3 mm for MDI, 2 mm
    for the USB pairs, which have C22 and C23 beyond): the case the rule is for."""
    for pin, net in (("10", "MDI3_N"), ("9", "MDI3_P"), ("7", "MDI2_N"), ("6", "MDI2_P"),
                     ("5", "MDI1_N"), ("4", "MDI1_P"), ("2", "MDI0_N"), ("1", "MDI0_P")):
        pad = s.P("U3", pin)
        s.leave(net, pad, (1, 0), [(pad[0] + 3.0, pad[1])], MW)
    for pin, net in (("12", "USB3_TX_N"), ("13", "USB3_TX_P"), ("15", "USB3_RX_N"),
                     ("16", "USB3_RX_P"), ("17", "USB2_D_N"), ("18", "USB2_D_P")):
        pad = s.P("U3", pin)
        s.leave(net, pad, (0, -1), [(pad[0], pad[1] - 2.0)], W)


def usb2_return(s):
    """What lies under and beside the USB 2.0 pair's stretch on B.Cu (ruling AR,
    revised: one In2 island boundary is acceptable if the crossing is flanked
    by GND vias and the B.Cu GND pour runs beside the pair across it, tied to
    In1). Fills the zones of the scratch copy, then samples:
      * the In2 island under the centre line of the pair, every 0.05 mm, and
        counts the island-to-island boundaries it passes;
      * B.Cu GND pour 0.6 mm from the centre line of the outer track on each
        side (0.3 mm clearance, 0.1 mm half-track, 0.2 mm into the pour),
        along the whole stretch and in the crossing window;
      * the GND vias within 2.5 mm of the crossing, and whether each one is
        part of the pour polygon that runs beside the pair.
    Returns (problems, text lines)."""
    b = s.board
    pcbnew.ZONE_FILLER(b).Fill(b.Zones())
    gnd = b.FindNet("GND")
    pour = next(z for z in b.Zones() if z.GetLayer() == pcbnew.B_Cu
                and not z.GetIsRuleArea() and z.GetNetCode() == gnd.GetNetCode())
    islands = [z for z in b.Zones() if z.GetLayer() == pcbnew.In2_Cu]
    polys = pour.GetFilledPolysList(pcbnew.B_Cu)

    def island_at(x, y):
        for z in islands:
            if z.Outline().Contains(vec(x, y)):
                return z.GetNetname() + "@" + str(round(pcbnew.ToMM(z.GetBoundingBox().GetLeft()) - ORIGIN[0], 1))
        return "gap"

    def polygon_at(x, y):
        for i in range(polys.OutlineCount()):
            if polys.Outline(i).PointInside(vec(x, y)):
                return i
        return None

    lines, problems = [], []
    path = USB2_BCU["USB2_D_N"]
    # island labels along the north track from x 12.4 (first copper clear of the via) to 21.5
    seq, x = [], 12.4
    while x <= 21.5:
        y = next(path[i][1] + (path[i + 1][1] - path[i][1]) *
                 (x - path[i][0]) / (path[i + 1][0] - path[i][0])
                 for i in range(len(path) - 1) if path[i][0] <= x <= path[i + 1][0]
                 and path[i + 1][0] != path[i][0])
        label = island_at(x, y)
        if not seq or seq[-1][0] != label:
            seq.append((label, round(x, 2)))
        x += 0.05
    names = [label for label, _ in seq]
    boundaries = sum(1 for a, c in zip(names, names[1:])
                     if a != "gap" and c != "gap" and a != c) + \
        sum(1 for a, c, d in zip(names, names[1:], names[2:])
            if a != "gap" and c == "gap" and d != "gap" and a != d)
    lines.append("In2 under the pair, west to east: "
                 + " -> ".join(f"{label} from x {at}" for label, at in seq))
    lines.append(f"island boundaries crossed between x 12.4 and x 21.5: {boundaries}")
    if boundaries != 1:
        problems.append(f"the stretch crosses {boundaries} In2 island boundaries, the ruling covers one")

    # GND pour beside the pair
    sides = ((USB2_BCU["USB2_D_N"], 0.6), (USB2_BCU["USB2_D_P"], -0.6))
    total = covered = win_total = win_covered = 0
    polygons, missing = set(), []
    for pts, d in sides:
        off = left_offset(pts, d)
        for (a, c) in zip(off, off[1:]):
            n = max(1, int(math.hypot(c[0] - a[0], c[1] - a[1]) / 0.1))
            for k in range(n + 1):
                x = a[0] + (c[0] - a[0]) * k / n
                y = a[1] + (c[1] - a[1]) * k / n
                if x < 12.9 or x > 21.0:
                    continue        # inside 0.7 mm of a signal via: the vias' own pads are there
                total += 1
                inside = polygon_at(x, y)
                covered += inside is not None
                if inside is None:
                    missing.append((round(x, 2), round(y, 2)))
                else:
                    polygons.add(inside)
                if CROSSING_X[0] - 0.5 <= x <= CROSSING_X[1] + 0.5:
                    win_total += 1
                    win_covered += inside is not None
    lines.append(f"B.Cu GND pour beside the pair, 0.6 mm from the outer track of each side, "
                 f"x 12.9 to 21.0: {covered} of {total} samples inside the pour; "
                 f"crossing window x {CROSSING_X[0] - 0.5:.1f} to {CROSSING_X[1] + 0.5:.1f}: "
                 f"{win_covered} of {win_total}")
    if missing:
        lines.append(f"  not covered at: {missing[:8]}{' ...' if len(missing) > 8 else ''}")
    if win_covered != win_total or not win_total:
        problems.append("the B.Cu GND pour does not run beside the pair across the crossing")
    lines.append(f"  the pour beside the pair is {len(polygons)} filled polygon(s)")

    # the flank vias: are they in that polygon?
    tied = []
    for via in b.GetTracks():
        if via.Type() != pcbnew.PCB_VIA_T or via.GetNetCode() != gnd.GetNetCode():
            continue
        vx = pcbnew.ToMM(via.GetPosition().x) - ORIGIN[0]
        vy = pcbnew.ToMM(via.GetPosition().y) - ORIGIN[1]
        if not (CROSSING_X[0] - 2.5 <= vx <= CROSSING_X[1] + 2.5 and 17.0 <= vy <= 21.0):
            continue
        ring = {polygon_at(vx + 0.55 * math.cos(t * math.pi / 4),
                           vy + 0.55 * math.sin(t * math.pi / 4)) for t in range(8)}
        ring.discard(None)
        tied.append((round(vx, 2), round(vy, 2), bool(ring & polygons)))
    lines.append("GND vias within 2.5 mm of the crossing (x, y, on the pour beside the pair): "
                 + ", ".join(map(str, tied)))
    north = [t for t in tied if t[1] < 19.1 and t[2]]
    south = [t for t in tied if t[1] > 19.75 and t[2]]
    if not (north and south):
        problems.append("the crossing is not flanked by a tied GND via on each side of the pair")
    return problems, lines


def run(label, work, drop_rule=False, board=None):
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, drop_rule, board)
        info = work(s)
        errors = s.drc()
        return errors, s.unconnected, info


def main():
    status = 0
    with tempfile.TemporaryDirectory() as tmp:
        original, built, best, mirrored, table, bad = mdi_order(Scratch(tmp))
    print("MDI order, straight lines U3 pad -> J2 pin (28 pin pairs): original netlist "
          f"{original}; board now {built}; best legal re-assignment {best}; "
          f"J2 mirrored to the bottom {mirrored}")
    print("MDI nets on J2:")
    for line in table:
        print("  ", line)
    print("every MDI net stays inside its group of cable pairs (MDI0/1 on A/B, "
          f"MDI2/3 on C/D): {'yes' if not bad else 'NO: ' + str(bad)}")
    status |= 1 if bad else 0

    def work(s):
        info = lay_usb(s)
        lay_mdi(s)
        return info

    errors, unconnected, info = run("board", work)
    left = sorted({i["description"].split("[")[1].split("]")[0]
                   for u in unconnected for i in u["items"] if "[" in i["description"]
                   and i["description"].split("[")[1].split("]")[0].startswith(("USB", "MDI"))
                   and not i["description"].split("[")[1].split("]")[0] == "MDI_CT"})
    print(f"board as committed, SuperSpeed + USB 2.0 + all four MDI pairs: "
          f"{len(errors)} violation(s); signal nets still unconnected: {left or 'none'}")
    for v in errors:
        print("  ", describe(v))
    status |= 1 if errors or left else 0

    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp)
        lay_usb(s)
        problems, lines = usb2_return(s)
    print("USB 2.0 stretch on B.Cu, return path:")
    for line in lines:
        print("  ", line)
    for problem in problems:
        print("   PROBLEM:", problem)
    status |= 1 if problems else 0

    # controls for the return-path check: it must report a crossing without its
    # flank vias, and a pour that something cuts
    def no_flank_vias(s):
        for via in list(s.board.GetTracks()):
            if via.Type() == pcbnew.PCB_VIA_T and via.GetNetname() == "GND":
                vx = pcbnew.ToMM(via.GetPosition().x) - ORIGIN[0]
                if 17.0 <= vx <= 19.5 and 17.5 <= pcbnew.ToMM(via.GetPosition().y) - ORIGIN[1] <= 21.0:
                    s.board.Remove(via)

    def cut_pour(s):
        s.trace("USB3_RX_P", [(19.1, 16.5), (19.1, 18.7)], 0.2, pcbnew.B_Cu)

    for name, work in (("crossing without its flank vias", no_flank_vias),
                       ("pour cut beside the pair at the crossing", cut_pour)):
        with tempfile.TemporaryDirectory() as tmp:
            s = Scratch(tmp)
            lay_usb(s)
            work(s)
            problems, _ = usb2_return(s)
        print(f"control, {name}: {'reported, as it must be' if problems else 'NOT reported'}")
        status |= 0 if problems else 1

    for drop in (True, False):
        errors, _, _ = run("rule", lay_escapes, drop_rule=drop)
        print(f"escapes of the 14 U3 signal pads, rule {'absent' if drop else 'present'}: "
              f"{len(errors)} violation(s)")
        if drop and not errors:
            status = 1
        if not drop and errors:
            status = 1
            for v in errors:
                print("  ", describe(v))

    # controls: the rule must not let anything nearer than 0.2 mm, and must not
    # reach past U3's pads or tracks
    def control_track(s):
        # 0.19 mm above pad 14 (+1V0, x = 24.6): a USB3_RX_P track at y = 20.15 - 0.19 - 0.1
        s.trace("USB3_RX_P", [(24.0, 19.86), (25.2, 19.86)], 0.2)

    def control_other_footprint(s):
        # 0.25 mm from pad 1 of C12 (+1V0), which is not U3: the class rule still holds
        pad = s.P("C12", "1")
        s.trace("MDI0_P", [(pad[0] - 1.0, pad[1] - 0.31 - 0.25 - 0.09),
                           (pad[0] + 1.0, pad[1] - 0.31 - 0.25 - 0.09)], MW)

    def control_via(s):
        # a via 0.25 mm from the end of U3 pad 3 (+1V0): vias are outside the rule
        pad = s.P("U3", "3")
        s.via("MDI0_P", pad[0] + 0.41 + 0.25 + 0.3, pad[1])

    for name, work in (("track 0.19 mm from a U3 pad", control_track),
                       ("track 0.25 mm from a pad of another footprint", control_other_footprint),
                       ("via 0.25 mm from a U3 pad", control_via)):
        errors, _, _ = run(name, work)
        ok = bool(errors)
        print(f"control, {name}: {'reported, as it must be' if ok else 'NOT reported'}")
        status |= 0 if ok else 1
    return status


if __name__ == "__main__":
    sys.exit(main())
