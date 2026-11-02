#!/usr/bin/env python3
"""Can the SuperSpeed lanes and the MDI escapes be laid out on the placed
board, at the geometry of hardware/fab/stackup-note.md?

Task 7 left the fit at U8, C22 and C23 open and handed it to task 8. This
script is the evidence for the answer. It copies the project (board,
.kicad_pro, .kicad_dru) to a temporary directory, lays the traces below on
the copy with pcbnew, runs kicad-cli's DRC there and prints what KiCad
reports. The repository's board is never written.

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
    $KIPY hardware/review/2026-10-31-placement/scratch_route_check.py

The traces are a feasibility demonstration, not the routing: task 9 routes.
They are laid exactly as the stackup note prescribes: USB3 pairs 0.20 mm wide
with a 0.17 mm pair gap, MDI 0.18 mm, a 0.15 mm neck for the first 1.0 mm from
the centre of every U3 pad (0.6 mm here, the shortest that clears the
neighbouring pad; the cap is 1.0 mm), the TX pair opened to 1.05 mm at the AC-coupling
capacitors, each U8 line passing through the 1.63 mm channel between U8's pad
rows or round the outside of a row.

Exit status 0 when nothing but the known structural item is reported (below).

KNOWN STRUCTURAL ITEM, reported separately and not a failure of the placement:
the "Power" net class asks for 0.30 mm clearance, and a track leaving a U3 pad
sits 0.20 mm from the neighbouring pad when that pad is a supply (U3 pins 11,
14 and 19 on the USB side, 3 and 8 on the MDI side), because the pads are on a
0.40 mm pitch. Necking the track to 0.10 mm would still leave 0.225 mm. The
existing U3 rule in raccoon-tap.kicad_dru only relaxes pad-to-pad spacing.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pcbnew

KICAD = Path(__file__).resolve().parents[2] / "kicad"
KICAD_CLI = "/opt/homebrew/bin/kicad-cli"
ORIGIN = (100.0, 80.0)          # gen_pcb.py ORIGIN_X, ORIGIN_Y
NECK_LEN = float(sys.argv[1]) if len(sys.argv) > 1 else 0.6   # mm from the pad centre; the note allows 1.0, a pad ends 0.41 from its centre


def mm(value):
    return pcbnew.FromMM(value)


def vec(x, y):
    return pcbnew.VECTOR2I(mm(ORIGIN[0] + x), mm(ORIGIN[1] + y))


class Scratch:
    def __init__(self, tmp):
        self.tmp = tmp
        shutil.copy(KICAD / "raccoon-tap.kicad_pcb", tmp)
        self.board = pcbnew.LoadBoard(str(tmp / "raccoon-tap.kicad_pcb"))
        self.pad = {}
        for fp in self.board.GetFootprints():
            for pad in fp.Pads():
                self.pad[(fp.GetReference(), pad.GetNumber())] = (
                    pcbnew.ToMM(pad.GetPosition().x) - ORIGIN[0],
                    pcbnew.ToMM(pad.GetPosition().y) - ORIGIN[1])

    def P(self, ref, number):
        return self.pad[(ref, number)]

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
        item = self.board.FindNet(net)
        assert item is not None, net
        via = pcbnew.PCB_VIA(self.board)
        via.SetPosition(vec(x, y))
        via.SetWidth(mm(diameter))
        via.SetDrill(mm(drill))
        via.SetViaType(pcbnew.VIATYPE_THROUGH)
        via.SetLayerPair(pcbnew.F_Cu, pcbnew.B_Cu)
        via.SetNet(item)
        self.board.Add(via)

    def leave(self, net, pad, direction, then, width, neck=0.15, neck_len=NECK_LEN):
        """A track leaving a U3 pad: `neck` wide for `neck_len` from the pad
        centre, then `width` along `then` (list of points)."""
        x, y = pad
        dx, dy = direction
        end = (x + dx * neck_len, y + dy * neck_len)
        self.trace(net, [pad, end], neck)
        self.trace(net, [end] + then, width)

    def drc(self):
        pcbnew.SaveBoard(str(self.tmp / "raccoon-tap.kicad_pcb"), self.board)
        for name in ("raccoon-tap.kicad_pro", "raccoon-tap.kicad_dru"):
            shutil.copy(KICAD / name, self.tmp)
        out = self.tmp / "drc.json"
        subprocess.run([KICAD_CLI, "pcb", "drc", "--severity-all", "--format",
                        "json", "--output", str(out),
                        str(self.tmp / "raccoon-tap.kicad_pcb")],
                       check=True, capture_output=True)
        found = json.loads(out.read_text())["violations"]
        return [v for v in found if v["severity"] == "error"]


def describe(violation):
    where = violation["items"][0]["pos"]
    return (f"{violation['description']}: "
            + "; ".join(i["description"] for i in violation["items"])
            + f" at ({where['x'] - ORIGIN[0]:.2f}, {where['y'] - ORIGIN[1]:.2f})")


def is_u3_supply_pad(violation):
    """A "Power" class clearance against a pad of U3: the structural item."""
    names = [i["description"] for i in violation["items"]]
    return ("Power" in violation["description"]
            and any(" von U3 " in n or " of U3 " in n for n in names))


def lay_superspeed(s):
    """TX: U3 -> C22/C23 -> U8 -> J3. RX: J3 -> U8 -> U3. Every pair is coupled
    (pitch 0.375, gap 0.175; on a 45-degree run the two lines are offset by
    0.375 x sqrt 2 along y, which is why the RX pair's P line turns 0.155 mm
    after its N line) wherever the geometry lets it be, and opens only where a
    pad or a channel makes it."""
    W, NECK, PITCH = 0.20, 0.15, 0.375
    h = PITCH / 2
    P = s.P
    pad = {n: P("U8", n) for n in "123456"}
    y_c = (pad["2"][1] + pad["5"][1]) / 2        # centre of the channel
    j5, j6, j8, j9 = P("J3", "5"), P("J3", "6"), P("J3", "8"), P("J3", "9")
    p13, p12, p15, p16 = (P("U3", n) for n in ("13", "12", "15", "16"))
    c22_1, c22_2 = P("C22", "1"), P("C22", "2")
    c23_1, c23_2 = P("C23", "1"), P("C23", "2")

    # --- TX, U3 side: necks, then the pair opens to 1.05 mm at the caps ------
    s.leave("USB3_TX_P", p13, (0, -1), [c22_1], W)
    s.leave("USB3_TX_N", p12, (0, -1), [(c23_1[0], c23_1[1] + 0.5), c23_1], W)

    # --- TX, after the caps: closes to a pair, runs west, opens at U8 ------
    # N stays above U8's TX row (0.62 mm stub down to pad 3); P goes into the
    # channel (y_c - 0.4) and out of it again east of the row.
    yn, yp = 15.2, 15.2 + PITCH                  # the pair east of U8
    y_ch = y_c - 0.40
    s.trace("USB3_TX_CONN_N", [c23_2, (c23_2[0], yn), (22.0, yn),
                               (21.4, 14.8125), (8.3125, 14.8125),
                               (7.5, j5[1]), (j5[0] + 0.9, j5[1])], W)
    s.trace("USB3_TX_CONN_N", [(pad["3"][0], 14.8125), pad["3"]], W)
    s.trace("USB3_TX_CONN_P", [c22_2, (c22_2[0], yp), (22.0, yp),
                               (20.9, y_ch), (16.5125, y_ch),
                               (15.0, 15.1875), (7.8125, 15.1875),
                               (7.0, j6[1]), (j6[0] + 0.9, j6[1])], W)
    s.trace("USB3_TX_CONN_P", [(pad["1"][0], y_ch), pad["1"]], W)

    # --- RX: J3 -> coupled -> rises -> opens round U8's RX row -> U3 --------
    y_rn, y_rp = y_c + 0.40, 19.07
    s.trace("USB3_RX_N", [(j8[0] + 0.9, j8[1]), (7.5, j8[1]),
                          (8.3125, 20.8125), (13.0, 20.8125), (16.3125, y_rn),
                          (21.3, y_rn), (22.2, 18.23),
                          (p15[0], 18.23), (p15[0], p15[1] - NECK_LEN)], W)
    s.trace("USB3_RX_N", [(p15[0], p15[1] - NECK_LEN), p15], NECK)
    s.trace("USB3_RX_N", [(pad["4"][0], y_rn), pad["4"]], W)
    s.trace("USB3_RX_P", [(j9[0] + 0.9, j9[1]), (7.0, j9[1]),
                          (7.8125, 21.1875), (13.155, 21.1875), (15.2725, y_rp),
                          (21.5, y_rp), (22.4, 18.6),
                          (p16[0], 18.6), (p16[0], p16[1] - NECK_LEN)], W)
    s.trace("USB3_RX_P", [(p16[0], p16[1] - NECK_LEN), p16], NECK)
    s.trace("USB3_RX_P", [(pad["6"][0], y_rp), pad["6"]], W)

    # --- D+/D-: the vias that take the pair to the bottom layer, west of the
    # RX rise and clear of U9's pads. Task 9 routes the pair; this only shows
    # the vias fit beside the lanes above.
    u9_6, u9_4 = P("U9", "6"), P("U9", "4")
    s.via("USB2_D_P", 12.2, u9_6[1])
    s.via("USB2_D_N", 12.2, u9_4[1])
    s.trace("USB2_D_P", [u9_6, (12.2, u9_6[1])], W)
    s.trace("USB2_D_N", [u9_4, (12.2, u9_4[1])], W)
    return {"U8 channel centre y": y_c, "TX_P line": y_ch, "RX_N line": y_rn}


def lay_mdi(s):
    """Each MDI pad leaves with the neck and runs straight east to x = 29.5,
    where task 9's fan-out begins; checks the escape and the room the pairs
    have between U3 and the capacitors at the corners."""
    for pin, net in (("10", "MDI3_N"), ("9", "MDI3_P"), ("7", "MDI2_N"),
                     ("6", "MDI2_P"), ("5", "MDI1_N"), ("4", "MDI1_P"),
                     ("2", "MDI0_N"), ("1", "MDI0_P")):
        pad = s.P("U3", pin)
        s.leave(net, pad, (1, 0), [(29.5, pad[1])], 0.18)


def mdi_order(s):
    """Why the MDI pairs arrive at J2 in reversed order: straight lines from
    U3's eight MDI signal pads to the same-numbered J2 pins, as placed and with
    J2 mirrored onto the bottom side (front still facing the board edge)."""
    import itertools

    def crossing(a, b, c, d):
        o = lambda p, q, r: (q[0] - p[0]) * (r[1] - p[1]) - (q[1] - p[1]) * (r[0] - p[0])
        return o(a, b, c) * o(a, b, d) < 0 and o(c, d, a) * o(c, d, b) < 0

    def count(j2):
        pads = {p.GetNumber(): (pcbnew.ToMM(p.GetPosition().x) - ORIGIN[0],
                                pcbnew.ToMM(p.GetPosition().y) - ORIGIN[1])
                for p in j2.Pads()}
        u3 = {n: s.P("U3", n) for n in map(str, (1, 2, 4, 5, 6, 7, 9, 10))}
        lines = {n: (u3[n], pads[n]) for n in u3}
        pins = sum(crossing(*lines[a], *lines[b]) for a, b in itertools.combinations(lines, 2))
        pairs = [("1", "2"), ("4", "5"), ("6", "7"), ("9", "10")]
        pair_pairs = sum(any(crossing(*lines[x], *lines[y]) for x in pa for y in pb)
                         for pa, pb in itertools.combinations(pairs, 2))
        return pins, pair_pairs

    j2 = s.board.FindFootprintByReference("J2")
    placed = count(j2)
    j2.Flip(j2.GetPosition(), pcbnew.FLIP_DIRECTION_LEFT_RIGHT)
    j2.SetOrientationDegrees(270)
    mirrored = count(j2)
    return placed, mirrored


def main():
    status = 0
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(Path(tmp))
        placed, mirrored = mdi_order(s)
        print(f"MDI order, straight lines U3 pad -> J2 pin: as placed {placed[0]} of 28 "
              f"pin pairs and {placed[1]} of 6 pair pairs cross; J2 mirrored to the "
              f"bottom side {mirrored[0]} and {mirrored[1]}")
        s = Scratch(Path(tmp))
        info = lay_superspeed(s)
        lay_mdi(s)
        errors = s.drc()
        structural = [v for v in errors if is_u3_supply_pad(v)]
        other = [v for v in errors if v not in structural]
        print("U8 channel:", {k: round(v, 2) for k, v in info.items()})
        print(f"{len(other)} violation(s) other than the known structural item")
        for v in other:
            print("  ", describe(v))
        print(f"{len(structural)} track-to-supply-pad violation(s) at U3 "
              "(known structural item, see the module docstring)")
        for v in structural:
            print("  ", describe(v))
        status = 1 if other else 0
    return status


if __name__ == "__main__":
    sys.exit(main())
