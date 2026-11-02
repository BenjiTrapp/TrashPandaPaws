#!/usr/bin/env python3
"""Why task 9 stopped at the supplies: U3's supply and GND pins cannot leave
their pads within the rules in force. Evidence, reproducible.

Every run copies the committed board and project to a temporary directory,
lays copper there with pcbnew and prints what kicad-cli's DRC reports. The
repository's board is never written.

  escapes      every U3 pad that has a net gets a 0.6 mm escape along its own
               axis, 0.15 mm wide (the narrowest track the board allows), as
               any route out of U3 has to start. Reported: every supply / GND
               escape next to an escape of another net. At the 0.40 mm pitch
               two 0.15 mm escapes are 0.25 mm apart; the Power class asks
               0.30 mm, and "track to U3 pad on fine-pitch parts" (ruling AN)
               covers track against pad only, not track against track.
  candidate    the same, with ruling AU's rule "track to track at the U3
               escape" (round 1 proposed it; it is now committed). Reported: 0.
  pin14        pin 14 (+1V0) with that rule, on the board with the
               SuperSpeed lanes laid: its escape runs up the channel between
               RX_N and TX_P and turns west where the channel ends, between
               RX_N's turn (y 18.075) and C22's pad (y 17.56). The 0.415 mm
               there cannot hold a 0.15 mm track; the DRC reports it even
               with the candidate rule. (A via inside the channel would cut
               In1 under RX_N and TX_P.)

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
Round 2 (after rulings AU and AV), with the committed rule "track to track
at the U3 escape" and its area in force, and with C8, C22 and C23 parked off the
board in the copy, the most any move of the parts ruling AV releases could achieve:

  enclosed     every way out for what the decoupling ring encloses: C10
               (+3V3, pins 23 / 26) and C18 (+5V_SW, pin 27), between the
               other caps of the column west of U3 (1.05 mm pitch, pad 1 0.64
               mm from U3's pads), and pins 32, 33 and 38, behind C15 and C14
               south of U3. Each case is one track or via; each is reported.
  control      the neighbouring cases that do get out (with C8 away), so the
               probe is shown able to pass.

    $KIPY hardware/review/2026-11-02-routing/u3_supply_escape_probe.py
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HARDWARE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(HARDWARE / "tools"))
import pcbnew  # noqa: E402
import route_pcb as rp  # noqa: E402

KICAD = HARDWARE / "kicad"
KICAD_CLI = "/opt/homebrew/bin/kicad-cli"
def escapes(board):
    P = rp.Pads(board)
    for pad in board.FindFootprintByReference("U3").Pads():
        n = pad.GetNumber()
        if not n or n == "41" or not pad.GetNetname():
            continue
        x, y = P("U3", n)
        dx, dy = {0: (1, 0), 1: (0, -1), 2: (-1, 0), 3: (0, 1)}[(int(n) - 1) // 10]
        rp.route_net(board, pad.GetNetname(), [(x, y), (x + dx * 0.6, y + dy * 0.6)], 0.15)


def pin14(board):
    r = rp.Router(board)
    rp.stage_usb3_tx(r)
    rp.stage_usb3_rx(r)
    x, y = r.P("U3", 14)
    exit_y = (18.075 - 0.1 + 17.56) / 2          # midway between RX_N's edge and C22.1
    rp.route_net(board, "+1V0", [(x, y), (x, exit_y), (23.3, exit_y)], 0.15)


def without(*refs):
    """Park the parts far off the board (removing a footprint through the
    bindings crashes pcbnew on save)."""
    def strip(board):
        for i, ref in enumerate(refs):
            board.FindFootprintByReference(ref).SetPosition(rp.vec(-40.0, -40.0 - 8.0 * i))
    return strip


SLOT_X = 20.83    # middle of the 0.64 mm between the column's pad 1 (east edge 20.51) and U3's west pads (21.15)
GAP_Y = 26.15     # middle of the 0.59 mm between U3's south pads (25.85) and the cap row (26.44)


def case(work):
    def go(board):
        without("C8", "C22", "C23")(board)
        P = rp.Pads(board)
        for net, pts, via in work(P):
            if pts:
                rp.route_net(board, net, pts, 0.15)
            if via:
                rp.add_via(board, net, *via)
    return go


ENCLOSED = [
    ("C18.1 / pin 27 (+5V_SW) north up the slot past C10.1",
     lambda P: [("+5V_SW", [P("C18", 1), (SLOT_X, 23.85), (SLOT_X, 21.9)], None)]),
    ("C18.1 / pin 27 (+5V_SW) south down the slot past C11.1",
     lambda P: [("+5V_SW", [P("C18", 1), (SLOT_X, 23.85), (SLOT_X, 25.6)], None)]),
    ("C18.1 / pin 27 (+5V_SW) via in the slot",
     lambda P: [("+5V_SW", None, (SLOT_X, 23.85))]),
    ("C10.1 / pins 23, 26 (+3V3) north up the slot past C17.1",
     lambda P: [("+3V3", [P("C10", 1), (SLOT_X, 22.8), (SLOT_X, 21.0)], None)]),
    ("C10.1 / pins 23, 26 (+3V3) south down the slot past C18.1",
     lambda P: [("+3V3", [P("C10", 1), (SLOT_X, 22.8), (SLOT_X, 24.4)], None)]),
    ("C10.1 / pins 23, 26 (+3V3) via in the slot",
     lambda P: [("+3V3", None, (SLOT_X, 22.8))]),
    ("C17.1 / pin 22 (DVDD10, to TP7) south down the slot past C10.1",
     lambda P: [("DVDD10_UPS", [P("C17", 1), (SLOT_X, 21.75), (SLOT_X, 23.0)], None)]),
    ("pin 32 (ETH_LED0) south",
     lambda P: [("ETH_LED0", [P("U3", 32), (22.6, 27.5)], None)]),
    ("pin 32 (ETH_LED0) west along the gap above C15",
     lambda P: [("ETH_LED0", [P("U3", 32), (22.6, GAP_Y), (20.5, GAP_Y)], None)]),
    ("pin 33 (+3V3) south",
     lambda P: [("+3V3", [P("U3", 33), (23.0, 27.5)], None)]),
    ("pin 33 (+3V3) west along the gap above C15",
     lambda P: [("+3V3", [P("U3", 33), (23.0, GAP_Y), (20.5, GAP_Y)], None)]),
    ("pin 38 (RSET) south",
     lambda P: [("RSET", [P("U3", 38), (25.0, 27.5)], None)]),
    ("pin 38 (RSET) east along the gap above C14 and C9",
     lambda P: [("RSET", [P("U3", 38), (25.0, GAP_Y), (29.0, GAP_Y)], None)]),
]
CONTROLS = [
    ("pin 21 (+5V_SW) via and C17.1 (DVDD10) both out of the slot's north mouth, C8 away",
     lambda P: [("+5V_SW", [P("U3", 21), (21.0, 21.2), (20.95, 20.75)], (20.95, 20.75)),
                ("DVDD10_UPS", [P("U3", 22), (21.0, 21.6), (20.4, 21.75)], None),
                ("DVDD10_UPS", [P("C17", 1), (20.0, 21.75), (20.0, 20.2), (19.0, 20.2)], None)]),
    ("pin 30 (ETH_LED1) and C11.1 (+3V3), two vias 0.9 mm apart in the slot's south mouth",
     lambda P: [("ETH_LED1", [P("U3", 30), (21.0, 25.0), (21.0, 25.85)], (21.0, 25.85)),
                ("+3V3", [P("C11", 1), (20.1, 25.85)], (20.1, 25.85))]),
    ("pin 30 (ETH_LED1) alone, via at the slot's south mouth",
     lambda P: [("ETH_LED1", [P("U3", 30), (20.9, 25.1), (20.9, 25.8)], (20.9, 25.8))]),
    ("pins 39 / 40 (+3V3) east under C14 to C9.1",
     lambda P: [("+3V3", [P("U3", 39), (25.4, 26.05), (27.17, 26.05), P("C9", 1)], None),
                ("+3V3", [P("U3", 40), (25.8, 26.05)], None)]),
    ("pin 34 (+1V0) to C15.1, pin 37 (+1V0) to C14.1",
     lambda P: [("+1V0", [P("U3", 34), (23.4, 26.0), P("C15", 1)], None),
                ("+1V0", [P("U3", 37), (24.6, 26.0), P("C14", 1)], None)]),
]


def strip_au(dru):
    start = dru.index('(rule "track to track at the U3 escape"')
    end = dru.index(")))", start) + 3
    return dru[:start] + dru[end:]


def run(work, extra_rule="", dru_edit=None):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name in ("raccoon-tap.kicad_pcb", "raccoon-tap.kicad_pro"):
            shutil.copy(KICAD / name, tmp / name)
        board = pcbnew.LoadBoard(str(tmp / "raccoon-tap.kicad_pcb"))
        work(board)
        pcbnew.SaveBoard(str(tmp / "raccoon-tap.kicad_pcb"), board)
        shutil.copy(KICAD / "raccoon-tap.kicad_pro", tmp)
        dru = (KICAD / "raccoon-tap.kicad_dru").read_text()
        (tmp / "raccoon-tap.kicad_dru").write_text((dru_edit(dru) if dru_edit else dru) + extra_rule)
        out = tmp / "drc.json"
        subprocess.run([KICAD_CLI, "pcb", "drc", "--severity-error", "--format", "json",
                        "--output", str(out), str(tmp / "raccoon-tap.kicad_pcb")],
                       check=True, capture_output=True)
        return [v for v in json.loads(out.read_text())["violations"] if v["severity"] == "error"]


def show(label, errors):
    print(f"{label}: {len(errors)} error(s)")
    for v in errors:
        p = v["items"][0]["pos"]
        print(f"   {v['type']}: " + " / ".join(i["description"] for i in v["items"])
              + f" at ({p['x'] - rp.ORIGIN[0]:.2f}, {p['y'] - rp.ORIGIN[1]:.2f})")


def round2():
    """Exit 0 when every enclosed case is refused and every control passes."""
    ok = True
    print("round 2, committed rules, C8 / C22 / C23 parked off the board:")
    for label, work in ENCLOSED:
        e = run(case(work))
        show("  ENCLOSED " + label, e)
        ok &= bool(e)
    for label, work in CONTROLS:
        e = run(case(work))
        show("  control  " + label, e)
        ok &= not e
    return ok


def main():
    if "--round2" in sys.argv:
        return 0 if round2() else 1
    # Round 1, re-run against the rules as they now stand: ruling AU's rule is
    # committed, so the escapes pass; without it they fail as they did.
    a = run(escapes, dru_edit=strip_au)
    show("escapes, committed rules without AU's rule (the round 1 finding)", a)
    b = run(escapes)
    show("escapes, committed rules (AU's rule in force)", b)
    c = run(pin14)
    show("pin 14 out of its channel, C22 where task 8 put it", c)
    return 0 if a and not b and c else 1


if __name__ == "__main__":
    sys.exit(main())
