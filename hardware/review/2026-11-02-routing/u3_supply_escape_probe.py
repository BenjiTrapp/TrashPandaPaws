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
  candidate    the same, with ONE extra rule that is not in the repository
               (a candidate for a ruling, not a change): track against track
               0.2 mm where both tracks touch U3's courtyard. Reported: 0.
  pin14        pin 14 (+1V0) with the candidate rule, on the board with the
               SuperSpeed lanes laid: its escape runs up the channel between
               RX_N and TX_P and turns west where the channel ends, between
               RX_N's turn (y 18.075) and C22's pad (y 17.56). The 0.415 mm
               there cannot hold a 0.15 mm track; the DRC reports it even
               with the candidate rule. (A via inside the channel would cut
               In1 under RX_N and TX_P.)

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
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
CANDIDATE = '''
(rule "PROBE ONLY: track to track at the U3 escape"
	(condition "A.Type == 'Track' && B.Type == 'Track' && A.intersectsCourtyard('U3') && B.intersectsCourtyard('U3')")
	(constraint clearance (min 0.2mm)))
'''


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


def run(work, extra_rule=""):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name in ("raccoon-tap.kicad_pcb", "raccoon-tap.kicad_pro"):
            shutil.copy(KICAD / name, tmp / name)
        board = pcbnew.LoadBoard(str(tmp / "raccoon-tap.kicad_pcb"))
        work(board)
        pcbnew.SaveBoard(str(tmp / "raccoon-tap.kicad_pcb"), board)
        shutil.copy(KICAD / "raccoon-tap.kicad_pro", tmp)
        (tmp / "raccoon-tap.kicad_dru").write_text((KICAD / "raccoon-tap.kicad_dru").read_text() + extra_rule)
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


def main():
    a = run(escapes)
    show("escapes, rules as committed", a)
    b = run(escapes, CANDIDATE)
    show("escapes, with the candidate track-to-track rule", b)
    c = run(pin14, CANDIDATE)
    show("pin 14 out of its channel, with the candidate rule", c)
    # the evidence holds when: the committed rules refuse the escapes, the
    # candidate admits them, and pin 14 is refused even so
    return 0 if a and not b and c else 1


if __name__ == "__main__":
    sys.exit(main())
