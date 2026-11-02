#!/usr/bin/env python3
"""Does raccoon-tap.kicad_dru do what stackup-note.md says it does?

Copies the project (board, .kicad_pro, .kicad_dru) into a scratch directory,
lays short test traces on it, runs kicad-cli's DRC there and prints, for each
case, the clearance violation KiCad reports (or none) next to what the note
expects. The repository's board is never written.

Run it with the interpreter from the KiCad bundle (it imports pcbnew):

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
    $KIPY hardware/fab/scratch_drc_check.py

Exit status 0 when every case behaves as expected.

The traces are laid below the board outline (y 125 mm and further), clear of
every part. U3's own pads are used for the last case.
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pcbnew

KICAD = Path(__file__).resolve().parent.parent / "kicad"
KICAD_CLI = "/opt/homebrew/bin/kicad-cli"
X0, X1 = 102.0, 106.0


def mm(value):
    return pcbnew.FromMM(value)


def add_track(board, net, x0, y0, x1, y1, width):
    found = board.FindNet(net)
    if found is None:
        found = pcbnew.NETINFO_ITEM(board, net)
        board.Add(found)
    track = pcbnew.PCB_TRACK(board)
    track.SetLayer(pcbnew.F_Cu)
    track.SetNet(found)
    track.SetStart(pcbnew.VECTOR2I(mm(x0), mm(y0)))
    track.SetEnd(pcbnew.VECTOR2I(mm(x1), mm(y1)))
    track.SetWidth(mm(width))
    board.Add(track)


# name, net a, net b, width, edge-to-edge gap, regex the violation text must
# match, or None for no violation (KiCad words its messages in the language set
# in its preferences, hence the alternatives)
CASES = [
    ("USB2 D+/D- at the pair gap 0.17", "USB2_D_P", "USB2_D_N", 0.20, 0.17, None),
    ("USB3 TX after the AC caps (_CONN nets) at 0.17", "USB3_TX_P_CONN",
     "USB3_TX_N_CONN", 0.20, 0.17, None),
    ("MDI0 pair at 0.21", "MDI0_P", "MDI0_N", 0.18, 0.21, None),
    ("USB3 RX pair at 0.15, below the pair gap", "USB3_RX_P", "USB3_RX_N",
     0.20, 0.15, r'"intra-pair clearance USB3"'),
    ("two different USB pairs at 0.17", "USB2_D_P", "USB3_RX_P", 0.20, 0.17,
     r'(Netzklasse|[Nn]et ?class)\s+"USB3"'),
    ("two different MDI pairs at 0.17", "MDI1_P", "MDI2_P", 0.18, 0.17,
     r'(Netzklasse|[Nn]et ?class)\s+"MDI"'),
]


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "a").mkdir()
        (tmp / "b").mkdir()
        shutil.copy(KICAD / "raccoon-tap.kicad_pcb", tmp / "a")
        board = pcbnew.LoadBoard(str(tmp / "a" / "raccoon-tap.kicad_pcb"))
        rows = []
        y = 125.0
        for name, net_a, net_b, width, gap, expected in CASES:
            add_track(board, net_a, X0, y, X1, y, width)
            add_track(board, net_b, X0, y + width + gap, X1, y + width + gap,
                      width)
            rows.append((name, net_a, net_b, expected, y))
            y += 3.0
        # stubs straight out of U3 pads 16 (USB3_RX_P) and 17 (USB2_D_N)
        u3 = board.FindFootprintByReference("U3")
        pads = {p.GetNumber(): p.GetPosition() for p in u3.Pads()}
        for number, net in (("16", "USB3_RX_P"), ("17", "USB2_D_N")):
            pos = pads[number]
            add_track(board, net, pcbnew.ToMM(pos.x), pcbnew.ToMM(pos.y),
                      pcbnew.ToMM(pos.x), pcbnew.ToMM(pos.y) + 2.5, 0.20)
        pcbnew.SaveBoard(str(tmp / "b" / "raccoon-tap.kicad_pcb"), board)
        shutil.copy(KICAD / "raccoon-tap.kicad_pro", tmp / "b")
        shutil.copy(KICAD / "raccoon-tap.kicad_dru", tmp / "b")
        subprocess.run(
            [KICAD_CLI, "pcb", "drc", "--severity-all", "--format", "json",
             "--output", str(tmp / "b" / "drc.json"),
             str(tmp / "b" / "raccoon-tap.kicad_pcb")],
            check=True, capture_output=True)
        violations = json.loads((tmp / "b" / "drc.json").read_text())[
            "violations"]

    clearance = [v for v in violations if v["type"] == "clearance"]

    def found(net_a, net_b, y0, y1):
        for v in clearance:
            items = v["items"]
            text = " ".join(i["description"] for i in items)
            ys = [i["pos"]["y"] for i in items]
            if f"[{net_a}]" in text and f"[{net_b}]" in text \
                    and all(y0 <= v_y <= y1 for v_y in ys):
                return v["description"]
        return None

    ok = True
    for name, net_a, net_b, expected, y0 in rows:
        got = found(net_a, net_b, y0 - 0.5, y0 + 1.5)
        good = (got is None) if expected is None else (
            got is not None and bool(re.search(expected, got)))
        ok &= good
        print(f"{'ok  ' if good else 'FAIL'} {name}: "
              f"{'no clearance violation' if got is None else got}")

    stub = None
    for v in clearance:
        text = " ".join(i["description"] for i in v["items"])
        if "Pad 17" in text and "[USB3_RX_P]" in text:
            stub = re.search(r"(?:tatsächlich|actual)\s+([0-9.]+) mm", v["description"])
    print("note  trace on U3 pad 16 against the neighbouring pad 17: "
          + (f"{stub.group(1)} mm, flagged against the class clearance"
             if stub else "no violation"))
    pad_pad = [v for v in clearance
               if all(i["description"].startswith("Pad") for i in v["items"])
               and "intra-pair" in v["description"]]
    good = not pad_pad
    ok &= good
    print(f"{'ok  ' if good else 'FAIL'} pad-to-pad spacing of coupled pairs "
          f"on U3 is not touched by the pair rule: {len(pad_pad)} violations")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
