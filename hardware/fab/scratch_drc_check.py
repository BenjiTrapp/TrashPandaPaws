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
    ("USB3 TX after the AC caps (USB3_TX_CONN_P/N) at 0.17", "USB3_TX_CONN_P",
     "USB3_TX_CONN_N", 0.20, 0.17, None),
    ("control: the old names USB3_TX_P_CONN/N_CONN at 0.17 are not a pair",
     "USB3_TX_P_CONN", "USB3_TX_N_CONN", 0.20, 0.17,
     r'(Netzklasse|[Nn]et ?class)\s+"USB3"'),
    ("MDI0 pair at 0.21", "MDI0_P", "MDI0_N", 0.18, 0.21, None),
    ("USB3 RX pair at 0.15, below the pair gap", "USB3_RX_P", "USB3_RX_N",
     0.20, 0.15, r'"intra-pair clearance USB3"'),
    ("two different USB pairs at 0.17", "USB2_D_P", "USB3_RX_P", 0.20, 0.17,
     r'(Netzklasse|[Nn]et ?class)\s+"USB3"'),
    ("two different MDI pairs at 0.17", "MDI1_P", "MDI2_P", 0.18, 0.17,
     r'(Netzklasse|[Nn]et ?class)\s+"MDI"'),
]


def drc(tmp, board):
    """Save `board` into a scratch project and return kicad-cli's clearance
    violations."""
    shutil.rmtree(tmp / "b", ignore_errors=True)
    (tmp / "b").mkdir()
    pcbnew.SaveBoard(str(tmp / "b" / "raccoon-tap.kicad_pcb"), board)
    shutil.copy(KICAD / "raccoon-tap.kicad_pro", tmp / "b")
    shutil.copy(KICAD / "raccoon-tap.kicad_dru", tmp / "b")
    subprocess.run(
        [KICAD_CLI, "pcb", "drc", "--severity-all", "--format", "json",
         "--output", str(tmp / "b" / "drc.json"),
         str(tmp / "b" / "raccoon-tap.kicad_pcb")],
        check=True, capture_output=True)
    violations = json.loads((tmp / "b" / "drc.json").read_text())["violations"]
    return [v for v in violations if v["type"] == "clearance"]


def load(tmp):
    shutil.rmtree(tmp / "a", ignore_errors=True)
    (tmp / "a").mkdir()
    shutil.copy(KICAD / "raccoon-tap.kicad_pcb", tmp / "a")
    return pcbnew.LoadBoard(str(tmp / "a" / "raccoon-tap.kicad_pcb"))


# Two adjacent U3 pads of different pairs, and the direction a trace leaves
# them in: pads 16 / 17 (USB3_RX_P, USB2_D_N, bottom side, trace 0.20) and
# pads 5 / 6 (MDI1_N, MDI2_P, left side, trace 0.18).
ESCAPES = [("16", "USB3_RX_P", (0, 1), 0.20), ("17", "USB2_D_N", (0, 1), 0.20),
           ("5", "MDI1_N", (-1, 0), 0.18), ("6", "MDI2_P", (-1, 0), 0.18)]
NECK_WIDTH, NECK_LENGTH = 0.15, 1.0


def lay_escapes(board, how, neck_length=NECK_LENGTH):
    """Lay the four escape traces. `how`: 'centre' (full width from the pad
    centre), 'outer' (full width from the outer end of the pad) or 'neck'
    (NECK_WIDTH for NECK_LENGTH from the pad centre, then full width)."""
    u3 = board.FindFootprintByReference("U3")
    pads = {p.GetNumber(): p for p in u3.Pads()}
    for number, net, (dx, dy), width in ESCAPES:
        pad = pads[number]
        x, y = pcbnew.ToMM(pad.GetPosition().x), pcbnew.ToMM(pad.GetPosition().y)
        size = pad.GetSize()
        half = max(pcbnew.ToMM(size.x), pcbnew.ToMM(size.y)) / 2
        if how == "centre":
            add_track(board, net, x, y, x + dx * 2.5, y + dy * 2.5, width)
        elif how == "outer":
            add_track(board, net, x + dx * half, y + dy * half,
                      x + dx * 2.5, y + dy * 2.5, width)
        else:
            add_track(board, net, x, y, x + dx * neck_length,
                      y + dy * neck_length, NECK_WIDTH)
            add_track(board, net, x + dx * neck_length, y + dy * neck_length,
                      x + dx * 2.5, y + dy * 2.5, width)


def escape_violations(clearance):
    """Clearance violations that involve one of the escape traces."""
    nets = {net for _, net, _, _ in ESCAPES}
    found = []
    for v in clearance:
        text = " ".join(i["description"] for i in v["items"])
        if any(f"[{n}]" in text for n in nets) and "Pad" in text:
            found.append(v["description"])
    return found


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        board = load(tmp)
        rows = []
        y = 125.0
        for name, net_a, net_b, width, gap, expected in CASES:
            add_track(board, net_a, X0, y, X1, y, width)
            add_track(board, net_b, X0, y + width + gap, X1, y + width + gap,
                      width)
            rows.append((name, net_a, net_b, expected, y))
            y += 3.0
        clearance = drc(tmp, board)
        escapes = {}
        for how, length in (("centre", None), ("outer", None),
                            ("neck", NECK_LENGTH), ("neck short", 0.5)):
            board = load(tmp)
            lay_escapes(board, how.split()[0], length or NECK_LENGTH)
            escapes[how] = escape_violations(drc(tmp, board))

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

    def worst(descriptions):
        values = [float(m.group(1)) for d in descriptions
                  for m in [re.search(r"(?:tatsächlich|actual)\s+([0-9.]+) mm", d)]
                  if m]
        return min(values) if values else None

    for how, label in (("centre", "full width from the pad centre"),
                       ("outer", "full width from the outer end of the pad")):
        w = worst(escapes[how])
        print(f"note  {label}: " + (
            f"{len(escapes[how])} trace-to-pad violations, closest "
            f"{w:.4f} mm against the class clearance" if escapes[how]
            else "no trace-to-pad violation"))
    good = not escapes["neck"]
    ok &= good
    print(f"{'ok  ' if good else 'FAIL'} necked to {NECK_WIDTH} mm for "
          f"{NECK_LENGTH} mm from the pad centre, then full width: "
          f"{len(escapes['neck'])} trace-to-pad violations")
    pad_pad = [v for v in clearance
               if all(i["description"].startswith("Pad") for i in v["items"])
               and "intra-pair" in v["description"]]
    good = not pad_pad
    ok &= good
    w = escapes["neck short"]
    print(f"note  the same neck cut to 0.5 mm: {len(w)} trace-to-pad violations")
    print(f"{'ok  ' if good else 'FAIL'} pad-to-pad spacing of coupled pairs "
          f"on U3 is not touched by the pair rule: {len(pad_pad)} violations")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
