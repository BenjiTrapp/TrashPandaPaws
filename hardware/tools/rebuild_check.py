#!/usr/bin/env python3
"""
Rebuild the board from its sources in a scratch directory and compare it with
the committed board, item by item. The PCB is frozen (tools/gen_pcb.py refuses
a routed board), so the committed file is the geometry, and this proves it is
still what gen_pcb.py followed by route_pcb.py makes: every track, via,
footprint (position, side, angle, DNP, pad nets), zone outline and silkscreen
text. Exit 0 if identical.

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
    $KIPY hardware/tools/rebuild_check.py

The committed board is only read.
"""

import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pcbnew  # noqa: E402

COMMITTED = HERE.parent / "kicad" / "raccoon-tap.kicad_pcb"
R = 4


def mm(v):
    return round(pcbnew.ToMM(v), R)


def pt(p):
    return (mm(p.x), mm(p.y))


def items(board):
    out = Counter()
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_VIA_T:
            out[("via", t.GetNetname(), pt(t.GetPosition()), mm(t.GetWidth()), mm(t.GetDrill()),
                 str(t.GetFrontTentingMode()), str(t.GetBackTentingMode()))] += 1
        else:
            a, b = sorted((pt(t.GetStart()), pt(t.GetEnd())))
            out[("track", t.GetNetname(), t.GetLayerName(), a, b, mm(t.GetWidth()))] += 1
    for fp in board.GetFootprints():
        pads = tuple(sorted((p.GetNumber(), p.GetNetname()) for p in fp.Pads()))
        out[("footprint", fp.GetReference(), fp.GetValue(), pt(fp.GetPosition()),
             round(fp.GetOrientationDegrees(), 3), fp.IsFlipped(), fp.IsDNP(), pads)] += 1
    for z in board.Zones():
        o = z.Outline()
        pts = tuple(pt(o.CVertex(i)) for i in range(o.FullPointCount()))
        out[("zone", z.GetNetname(), z.GetZoneName(), z.GetLayerName(), z.GetIsRuleArea(), pts)] += 1
    for d in board.GetDrawings():
        if d.Type() == pcbnew.PCB_TEXT_T:
            out[("text", d.GetText(), d.GetLayerName(), pt(d.GetPosition()))] += 1
    return out


def main():
    with tempfile.TemporaryDirectory() as tmp:
        placed, routed = Path(tmp) / "placed.kicad_pcb", Path(tmp) / "routed.kicad_pcb"
        for cmd in ([str(HERE / "gen_pcb.py"), "--out", str(placed)],
                    [str(HERE / "route_pcb.py"), "--in", str(placed), "--out", str(routed)]):
            result = subprocess.run([sys.executable, *cmd], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"{Path(cmd[0]).name} failed ({result.returncode}):\n{result.stderr[-1500:]}")
                return 2
        rebuilt, committed = items(pcbnew.LoadBoard(str(routed))), items(pcbnew.LoadBoard(str(COMMITTED)))
    only_new, only_old = rebuilt - committed, committed - rebuilt
    total = sum(committed.values())
    print(f"committed {total} items, rebuilt {sum(rebuilt.values())}; "
          f"identical {total - sum(only_old.values())} of {total}")
    for label, diff in (("only in the rebuild", only_new), ("only in the committed board", only_old)):
        for item in list(diff)[:10]:
            print(f"  {label}: {item}")
    return 0 if not only_new and not only_old else 1


if __name__ == "__main__":
    sys.exit(main())
