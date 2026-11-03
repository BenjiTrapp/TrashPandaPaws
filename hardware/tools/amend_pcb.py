#!/usr/bin/env python3
"""
Change the routed board in place, without regenerating it (the PCB is frozen:
tools/gen_pcb.py refuses a routed board). Each amendment is a stage of
tools/route_pcb.py, so a fresh route of the placed board reproduces the same
copper; this script applies the stages that came after the board was routed.

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
    $KIPY hardware/tools/amend_pcb.py [--board <board>] pad_vias

Amendments, in the order they were made:
  pad_vias   ruling BA: no open via in or touching a pad of a hand-soldered
             part; moved off the pad where the copper allows, otherwise
             tented from the back.

An amendment that finds nothing to do says so and changes nothing. The zones
are refilled before the board is saved.
"""

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pcbnew  # noqa: E402
import route_pcb as rp  # noqa: E402

AMENDMENTS = {"pad_vias": rp.stage_pad_vias}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--board", default=str(rp.DEFAULT_PCB))
    parser.add_argument("amendments", nargs="+", choices=sorted(AMENDMENTS))
    args = parser.parse_args()
    board = pcbnew.LoadBoard(args.board)
    if not rp.track_count(board):
        print("error: the board is not routed; route it with tools/route_pcb.py", file=sys.stderr)
        return 2
    r = rp.Router(board)
    for name in args.amendments:
        AMENDMENTS[name](r)
    pcbnew.ZONE_FILLER(board).Fill(board.Zones())
    pcbnew.SaveBoard(args.board, board)
    for ref, pad, what in getattr(r, "pad_vias", []):
        print(f"ruling BA: {ref}.{pad}: {what}")
    for net, x, y, why in r.vias:
        print(f"  via {net:8s} ({x:6.2f}, {y:6.2f})  {why}")
    gaps = rp.reference_gaps(board)
    print("In1 under the F.Cu pair tracks: " + ("no gap" if not gaps else str({k: len(v) for k, v in gaps.items()})))
    return 1 if gaps else 0


if __name__ == "__main__":
    sys.exit(main())
