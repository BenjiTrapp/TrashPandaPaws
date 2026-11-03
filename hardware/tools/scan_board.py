#!/usr/bin/env python3
"""
Scan the routed board for what review 1 of task 9 found and the DRC does not
see. Exit 1 if any of the first two finds something.

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
    $KIPY hardware/tools/scan_board.py [--board <board>]

  via-in-pad  ruling BI: every via keeps at least 0.1 mm of copper from a pad
              of a hand-soldered part (all but U3 and Y1); U8 pin 2 is the
              listed exception (ruling BA, tented from the back).
  area edge   ruling BF: no F.Cu track runs both inside and outside U3's
              escape area, so ruling AU's 0.2 mm reaches past its edge only
              as far as a track's round end does; where that is used is
              listed (reported, not judged).
  coupling    ruling BE (reported, not judged): per pair net, the length at
              the designed gap and the length 0.6 mm or more from its partner.
  antipads    In1's hole round a non-GND via to the nearest pair track edge,
              listed where it is under 0.1 mm (reported, not judged).
"""

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pcbnew  # noqa: E402
import route_pcb as rp  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--board", default=str(rp.DEFAULT_PCB))
    args = parser.parse_args()
    board = pcbnew.LoadBoard(args.board)
    status = 0

    hits = rp.pad_via_gaps(board)
    print(f"via-in-pad: vias under {rp.PAD_VIA_GAP} mm from a hand-soldered pad: {len(hits)}")
    for net, at, ref, pad, gap, *_ in hits:
        print(f"  {net} via {at}: {gap} mm from {ref}.{pad}")
    status |= 1 if hits else 0

    crossing = []
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_TRACE_T and t.GetLayer() == pcbnew.F_Cu:
            a, b = rp.xy(t.GetStart()), rp.xy(t.GetEnd())
            if len(rp.split_at_area([a, b])) > 2:
                crossing.append((t.GetNetname(), a, b))
    print(f"area edge: F.Cu tracks running across the edge of U3's escape area: {len(crossing)}")
    for net, a, b in crossing:
        print(f"  {net} {a} -> {b}")
    status |= 1 if crossing else 0

    over = rp.au_overhangs(board)
    print(f"area edge: ruling AU used past the edge (net pair: least gap, reach past the edge, mm): {len(over)}")
    for (na, nb), (g, o) in sorted(over.items()):
        print(f"  {na} / {nb}: {g:.3f}, {o:.3f}")

    print(f"coupling (edge gap within {rp.COUPLING_TOL} mm of the pair gap): total / at the gap / >= 0.6 mm apart, mm")
    for net, (tot, at, far) in rp.coupling(board).items():
        print(f"  {net:15s} {tot:7.2f} {at:7.2f} ({100 * at / tot if tot else 0:4.0f} %) {far:7.2f}")

    print(f"antipads: In1 holes under {rp.ANTIPAD_SPARE} mm from a pair track edge")
    for v, m, near_net in rp.antipad_margins(board):
        if m < rp.ANTIPAD_SPARE:
            print(f"  {v.GetNetname()} via {tuple(round(c, 3) for c in rp.xy(v.GetPosition()))}: {m:.3f} mm to {near_net}")
    return status


if __name__ == "__main__":
    sys.exit(main())
