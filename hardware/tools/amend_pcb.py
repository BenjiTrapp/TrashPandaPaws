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
  coupling   rulings BE / BF / BG (review 1): USB3 TX and TX_CONN re-laid
             coupled with route_pair, pin 14's escape re-routed at the class
             clearance, USB 2.0's run west from U3 moved south.
  decoupling ruling BH: C14 to B.Cu at pin 37's via, new C27 on B.Cu at
             pin 19's via.
  via_gaps   ruling BI: every via at least 0.1 mm of copper from a
             hand-soldered pad.
  antipads   review 1: In1's hole round a non-GND via kept clear of pair
             track edges.
  split_area ruling BF: tracks cut at the edge of U3's escape area, so the
             DRC applies ruling AU only inside it.
  rx         ruling BK: the AR flank via moved south of RX, RX re-laid coupled
             with route_pair.
  c9         ruling BK: C9 to B.Cu at the via of U3 pins 39 / 40.
  pin3_via   review 1: pin 3's +1V0 via 0.56 mm, centred between MDI1_P and
             MDI0_N, so In1's hole keeps 0.1 mm from both.
  split_area_out
             ruling BQ: tracks cut again 0.25 mm (+ half their width) past
             the edge of U3's escape area, which bounds ruling AU's reach.

  silk_id    task 10: board name and revision on F.SilkS and in the title block,
             which the release gate found missing.

Run them in this order (review 1: coupling decoupling via_gaps antipads
split_area; review 2: rx c9 pin3_via; review 3: split_area_out; task 10:
silk_id).

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

AMENDMENTS = {"pad_vias": rp.stage_pad_vias, "coupling": rp.stage_coupling,
              "decoupling": rp.stage_decoupling, "via_gaps": rp.stage_via_gaps,
              "antipads": rp.stage_antipads, "split_area": rp.stage_split_area,
              "rx": rp.stage_rx, "c9": rp.stage_c9, "pin3_via": rp.stage_pin3_via,
              "split_area_out": rp.stage_split_area_out, "silk_id": rp.stage_silk_id}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--board", default=str(rp.DEFAULT_PCB))
    parser.add_argument("amendments", nargs="+", choices=list(AMENDMENTS))
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
    for net, a, b, ref, pad, gap in getattr(r, "via_moves", []):
        print(f"ruling BI: {net} via {a} -> {b} ({gap} mm from {ref}.{pad})")
    for net, a, b, m0, m1, near_net in getattr(r, "antipad_moves", []):
        print(f"In1 hole: {net} via {a} -> {b}, margin to {near_net} {m0} -> {m1} mm")
    left = rp.pad_via_gaps(board)
    print(f"ruling BI: vias closer than {rp.PAD_VIA_GAP} mm to a hand-soldered pad: {len(left)}")
    for net, x, y, why in r.vias:
        print(f"  via {net:8s} ({x:6.2f}, {y:6.2f})  {why}")
    gaps = rp.reference_gaps(board)
    print("In1 under the F.Cu pair tracks: " + ("no gap" if not gaps else str({k: len(v) for k, v in gaps.items()})))
    return 1 if gaps or left else 0


if __name__ == "__main__":
    sys.exit(main())
