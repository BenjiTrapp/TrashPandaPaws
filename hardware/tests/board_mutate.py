#!/usr/bin/env python3
"""
Plant a defect on a scratch copy of a board, for the mutation tests of
check_fab_release.py (ruling BJ). Run under KiCad's Python, like board_probe.py:

    $KIPY board_mutate.py IN OUT void-in1 X0 Y0 X1 Y1
    $KIPY board_mutate.py IN OUT via NET X Y [DIAMETER DRILL]
    $KIPY board_mutate.py IN OUT remove-via X Y
    $KIPY board_mutate.py IN OUT shift NET DX DY [X_FROM X_TO]

Coordinates are board-relative (the board origin is at 100, 80), in mm.

  void-in1  a keep-out for copper pours on In1 over the rectangle: the pair
            above it loses its continuous ground reference there
  via       a via of NET at X, Y (written as text; pcbnew 10.0.6 saves a via added with SetNet on the wrong net), which leaves a hole in the In1 pour round it
  remove-via  deletes the via at X, Y (within 0.05 mm)
  shift     moves every track segment of NET by (DX, DY), only those lying
            wholly between X_FROM and X_TO if given: the pair stops being coupled
"""

import sys
from pathlib import Path

import pcbnew

ORIGIN = (100.0, 80.0)


def vec(x, y):
    return pcbnew.VECTOR2I(pcbnew.FromMM(ORIGIN[0] + x), pcbnew.FromMM(ORIGIN[1] + y))


def void_in1(board, x0, y0, x1, y1):
    area = pcbnew.ZONE(board)
    area.SetIsRuleArea(True)
    area.SetLayer(pcbnew.In1_Cu)
    area.SetDoNotAllowZoneFills(True)
    area.SetDoNotAllowTracks(False)
    area.SetDoNotAllowVias(False)
    area.SetDoNotAllowPads(False)
    area.SetDoNotAllowFootprints(False)
    chain = pcbnew.SHAPE_LINE_CHAIN()
    for px, py in ((x0, y0), (x1, y0), (x1, y1), (x0, y1)):
        chain.Append(vec(px, py))
    chain.SetClosed(True)
    area.Outline().AddOutline(chain)
    board.Add(area)


def add_via(src, dst, net, x, y, diameter=0.6, drill=0.3):
    """Written into the file as text, on a board whose zone fills are removed:
    pcbnew 10.0.6 gives a via the net of the pour it stands in, on SaveBoard
    after SetNet and on load from text; the probe refills the zones itself."""
    board = pcbnew.LoadBoard(str(src))
    for zone in board.Zones():
        zone.UnFill()
    pcbnew.SaveBoard(str(dst), board)
    text = Path(dst).read_text()
    via = (f'\t(via\n\t\t(at {ORIGIN[0] + x:g} {ORIGIN[1] + y:g})\n\t\t(size {diameter:g})\n'
           f'\t\t(drill {drill:g})\n\t\t(layers "F.Cu" "B.Cu")\n\t\t(net "{net}")\n'
           f'\t\t(uuid "00000000-0000-4000-8000-{abs(hash((net, x, y))) % 10**12:012d}")\n\t)\n')
    Path(dst).write_text(text[:text.rstrip().rindex(")")] + via + ")\n")


def remove_via(board, x, y):
    for t in list(board.GetTracks()):
        if t.Type() == pcbnew.PCB_VIA_T:
            p = t.GetPosition()
            if (abs(pcbnew.ToMM(p.x) - ORIGIN[0] - x) < 0.05 and abs(pcbnew.ToMM(p.y) - ORIGIN[1] - y) < 0.05):
                board.Remove(t)
                return
    raise SystemExit(f"no via at {x}, {y}")


def shift(board, net, dx, dy, x_from=None, x_to=None):
    moved = 0
    for t in board.GetTracks():
        if t.Type() != pcbnew.PCB_TRACE_T or t.GetNetname() != net:
            continue
        a, b = t.GetStart(), t.GetEnd()
        ax, bx = pcbnew.ToMM(a.x) - ORIGIN[0], pcbnew.ToMM(b.x) - ORIGIN[0]
        if x_from is not None and not (x_from <= min(ax, bx) and max(ax, bx) <= x_to):
            continue
        d = pcbnew.VECTOR2I(pcbnew.FromMM(dx), pcbnew.FromMM(dy))
        t.SetStart(a + d)
        t.SetEnd(b + d)
        moved += 1
    if not moved:
        raise SystemExit(f"no track of {net} to move")


def main():
    src, dst, mode, *args = sys.argv[1:]
    if mode == "via":
        add_via(src, dst, args[0], *map(float, args[1:]))
        return
    board = pcbnew.LoadBoard(src)
    if mode == "void-in1":
        void_in1(board, *map(float, args))
    elif mode == "remove-via":
        remove_via(board, *map(float, args))
    elif mode == "shift":
        shift(board, args[0], *map(float, args[1:]))
    else:
        raise SystemExit(f"unknown mode {mode}")
    pcbnew.SaveBoard(dst, board)


if __name__ == "__main__":
    main()
