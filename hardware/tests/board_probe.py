#!/usr/bin/env python3
"""
Measure a routed raccoon-tap board for the two properties KiCad's DRC cannot
see (ruling BJ). Run it under KiCad's own Python, which has pcbnew:

    KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
    $KIPY hardware/tests/board_probe.py [--board <board>] [--in1] [--coupling]

It only measures and prints JSON; every judgement (which gaps are allowed, how
much uncoupled length each pair has been granted) lives in check_fab_release.py,
so a failing board and the reason it fails are decided in one place. It never
writes the board.

  --in1       Refills the zones in memory, then walks the centre line and both
              edges of every pair track (every 0.02 mm) and reports each point
              that has no In1 GND copper under it, attributed to the hole in
              In1 that explains it (a via or hole of some net) or to nothing.
              In1 is the plane that is the pair's reference; a pair on B.Cu is
              reported by its layer and judged separately.
  --coupling  For every pair track, every 0.05 mm, the edge-to-edge gap to the
              nearest copper of its partner net on the same layer (tracks,
              pads and vias), with the track's width. Needs no zone fill.
"""

import argparse
import json
import math
import re
import sys

import pcbnew

ORIGIN = (100.0, 80.0)
IN1_STEP = 0.02
COUPLING_STEP = 0.05
PAIR_PREFIX = re.compile(r"^(USB3|USB2|MDI)")
FAR = 99.0


def mm(v):
    return pcbnew.ToMM(v)


def rel(p):
    return (mm(p.x) - ORIGIN[0], mm(p.y) - ORIGIN[1])


def vec(x, y):
    return pcbnew.VECTOR2I(pcbnew.FromMM(ORIGIN[0] + x), pcbnew.FromMM(ORIGIN[1] + y))


def pair_nets(board):
    """{net: partner} for every net on a trailing _P / _N whose partner net
    also exists and that belongs to the USB or MDI groups."""
    names = {str(n) for n in board.GetNetsByName().keys()}
    out = {}
    for n in names:
        m = re.match(r"^(.*)_([PN])$", n)
        if not m or not PAIR_PREFIX.match(n):
            continue
        other = m.group(1) + "_" + ("N" if m.group(2) == "P" else "P")
        if other in names:
            out[n] = other
    return out


def traces(board, nets):
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_TRACE_T and t.GetNetname() in nets:
            yield t


def seg_dist(a, b, p):
    dx, dy = b[0] - a[0], b[1] - a[1]
    l2 = dx * dx + dy * dy
    t = 0.0 if l2 == 0 else max(0.0, min(1.0, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / l2))
    return math.hypot(a[0] + t * dx - p[0], a[1] + t * dy - p[1])


def in1_holes(board):
    """Every hole In1 has round something that is not GND: (kind, label, net,
    x, y, radius of the cleared area)."""
    clearance = 0.3
    for z in board.Zones():
        if (not z.GetIsRuleArea() and z.GetLayer() == pcbnew.In1_Cu
                and z.GetNetname() == "GND"):
            clearance = mm(z.GetLocalClearance()) or clearance
    holes = []
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_VIA_T and t.GetNetname() != "GND":
            x, y = rel(t.GetPosition())
            holes.append(("via", "via", t.GetNetname(), x, y,
                          mm(t.GetWidth(pcbnew.In1_Cu)) / 2 + clearance))
    for fp in board.GetFootprints():
        for pad in fp.Pads():
            if not pad.HasHole() or pad.GetNetname() == "GND":
                continue
            x, y = rel(pad.GetPosition())
            size = pad.GetSize(pcbnew.In1_Cu) if pad.IsOnLayer(pcbnew.In1_Cu) else pad.GetDrillSize()
            holes.append(("pad", f"{fp.GetReference()}.{pad.GetNumber()}", pad.GetNetname(), x, y,
                          max(mm(size.x), mm(size.y)) / 2 + clearance))
    return holes


def gnd_fills(board, layer):
    return [z.GetFilledPolysList(layer) for z in board.Zones()
            if not z.GetIsRuleArea() and z.GetLayer() == layer and z.GetNetname() == "GND"]


def probe_ar(board, nets, in1_fills, step=0.05):
    """Ruling AR, for whatever pair track is on B.Cu: the In2 island under it
    (its sequence along the track) and the GND vias round it, with whether
    each stands in the B.Cu GND pour and in the In1 plane."""
    islands = [z for z in board.Zones() if z.GetLayer() == pcbnew.In2_Cu and not z.GetIsRuleArea()]
    bcu_fills = gnd_fills(board, pcbnew.B_Cu)
    out = {"in2": {}, "vias": [], "bbox": None}
    xs, ys = [], []
    for t in traces(board, nets):
        if t.GetLayer() != pcbnew.B_Cu:
            continue
        a, b = rel(t.GetStart()), rel(t.GetEnd())
        xs += [a[0], b[0]]
        ys += [a[1], b[1]]
        length = math.hypot(b[0] - a[0], b[1] - a[1])
        seq = out["in2"].setdefault(t.GetNetname(), [])
        for k in range(int(length / step) + 1):
            x = a[0] + (b[0] - a[0]) * k * step / length
            y = a[1] + (b[1] - a[1]) * k * step / length
            pt = vec(x, y)
            label = next((z.GetNetname() + "@%.1f" % (mm(z.GetBoundingBox().GetLeft()) - ORIGIN[0])
                          for z in islands if z.Outline().Contains(pt)), "gap")
            seq.append([label, round(x, 2), round(y, 2)])
    if xs:
        out["bbox"] = [min(xs), min(ys), max(xs), max(ys)]
        for t in board.GetTracks():
            if t.Type() == pcbnew.PCB_VIA_T and t.GetNetname() == "GND":
                x, y = rel(t.GetPosition())
                if min(xs) - 2 <= x <= max(xs) + 2 and min(ys) - 3 <= y <= max(ys) + 3:
                    pt = t.GetPosition()
                    out["vias"].append({
                        "at": [round(x, 3), round(y, 3)],
                        "in_bcu_pour": any(f.Contains(pt) for f in bcu_fills),
                        "in_in1": any(f.Contains(pt) for f in in1_fills)})
    return out


def pad_list(board):
    return [{"ref": fp.GetReference(), "num": pad.GetNumber(), "net": pad.GetNetname(),
             "at": [round(c, 3) for c in rel(pad.GetPosition())]}
            for fp in board.GetFootprints() for pad in fp.Pads()]


def probe_in1(board, nets):
    filler = pcbnew.ZONE_FILLER(board)
    filler.Fill(board.Zones())
    fills = gnd_fills(board, pcbnew.In1_Cu)
    other = [z.GetNetname() for z in board.Zones()
             if not z.GetIsRuleArea() and z.GetLayer() == pcbnew.In1_Cu
             and z.GetNetname() != "GND"]
    holes = in1_holes(board)
    result = {"in1_gnd_zones": len(fills), "in1_other_zones": other, "nets": {},
              "ar": probe_ar(board, nets, fills)}
    for t in traces(board, nets):
        net = t.GetNetname()
        entry = result["nets"].setdefault(net, {"samples": 0, "length": 0.0, "layers": {}, "gaps": []})
        layer = t.GetLayerName()
        a, b = rel(t.GetStart()), rel(t.GetEnd())
        length = math.hypot(b[0] - a[0], b[1] - a[1])
        entry["length"] += length
        entry["layers"][layer] = entry["layers"].get(layer, 0.0) + length
        if length == 0:
            continue
        if layer != "F.Cu":
            continue
        ux, uy = (b[0] - a[0]) / length, (b[1] - a[1]) / length
        half = mm(t.GetWidth()) / 2
        for k in range(int(length / IN1_STEP) + 1):
            cx, cy = a[0] + ux * k * IN1_STEP, a[1] + uy * k * IN1_STEP
            for side in (-1, 0, 1):
                px, py = cx - uy * half * side, cy + ux * half * side
                entry["samples"] += 1
                pt = vec(px, py)
                if any(f.Contains(pt) for f in fills):
                    continue
                best = None
                for kind, label, hnet, hx, hy, r in holes:
                    margin = math.hypot(px - hx, py - hy) - r
                    if margin <= 0.05 and (best is None or margin < best[0]):
                        best = (margin, kind, label, hnet, hx, hy)
                entry["gaps"].append({
                    "at": [round(px, 3), round(py, 3)], "side": side,
                    "hole": None if best is None else {
                        "kind": best[1], "label": best[2], "net": best[3],
                        "at": [round(best[4], 3), round(best[5], 3)]}})
    return result


def probe_coupling(board, nets):
    tracks = {}
    for t in traces(board, nets):
        tracks.setdefault(t.GetNetname(), []).append(
            (t.GetLayer(), rel(t.GetStart()), rel(t.GetEnd()), mm(t.GetWidth())))
    pads, vias = {}, {}
    for fp in board.GetFootprints():
        for pad in fp.Pads():
            if pad.GetNetname() in nets:
                pads.setdefault(pad.GetNetname(), []).append(pad)
    for t in board.GetTracks():
        if t.Type() == pcbnew.PCB_VIA_T and t.GetNetname() in nets:
            vias.setdefault(t.GetNetname(), []).append((rel(t.GetPosition()), mm(t.GetWidth()) / 2))
    out = {}
    for net, segs in tracks.items():
        other = nets[net]
        samples = []
        for layer, a, b, w in segs:
            length = math.hypot(b[0] - a[0], b[1] - a[1])
            n = max(1, int(round(length / COUPLING_STEP)))
            for i in range(n):
                f = (i + 0.5) / n
                q = (a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f)
                best = FAR
                for l2, c, d, w2 in tracks.get(other, []):
                    if l2 == layer:
                        best = min(best, seg_dist(c, d, q) - w2 / 2 - w / 2)
                qv = vec(*q)
                for pad in pads.get(other, []):
                    if pad.IsOnLayer(layer):
                        sq = pad.GetEffectiveShape(layer).SquaredDistance(qv)
                        best = min(best, math.sqrt(sq) / 1e6 - w / 2)
                for c, r in vias.get(other, []):
                    best = min(best, math.hypot(q[0] - c[0], q[1] - c[1]) - r - w / 2)
                samples.append([round(q[0], 3), round(q[1], 3), round(min(best, FAR), 3),
                                round(w, 3), round(length / n, 4), board.GetLayerName(layer)])
        out[net] = samples
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--board", required=True)
    ap.add_argument("--in1", action="store_true")
    ap.add_argument("--coupling", action="store_true")
    args = ap.parse_args()
    board = pcbnew.LoadBoard(args.board)
    nets = pair_nets(board)
    result = {"pairs": sorted(nets), "pads": pad_list(board)}
    if args.in1:
        result["in1"] = probe_in1(board, nets)
    if args.coupling:
        result["coupling"] = probe_coupling(board, nets)
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
