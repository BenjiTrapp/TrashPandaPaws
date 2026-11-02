"""Grid router for the supply and low-speed connections of the board (task 9).

Not a general autorouter: it connects what tools/route_pcb.py asks it to, one
connection at a time, on F.Cu and B.Cu, round everything already on the board,
at the clearances of the project's rules (net classes, "track to U3 pad on
fine-pitch parts", ruling AU's "track to track at the U3 escape"), and with
the board's own constraints written in:

  * a via that is not on GND must not cut In1 under a pair track (the hole In1
    leaves round it is the via's radius + 0.3 mm);
  * ruling AW (the USB 2.0 pair's return pour, x 17 to 21): on B.Cu in that
    band a track may only run east-west (parallel to the pair) and only more
    than 2.5 mm from it (AW_WINDOW), and no via comes within 1.2 mm of the
    pair there;
  * a pair track keeps the class clearance from what is routed here (the
    stackup note's 2 to 3 h is not enforced; the report measures it);
  * tracks stay 0.5 mm from the board edge and out of the screw-head keepouts.

The grid is 0.05 mm. A cell is free for a track centre when every foreign item
is further than clearance + half the track width (+ a small margin for the
grid); kicad-cli's DRC remains the judge of the result.
"""

import heapq
import math

import pcbnew

G = 0.05
MARGIN = 0.02          # spare round ordinary items, for segments between grid points
TIGHT = -0.0005          # round U3's pads and the escapes in its area, where the pitch leaves exactly the rule
ORIGIN = (100.0, 80.0)
W, H = 58.0, 36.0
NX, NY = int(round(W / G)) + 1, int(round(H / G)) + 1
F, B = 0, 1
LAYER = {F: pcbnew.F_Cu, B: pcbnew.B_Cu}
POWER = {"GND", "+5V", "+3V3", "+1V0", "SW_1V0"}      # the Power net class patterns
PAIR_SPACING = 0.0      # the class clearance only; the 2-3 h of the stackup note is not enforced here (measured in the report)
U3_AREA = (20.55, 19.55, 27.45, 26.45)
AW_BAND = (17.0, 21.0)
AW_WINDOW = (16.5, 22.3)      # y range round the pair (19.2 / 19.57) where nothing crosses on B.Cu
VIA_D, VIA_DRILL = 0.6, 0.3


def cls(net):
    return 0.3 if net in POWER else 0.2


def mmxy(v):
    return (pcbnew.ToMM(v.x) - ORIGIN[0], pcbnew.ToMM(v.y) - ORIGIN[1])


def d_seg(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    l2 = dx * dx + dy * dy
    t = 0.0 if l2 == 0 else max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / l2))
    return math.hypot(ax + t * dx - px, ay + t * dy - py)


def in_area(x, y, a=U3_AREA):
    return a[0] <= x <= a[2] and a[1] <= y <= a[3]


class Item:
    """kind: pad / track / via / hole. Geometry: ('rect', cx, cy, hx, hy),
    ('circle', cx, cy, r) or ('seg', ax, ay, bx, by, hw)."""
    def __init__(self, kind, layers, net, geom, u3=False, area=False, pair=False):
        self.kind, self.layers, self.net, self.geom = kind, layers, net, geom
        self.u3, self.area, self.pair = u3, area, pair

    def dist(self, x, y):
        g = self.geom
        if g[0] == "rect":
            ex, ey = abs(x - g[1]) - g[3], abs(y - g[2]) - g[4]
            if ex <= 0 and ey <= 0:
                return max(ex, ey)                  # inside: negative
            return math.hypot(max(ex, 0.0), max(ey, 0.0))
        if g[0] == "circle":
            return math.hypot(x - g[1], y - g[2]) - g[3]
        return d_seg(x, y, g[1], g[2], g[3], g[4]) - g[5]

    def bbox(self):
        g = self.geom
        if g[0] == "rect":
            return g[1] - g[3], g[2] - g[4], g[1] + g[3], g[2] + g[4]
        if g[0] == "circle":
            return g[1] - g[3], g[2] - g[3], g[1] + g[3], g[2] + g[3]
        return min(g[1], g[3]) - g[5], min(g[2], g[4]) - g[5], max(g[1], g[3]) + g[5], max(g[2], g[4]) + g[5]


def collect(board, pair_nets):
    items = []
    for fp in board.GetFootprints():
        ref = fp.GetReference()
        for pad in fp.Pads():
            x, y = mmxy(pad.GetPosition())
            net = pad.GetNetname()
            if pad.GetAttribute() == pcbnew.PAD_ATTRIB_NPTH:
                r = pcbnew.ToMM(pad.GetDrillSize().x) / 2
                items.append(Item("hole", {F, B}, None, ("circle", x, y, r)))
                continue
            layers = {F, B} if pad.HasHole() else ({F} if pad.IsOnLayer(pcbnew.F_Cu) else {B})
            if pad.GetShape() == pcbnew.PAD_SHAPE_CIRCLE:
                geom = ("circle", x, y, pcbnew.ToMM(pad.GetSize(pcbnew.F_Cu).x) / 2)
            else:
                bb = pad.GetBoundingBox()
                x0, y0 = mmxy(bb.GetOrigin())
                x1, y1 = mmxy(bb.GetEnd())
                geom = ("rect", (x0 + x1) / 2, (y0 + y1) / 2, (x1 - x0) / 2, (y1 - y0) / 2)
            items.append(Item("pad", layers, net, geom, u3=(ref == "U3")))
    for t in board.GetTracks():
        net = t.GetNetname()
        if t.Type() == pcbnew.PCB_VIA_T:
            x, y = mmxy(t.GetPosition())
            items.append(Item("via", {F, B}, net, ("circle", x, y, pcbnew.ToMM(t.GetWidth(pcbnew.F_Cu)) / 2)))
        elif t.Type() == pcbnew.PCB_TRACE_T:
            layer = F if t.GetLayer() == pcbnew.F_Cu else B
            (ax, ay), (bx, by) = mmxy(t.GetStart()), mmxy(t.GetEnd())
            area = in_area(ax, ay) or in_area(bx, by)
            items.append(Item("track", {layer}, net, ("seg", ax, ay, bx, by, pcbnew.ToMM(t.GetWidth()) / 2),
                              area=area, pair=net in pair_nets))
    return items


class Router:
    def __init__(self, board, pair_nets, usb2_nets=("USB2_D_P", "USB2_D_N")):
        self.board = board
        self.pair_nets = set(pair_nets)
        self.usb2 = set(usb2_nets)
        self.items = collect(board, self.pair_nets)
        self.keepouts = []
        for z in board.Zones():
            if z.GetIsRuleArea() and z.GetDoNotAllowTracks():
                bb = z.GetBoundingBox()
                self.keepouts.append(z)
        self.islands = [z for z in board.Zones() if not z.GetIsRuleArea()
                        and z.GetLayer() == pcbnew.In2_Cu]
        self.log = []

    # -- maps -------------------------------------------------------------
    def clearance(self, item, net, via):
        if item.kind == "hole":
            return 0.25
        if item.net == net and net:
            return None
        c = max(cls(item.net or ""), cls(net))
        if not via and item.kind == "pad" and item.u3:
            c = 0.2
        if not via and item.kind == "track" and item.pair:
            c = max(c, PAIR_SPACING)
        if not via and item.kind == "track" and item.area:
            c = 0.2 if not item.pair else 0.2
        return c

    def track_map(self, net, width, layer, box):
        x0, y0, x1, y1 = box
        i0, j0 = max(0, int(x0 / G)), max(0, int(y0 / G))
        i1, j1 = min(NX - 1, int(x1 / G) + 1), min(NY - 1, int(y1 / G) + 1)
        ni, nj = i1 - i0 + 1, j1 - j0 + 1
        blocked = bytearray(ni * nj)
        hw = width / 2
        for it in self.items:
            if layer not in it.layers:
                continue
            c = self.clearance(it, net, via=False)
            if c is None:
                continue
            bx0, by0, bx1, by1 = it.bbox()
            # the AU rule only between two tracks that both touch the area
            tight = (it.kind == "pad" and it.u3) or (it.kind == "track" and it.area)
            m = TIGHT if tight else MARGIN
            reach = c + hw + m
            ii0 = max(i0, int((bx0 - reach) / G)); ii1 = min(i1, int((bx1 + reach) / G) + 1)
            jj0 = max(j0, int((by0 - reach) / G)); jj1 = min(j1, int((by1 + reach) / G) + 1)
            far = reach
            for i in range(ii0, ii1 + 1):
                x = i * G
                for j in range(jj0, jj1 + 1):
                    y = j * G
                    r = reach
                    if it.kind == "track" and it.area:
                        # AU: 0.2 only if this cell is in the area too; else the class value
                        if not in_area(x, y):
                            cc = max(cls(it.net), cls(net))
                            if it.pair:
                                cc = max(cc, PAIR_SPACING)
                            r = cc + hw + MARGIN
                    if it.dist(x, y) < r:
                        blocked[(i - i0) * nj + (j - j0)] = 1
        edge = 0.5 + hw + MARGIN
        for i in range(i0, i1 + 1):
            x = i * G
            for j in range(j0, j1 + 1):
                y = j * G
                if x < edge or y < edge or x > W - edge or y > H - edge:
                    blocked[(i - i0) * nj + (j - j0)] = 1
                elif layer == B and AW_BAND[0] - hw - MARGIN <= x <= AW_BAND[1] + hw + MARGIN \
                        and AW_WINDOW[0] <= y <= AW_WINDOW[1]:
                    blocked[(i - i0) * nj + (j - j0)] = 1
        self._keepout(blocked, i0, j0, i1, j1, nj, hw + MARGIN, vias=False)
        return blocked, (i0, j0, ni, nj)

    def via_map(self, net, box):
        x0, y0, x1, y1 = box
        i0, j0 = max(0, int(x0 / G)), max(0, int(y0 / G))
        i1, j1 = min(NX - 1, int(x1 / G) + 1), min(NY - 1, int(y1 / G) + 1)
        ni, nj = i1 - i0 + 1, j1 - j0 + 1
        blocked = bytearray(ni * nj)
        rv = VIA_D / 2
        for it in self.items:
            c = self.clearance(it, net, via=True)
            extra = []
            if c is None:
                if it.kind == "pad" and it.net == net:
                    c = 0.05        # a via may touch its own pad, not sit in it (solder)
                elif it.kind == "via" and it.net == net:
                    # not on top of another via: hole to hole 0.25 mm
                    reach = 0.25 + VIA_DRILL + MARGIN
                    g = it.geom
                    for i in range(max(i0, int((g[1] - reach) / G)), min(i1, int((g[1] + reach) / G) + 1) + 1):
                        for j in range(max(j0, int((g[2] - reach) / G)), min(j1, int((g[2] + reach) / G) + 1) + 1):
                            if math.hypot(i * G - g[1], j * G - g[2]) < reach:
                                blocked[(i - i0) * nj + (j - j0)] = 1
                    continue
                else:
                    continue
            if it.kind == "hole":
                reach = 0.25 + rv + MARGIN        # min_hole_clearance, copper to hole
            else:
                reach = c + rv + MARGIN
            if net != "GND" and it.kind == "track" and it.pair and it.net != net:
                reach = max(reach, rv + 0.3 + MARGIN)      # In1 hole under a pair track
            if it.kind == "track" and it.net in self.usb2 and B in it.layers:
                # ruling AW: keep the return pour beside the pair whole (band x 17 to 21)
                bx0_, _, bx1_, _ = it.bbox()
                if bx1_ > AW_BAND[0] and bx0_ < AW_BAND[1]:
                    reach = max(reach, 1.2)
            bx0, by0, bx1, by1 = it.bbox()
            ii0 = max(i0, int((bx0 - reach) / G)); ii1 = min(i1, int((bx1 + reach) / G) + 1)
            jj0 = max(j0, int((by0 - reach) / G)); jj1 = min(j1, int((by1 + reach) / G) + 1)
            for i in range(ii0, ii1 + 1):
                x = i * G
                for j in range(jj0, jj1 + 1):
                    if it.dist(x, j * G) < reach:
                        blocked[(i - i0) * nj + (j - j0)] = 1
        edge = 0.5 + rv + MARGIN
        for i in range(i0, i1 + 1):
            x = i * G
            for j in range(j0, j1 + 1):
                y = j * G
                if x < edge or y < edge or x > W - edge or y > H - edge:
                    blocked[(i - i0) * nj + (j - j0)] = 1
        self._keepout(blocked, i0, j0, i1, j1, nj, rv + MARGIN, vias=True)
        return blocked, (i0, j0, ni, nj)

    def _keepout(self, blocked, i0, j0, i1, j1, nj, reach, vias):
        for z in self.keepouts:
            if vias and not z.GetDoNotAllowVias():
                continue
            bb = z.GetBoundingBox()
            (zx0, zy0), (zx1, zy1) = mmxy(bb.GetOrigin()), mmxy(bb.GetEnd())
            a0 = max(i0, int((zx0 - reach) / G)); a1 = min(i1, int((zx1 + reach) / G) + 1)
            b0 = max(j0, int((zy0 - reach) / G)); b1 = min(j1, int((zy1 + reach) / G) + 1)
            for i in range(a0, a1 + 1):
                for j in range(b0, b1 + 1):
                    k = (i - i0) * nj + (j - j0)
                    if not blocked[k] and z.Outline().Collide(
                            pcbnew.VECTOR2I(pcbnew.FromMM(ORIGIN[0] + i * G), pcbnew.FromMM(ORIGIN[1] + j * G)),
                            pcbnew.FromMM(reach)):
                        blocked[k] = 1

    def island_of(self, net, x, y):
        """The In2 island of `net` a via at (x, y) lands in (0.32 mm inside its outline), or None."""
        p = pcbnew.VECTOR2I(pcbnew.FromMM(ORIGIN[0] + x), pcbnew.FromMM(ORIGIN[1] + y))
        for k, z in enumerate(self.islands):
            if z.GetNetname() == net and z.Outline().Contains(p) and _inside_by(z, p, 0.32):
                return k
        return None

    # -- search -----------------------------------------------------------
    def search(self, net, width, starts, goal, box, allow_b=True, via_cost=40.0, b_cost=1.3,
               max_vias=2, aim=None, avoid=()):
        """A* from `starts` [(layer, x, y)] until goal(layer, i, j, via_here) says
        yes. goal returns 'track' (reached copper), 'via' (a via here reaches
        it) or None. Returns [(layer, x, y), ...] with layer changes = vias."""
        tm = {F: self.track_map(net, width, F, box)}
        if allow_b:
            tm[B] = self.track_map(net, width, B, box)
        vm, (vi0, vj0, vni, vnj) = self.via_map(net, box)
        (i0, j0, ni, nj) = tm[F][1]

        def free(layer, i, j):
            if layer not in tm:
                return False
            for lay, ax0, ay0, ax1, ay1 in avoid:
                if lay == layer and ax0 <= i * G <= ax1 and ay0 <= j * G <= ay1:
                    return False
            bl, (a0, b0, an, bn) = tm[layer]
            ii, jj = i - a0, j - b0
            return 0 <= ii < an and 0 <= jj < bn and not bl[ii * bn + jj]

        def via_ok(i, j):
            ii, jj = i - vi0, j - vj0
            return 0 <= ii < vni and 0 <= jj < vnj and not vm[ii * vnj + jj]

        openh = []
        best = {}
        came = {}
        # A* towards `aim` (a point of the target, mm) when there is one
        ai, aj = (aim[0] / G, aim[1] / G) if aim else (None, None)

        def h(i, j):
            return 0.0 if ai is None else 0.98 * math.hypot(i - ai, j - aj)

        for layer, x, y in starts:
            s = (layer, int(round(x / G)), int(round(y / G)), 0)
            best[s] = 0.0
            heapq.heappush(openh, (h(s[1], s[2]), 0.0, s))
            came[s] = None
        moves = [(1, 0, 1.0), (-1, 0, 1.0), (0, 1, 1.0), (0, -1, 1.0),
                 (1, 1, 1.4142), (1, -1, 1.4142), (-1, 1, 1.4142), (-1, -1, 1.4142)]
        found = None
        n = 0
        while openh:
            f, gcost, s = heapq.heappop(openh)
            if gcost > best.get(s, 1e18) + 1e-9:
                continue
            n += 1
            if n > 3000000:
                break
            layer, i, j, nv = s
            r = goal(layer, i, j, via_ok(i, j))
            if r:
                found = (s, r)
                break
            mult = b_cost if layer == B else 1.0
            in_band = layer == B and AW_BAND[0] - 0.3 <= i * G <= AW_BAND[1] + 0.3
            for di, dj, c in moves:
                if in_band and dj != 0:
                    continue        # ruling AW: east-west only on B.Cu in the band
                t = (layer, i + di, j + dj, nv)
                if not free(layer, i + di, j + dj):
                    continue
                g2 = gcost + c * mult
                if g2 < best.get(t, 1e18):
                    best[t] = g2
                    came[t] = s
                    heapq.heappush(openh, (g2 + h(i + di, j + dj), g2, t))
            if allow_b and nv < max_vias and via_ok(i, j):
                other = B if layer == F else F
                if free(other, i, j):
                    t = (other, i, j, nv + 1)
                    g2 = gcost + via_cost
                    if g2 < best.get(t, 1e18):
                        best[t] = g2
                        came[t] = s
                        heapq.heappush(openh, (g2 + h(i, j), g2, t))
        if not found:
            return None
        s, how = found
        path = []
        while s is not None:
            path.append((s[0], s[1] * G, s[2] * G))
            s = came[s]
        path.reverse()
        return path, how


def _inside_by(zone, p, d):
    o = zone.Outline()
    for k in range(16):
        a = 2 * math.pi * k / 16
        q = pcbnew.VECTOR2I(p.x + int(pcbnew.FromMM(d) * math.cos(a)), p.y + int(pcbnew.FromMM(d) * math.sin(a)))
        if not o.Contains(q):
            return False
    return True


def simplify(path):
    """Grid path -> list of (layer, [points]) runs, collinear points dropped."""
    runs = []
    cur_layer, pts = path[0][0], [path[0][1:]]
    for layer, x, y in path[1:]:
        if layer != cur_layer:
            runs.append((cur_layer, pts))
            cur_layer, pts = layer, [(x, y)]
            continue
        pts.append((x, y))
    runs.append((cur_layer, pts))
    out = []
    for layer, pts in runs:
        keep = [pts[0]]
        for k in range(1, len(pts) - 1):
            ax, ay = keep[-1]
            bx, by = pts[k]
            cx, cy = pts[k + 1]
            if abs((bx - ax) * (cy - by) - (by - ay) * (cx - bx)) > 1e-9:
                keep.append(pts[k])
        if len(pts) > 1:
            keep.append(pts[-1])
        out.append((layer, [(round(x, 3), round(y, 3)) for x, y in keep]))
    return out


class Target:
    """Where a connection may end: copper of the net (the listed pads, and
    anything routed or placed on those pads' side so far), or a via that lands
    in one of the net's In2 islands, or (GND) any via."""
    def __init__(self, router, net, pads=(), island=False, any_via=False, points=(), copper=False,
                 exclude=()):
        self.r, self.net = router, net
        self.shapes = []
        self.island, self.any_via = island, any_via
        for it in router.items:
            if it.net != net or it in exclude:
                continue
            if it.kind == "pad" and it in pads:
                self.shapes.append(it)
            elif copper and it.kind in ("track", "via"):
                self.shapes.append(it)
        self.points = list(points)  # (layer, x, y, radius)

    def hit(self, layer, i, j, via_here):
        x, y = i * G, j * G
        for it in self.shapes:
            if layer in it.layers and it.dist(x, y) < -0.01:
                return "track"
        for lay, px, py, rad in self.points:
            if (lay is None or lay == layer) and math.hypot(x - px, y - py) <= rad:
                return "track"
        if via_here and self.any_via:
            return "via"
        if via_here and self.island and self.r.island_of(self.net, x, y) is not None:
            return "via"
        return None
