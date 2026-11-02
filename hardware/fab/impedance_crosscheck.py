#!/usr/bin/env python3
"""Cross-check of the diff-pair geometry in stackup-note.md.

Two independent numbers per geometry:

  pcbway   the formula PCBWay's own Edge Coupled Microstrip calculator runs
           (hardware/fab/pcbway-source-excerpts.txt [1]); the same function
           check_fab_release.py uses to guard the net classes.
  fd2d     a 2-D finite-element Laplace solve of the cross-section (bilinear
           elements, rectangular copper, ground plane below, grounded box
           around), odd-mode impedance doubled. Written for this check and
           NOT a PCBWay tool. Checked once against Hammerstad's closed form
           for a single microstrip (w/h = 1, Er 4.5, approximated by a pair
           2 mm apart, copper 5 um): 68.7 ohm against 70.4 ohm, a 2 %
           difference that is not explained further here.

The solder-mask case is an upper bound: mask is modelled as Er 3.5 filling
everything from the laminate up to 15 um above the copper. PCBWay publishes
neither the mask thickness nor its Er on the pages used; 3.5 is an assumption.

Needs numpy and scipy (not a dependency of the repo):
    python3.12 -m venv /tmp/v && /tmp/v/bin/pip install numpy scipy pyyaml
    /tmp/v/bin/python hardware/fab/impedance_crosscheck.py
"""

import math
import sys
from pathlib import Path

import numpy as np
import scipy.sparse as sp
import scipy.sparse.linalg as sla

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from check_fab_release import pcbway_edge_coupled_zd  # noqa: E402

C0 = 299792458.0
EPS0 = 8.8541878128e-12


def fd2d_zdiff(w, s, h, t, er, mask_over_cu=None, mask_er=3.5, d=5e-6):
    """Differential impedance in ohm of an edge-coupled microstrip pair.
    All lengths in metres. `mask_over_cu` is None for bare copper, or the
    mask thickness above the copper top."""
    width = 12 * h + w + s
    height = 14 * h
    nx, ny = int(round(width / d)), int(round(height / d))
    nh, nt = int(round(h / d)), int(round(t / d))
    x1 = int(round(s / 2 / d))
    x2 = x1 + int(round(w / d))

    def capacitance(er_sub, with_mask):
        eps = np.ones((ny, nx))
        eps[:nh, :] = er_sub
        if with_mask and mask_over_cu is not None:
            eps[nh:nh + nt + int(round(mask_over_cu / d)), :] = mask_er
        n = (ny + 1) * (nx + 1)
        idx = np.arange(n).reshape(ny + 1, nx + 1)
        corners = [idx[:-1, :-1].ravel(), idx[:-1, 1:].ravel(),
                   idx[1:, 1:].ravel(), idx[1:, :-1].ravel()]
        ke = np.array([[4, -1, -2, -1], [-1, 4, -1, -2],
                       [-2, -1, 4, -1], [-1, -2, -1, 4]]) / 6.0
        e = eps.ravel()
        rows, cols, vals = [], [], []
        for a in range(4):
            for b in range(4):
                rows.append(corners[a])
                cols.append(corners[b])
                vals.append(e * ke[a, b])
        k = sp.csr_matrix((np.concatenate(vals),
                           (np.concatenate(rows), np.concatenate(cols))),
                          shape=(n, n))
        v = np.zeros(n)
        fixed = np.zeros(n, bool)
        for edge in (idx[0, :], idx[-1, :], idx[:, 0], idx[:, -1]):
            fixed[edge] = True               # ground plane, box, symmetry plane
        copper = idx[nh:nh + nt + 1, x1:x2 + 1].ravel()
        fixed[copper] = True
        v[copper] = 1.0
        free = ~fixed
        v[free] = sla.spsolve(k[free][:, free].tocsc(),
                              -k[free][:, fixed] @ v[fixed])
        return 2.0 * 0.5 * v @ (k @ v) * EPS0     # odd-mode C per conductor

    c_diel, c_air = capacitance(er, True), capacitance(1.0, False)
    return 2.0 / (C0 * math.sqrt(c_diel * c_air))


GEOMETRIES = (("USB3 / USB2, target 90 ohm", 0.23, 0.16),
              ("MDI, target 100 ohm", 0.20, 0.18))
CASES = (
    ("nominal: h 0.1855, Er 4.74", 0.1855, 4.74),
    ("h 0.196 (prepreg as pressed from the sheet)", 0.196, 4.74),
    ("h -10 % (0.1670)", 0.1670, 4.74),
    ("h +10 % (0.2041)", 0.2041, 4.74),
    ("stackup 3, 30 % residual copper: h 0.1715", 0.1715, 4.74),
    ("Er 4.5", 0.1855, 4.5),
    ("Er 4.2", 0.1855, 4.2),
)


def main():
    print("units: mm and ohm; copper 35 um (1 oz) throughout")
    for name, w, s in GEOMETRIES:
        print(f"\n{name}: width {w}, gap {s}")
        print(f"  {'case':46s} {'pcbway':>7s} {'fd2d':>7s} {'fd2d+mask':>10s}")
        for label, h, er in CASES:
            bare = fd2d_zdiff(w * 1e-3, s * 1e-3, h * 1e-3, 35e-6, er)
            mask = fd2d_zdiff(w * 1e-3, s * 1e-3, h * 1e-3, 35e-6, er,
                              mask_over_cu=15e-6)
            print(f"  {label:46s} {pcbway_edge_coupled_zd(1, h, w, s, er):7.1f}"
                  f" {bare:7.1f} {mask:10.1f}")


if __name__ == "__main__":
    main()
