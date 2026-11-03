#!/usr/bin/env python3
"""Cross-check of the diff-pair geometry in stackup-note.md.

Three numbers per geometry:

  pcbway   the formula PCBWay's own Edge Coupled Microstrip calculator runs
           (hardware/fab/pcbway-source-excerpts.txt [1]); the same function
           check_fab_release.py uses to guard the net classes. Bare copper.
  as-built pcbway minus PCBWAY_MASK_OFFSET_OHM, PCBWay's own figure for what
           one pass of solder mask does to a differential pair
           (excerpt [4]). This is the column the net classes are centred on.
  fd2d     a 2-D finite-element Laplace solve of the cross-section (bilinear
           elements, rectangular copper, ground plane below, grounded box
           around), odd-mode impedance doubled. Written for this check and
           NOT a PCBWay tool. Checked once against Hammerstad's closed form
           for a single microstrip (w/h = 1, Er 4.5, approximated by a pair
           2 mm apart, copper 5 um): 68.7 ohm against 70.4 ohm, a 2 %
           difference that is not explained further here.

The fd2d+mask column is an estimate, kept as a second opinion on the
as-built column, and it is an upper bound: mask is modelled as Er 3.5 filling
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
from check_fab_release import (  # noqa: E402
    PCBWAY_MASK_OFFSET_OHM, pcbway_edge_coupled_zd)

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


GEOMETRIES = (("USB3 / USB2, target 90 ohm", 0.20, 0.17, 90.0),
              ("MDI, target 100 ohm", 0.18, 0.21, 100.0))
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
    print("units: mm and ohm; copper 35 um (1 oz) throughout; as-built = "
          f"pcbway - {PCBWAY_MASK_OFFSET_OHM:g}; window = target +/-10 %")
    for name, w, s, target in GEOMETRIES:
        print(f"\n{name}: width {w}, gap {s}, window "
              f"{0.9 * target:g}..{1.1 * target:g}")
        print(f"  {'case':46s} {'pcbway':>7s} {'as-built':>9s} {'fd2d':>7s}"
              f" {'fd2d+mask':>10s}")
        for label, h, er in CASES:
            bare = fd2d_zdiff(w * 1e-3, s * 1e-3, h * 1e-3, 35e-6, er)
            mask = fd2d_zdiff(w * 1e-3, s * 1e-3, h * 1e-3, 35e-6, er,
                              mask_over_cu=15e-6)
            pw = pcbway_edge_coupled_zd(1, h, w, s, er)
            flag = "" if 0.9 * target <= pw - PCBWAY_MASK_OFFSET_OHM \
                <= 1.1 * target else "  <- outside"
            print(f"  {label:46s} {pw:7.1f} {pw - PCBWAY_MASK_OFFSET_OHM:9.1f}"
                  f" {bare:7.1f} {mask:10.1f}{flag}")

    print("\ncombined corners: as-built with one and with two mask passes "
          "(PCBWay: the reduction doubles with two passes)")
    for name, w, s, target in GEOMETRIES:
        print(f"\n{name}: width {w}, gap {s}, window "
              f"{0.9 * target:g}..{1.1 * target:g}")
        print(f"  {'case':46s} {'1 pass':>7s} {'2 passes':>9s}")
        for label, h, er in CASES:
            pw = pcbway_edge_coupled_zd(1, h, w, s, er)
            cells = []
            for passes in (1, 2):
                value = pw - passes * PCBWAY_MASK_OFFSET_OHM
                inside = 0.9 * target <= value <= 1.1 * target
                cells.append(f"{value:7.1f}{'' if inside else ' *'}")
            print(f"  {label:46s} {cells[0]:>7s} {cells[1]:>9s}")
    print("\n* outside the window")


if __name__ == "__main__":
    main()
