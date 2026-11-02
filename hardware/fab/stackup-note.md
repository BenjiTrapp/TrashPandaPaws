# Stackup and differential-pair geometry for the PCBWay order

Board: `hardware/kicad/raccoon-tap.kicad_pcb`, 4 layers, 1.6 mm, 1 oz outer
copper. Layer use: `F.Cu` signals, `In1.Cu` solid GND, `In2.Cu` power, `B.Cu`
signals plus a GND pour (`netlist.yaml` `stackup`).

This note is attached to the order (task 11). Every number below has a source
or is marked as derived. The PCBWay passages it relies on are quoted verbatim
in `pcbway-source-excerpts.txt` next to this file, as sections `[1]` to `[4]`
(fetched 2026-11-02; the full pages are **not** committed, see Open items).

## What this note is, and what it is not

PCBWay's impedance calculator is a page of JavaScript, not a service. The page
itself says: "Note: The results are only for approximation and rough
estimation, the final values and the corresponding layer construction have to
be calculated by us." (excerpt `[1]`). It also points to the stackup page used
below ("The stackup information check here.").

So: **the widths and gaps below are what PCBWay's published calculator
returns for PCBWay's published stackup. They are not a quote from PCBWay's
engineering department and have not been confirmed by it.** The order must ask
for that confirmation (Open items 1 and 2).

## Stackup

**Chosen:** the first entry of PCBWay's "PCB standard stackup" list for
*4 Layers, 1.6MM* on https://www.pcbway.com/multi-layer-laminated-structure.html
(excerpt `[2]`). The page names it only "4-layers PCB", type "Regular",
"Thickness: 1.6MM", "Finished Outer Copper: 1OZ", "Inner Copper: 1OZ",
"Inner layer Residual copper ratio: 70%". It has no other name or code.

| Layer | Material, as PCBWay lists it | Nominal (mm) | After lamination (mm) |
|---|---|---|---|
| L1 / `F.Cu` | Outer Base Copper 0.5OZ, plated to 1OZ | 0.0175 | 0.0175 |
| prepreg | 7628 RC46%, DK:4.74 | 0.1960 | **0.1855** |
| L2 / `In1.Cu` | Inner Copper 1OZ | 0.0350 | |
| core | Core, DK:4.6 | 1.0300 | |
| L3 / `In2.Cu` | Inner Copper 1OZ | 0.0350 | |
| prepreg | 7628 RC46%, DK:4.74 | 0.1960 | 0.1855 |
| L4 / `B.Cu` | Outer Base Copper 0.5OZ, plated to 1OZ | 0.0175 | 0.0175 |

PCBWay's footer for the entry: "Thickness after lamination: 1.51mm, tolerance:
±10%." and "Finished PCB Thickness: 1.61mm, tolerance: ±10%."

Why this entry: among the 4-layer, 1.6MM entries in the page as fetched, only
entries 1 to 3 have 1OZ outer and 1OZ inner copper, which is what the board
specifies; they differ only in the assumed inner-layer residual copper ratio
(70 %, 50 %, 30 %). Entry 1 carries PCBWay's own footnote: "Inner layer
Residual copper ratio > 60%, it is suitable to choose a lamination structure
with 70% inner layer Residual copper ratio." (excerpt `[2]`). This note reads
that as applying to a board whose inner layers are mostly copper, which
`In1.Cu` (solid GND) and `In2.Cu` (power islands) are; that is the note's
reading, not a statement about this board by PCBWay (Open item 2).

**Reference plane:** `In1.Cu` (L2), 0.1855 mm below `F.Cu`, as the targets in
`netlist.yaml` require. The 1.03 mm core lies below the reference plane and
does not enter the microstrip calculation.

**Not in the KiCad file:** `raccoon-tap.kicad_pcb` has no `(stackup ...)`
block (checked with grep), and `gen_pcb.py` only sets four copper layers, so
the board file carries no dielectric thicknesses. Task 8 regenerates that file
and may add the table above to it; this task must not touch it.

## Dielectric constant

**4.74**, the "DK:4.74" PCBWay lists for the 7628 RC46% prepreg between `F.Cu`
and `In1.Cu`. It is a single nominal value; PCBWay says of FR-4 in general:
"FR4 board materials have dielectric constants ranging from 3.9 to 4.5,
decreasing with increasing frequency" (excerpt `[4]`). Whether 4.74 holds at
2.5 GHz (the SuperSpeed Nyquist frequency) is not stated for this prepreg. The
sensitivity table shows the effect: Er 4.5 moves the result by about +2 ohm.

Copper: `t` = 1 oz/ft², which the calculator converts to 1.379 mil. The
prepreg thickness input is the **after-lamination** figure, 0.1855 mm.

## Result per impedance target

Calculator: Edge Coupled Microstrip, PCBWay's own formula, run exactly as the
page runs it (excerpt `[1]`). It is a closed-form approximation:
`Zo = 87 / sqrt(1.41 + Er) * ln(5.98 h / (0.8 w + t))`,
`Zd = 2 Zo (1 - 0.48 exp(-0.96 s / h))`.
`node hardware/fab/run_pcbway_page_formula.js` runs the page's own function,
copied unchanged into the excerpt file, against a stubbed page and prints 89.94 ohm and 98.89 ohm for the two geometries below (the page rounds
to 0.01 ohm). The same arithmetic is ported to Python in `check_fab_release.py`
(`pcbway_edge_coupled_zd`: 89.938 and 98.886), and a test there compares the
port with the page's function whenever Node is installed.

Inputs: `t` = 1 oz, `h` = 0.1855 mm, `Er` = 4.74. Solder mask is **not** in
the calculator: "the outer layer impedance testing does not include the solder
mask" (excerpt `[1]`).

| Target | Net classes | Width `w` | Gap `s` | Calculator `Zd` | `Zo` (one trace) |
|---|---|---|---|---|---|
| 90 ohm differential | `USB3` (USB 3.0 SuperSpeed **and** USB 2.0 D+/D-, by the netclass patterns `USB3_*`, `USB2_*`) | **0.23 mm** (9.1 mil) | **0.16 mm** (6.3 mil) | 89.9 ohm | 56.9 ohm |
| 100 ohm differential | `MDI` (the four MDI pairs) | **0.20 mm** (7.9 mil) | **0.18 mm** (7.1 mil) | 98.9 ohm | 61.0 ohm |

Why these two pairs of numbers out of the many that give 90 and 100 ohm:

* **Both sit just below target.** PCBWay: "Choose wider trace width, not
  narrower." and "Avoid cases where, for example, the 100 ohms bias toward
  larger values and the 90 ohms biased toward smaller values." (excerpt `[4]`).
  Both targets are therefore approached from the low side, 0.1 ohm and 1.1 ohm
  under.
* **Spacing stays in PCBWay's normal process.** The Advanced PCB table row 15
  lists 35 um outer copper at "≥5/6 mil" in the first data column and "≥5/5
  mil" in the second (excerpt `[3]`); 6.3 mil and 7.1 mil gaps and 7.9 mil and
  9.1 mil widths are inside the first. (Reading the first column as "Normal
  process" is the note's reading of the table header; open item 4.)
* **The pair pitch matches the QFN.** U3 has 0.4 mm pitch pads, 0.25 mm wide.
  Trace pitch `w + s` is 0.39 mm (USB3) and 0.38 mm (MDI), so a pair leaves
  its two pads almost straight, with no lateral jog.

Netclass values set in `hardware/kicad/raccoon-tap.kicad_pro`:

| Class | `diff_pair_width` | `diff_pair_gap` | `track_width` | `clearance` |
|---|---|---|---|---|
| `USB3` | 0.23 | 0.16 | 0.23 | 0.16 |
| `MDI` | 0.20 | 0.18 | 0.20 | 0.16 |

`clearance` was 0.2 in both classes and has to come down: with a pair gap
(0.16 and 0.18) below the class clearance, KiCad's DRC is expected to measure
the two traces of a pair against that clearance like any two nets and flag
them. (Expected, not tested here: there are no traces yet; the first DRC after
task 9's routing will show it.) 0.16 mm is 6.3 mil, above the 6 mil in PCBWay's
normal-process column and above the board's `min_clearance` of 0.15 in the
same file. `diff_pair_via_gap` (0.25) is **not** derived from any impedance
calculation and was left as it was; the router's two diff-pair presets in
`board.design_settings.diff_pair_dimensions` were replaced with the two
geometries above.

The block below is read by `hardware/tests/check_fab_release.py`
(`check_no_placeholder_geometry`): it compares these values with the project
file, recomputes the impedance from `inputs` and fails when a net class
differs, when the result is more than 3 % from the target, or when the note is
missing.

<!-- netclass-geometry -->
```yaml
inputs:
  t_oz: 1.0
  h_mm: 0.1855
  er: 4.74
classes:
  USB3: {target_ohm: 90.0, width_mm: 0.23, gap_mm: 0.16, clearance_mm: 0.16}
  MDI: {target_ohm: 100.0, width_mm: 0.20, gap_mm: 0.18, clearance_mm: 0.16}
```

## How far the result moves

`hardware/fab/impedance_crosscheck.py` evaluates the same geometries with
PCBWay's formula and with an independent 2-D finite-element solve written for
this check (not a PCBWay tool; it needs numpy and scipy). Output of
`python hardware/fab/impedance_crosscheck.py`, ohm, copper 35 um:

```
USB3 / USB2, target 90 ohm: width 0.23, gap 0.16
  case                                            pcbway    fd2d  fd2d+mask
  nominal: h 0.1855, Er 4.74                        89.9    92.8       85.5
  h 0.196 (prepreg as pressed from the sheet)       91.9    94.2       86.8
  h -10 % (0.1670)                                  86.1    89.4       82.6
  h +10 % (0.2041)                                  93.3    95.5       87.9
  stackup 3, 30 % residual copper: h 0.1715         87.1    90.3       83.3
  Er 4.5                                            91.7    94.7       87.1
  Er 4.2                                            94.2    97.4       89.2

MDI, target 100 ohm: width 0.2, gap 0.18
  case                                            pcbway    fd2d  fd2d+mask
  nominal: h 0.1855, Er 4.74                        98.9   100.8       92.8
  h 0.196 (prepreg as pressed from the sheet)      100.8   102.3       94.2
  h -10 % (0.1670)                                  95.0    97.3       89.7
  h +10 % (0.2041)                                 102.2   103.7       95.4
  stackup 3, 30 % residual copper: h 0.1715         96.0    98.2       90.5
  Er 4.5                                           100.9   102.9       94.5
  Er 4.2                                           103.5   105.8       96.8
```

Reading it:

* The solver sits about 1.5 to 3.5 ohm above PCBWay's formula in every case
  of the table. That is the size of disagreement to expect between a
  closed-form approximation and a field solve; neither is PCBWay's engineering
  figure.
* **Solder mask is the large term and the calculator ignores it.** PCBWay
  states: "Typically, printing one pass of solder mask reduces single-ended
  impedance by 2 ohms and differential impedance by 8 ohms." (excerpt `[4]`).
  The `fd2d+mask` column is this note's estimate with an *assumed* mask (Er
  3.5, filling up to 15 um above the copper; PCBWay gives neither on the pages
  used); it lands 7 to 8 ohm lower, matching PCBWay's own 8 ohm. With the mask
  the nominal USB3 case is 85.5 ohm and the nominal MDI case 92.8 ohm, both
  inside ±10 % (81 to 99 and 90 to 110), but the MDI corner "h -10 % and mask"
  (89.7 ohm) is 0.3 ohm outside the lower limit.
* Prepreg thickness matters more than anything else the layout controls.
  PCBWay: "the resin will fill the gaps left by the etched traces, resulting
  in reduced resin thickness between the layers." (excerpt `[4]`). `In1.Cu` is
  a solid plane, so on that side there are no gaps to fill. The note infers
  that the pressed thickness could sit nearer the 0.196 mm nominal than the
  0.1855 mm listed for 70 % residual copper; this is an inference, not
  PCBWay's statement. It would move the result up by about 2 ohm, away from
  the mask effect.

Neither the bare nor the masked column is "the" answer. What PCBWay will
actually build is decided by their engineering calculation with the mask
(Open item 1). The geometry above is a start inside their ±10 % window: in the
table, every case stays inside it except the one MDI corner named above.

## Tolerance

"Impedance control tolerance | ±10%，50Ω and below：±5Ω" (https://www.pcbway.com/
capabilities.html, row 35; excerpt `[3]`). Every target here is above 50 ohm, so
the ±10 % applies: 90 ohm → 81 to 99 ohm, 100 ohm → 90 to 110 ohm. That is the
same ±10 % `netlist.yaml` records for the SuperSpeed pair.

## Minimum trace width and spacing

**No separate rule for the impedance-control service was found** on the four
PCBWay pages read (excerpts `[1]` to `[4]`). The rules that exist are the
general ones:

* Standard PCB: "Min Trace | 0.1mm/4mil" and "Min Spacing ... 4mil(0.1mm)"
  (https://www.pcbway.com/capabilities.html, excerpt `[3]`).
* Advanced PCB table, row 15, outer layer, copper thickness 35 um,
  "(before compensation)": "≥5/6 mil" and "≥5/5 mil" (excerpt `[3]`).
* "The min. dielectric thickness between layers should be 50um." (excerpt
  `[4]`); the 0.1855 mm prepreg is far above it.

The geometry here uses 7.9 mil and 9.1 mil widths and 6.3 mil and 7.1 mil
gaps; the smallest gap is 0.3 mil above the 6 mil of the first column. Whether
the impedance service applies a stricter figure is Open item 3.

## Fit on 58 x 36 mm

**Result: no remedy needed. The board stays 58 x 36 mm and the routing plan is
not changed.** Basis, all arithmetic on the geometry above and on pads that
exist; nothing is routed yet:

1. **The geometry is not wider than the placeholders it replaces.** Pair
   outline (`2w + s`): USB3 0.62 mm now against 0.60 mm (`0.2 / 0.2`); MDI
   0.58 mm now against 0.61 mm (`0.18 / 0.25`). The concern that a computed
   geometry would be much wider than the placeholders does not materialise
   for this stackup: the traces are wider, 0.23 and 0.20 mm against 0.2 and
   0.18 mm, but the gaps are tighter, and the outline moves by at most 0.03 mm.
2. **U3 escape (QFN-40, 0.4 mm pitch, pads 0.25 mm wide, from the footprint
   `QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm` as embedded in the current board
   file):**
   adjacent pads are 0.4 mm apart centre to centre, so adjacent traces have
   an edge gap of 0.4 - `w`.
   * USB3 `w` 0.23: 0.17 mm. This is the case that matters: U3 pin 16
     (`USB3_RX_P`) is next to pin 17 (`USB2_D_N`) on the same side, two
     different pairs, 0.17 mm apart. It clears the class clearance of 0.16 mm
     by 0.01 mm. With the old clearance of 0.2 it would not.
   * MDI `w` 0.20: 0.20 mm, e.g. pin 5 (`MDI1_N`) next to pin 6 (`MDI2_P`).
   * Pair to pair on the MDI side (pins 1/2, 4/5, 6/7, 9/10; pad centres
     -1.6, -0.4, +0.4, +1.6 mm): the nearest pairs (4/5 and 6/7) are 0.8 mm
     apart, outlines 0.58 mm, edge gap 0.22 mm.
   * The four MDI pairs need about 3.8 mm along the 5 mm side of the package.
3. **Seven pairs between U3 and the connectors:** four MDI pairs at 0.58 mm and
   three USB pairs at 0.62 mm outline; with 0.16 mm clearance between pairs
   the sum is about 4 x 0.74 + 3 x 0.78 = 5.3 mm of lane width if all seven
   ran side by side, against 36 mm of board height. The MDI pairs (pins 1 to
   10) and the USB pairs (pins 11 to 20) leave U3 on adjacent sides, so per
   side the MDI group needs about 3.0 mm of lanes and the USB group about
   2.3 mm.

What this does **not** show: a routed board. The placement is about to change
(task 8 rotates U3 and adds parts), the SuperSpeed path now includes C22,
C23 and U8 (`SP3019-04HTG`), whose pads are not the width of the trace and
are not modelled here, and every layer change will use `diff_pair_via_gap`
0.25, which was not derived. Task 8 and task 9 must
re-check this section against the real placement; if a pair cannot be laid
out within the geometry, the controller-ruled order applies: grow the board
first, then change the routing plan, and stop and report if neither is
enough. The impedance targets, board thickness, copper weight and the
impedance-control service stay as they are.

## Open items

These are not closed by this note. Numbers 1 to 3 are for PCBWay to confirm
before anything is ordered; none has been asked yet.

1. **Confirm the geometry with PCBWay engineering, with solder mask.** Ask
   them to calculate 90 ohm and 100 ohm differential for this stackup (entry 1,
   70 % residual copper, 0.1855 mm prepreg) with their solder mask on, and
   adjust `w` and `s` if needed. The mask effect is 7 to 8 ohm by their own
   statement; this note's numbers come from a calculator that leaves it out.
2. **Confirm the stackup.** The page the entry comes from says "PCBWay supports
   customers to customize structures"; the order should name entry 1 of the
   4-layer 1.6MM list as the build-up, or ask PCBWay to state the stackup they
   will press.
3. **Confirm the minimum width and spacing for the impedance-control
   service.** None is published on the pages read. If theirs is stricter than
   5/6 mil, the 0.16 mm gap is the number at risk.
4. **Column header of the capabilities table.** The note reads the first data
   column of row 15 as "Normal process" because it is the first of the
   columns the table header lists ("Normal process | Medium difficulty |
   High difficulty | ..."). That is a reading of the page text, not a PCBWay
   statement about which column applies to this order.
5. **The PCBWay pages are not committed.** Only `pcbway-source-excerpts.txt`
   is, with the md5 of each full page as fetched on 2026-11-02. The pages
   change daily (news block), so the md5 values cannot be reproduced; they
   identify the copy the excerpts came from. Unlike the datasheets in
   `hardware/datasheets/`, these are web pages, not PDFs, and are not in the
   `netlist.yaml` sources block.
6. **The 100 ohm examples on PCBWay's Impedance Control page** give trace/space
   of 70/130, 95/140, 125/130 and 105/150 um for four stackups shown only as
   an image (excerpt `[4]`). They are narrower than this note's 200/180 um, but
   their stackups are unknown, so they are not used here as a check.
7. **Not modelled:** surface finish ("The surface finish is neglected.", excerpt
   `[1]`), etch trapezoid (the finite-element check uses rectangular copper),
   the pads of U8, C22 and C23, vias, and loss at 2.5 GHz.
