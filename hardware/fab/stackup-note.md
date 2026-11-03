# Stackup and differential-pair geometry for the PCBWay order

Board: `hardware/kicad/raccoon-tap.kicad_pcb`, 4 layers, 1.6 mm, 1 oz outer
copper. Layer use: `F.Cu` signals, `In1.Cu` solid GND, `In2.Cu` power, `B.Cu`
signals plus a GND pour (`netlist.yaml` `stackup`).

This note is attached to the order (task 11), together with
`fabrication-note.md` (tented vias, assembly split). Every number below has a source
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
returns for PCBWay's published stackup, less PCBWay's own published figure for
solder mask. They are not a quote from PCBWay's engineering department and
have not been confirmed by it.** The order must ask for that confirmation
(Open items 1 and 2).

**Revision.** The first version of this note centred the geometry on the
calculator's bare-copper value (0.23 / 0.16 mm, 89.9 ohm) and left solder mask
for PCBWay to sort out. With PCBWay's own 8 ohm for mask that geometry is
81.9 ohm as built, about 1 ohm above the 81 ohm floor of the ±10 % window, and
PCBWay would have had
to narrow the traces, which their own guidance advises against. The
geometry below is centred on the as-built value instead.

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

Why this entry: among the 4-layer, 1.6MM entries excerpted from the page as
fetched (entries 1 to 3), all three have 1OZ outer and 1OZ inner copper, which
is what the board specifies. The page lists 112 entries and only 1 to 3 were
excerpted, so this note does not show that no other entry has 1OZ/1OZ.
Entries 1 to 3 differ only in the assumed inner-layer residual copper ratio
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
copied unchanged into the excerpt file, against a stubbed page and prints
97.66 ohm and 107.23 ohm for the two geometries below (the page rounds to 0.01
ohm). The same arithmetic is ported to Python in `check_fab_release.py`
(`pcbway_edge_coupled_zd`), and a test there compares the port with the page's
function whenever Node is installed.

Inputs: `t` = 1 oz, `h` = 0.1855 mm, `Er` = 4.74.

**Solder mask is a sourced input, not an afterthought.** The calculator leaves
it out: "the outer layer impedance testing does not include the solder mask"
(excerpt `[1]`, the bold note under the calculator's introduction). PCBWay
gives a figure for it on https://www.pcbway.com/pcb_prototype/
Impedance_Control.html, under the heading "Factors that Influence Impedance", entry
"Soldermask thickness" (excerpt `[4]`, which has both lines): "Typically, printing one pass of
solder mask reduces single-ended impedance by 2 ohms and differential
impedance by 8 ohms." This note uses **8 ohm, one pass**
(`mask_offset_ohm` in the block below; `PCBWAY_MASK_OFFSET_OHM` in
`check_fab_release.py`). The same page continues "The reduction value doubles
when printing two passes"; how many passes PCBWay prints on this order is not
stated and is Open item 1. The class is centred on

    as built = calculator (bare copper) - 8 ohm

| Target | Net classes | Width `w` | Gap `s` | Calculator, bare | as built (minus 8) | `Zo` (one trace, bare) |
|---|---|---|---|---|---|---|
| 90 ohm differential | `USB3` (USB 3.0 SuperSpeed **and** USB 2.0 D+/D-, by the netclass patterns `USB3_*`, `USB2_*`) | **0.20 mm** (7.9 mil) | **0.17 mm** (6.7 mil) | 97.7 ohm | **89.7 ohm** | 61.0 ohm |
| 100 ohm differential | `MDI` (the four MDI pairs) | **0.18 mm** (7.1 mil) | **0.21 mm** (8.3 mil) | 107.2 ohm | **99.2 ohm** | 64.0 ohm |

Why these two pairs of numbers out of the many that give 98 and 108 ohm bare:

* **They are as built within 1 % of target, both slightly low** (-0.3 % and
  -0.8 %). PCBWay: "Choose wider trace width, not narrower. ... Therefore,
  when calculating, aiming for relatively wider trace width means slightly
  lower target impedance" and "Avoid cases where, for example, the 100 ohms
  bias toward larger values and the 90 ohms biased toward smaller values."
  (excerpt `[4]`). Both here are biased the same way.
* **They keep the U3 escape straight.** U3 has 0.4 mm pitch pads, 0.25 mm wide.
  Trace pitch `w + s` is 0.37 mm (USB3) and 0.39 mm (MDI), so a pair leaves its
  two pads almost without a lateral jog. Both widths are at or below 0.20 mm,
  which is what lets two traces from adjacent pads of different pairs keep the
  0.2 mm class clearance between them (see the fit section for what the pads
  themselves do).
* **Spacing stays in PCBWay's normal process**, see the minimum-spacing
  section for the margins.
* Other pairs that reach the same as-built value exist (for example USB3
  0.19 / 0.16 and MDI 0.17 / 0.19 or 0.18 / 0.21 give 98.7 and 107.6 / 107.2
  ohm bare, checked with the same formula); the pair gap of 0.17 mm was
  preferred to 0.16 mm for the margin over the 6 mil in PCBWay's table.

Netclass values set in `hardware/kicad/raccoon-tap.kicad_pro`:

| Class | `diff_pair_width` | `diff_pair_gap` | `track_width` | `clearance` |
|---|---|---|---|---|
| `USB3` | 0.20 | 0.17 | 0.20 | 0.2 |
| `MDI` | 0.18 | 0.21 | 0.18 | 0.2 |

The router's two diff-pair presets in `board.design_settings.
diff_pair_dimensions` hold the same two geometries. `diff_pair_via_gap` (0.25)
is **not** derived from any impedance calculation and was left as it was.

### Clearance, and the gap inside one pair

The class `clearance` stays at 0.2 mm. It does not only separate the two
traces of a pair: it is also the spacing between one pair and the next and
between a pair and any other net, and lowering it to the in-pair gap would
have let the router put an aggressor pair at 0.16 mm, under one dielectric
height `h` (0.1855 mm), from a SuperSpeed pair. The in-pair gap therefore has
its own rule in `hardware/kicad/raccoon-tap.kicad_dru`, in the style of the
file's existing U3 rule:

* `intra-pair clearance USB3`: min 0.17 mm, for two items of class `USB3` where
  `A.isCoupledDiffPair()` holds (KiCad's own test for the two nets of one pair,
  made by name: `..._P` with `..._N`, the suffix last), and not for two pads.
  It is the only pair rule. It covers the SuperSpeed TX pair after the
  AC-coupling capacitors as well, because that pair is named
  **`USB3_TX_CONN_P` / `USB3_TX_CONN_N`**: they were `USB3_TX_P_CONN` /
  `USB3_TX_N_CONN` until the review, which KiCad does not pair (the suffix
  was not last), so neither the differential-pair router nor
  `isCoupledDiffPair()` would have seen them. The nets were renamed in
  `netlist.yaml`, the schematic regenerated, and the by-name rule that had
  been written for the old names deleted after the scratch run below showed
  the one rule covering the new names (and, as a control, not the old ones);
* no rule for `MDI`: its pair gap, 0.21 mm, is above the 0.2 mm class
  clearance.

`python hardware/tests/check_fab_release.py` checks that the rule exists, is
scoped to the class, to a coupled pair and to anything but two pads, and has
the pair gap as its minimum; and that every net of the two classes carrying a
`_P` / `_N` token ends in it and has its partner, so a name KiCad cannot pair
cannot come back. A scratch-board run shows what KiCad does with it
(`$KIPY hardware/fab/scratch_drc_check.py`; it copies the project to a
temporary directory and never writes the repository's board):

```
ok   USB2 D+/D- at the pair gap 0.17: no clearance violation
ok   USB3 TX after the AC caps (USB3_TX_CONN_P/N) at 0.17: no clearance violation
ok   control: the old names USB3_TX_P_CONN/N_CONN at 0.17 are not a pair: Freiraum-Verstoß (Netzklasse "USB3" Freiraum 0.2000 mm; tatsächlich 0.1700 mm)
ok   MDI0 pair at 0.21: no clearance violation
ok   USB3 RX pair at 0.15, below the pair gap: Freiraum-Verstoß (Regel "intra-pair clearance USB3" Freiraum 0.1700 mm; tatsächlich 0.1500 mm)
ok   two different USB pairs at 0.17: Freiraum-Verstoß (Netzklasse "USB3" Freiraum 0.2000 mm; tatsächlich 0.1700 mm)
ok   two different MDI pairs at 0.17: Freiraum-Verstoß (Netzklasse "MDI" Freiraum 0.2000 mm; tatsächlich 0.1700 mm)
note  full width from the pad centre: 4 trace-to-pad violations, closest 0.1750 mm against the class clearance
note  full width from the outer end of the pad: 4 trace-to-pad violations, closest 0.1807 mm against the class clearance
ok   necked to 0.15 mm for 1.0 mm from the pad centre, then full width: 0 trace-to-pad violations
note  the same neck cut to 0.5 mm: 0 trace-to-pad violations
ok   pad-to-pad spacing of coupled pairs on U3 is not touched by the pair rule: 0 violations
```

The 2 to 3 `h` spacing between pairs that the class clearance of 0.2 mm
(1.1 `h`) only floors is a constraint for task 9, see "Constraints for task 9".

### Machine-readable block

The block below is read by `hardware/tests/check_fab_release.py`
(`check_no_placeholder_geometry`). It takes the targets from `netlist.yaml`
`stackup.impedance`, compares these values with the project file and the
`.kicad_dru`, recomputes the as-built impedance from `inputs`, and fails when a
net class differs, when the as-built value is more than 3 % from the target,
when `mask_offset_ohm` is not PCBWay's 8 ohm, when the class clearance is below
0.2 mm, when the neck limits for task 9 are missing or looser than 0.15 mm and
1.0 mm, or when the note is missing.

<!-- netclass-geometry -->
```yaml
inputs:
  t_oz: 1.0
  h_mm: 0.1855
  er: 4.74
  # PCBWay, Impedance_Control page, excerpt [4]: one pass of solder mask lowers
  # a differential pair's impedance by 8 ohms
  mask_offset_ohm: 8.0
classes:
  USB3: {target_ohm: 90.0, width_mm: 0.20, gap_mm: 0.17, clearance_mm: 0.2}
  MDI: {target_ohm: 100.0, width_mm: 0.18, gap_mm: 0.21, clearance_mm: 0.2}
task9:
  # U3 pads: neck no wider and no longer than this, measured from the pad centre (ruling AI; see
  # "Constraints for task 9"); the check fails if these limits are loosened
  neck_max_width_mm: 0.15
  neck_max_length_mm: 1.0
```

## How far the result moves

`hardware/fab/impedance_crosscheck.py` evaluates the same geometries three
ways: PCBWay's formula on bare copper; that value minus 8 ohm ("as-built",
what the net classes are centred on); and an independent 2-D finite-element
solve written for this check (not a PCBWay tool; it needs numpy and scipy),
once on bare copper and once with an *assumed* solder mask (Er 3.5, filling up
to 15 um above the copper; PCBWay gives neither on the pages used). Output of
`python hardware/fab/impedance_crosscheck.py`, ohm, copper 35 um:

```
units: mm and ohm; copper 35 um (1 oz) throughout; as-built = pcbway - 8; window = target +/-10 %

USB3 / USB2, target 90 ohm: width 0.2, gap 0.17, window 81..99
  case                                            pcbway  as-built    fd2d  fd2d+mask
  nominal: h 0.1855, Er 4.74                        97.7      89.7    99.6       91.5
  h 0.196 (prepreg as pressed from the sheet)       99.5      91.5   101.0       92.8
  h -10 % (0.1670)                                  93.9      85.9    96.2       88.5
  h +10 % (0.2041)                                 100.9      92.9   102.4       94.0
  stackup 3, 30 % residual copper: h 0.1715         94.9      86.9    97.1       89.3
  Er 4.5                                            99.6      91.6   101.7       93.2
  Er 4.2                                           102.3      94.3   104.5       95.4

MDI, target 100 ohm: width 0.18, gap 0.21, window 90..110
  case                                            pcbway  as-built    fd2d  fd2d+mask
  nominal: h 0.1855, Er 4.74                       107.2      99.2   108.5      100.1
  h 0.196 (prepreg as pressed from the sheet)      109.2     101.2   110.2      101.5
  h -10 % (0.1670)                                 103.3      95.3   104.7       96.7
  h +10 % (0.2041)                                 110.6     102.6   111.7      102.9
  stackup 3, 30 % residual copper: h 0.1715        104.3      96.3   105.8       97.6
  Er 4.5                                           109.4     101.4   110.8      101.9
  Er 4.2                                           112.3     104.3   113.9      104.3
```

Reading it:

* **Every case of the as-built column lies inside ±10 %** (81 to 99 ohm and
  90 to 110 ohm), including the prepreg thickness at -10 % and the 30 %
  residual-copper stackup. Nominal as built is 89.7 and 99.2 ohm.
* **The independent estimate agrees.** The solver with an assumed mask lands at
  91.5 and 100.1 ohm nominal, 1.8 and 0.9 ohm above the as-built column. That
  is the size of disagreement to expect between a closed-form approximation
  and a field solve; neither is PCBWay's engineering figure, and the mask in
  the solver is an assumption.
* **What the as-built column rests on is the 8 ohm.** It is PCBWay's "typically,
  one pass" figure. Two passes would double it (the page says so) and the
  nominal values would fall to 81.7 and 91.2 ohm, at the lower edge of the
  window; the combined corners below leave it.
* Prepreg thickness matters more than anything else the layout controls.
  PCBWay: "the resin will fill the gaps left by the etched traces, resulting
  in reduced resin thickness between the layers." (excerpt `[4]`). `In1.Cu` is
  a solid plane, so on that side there are no gaps to fill. The note infers
  that the pressed thickness could sit nearer the 0.196 mm nominal than the
  0.1855 mm listed for 70 % residual copper; this is an inference, not
  PCBWay's statement. It would move the result up by about 2 ohm.

**Combined corners.** The table changes one factor at a time. The same script
also prints the as-built value for one and for two mask passes (PCBWay: "The
reduction value doubles when printing two passes compared to one pass.",
excerpt `[4]`, so 16 ohm), against the prepreg and stackup cases:

```
combined corners: as-built with one and with two mask passes (PCBWay: the reduction doubles with two passes)

USB3 / USB2, target 90 ohm: width 0.2, gap 0.17, window 81..99
  case                                            1 pass  2 passes
  nominal: h 0.1855, Er 4.74                        89.7      81.7
  h 0.196 (prepreg as pressed from the sheet)       91.5      83.5
  h -10 % (0.1670)                                  85.9    77.9 *
  h +10 % (0.2041)                                  92.9      84.9
  stackup 3, 30 % residual copper: h 0.1715         86.9    78.9 *
  Er 4.5                                            91.6      83.6
  Er 4.2                                            94.3      86.3

MDI, target 100 ohm: width 0.18, gap 0.21, window 90..110
  case                                            1 pass  2 passes
  nominal: h 0.1855, Er 4.74                        99.2      91.2
  h 0.196 (prepreg as pressed from the sheet)      101.2      93.2
  h -10 % (0.1670)                                  95.3    87.3 *
  h +10 % (0.2041)                                 102.6      94.6
  stackup 3, 30 % residual copper: h 0.1715         96.3    88.3 *
  Er 4.5                                           101.4      93.4
  Er 4.2                                           104.3      96.3

* outside the window
```

With one mask pass every case is inside ±10 %. **With two passes, the
combined corners of a thin prepreg (h -10 %, or the 30 %-residual stackup)
with the mask fall outside the window for both classes: 77.9 and 78.9 ohm for
USB3, 87.3 and 88.3 ohm for MDI.** Nominal at two passes (81.7 and 91.2 ohm) is
inside by 0.7 and 1.2 ohm only. This geometry therefore holds only if PCBWay
prints one pass or compensates for the second, which is why the number of passes
is the first question in Open item 1, and why an answer of two passes would
mean recomputing the geometry, not accepting it.

Neither column is "the" answer. What PCBWay will actually build is decided by
their engineering calculation with their mask (Open item 1).

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

Margins of this geometry against the first column ("≥5/6 mil", width / spacing):

| | smallest width | margin over 5 mil | smallest spacing | margin over 6 mil |
|---|---|---|---|---|
| `USB3` | 0.20 mm = 7.9 mil | 2.9 mil | pair gap 0.17 mm = 6.7 mil | **0.7 mil** |
| `MDI` | 0.18 mm = 7.1 mil | 2.1 mil | pair gap 0.21 mm = 8.3 mil | 2.3 mil |

Every other spacing is the class clearance, 0.2 mm = 7.9 mil, 1.9 mil over 6.
The one thin margin is the 0.17 mm USB3 pair gap (0.7 mil, about 0.02 mm).
Row 15 says "(before compensation)": whether PCBWay's compensation changes
these file values is not stated, so the margin is the margin on the design
file only. Whether the impedance service applies a stricter figure is Open
item 3.

## Constraints for task 9

Task 9 routes to the geometry above. These constraints come with it; none is
optional.

1. **Neck at the U3 pads: at most 0.15 mm wide, for at most 1.0 mm measured
   from the pad, then widen to the controlled width. No clearance exception.**
   Decided in review. The reason: 0.25 mm pads on a 0.4 mm pitch leave a
   0.20 mm trace 0.175 mm from the neighbouring pad (0.185 mm for 0.18 mm),
   against the 0.2 mm class clearance, and a bounded sub-millimetre
   discontinuity costs less than lowering the clearance between different
   pairs. It applies to every `USB3` and `MDI` trace that leaves a U3 pad.
   The limits are in the machine-readable block (`task9`) and
   `check_fab_release.py` fails if they are loosened.
   * **Leaving from the outer end of the pad is the preferred first choice**
     where the geometry allows it. It was measured on the scratch board
     (`scratch_drc_check.py`): at full width it brings the closest distance
     from 0.1750 to 0.1807 mm only, still under 0.2 mm, so with these widths
     it does not replace the neck. Whether it would shorten the neck that is
     needed was not measured (the scratch run was made without a neck from the
     outer end), so "may shorten" is the most that can be said.
   * Measured, the same scratch pads are clean (0 trace-to-pad violations)
     with a 0.15 mm neck of 1.0 mm and with one of 0.5 mm, each stepping to full
     width. 1.0 mm is the cap, not a target: use the shortest neck that clears.
   * What it costs, from the same formula as everywhere else in this note:
     two 0.15 mm traces at the 0.25 mm gap the pad pitch leaves give 119.9 ohm
     bare, 111.9 ohm as built, against 90 ohm (USB3) and 100 ohm (MDI), over at
     most 1.0 mm. That is about 24 % above the USB3 target and about 12 %
     above the MDI target, i.e. outside the +/-10 % window for both classes
     (111.9 / 90 = 1.243; 111.9 / 100 = 1.119). The effect of that step at 5 Gbit/s is not modelled; a
     0.15 mm trace is 5.9 mil, above the 5 mil of PCBWay's table row 15.
2. **Route every pair with the differential-pair router.** All seven pairs are
   named so that KiCad pairs them (`USB2_D_P/N`, `USB3_RX_P/N`, `USB3_TX_P/N`,
   `USB3_TX_CONN_P/N`, `MDI0..3_P/N`); the TX pair after C22 and C23 was
   renamed for it. The pair gap inside a USB3 pair comes from the `.kicad_dru`
   rule; MDI is routed at its 0.21 mm gap, above the class clearance.
3. **Spacing between pairs: at least 2 to 3 `h`**, that is 0.37 to 0.56 mm edge
   to edge with `h` = 0.1855 mm, outside the pad escape of U3, and the same
   from a pair to other signal copper. This is a general layout rule of
   thumb; it is **not** taken from PCBWay or from a document in this
   repository, and nothing enforces it: the class clearance of 0.2 mm (1.1
   `h`) is only the floor. Task 9 should treat it as a design constraint and
   confirm it, or relax it with a reason.
4. **U8, C22, C23:** see the last item of the next section. Neither the fit
   there nor the discontinuities are settled.

## Fit on 58 x 36 mm

**Result: the geometry is frozen for impedance. Fit is shown for the straight
lanes and, with the neck, for the U3 pad pitch; it is not established at U8,
C22 and C23. The board stays 58 x 36 mm for now; nothing here asks for it to
grow.** Basis, all arithmetic on the geometry above and on pads that
exist, plus the scratch-board DRC run above; nothing is routed yet.

1. **The geometry is not wider than the placeholders it replaces.** Pair
   outline (`2w + s`): USB3 0.57 mm now against 0.60 mm (`0.2 / 0.2`); MDI
   0.57 mm now against 0.61 mm (`0.18 / 0.25`). The widths are those of the
   placeholders, the gaps are tighter. The concern that a computed geometry
   would be much wider than the placeholders does not materialise for this
   stackup.
2. **U3 (QFN-40, 0.4 mm pitch, pads 0.25 mm wide, from the footprint
   `QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm` as embedded in the current board
   file):** adjacent pads are 0.4 mm apart centre to centre.
   * Trace to trace from adjacent pads: 0.4 - `w`, so 0.20 mm (USB3) and
     0.22 mm (MDI), at the 0.2 mm class clearance and 0.02 mm over it. The
     first version of this note had 0.17 mm for USB3.
   * **Trace to the neighbouring pad is closer: 0.175 mm for a 0.20 mm trace
     (0.185 mm for 0.18 mm), and KiCad flags it** against the 0.2 mm class
     clearance. It follows from 0.25 mm pads on a 0.4 mm pitch, holds for the
     old placeholders as well (same widths), and is not covered by the
     existing U3 rule, which handles pad against pad only. The scratch-board
     run above shows it (4 violations, closest 0.1750 mm), shows that leaving
     from the pad's outer end does not remove it (0.1807 mm), and shows that a
     neck removes it. It is settled by the neck in "Constraints for task 9",
     not by a clearance exception.
   * Pair to pair on the MDI side (pins 1/2, 4/5, 6/7, 9/10; pad centres
     -1.6, -0.4, +0.4, +1.6 mm): the nearest pairs (4/5 and 6/7) are 0.8 mm
     apart centre to centre, outlines 0.57 mm, edge gap 0.23 mm. The 2 to 3
     `h` constraint above cannot hold inside the escape; it has to start
     where the pairs leave it.
   * The four MDI pairs need about 3.8 mm along the 5 mm side of the package.
3. **Seven pairs between U3 and the connectors:** seven pair outlines of 0.57
   mm and six gaps of 0.4 mm (the low end of the 2 to 3 `h` constraint) are
   6.4 mm of lane width if all ran side by side, against 36 mm of board
   height. The MDI pairs (pins 1 to 10) and the USB pairs (pins 11 to 20)
   leave U3 on adjacent sides, so per side the MDI group needs about 3.5 mm of
   lanes (4 x 0.57 + 3 x 0.4) and the USB group about 2.5 mm (3 x 0.57 + 2 x
   0.4).
4. **U8 and C22 / C23, estimated from the KiCad library footprints named in
   `netlist.yaml`, not placed:**
   * U8 is `Package_TO_SOT_SMD:SOT-23-6`: pads 1.325 x 0.6 mm at 0.95 mm
     pitch (`SOT-23-6.kicad_mod`, installed library). The TX pair sits on
     pins 1 and 3 with GND (pin 2) between; the RX pair on pins 6 and 4 with
     pin 5 (NC) between (`netlist.yaml`, U8 pin notes). The two pads of a pair
     are 1.9 mm apart and 0.35 mm of copper-free gap separates neighbouring
     pads, too little for a 0.20 mm trace between two pads at 0.2 mm
     clearance (it would need 0.6 mm). Each trace of the pair therefore
     reaches its own pad from outside the package, and the pair cannot stay
     coupled at 0.37 mm pitch over U8: it opens to about 1.9 mm for the length
     of the package. J3's TX pins 5 and 6 and RX pins 8 and 9 are 2.0 mm apart
     in the footprint `USB3_A_Plug_Wuerth_692112030100_Horizontal` as embedded
     in the current board file, which is the natural alignment with U8; the uncoupled
     stretch is then the distance from U8 to J3 and has to be kept as short as
     placement allows.
   * C22 and C23 are 0402 (`C_0402_1005Metric`): pads 0.56 x 0.62 mm at
     +/-0.48 mm. Two capacitors side by side need their pads at least 0.62 +
     0.2 mm = 0.82 mm apart, against the 0.37 mm pair pitch, so the pair has to
     open by about 0.45 mm at the capacitors (about 1 mm of run at 45 degrees)
     or the capacitors have to be staggered along the pair.
   * **These are the actual pinch and discontinuity points on the 90 ohm
     path, and the fit there is open.** Task 8 places U8, C22 and C23; it
     should put them so that the pair is coupled up to the capacitors and the
     uncoupled run from U8 to J3 is short. The calculator geometry does not
     change with this. Neither the discontinuities (pad widths, the opening of
     the pair) nor their effect at 5 Gbit/s are modelled.

If a pair cannot be laid out within the geometry, the controller-ruled order
applies: grow the board first, then change the routing plan, and stop and
report if neither is enough. The impedance targets, board thickness, copper
weight and the impedance-control service stay as they are.

## Open items

These are not closed by this note. Numbers 1 to 3 are for PCBWay to confirm
before anything is ordered; none has been asked yet.

1. **Confirm the geometry with PCBWay engineering, with solder mask.** Ask
   them to calculate 90 ohm and 100 ohm differential for this stackup (entry 1,
   70 % residual copper, 0.1855 mm prepreg) with their solder mask on, and
   say how many mask passes they print (two passes with a thin prepreg
   leave the window, see the combined corners; three or more passes are
   covered only by PCBWay's sentence that "after printing three times or more,
   the impedance value no longer changes", which gives no value, and their
   table covers one and two passes only, so the answer must include the
   three-or-more case). The net classes are centred on the
   calculator's value minus PCBWay's "typically, one pass" 8 ohm; if their
   figure differs, change `mask_offset_ohm` in the block above and
   `PCBWAY_MASK_OFFSET_OHM` in `check_fab_release.py` together and
   recompute. The as-built values in this note are 89.7 and 99.2 ohm
   nominal; they are the note's, not PCBWay's.
2. **Confirm the stackup.** The page the entry comes from says "PCBWay supports
   customers to customize structures"; the order should name entry 1 of the
   4-layer 1.6MM list as the build-up, or ask PCBWay to state the stackup they
   will press. The reading of the 70 % residual-copper entry for a board with a
   solid ground plane is the note's.
3. **Confirm the minimum width and spacing for the impedance-control
   service.** None is published on the pages read. If theirs is stricter than
   5/6 mil, the 0.17 mm USB3 pair gap is the number at risk (0.7 mil margin).
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
   an image (excerpt `[4]`). They are narrower than this note's 180/210 um, but
   their stackups are unknown, so they are not used here as a check.
7. **Not modelled:** surface finish ("The surface finish is neglected.", excerpt
   `[1]`), etch trapezoid (the finite-element check uses rectangular copper),
   the pads of U8, C22 and C23, vias, and loss at 2.5 GHz.
8. **Settled in review, recorded here so it is not reopened:** the U3
   track-to-pad clearance (0.175 mm against 0.2 mm) is handled by the neck in
   "Constraints for task 9", not by a clearance exception.
9. **Settled in review:** the AC-coupled TX nets are named
   `USB3_TX_CONN_P` / `USB3_TX_CONN_N` so that KiCad recognises them as a
   pair. `netlist.yaml` and the regenerated schematic carry the new names;
   task 8 regenerates the board from the netlist.
10. **The 2 to 3 `h` pair-to-pair spacing** is a rule of thumb without a
    source in this repository; it is a constraint for task 9, not a verified
    requirement.
