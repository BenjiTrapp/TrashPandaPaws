# Raccoon Tap rev 2.1-draft: ordering the board from PCBWay

**Nothing has been ordered, uploaded or paid for.** This folder is the package a
human uploads; everything that only PCBWay can answer is a question in
"Questions for PCBWay" below and has not been asked.

Board: `hardware/kicad/raccoon-tap.kicad_pcb`, SHA-256
`0f309dab5a1cfcf0e0f163f1aa0cdc70a7fec1a031040b2d25a5e4372c9f9d25`. 58 x 36 mm,
4 layers, routed; DRC 0 errors and 0 unconnected, ERC 0 violations.

The operator solders this board by hand with an iron and flux. **PCBWay places
two parts and nothing else: U3 and Y1.**

> **PAYMENT GATE (ruling CB). Do not pay until PCBWay's placement preview shows
> U3's pin-1 dot on the corner carrying the silkscreen triangle: the corner
> nearest Y1.** Y1 is centred on one side of U3, so two corners of U3 are equally
> near it; of those two, pin 1 is the one **toward J2 (the RJ45 jack) and away
> from J3 (the USB plug)**, and it is the only corner of U3 with a filled triangle
> beside it. This test does not depend on how the preview is turned or mirrored.
> **Payment waits for your written confirmation of it to PCBWay.** The other
> checks of the preview are in the box under "CPL" below.

How to use this file: read "The PCB" to "Hand-soldering the rest" once, then
fill the form with **"Placing the order: PCBWay's form, field by field"**, which
also has the text to paste into the special-requirements boxes and the exact
list of files for the zip.

## What is in `hardware/fab/`

| File | Goes to PCBWay as |
|---|---|
| `gerber/raccoon-tap-F_Cu.gtl`, `-GND.g1` (In1), `-Power.g2` (In2), `-B_Cu.gbl` | copper, layers 1 to 4 |
| `gerber/raccoon-tap-F_Mask.gts`, `-B_Mask.gbs` | solder mask |
| `gerber/raccoon-tap-F_Silkscreen.gto`, `-B_Silkscreen.gbo` | legend |
| `gerber/raccoon-tap-Edge_Cuts.gm1` | board outline |
| `gerber/raccoon-tap-PTH.drl`, `-NPTH.drl` (+ `-drl_map.pdf`) | Excellon drill, plated and non-plated |
| `gerber/raccoon-tap-F_Paste.gtp` | stencil: **openings for U3 and Y1 only** (see below) |
| `gerber/raccoon-tap-job.gbrjob` | KiCad's X2 job file, **amended by the exporter** (`export_fab.py`, `amend_job_file`): KiCad wrote its default stackup (0.48 mm of FR4 between every pair of layers), finish "None" and its netclass clearances, because the board file has no stackup section. It now carries the stackup of `stackup-note.md` (prepreg 0.1855 mm, DK 4.74; core 1.03 mm), finish **ENIG** (ruling CA), the paste layer in its file list, and no "DesignRules" block (KiCad's 0.2 mm would understate the board; the real minima are under "The PCB"). Goes in the zip |
| `raccoon-tap-assembly-bom.csv` | the BOM for the assembly: U3 and Y1 |
| `raccoon-tap-cpl.csv` | component placement list: U3 and Y1 |
| `stackup-note.md`, `fabrication-note.md`, this file | **not pasted into the order**: they are the operator's record and carry internal ruling letters. The text PCBWay gets is the short block under "Placing the order". Send `stackup-note.md` if PCBWay's engineers ask what the impedance geometry rests on |
| `gerber/raccoon-tap-drc.rpt`, `gerber/release-manifest.json`, `gerber/*-drl_map.pdf` | proof the set is the export of a board that passed DRC, and drill maps for reading (not for PCBWay, for you; not in the zip) |

Not for PCBWay: `hardware/bom.csv` is the **hand-solder BOM**, see below.

### Before uploading: is the set current?

    python3 hardware/tests/check_fab_release.py -v

It fails if any gerber was made from a board other than the one in the
repository (SHA-256 of the board, its rules and its project file are in
`release-manifest.json`), if a file was changed after the export, if a layer is
missing or a stray file is there, if the DRC report beside the set shows any
error or unconnected pad, and if a fresh export of the board does not give the
files that are committed. To rebuild after a board change: `python3
hardware/tools/export_fab.py`. It runs the DRC first and writes nothing if the
board fails.

### Archiving (ruling E)

`.gitignore` excludes `hardware/gerber/*.gbr` and `*.drl`. The set is exported
to `hardware/fab/gerber/`, which no rule covers, so **the release set is
versioned in git, deliberately**, and no exception was added to `.gitignore`.
The reason: the set that was ordered must be recoverable, byte for byte, next
to the board it came from, and the freshness check reads it from the repository.
A test (`ReleaseSetIsVersioned`) fails if a rule ever starts to ignore it.

## The PCB

| Parameter | Value | Source |
|---|---|---|
| Layers | 4: `F.Cu` signals, `In1.Cu` solid GND, `In2.Cu` power, `B.Cu` signals and GND pour | `netlist.yaml` stackup |
| Size | 58 x 36 mm (the job file's 58.1 x 36.1 includes the outline's line width) | board |
| Thickness | 1.6 mm | stackup note |
| Copper | 1 oz finished outer, 1 oz inner | stackup note |
| Stackup | PCBWay "PCB standard stackup", 4 layers, 1.6MM, **entry 1** (7628 RC46% prepreg 0.1855 mm after lamination, DK 4.74; core 1.03 mm; inner residual copper 70 %) | stackup note |
| Quantity | 5 | task plan |
| Tracks | **Minimum track width 0.15 mm (5.9 mil), and it is not confined to U3's pads.** Measured on the board (pcbnew, every segment): **127 segments, 90.5 mm, at 0.15 mm, all on `F.Cu`, on 26 nets**, inside the area x 16.4 to 31.1 mm, y 15.9 to 32.2 mm from the board's top-left corner (round U3 and Y1). 25.2 mm of it lies in U3's escape area (the square reaching 3.45 mm from U3's centre), including the impedance pairs' necks of 0.5 to 0.6 mm per net at U3's pads; 65.3 mm runs outside it: +1V0 15.5 mm, XTAL1 9.6, +5V_SW 8.9, RSET 7.1, XTAL2_Y1 5.0, XTAL2 4.3, +3V3 4.1, DVDD10_UPS 3.6, GND 3.0, AVDD33_LDO 2.2, ETH_LED1 1.4, ETH_LED0 0.6. Controlled widths: 0.18 mm (MDI), 0.20 mm (USB). Other widths 0.3 to 0.8 mm (power) | board (pcbnew 10.0.6, 2026-11-03) |
| Spacing | **Minimum 0.15 mm (5.9 mil): between adjacent pads of U3** (0.4 mm pitch, 0.25 mm pads). Then 0.17 mm (USB pair gaps, `F.Cu` and `B.Cu`), 0.19 mm (a USB3_TX_CONN track to C22's pad, inside the pair), and at least 0.2 mm everywhere else; copper pours keep at least 0.30 mm | board (pcbnew, every pair of copper items of different nets) |
| Process class on the order form | **"Min track/spacing": 5/5mil**, not the form's default 6/6mil: both the track width and the pad gap are 5.9 mil, under 6. 5/5 mil is 0.127 mm, so it holds both with 0.023 mm to spare. PCBWay's Advanced PCB table (row 15, 35 um copper) has "≥5/6 mil" and "≥5/5 mil" in its first two process columns (`pcbway-source-excerpts.txt` [3]); this note reads them as "normal process" and "medium difficulty", so expect 5/5 mil to cost more | form: excerpt [5]; table: excerpt [3] |
| Smallest drill | 0.3 mm (every via but one); plated holes for parts 0.9, 1.0, 1.02 and 1.7 mm; **H1 and H2, the mounting holes, 2.7 mm plated**; non-plated: 2 x 1.1 mm (J3's locating pegs) and 2 x 3.25 mm (J2's locating pegs) | `raccoon-tap-PTH.drl`, `-NPTH.drl`, board |
| Plated slots | **2, each 1.0 x 2.5 mm, plated: J3's shell tabs (USB plug, net GND).** Long axis across the board's left edge (along X); centres 2.55 mm from the left edge, 12.15 mm and 23.85 mm from the top edge; copper pad round each 1.6 x 4.0 mm. In `raccoon-tap-PTH.drl` as G85 routed slots (tool T4, 1.0 mm, from X 103.3 to 101.8 at Y -92.15 and at Y -103.85). **They must be made as slots, not round holes**: J3 cannot be fitted otherwise, and a plated slot cannot be added after plating. Question 12 | `raccoon-tap-PTH.drl`; board (J3 pad `SH`, drill 1.0 x 2.5 mm) |
| Fiducials | 3, 1 mm copper with 2 mm mask opening, at (2.5, 2.5), (47.0, 33.5) and (2.5, 33.5) mm from the top-left corner | board |
| Surface finish | **ENIG** (ruling CA) | controller ruling CA, below |
| Solder mask colour | green, PCBWay's default. Do not change it without asking Question 1 again: the mask is part of the impedance. | stackup note |

**Surface finish: ENIG (ruling CA).** Choose ENIG on the order form; do not leave
the default. The ruling's reason: U3 is a QFN-40 on a 0.4 mm pitch, and ENIG is
flat, whereas HASL leaves an uneven surface that makes fine-pitch stencil assembly
and the hand-soldering of the neighbouring parts worse. The extra cost is
immaterial for five boards against a misplaced or badly soldered U3. The job
file says ENIG as well (the exporter replaced KiCad's "None", above). Whether PCBWay's ENIG changes the
impedance numbers is not known: `stackup-note.md` neglects the finish, as PCBWay's own
calculator does (Question 1 asks them to calculate the pairs with the finish on).

## Vias: three sizes, and what is covered

The board has 123 vias (pad / drill, mm):

| Pad / drill | Count | Where |
|---|---|---|
| 0.6 / 0.3 | 121 | everywhere by default |
| 0.8 / 0.4 | 1 | J3 pin 1's +5V via (current) |
| 0.56 / 0.3 | 1 | **the board's minimum via**: U3 pin 3's +1V0 via at (28.31, 24.375) mm from the top-left corner (128.31, 104.375 on the page). Annular ring 0.13 mm, **which may be below PCBWay's published minimum for an annular ring (believed to be 0.15 mm), i.e. out of process; not confirmed**. The smaller pad is what keeps In1's hole round it 0.11 mm from both MDI pairs (ruling BP). Ask Question 7. |

That is three via sizes on two drill diameters (0.3 and 0.4 mm).

**Tented from the back** (B.Mask covers them; ten vias, rulings BA and BP):

* U3's exposed pad (pin 41): nine vias, 3 x 3 on a 1.1 mm grid. PCBWay reflows
  U3, so they carry the thermal path to In1 and must not draw solder through
  from the underside.
* U8 pin 2's GND via, SP3019 at (15.6, 15.86) mm from the top-left corner. The
  via sits inside a pad that the operator solders: from the front it is open,
  inside the pad's own mask opening, by design; from the back the mask closes
  it. The soldering technique for it (flux, a little extra solder on that pad)
  is in `fabrication-note.md`.

The design file already says so (`tenting back yes` on those ten, checked in
the `B_Mask` gerber: no opening at either place). **State it on the order as
well** (block A under "Placing the order" does), so that a "vias not covered"
default is not applied to them. Every other
via follows the board default: tented on both sides.

**Resin-filled and capped vias: a priced option, not decided here (ruling BD).**
They would remove the open via of U8 pin 2 and make U3's thermal vias solder-
tight, but PCBWay offers them for all vias of a board and charges for it
(for a single via it is out of proportion, ruling BD). The price has **not**
been obtained: PCBWay publishes none, it appears only in the quote form.
To get it: in PCBWay's quote form (4 layers, 58 x 36 mm, quantity 5, every other
field as under "Placing the order") tick the option listed under "Customized
Services and Advanced Options" as "All vias filled with resin and capped" (label
read from the standard quote page on 2026-11-03, excerpt [5]; its tooltip: "If you
check this option, all vias will be filled with resin,then capped and plated
cover.") and read the difference, then give it to the operator, who decides. Weigh against it,
for the present choice: U3's nine paste windows sit over the open tops of its
thermal vias, which are closed only by the mask at the back. Voids from outgassing,
or a blown back tent, are the usual risk of that arrangement (a general risk, not
from a source in this repository); the X-ray in Question 9 is the check. If the operator takes the option, the B-side tenting
request above becomes moot for the ten vias and Question 7 must be asked
again for filled 0.3 mm vias.

## Controlled impedance

Targets (`netlist.yaml`, `stackup-note.md`):

* **90 ohm differential**, ±10 % (81 to 99 ohm): the `USB3` class, i.e. USB 3.0
  SuperSpeed (TX, RX, and TX after the AC-coupling capacitors) and USB 2.0 D+/D-:
  0.20 mm tracks, 0.17 mm gap.
* **100 ohm differential**, ±10 % (90 to 110 ohm): the four `MDI` pairs: 0.18 mm
  tracks, 0.21 mm gap.
* Reference plane: `In1.Cu`, 0.1855 mm below `F.Cu`. Impedance on `F.Cu`
  (microstrip); the USB 2.0 pair also has one short stretch on `B.Cu` (ruling AR).

`stackup-note.md` is what these numbers rest on: PCBWay's published calculator
for PCBWay's published stackup, less PCBWay's published 8 ohm for **one pass** of
solder mask. They are the project's figures, **not confirmed by PCBWay
engineering**. The single most important thing to find out is the number of mask
passes: **two passes** double the mask's effect and put the combined corners of a
thin prepreg (h -10 %, or the 30 %-residual stackup) outside the window for both
classes (77.9 and 78.9 ohm USB, 87.3 and 88.3 ohm MDI). If PCBWay says two
passes, the geometry must be recomputed, not accepted. Ask for an impedance
test report (coupon) with the boards.

## Partial assembly: exactly two parts, U3 and Y1

**Partial assembly of exactly two parts: U3 and Y1** (rulings Y and AC). Every
other part is fitted by the operator, by hand. Do not let the order form fill
the rest of the BOM; the assembly BOM has two lines.

* **U3** RTL8153B-VB-CG, QFN-40 5 x 5 mm, 0.4 mm pitch, exposed pad: impossible
  by hand.
* **Y1** Abracon ABM8-25.000MHZ-D2Y-T, 3225, four pads under the body: borderline
  with an iron, so it goes to the machine as well (ruling Y). It was checked
  point by point against [RTL-DS] table 23 and stays (ruling AC); the footprint
  has extended pads (`Crystal_SMD_3225-4Pin_3.2x2.5mm_HandSoldering`) for hand rework.

One side only: both parts are on the **top**; the machine places 2 positions x 5
boards. The stencil is the top paste layer only. **`F_Paste.gtp` has openings
for U3 and Y1 only**, on purpose: the board's own paste layer has an opening on
every top pad, and a stencil cut from it would put paste on pads of parts the
operator solders by hand, which would then be reflowed into lumps. The layer is
plotted from a scratch copy of the board in which all other pads have no paste;
the check `PasteIsOpenOnlyForTheAssembledParts` proves every opening lies on U3
or Y1 and that the full layer would not pass.

### Three parts on the bottom side, hand-soldered (ruling BL)

**C9, C14 and C27** (0402, 100 nF) are on the **bottom** side: decoupling that
has to sit at the existing vias of U3 pins 39/40, 37 and 19. The operator solders
them. **This is not a double-sided SMT job**: PCBWay's machine places only the
two top-side parts, there is no bottom paste layer in the set, and no bottom
stencil is wanted. Say so on the order, and put the operator on notice that a
board with parts on both sides is soldered on both sides by hand.

### CPL: rotation checked against pin 1, not copied

`raccoon-tap-cpl.csv` (Designator, Val, Package, Mid X, Mid Y, Rotation, Layer):

| Part | Mid X | Mid Y | Rotation | Layer |
|---|---|---|---|---|
| U3 | 124.0000 | -103.0000 | 180 | Top |
| Y1 | 124.0000 | -111.0000 | 0 | Top |

* **Coordinate system: the gerbers'.** X to the right, **Y up**, origin at the
  page origin of the KiCad file, because the board has no drill/place origin.
  Hence Mid Y is negative. The board outline runs from X 100 to 158 and Y -80 to
  -116. Measured from the board's **lower-left corner**, U3's centre is at
  (24.0, 13.0) mm and Y1's at (24.0, 5.0) mm.
* **This departs from PCBWay's own KiCad instruction.** PCBWay's help-centre page
  "Generate Position File Centroid File(pick place) in Kicad" (last updated
  16/07/2024; fetched 2026-11-03, excerpt [6] in `pcbway-source-excerpts.txt`)
  says: "Select the menu bar Place-> Drilling and Position Offset, place the
  origin at the bottom left corner of the PCB board frame". PCBWay's general
  centroid article (excerpt [7]) says: "The board's origin is defined as the (0,
  0) value and is located at the lower left corner of the board from a top point
  of view." The board file is frozen, so its origin was not moved and the CPL
  keeps the page origin. Whether PCBWay accepts that, or wants the lower-left
  values above, **is an assumption to confirm in the quote** (Question 10 (d)).
  **The placement preview is a gate before payment, not a courtesy** (Question 10,
  and the box below).
* **U3 rotation 180**: U3's library pose (rotation 0) has pin 1 at the upper
  left; the board has it turned half a turn. Pad 1 is at (+2.4375, -1.8) mm
  from the centre in the gerber (Y up), and the pin-1 triangle on the silkscreen
  is just outside the pad column at the height of pin 1. **To check a picture, do
  not use "left" or "right"**: a preview may be turned or mirrored. Use ruling
  CB: the pin-1 dot sits on the corner carrying the silkscreen triangle, the
  corner nearest Y1 (of the two corners that face Y1, the one toward J2, the RJ45).
  The board's F.Fab outline has its chamfer at the same corner.
* How it was verified (`CplRotationIsVerifiedAgainstPinOne`): the rotation is
  derived from where the **copper gerber** has pad 1 (from its X2 attribute
  `%TO.P,U3,1`), less where the footprint puts pad 1 at rotation 0; then the
  footprint's silkscreen pin-1 marking is carried to the board with that
  rotation and must land next to pad 1 and not next to any other pad. Rotations
  of 0, 90 and 270 degrees for U3 and a mirrored Y are rejected by the same
  function. The value in the placement table was never used.
* **Y1 has no reliable pin-1 mark on the part.** The ABM8 datasheet (outline
  drawing): "the chamfer could be located on pin #1, 3, or 4". What matters is
  that pads 1 and 3 are the two crystal terminals and 2 and 4 are ground (top
  view: 4 and 3 on the upper row, 1 and 2 on the lower). A half turn swaps a
  terminal with the other terminal and ground with ground: harmless. A quarter
  turn puts a terminal on ground: fatal. So the instruction to the machine is "long
  axis of the body along the long axis of the pads"; the footprint's L-shaped
  silkscreen mark sits at pad 1 (lower left). Rotation 0.
* **The CPL's format is unverified against PCBWay, not only its rotation.** Nobody has
  checked these against PCBWay's template or an accepted file: the `Layer` value `Top`
  (against `T` / `B`), the absence of a unit suffix (`mm`) on Mid X and Mid Y, the
  negative Mid Y (a consequence of the page origin), the column set and order
  (Designator, Val, Package, Mid X, Mid Y, Rotation, Layer). The column names follow what
  the exporter calls PCBWay's sample; no PCBWay template was fetched or checked in this
  task. All of it goes to Question 10.
* **The CPL's rotation convention may not be PCBWay's.** KiCad's rotation is
  counter-clockwise from the library pose. Some assemblers apply their own zero
  orientation to QFN parts. The CPL is correct in KiCad's convention; PCBWay's
  engineers confirm with their preview from the silkscreen mark (Question 10).
  A QFN placed half a turn out is a dead board, so look at the picture.

> **GATE: do not pay until you have seen PCBWay's placement preview of this CPL and
> have confirmed it yourself.** **U3's pin-1 dot must sit on the corner carrying the
> silkscreen triangle: the corner nearest Y1** (ruling CB; of the two corners of U3
> that face Y1, the one toward J2, the RJ45, and away from J3, the USB plug). Y1's
> long axis along the long axis of its pads, both parts on the top side, both inside
> the outline. These tests hold however the picture is turned or mirrored. The
> preview is the real safeguard against a format or rotation mismatch; every check
> in this repository confirms the CPL against the board, none confirms it against
> PCBWay. **Payment waits for that confirmation.** If the preview disagrees, stop and
> correct the CPL (or have PCBWay's engineers do it, in writing) before paying.

## Sourcing

### U3: name LCSC `C2802072` in the BOM

From `hardware/review/u3-sourcing.md` (checked 2026-11-01):

* **PCBWay can probably buy U3 itself, but only if the BOM says where.** Mouser
  and DigiKey, the distributors PCBWay names first, list nothing for this part;
  it is sold through Realtek's own channel and through **LCSC `C2802072`** (stock 3,330
  on 2026-11-01; $3.56 for 1, $3.03 for 10). `raccoon-tap-assembly-bom.csv` names
  LCSC and `C2802072` on U3's line. PCBWay's page says it buys from "distributors
  you recommend" and that "No substitutes will be used without getting your
  approval".
* **Fallback: consign.** If PCBWay answers "cannot source" or quotes a silly
  price, the operator buys 8 pieces (5 + 3 spare) from LCSC ($28.52 for 8 at the
  1-piece price, or $30.35 for 10 at the 10-piece price, `u3-sourcing.md`; plus
  shipping and import VAT) and sends them on **one continuous cut-tape strip**
  with the markings on every package matching the BOM. U3 is **MSL 3** ([RTL-DS]
  table 25, "Moisture Sensitivity Level (MSL) Level 3"): ask LCSC for dry pack, or
  tell PCBWay the strip must be baked before reflow (the form's "sensitive
  components" box, below).
* Do **not** buy U3 from brokers (UppConn, PCBX, DigiPart, eBay): possibly
  relabelled stock, for a part that cannot be replaced.

### Y1

DigiKey (27,729 in stock, $0.884 at 10) and Mouser (9,289), both of which PCBWay
names first. The assembly BOM carries the manufacturer part number only; **no
DigiKey or Mouser part number is recorded** (none was verified). Check the
variant: distributor listings disagree on whether the D2Y **tolerance at 25 C** is
±20 or ±50 ppm; either satisfies [RTL-DS] table 23. What to confirm on the order
confirmation is the **stability over 0 to 70 C: ±30 ppm** (`netlist.yaml`, Y1).

## Hand-soldering the rest

`hardware/bom.csv` is the operator's BOM: every line except U3 and Y1, which
the machine fits (those two lines are in the file too, as the record of the whole
board, and their description starts with "PLACED BY PCBWAY"; do not order or
solder them from it). R12 and C24 are DNP (column Populate): leave the pads empty.
The three bottom-side parts C9, C14, C27 are lines of the 100 nF row. U8 pin 2's
via and the rest of the assembly notes are in `fabrication-note.md`; its first-
build checks (SuperSpeed link, thermals of U3) come after the first board is up.

## Placing the order: PCBWay's form, field by field

The labels below are copied from PCBWay's standard quote page
(`https://www.pcbway.com/orderonline.aspx`, fetched 2026-11-03; the passages are
excerpt [5] in `pcbway-source-excerpts.txt`). The page was read as HTML, not
filled in or submitted, so the steps after it (upload, checkout, where the BOM and
CPL are attached) **were not seen**; where this table says "not known", it is not.
If a label on the live form differs, go by the meaning, and ask rather than guess.

### 1. The zip with the board data

From the repository root:

    python3 hardware/tests/check_fab_release.py -v
    cd hardware/fab/gerber && zip ~/raccoon-tap-pcbway.zip raccoon-tap-F_Cu.gtl raccoon-tap-GND.g1 raccoon-tap-Power.g2 raccoon-tap-B_Cu.gbl raccoon-tap-F_Mask.gts raccoon-tap-B_Mask.gbs raccoon-tap-F_Silkscreen.gto raccoon-tap-B_Silkscreen.gbo raccoon-tap-Edge_Cuts.gm1 raccoon-tap-F_Paste.gtp raccoon-tap-PTH.drl raccoon-tap-NPTH.drl raccoon-tap-job.gbrjob

Do not zip until the check passes. The zip holds exactly these 13 files: four
copper layers, two masks, two legends, the outline, the top paste layer (U3 and Y1
only), the plated and non-plated drill files and the job file. Not in it: the DRC
report, the manifest and the two drill-map PDFs. The assembly BOM and the CPL are
separate uploads for the assembly (`raccoon-tap-assembly-bom.csv`,
`raccoon-tap-cpl.csv`); where PCBWay asks for them is **not known** (not on the
quote page).

### 2. PCB section

| Field on the form | Choose | Why |
|---|---|---|
| Board type | Single pieces | five single boards. The assembly section of the same page says: "We suggest choose to do panel if single PCB qty is more than 20pcs or any side of single board is smaller than 50mm." This board is 36 mm on one side, so expect PCBWay to propose rails or a panel (Question 9); accept or refuse it when they do |
| Size (single) | 58 x 36 mm | outline |
| Quantity (single) | 5 | |
| Layers | 4 Layers | |
| Material | FR-4 | |
| FR4-TG | the form's default | the design does not specify a TG. The page says multilayer FR-4 is "Normally ... automatically upgraded to TG150 for FREE", with exceptions such as custom stackup and resin-filled vias |
| Thickness | 1.6 | |
| **Min track/spacing** | **5/5mil** (the form's default is 6/6mil: change it) | the board's minimum track and minimum gap are both 0.15 mm = 5.9 mil (see "The PCB") |
| Min hole size | 0.3mm ↑ | smallest drill 0.3 mm |
| Solder mask | Green | the mask is part of the impedance; do not change it without asking Question 1 again |
| Silkscreen | White | the design specifies no colour; white is the default |
| Edge connector | No | |
| **Surface finish** | **Immersion gold(ENIG)** (the default is HASL lead free: change it) | ruling CA. Thickness of immersion gold: the design does not specify one; leave the default |
| Via process | Tenting vias | the page says of this field: "For gerber files, we will process according to the files, and this option is invalid." The mask gerbers already tent every via on both sides except ten that are open on the top only (U3's nine, U8 pin 2's) |
| Finished copper | 1 oz Cu | |
| Inner Copper | 1 oz | |
| Remove product No. | the operator's choice | not a design requirement |
| Customized Services and Advanced Options: **Impedance control** | **tick it** | the page warns: "If impedance requirements are specified in the documentation but not selected in the order, it will be regarded as ignoring the impedance requirement." |
| Custom stackup | leave unticked | the board uses PCBWay's own standard stackup, entry 1, named in the text below. Whether PCBWay needs this box ticked to hold a named standard entry is Question 2; tick it only if they say so |
| **All vias filled with resin and capped** | **the operator decides (ruling BD)** | to get the price: quote once without and once with it ticked, read the difference, give it to the operator. Not ticked unless the operator says so |
| Every other advanced option (castellated holes, edge plating, via in pad, ...) | unticked | none is used |
| **Other special request** | **paste block A below** | |
| SMD-Stencil, "Order together with PCB" | **not known** whether PCBWay's assembly brings its own stencil (Question 9). If you order one here: Stencil side Top, and paste block B into its "Other Special request" box | the stencil is cut from `raccoon-tap-F_Paste.gtp` |

### 3. Assembly section ("The PCBs above need assembly": tick it)

| Field on the form | Choose | Why |
|---|---|---|
| 3 flexible options | **Turnkey** if PCBWay buys both parts (U3 from LCSC `C2802072`, named in the BOM; Y1 by manufacturer part number); **Combo** if the operator consigns U3 (fallback, "Sourcing" above) | operator's decision |
| Board type | Single pieces (see the PCB section's row) | |
| Assembly side(s) | **Top side** | U3 and Y1 are both on top. The three bottom parts are hand-soldered (ruling BL), so not "Both sides" |
| Quantity | 5 | |
| Contains sensitive components/parts | **Yes**, and paste block C into the box that opens | U3 is MSL 3 |
| Do you accept alternatives/substitutes made in China? | **No** | U3 has no substitute; Y1 is ruled to be the ABM8 (ruling AC) |
| Function test | No | |
| Firmware loading | No | |
| Number of Unique Parts | 2 | |
| Number of SMD Parts | 2 | per board |
| Number of BGA/QFP Parts | 1 | U3; the form's own hint counts "ICs with more than 16pins ... (SOP,QFP,QFN,BGA)" |
| Number of Through-Hole Parts | 0 | PCBWay fits none |

### Block A: PCB "Other special request" (paste as it stands)

    4 layers, 1.6 mm, 1 oz outer / 1 oz inner, ENIG, green mask, white legend.
    Stackup: your standard 4-layer 1.6MM stackup, entry 1 (7628 RC46% prepreg, 0.1855 mm after lamination, DK 4.74; core 1.03 mm). The job file in the zip carries the same stackup.
    IMPEDANCE CONTROL, L1 (top) referenced to L2 (GND): 90 ohm differential +/-10% at 0.20 mm track / 0.17 mm gap (nets USB3_*, USB2_*); 100 ohm differential +/-10% at 0.18 mm / 0.21 mm gap (nets MDI0..MDI3). The geometry already allows 8 ohm for ONE pass of solder mask. Before production, tell me how many mask passes you print and the widths you calculate. Do not change any trace width or gap without asking me first. Please supply an impedance test coupon and report.
    Minimum track 0.15 mm (5.9 mil); minimum spacing 0.15 mm (between QFN pads).
    Vias: 121 x 0.6/0.3 mm, 1 x 0.8/0.4 mm, and 1 x 0.56/0.30 mm (0.13 mm annular ring): please confirm it is within your process.
    Via covering as in the mask gerbers: all vias tented on both sides, except 10 vias inside pads (9 in U3's exposed pad, 1 in U8 pin 2) that are open on top and must stay tented on the bottom.
    2 PLATED SLOTS, 1.0 x 2.5 mm, for J3 (G85 in the PTH drill file): please make them as slots, not round holes.
    Partial assembly, top side only: U3 and Y1, nothing else (BOM and CPL attached). Three parts on the bottom are soldered by hand later: no bottom stencil, no bottom assembly.
    Please send the placement preview before I pay, and wait for my confirmation.

### Block B: stencil "Other Special request" (only if a stencil is ordered there)

    Top side only. Openings for U3 and Y1 only, as in raccoon-tap-F_Paste.gtp; no other pad gets paste. U3's exposed pad is already split into 9 windows. Please ask me before changing any aperture.

The tooltip of that box says: "We normally will reduce apatures for ICs to make
stencil, so if don't want to change the apatures, please note it when place the
order." Block B asks to be told, rather than forbidding a change: whether Y1's
apertures should be reduced is PCBWay's call to propose and the operator's to
accept.

### Block C: assembly, "Contains sensitive components/parts" (max. 500 characters)

    RTL8153B-VB-CG (U3): moisture sensitivity level MSL 3 (Realtek datasheet, table 25). If the parts are not in sealed dry pack, it needs to bake before placement. QFN-40, 0.4 mm pitch, exposed pad: please X-ray the exposed pad.

### 4. Before paying

1. PCBWay's answers to the questions below, Question 1 (mask passes) first.
2. The operator's decisions: resin fill (price from the resin row of section 2), U3
   bought or consigned.
3. **The placement preview, checked against the payment gate at the top of this
   file (ruling CB). Payment waits for that confirmation.**

## Questions for PCBWay

Not yet asked. Answers go into the order and, where they change a number, into
`stackup-note.md` first.

1. **How many passes of solder mask do you print on this build, and what is the
   mask's effect on 90 ohm and 100 ohm differential on my stackup?** One pass
   keeps every case inside ±10 %; two passes move four tolerance corners
   outside it. Please calculate 90 ohm (0.20 mm / 0.17 mm gap) and 100 ohm (0.18 /
   0.21) with your mask and your ENIG finish on and tell me the widths you would use.
2. **Confirm the stackup:** 4 layers, 1.6MM, entry 1 of your standard list
   (7628 RC46%, 0.1855 mm after lamination, DK 4.74, 70 % residual copper) for a
   board with a solid ground plane; or state the stackup you will press. Do I
   need to tick "Custom stackup" for you to hold that entry? (The job file in the
   zip carries the same stackup; KiCad's default of 0.48 mm per dielectric was
   replaced by the exporter, so if your CAM reads a different stackup from it, tell
   me.)
3. **Will you change any trace width or gap on the controlled pairs?** If so,
   send an engineering question first; I do not accept silent compensation.
4. **Process class: I have declared "Min track/spacing" 5/5mil.** The board's
   minimum track is 0.15 mm (5.9 mil), about 90 mm of it on the top layer round
   U3 and Y1, and its minimum spacing is 0.15 mm (5.9 mil) between U3's pads.
   Confirm that 5/5 mil covers it, and tell me if the impedance-control service has
   a stricter minimum: the USB pair gap is 0.17 mm (6.7 mil).
5. **Impedance report:** will a test coupon and report come with the boards, and at
   what cost?
6. **Vias covered from the back (ten, listed above):** confirm they are tented,
   not left open by a default.
7. **Is the 0.56 / 0.3 mm via (0.13 mm annular ring) inside your normal process?**
   Same for the 0.3 mm drill generally.
8. **Resin-filled and capped vias for the whole board: the price difference** for 5
   boards (ruling BD). Operator decides.
9. **Assembly, U3 and Y1 only:** setup / engineering fee; whether the assembly
   includes its own stencil or I must order one in the PCB form; stencil fee and whether
   one-sided; placement fee for 2 positions x 5; **X-ray of the QFN's exposed pad,
   included or charged**; part cost as you charge it and the spare quantity you add;
   whether you accept **LCSC C2802072** for U3 (say so before ordering if you cannot);
   assembly and sourcing lead time per part; shipping; any partial-assembly or
   minimum-order surcharge. Also: does the board need rails, tabs or a panel for the
   machine (it has none), and will it be delivered as single boards?
10. **Placement preview and CPL format: a hard gate before I pay.** Send me the
    preview of U3 and Y1 on the board **before** I pay, and wait for my confirmation.
    I will check that U3's pin-1 dot sits on the corner carrying the silkscreen
    triangle, the corner nearest Y1 (of the two corners facing Y1, the one toward the
    RJ45 jack J2), and that Y1's pads are matched. Also tell me, for
    this CPL, whether you accept: (a) the rotation convention (KiCad's, counter-clockwise
    from the library pose); (b) the `Layer` value `Top`, or do you need `T` / `Top` /
    `TopLayer`; (c) Mid X and Mid Y as plain millimetre numbers **without** a unit
    suffix; (d) a **negative** Mid Y and an origin that is the page origin, not the
    board's corner, although your KiCad instruction puts the origin at the bottom
    left corner of the board (positions from the lower-left corner: U3 24.0 / 13.0 mm,
    Y1 24.0 / 5.0 mm); (e)
    the columns Designator, Val, Package, Mid X, Mid Y, Rotation, Layer, in that
    order; or send me your template.
11. **Surface finish:** ENIG is ruled (ruling CA) and goes on the order form. Confirm
    that your ENIG is available for this build (4 layers, 1.6 mm, 5 pieces, 0.15 mm
    minimum track) and give the price against lead-free HASL, for the record only.
12. **J3's two plated slots, 1.0 x 2.5 mm** (G85 routed slots in the PTH drill
    file, centres 2.55 mm from the left edge and 12.15 / 23.85 mm from the top):
    confirm they will be made as plated slots, not round holes, and state your slot
    tolerance.

## What is not yet in hand (for a human)

* **Würth 692112030100 datasheet (ruling U).** `https://www.we-online.com/components/
  products/datasheet/692112030100.pdf` returns HTTP 403 to automated fetches. Download
  it **by hand**, commit it under `hardware/datasheets/` and record its md5 in the
  `[WE-692]` entry of `netlist.yaml`'s header. Until then the Würth sheet is
  corroboration only; the crossover of J3's SuperSpeed pins (5/6 to our transmitter,
  8/9 to our receiver) rests on the USB 3.0 specification, Revision 1.0 (USB-IF,
  12 Nov 2008) section 5.3.1.2, Table 5-2 "USB 3.0 Standard-A Connector Pin Assignments",
  with its note that Tx and Rx are defined from the host's perspective. That citation
  stands by itself; it was enough for the release (ruling U).
* **PCBWay's answers** to the twelve questions, and the quote. **The placement
  preview (Question 10) is a gate: no payment before the operator has seen it.**
* **Decisions** for the operator: resin-filled vias (ruling BD), U3 bought by PCBWay
  or consigned, Y1 from DigiKey or Mouser. The surface finish is no longer one: it
  is ENIG (ruling CA).
* **The first-build measurements** in `fabrication-note.md`, including U3's case
  temperature: U3 has an estimate (about 82 to 88 C junction at 70 C ambient and
  typical load) built on an assumed theta-JA, not an assessment.
