# Raccoon Tap rev 2.1-draft: ordering the board from PCBWay

**Nothing has been ordered, uploaded or paid for.** This folder is the package a
human uploads; everything that only PCBWay can answer is a question in
"Questions for PCBWay" below and has not been asked.

Board: `hardware/kicad/raccoon-tap.kicad_pcb`, SHA-256
`0f309dab5a1cfcf0e0f163f1aa0cdc70a7fec1a031040b2d25a5e4372c9f9d25`. 58 x 36 mm,
4 layers, routed; DRC 0 errors and 0 unconnected, ERC 0 violations.

The operator solders this board by hand with an iron and flux. **PCBWay places
two parts and nothing else: U3 and Y1.**

## What is in `hardware/fab/`

| File | Goes to PCBWay as |
|---|---|
| `gerber/raccoon-tap-F_Cu.gtl`, `-GND.g1` (In1), `-Power.g2` (In2), `-B_Cu.gbl` | copper, layers 1 to 4 |
| `gerber/raccoon-tap-F_Mask.gts`, `-B_Mask.gbs` | solder mask |
| `gerber/raccoon-tap-F_Silkscreen.gto`, `-B_Silkscreen.gbo` | legend |
| `gerber/raccoon-tap-Edge_Cuts.gm1` | board outline |
| `gerber/raccoon-tap-PTH.drl`, `-NPTH.drl` (+ `-drl_map.pdf`) | Excellon drill, plated and non-plated |
| `gerber/raccoon-tap-F_Paste.gtp` | stencil: **openings for U3 and Y1 only** (see below) |
| `gerber/raccoon-tap-job.gbrjob` | KiCad's job file; it says surface finish "None" because the board file does not carry one: ignore it, the finish is chosen in the order form: **ENIG** (ruling CA) |
| `raccoon-tap-assembly-bom.csv` | the BOM for the assembly: U3 and Y1 |
| `raccoon-tap-cpl.csv` | component placement list: U3 and Y1 |
| `stackup-note.md`, `fabrication-note.md`, this file | attach to the order as "special requirements" |
| `gerber/raccoon-tap-drc.rpt`, `gerber/release-manifest.json` | proof the set is the export of a board that passed DRC (not for PCBWay, for you) |

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
| Tracks | 0.18 mm (MDI), 0.20 mm (USB), necks of 0.15 mm for at most 1.0 mm at U3's pads; pair gaps 0.17 mm (USB) and 0.21 mm (MDI); everything else at least 0.2 mm clearance | stackup note |
| Smallest drill | 0.3 mm (every via); mounting 3.25 mm and 1.1 mm NPTH; through-hole parts 0.9 to 2.7 mm | `raccoon-tap-PTH.drl`, `-NPTH.drl` |
| Fiducials | 3, 1 mm copper with 2 mm mask opening, at (2.5, 2.5), (47.0, 33.5) and (2.5, 33.5) mm from the top-left corner | board |
| Surface finish | **ENIG** (ruling CA) | controller ruling CA, below |
| Solder mask colour | green, PCBWay's default. Do not change it without asking Question 1 again: the mask is part of the impedance. | stackup note |

**Surface finish: ENIG (ruling CA).** Choose ENIG on the order form; do not leave
the default. The ruling's reason: U3 is a QFN-40 on a 0.4 mm pitch, and ENIG is
flat, whereas HASL leaves an uneven surface that makes fine-pitch stencil assembly
and the hand-soldering of the neighbouring parts worse. The extra cost is
immaterial for five boards against a misplaced or badly soldered U3. The job
file's "None" (above) is not an instruction. Whether PCBWay's ENIG changes the
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
well**, so that a "vias not covered" default is not applied to them. Every other
via follows the board default: tented on both sides.

**Resin-filled and capped vias: a priced option, not decided here (ruling BD).**
They would remove the open via of U8 pin 2 and make U3's thermal vias solder-
tight, but PCBWay offers them for all vias of a board and charges for it
(for a single via it is out of proportion, ruling BD). The price has **not**
been obtained: PCBWay publishes none, it appears only in the quote form.
To get it: in PCBWay's Advanced PCB quote (4 layers, 58 x 36 mm, quantity 5) switch on
the option listed there as "All vias filled with resin and capped" (the wording is
from a search result for that form; the form itself was not opened, and it may differ)
and read the difference, then give it to the operator, who decides. If the operator takes the option, the B-side tenting
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
  (24.0, 13.0) mm and Y1's at (24.0, 5.0) mm. PCBWay's own KiCad instruction
  says to put the origin at the lower-left corner; the board file was frozen, so
  the origin was not moved. **The placement preview is a gate before payment, not
  a courtesy** (Question 10, and the box below).
* **U3 rotation 180**: with the board seen from the front, pin 1 is at the
  **lower right** of the package. U3's library pose (rotation 0) has pin 1 at the
  upper left; the board has it turned half a turn. Pad 1 is at (+2.4375, -1.8) mm
  from the centre in the gerber, the pin-1 triangle on the silkscreen is just
  outside the right-hand pad column at the height of pin 1.
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
> have confirmed it yourself.** U3's pin 1 at the **lower right** of the package as seen
> from the front, Y1's long axis along the long axis of its pads, both on the top
> side, both inside the outline. The preview is the real safeguard against a format
> or rotation mismatch; every check in this repository confirms the CPL against the
> board, none confirms it against PCBWay. If the preview disagrees, stop and correct
> the CPL (or have PCBWay's engineers do it, in writing) before paying.

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
  price, the operator buys 8 pieces (5 + 3 spare) from LCSC (about $28.5 to $30.4,
  plus shipping and import VAT) and sends them on **one continuous cut-tape strip**
  with the markings on every package matching the BOM.
* Do **not** buy U3 from brokers (UppConn, PCBX, DigiPart, eBay): possibly
  relabelled stock, for a part that cannot be replaced.

### Y1

DigiKey (27,729 in stock, $0.884 at 10) and Mouser (9,289), both of which PCBWay
names first. The assembly BOM carries the manufacturer part number only; **no
DigiKey or Mouser part number is recorded** (none was verified). Check the
variant: distributor listings disagree on whether "D2Y" is ±20 or ±50 ppm; either
satisfies [RTL-DS] table 23, but confirm ±30 ppm on the order confirmation.

## Hand-soldering the rest

`hardware/bom.csv` is the operator's BOM: every line except U3 and Y1, which
the machine fits (those two lines are in the file too, as the record of the whole
board, and their description starts with "PLACED BY PCBWAY"; do not order or
solder them from it). R12 and C24 are DNP (column Populate): leave the pads empty.
The three bottom-side parts C9, C14, C27 are lines of the 100 nF row. U8 pin 2's
via and the rest of the assembly notes are in `fabrication-note.md`; its first-
build checks (SuperSpeed link, thermals of U3) come after the first board is up.

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
   board with a solid ground plane; or state the stackup you will press.
3. **Will you change any trace width or gap on the controlled pairs?** If so,
   send an engineering question first; I do not accept silent compensation.
4. **Minimum width and spacing in the impedance-control service**, if stricter than
   5/6 mil: the USB pair gap is 0.17 mm (6.7 mil, 0.7 mil over 6 mil) and the
   necks at U3 are 0.15 mm (5.9 mil).
5. **Impedance report:** will a test coupon and report come with the boards, and at
   what cost?
6. **Vias covered from the back (ten, listed above):** confirm they are tented,
   not left open by a default.
7. **Is the 0.56 / 0.3 mm via (0.13 mm annular ring) inside your normal process?**
   Same for the 0.3 mm drill generally.
8. **Resin-filled and capped vias for the whole board: the price difference** for 5
   boards (ruling BD). Operator decides.
9. **Assembly, U3 and Y1 only:** setup / engineering fee; stencil fee and whether
   one-sided; placement fee for 2 positions x 5; **X-ray of the QFN's exposed pad,
   included or charged**; part cost as you charge it and the spare quantity you add;
   whether you accept **LCSC C2802072** for U3 (say so before ordering if you cannot);
   assembly and sourcing lead time per part; shipping; any partial-assembly or
   minimum-order surcharge. Also: does the board need rails, tabs or a panel for the
   machine (it has none), and will it be delivered as single boards?
10. **Placement preview and CPL format: a hard gate before I pay.** Send me the
    preview of U3 and Y1 on the board **before** I pay, with U3's pin 1 at the lower
    right and the pads of Y1 matched, and wait for my confirmation. Also tell me, for
    this CPL, whether you accept: (a) the rotation convention (KiCad's, counter-clockwise
    from the library pose); (b) the `Layer` value `Top`, or do you need `T` / `Top` /
    `TopLayer`; (c) Mid X and Mid Y as plain millimetre numbers **without** a unit
    suffix; (d) a **negative** Mid Y and an origin that is the page origin, not the
    board's corner (positions from the lower-left corner are in the table above); (e)
    the columns Designator, Val, Package, Mid X, Mid Y, Rotation, Layer, in that
    order; or send me your template.
11. **Surface finish:** ENIG is ruled (ruling CA) and goes on the order form. Confirm
    that your ENIG is available for this build (4 layers, 1.6 mm, 5 pieces, 0.15 mm
    necks) and give the price against lead-free HASL, for the record only.

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
* **PCBWay's answers** to the eleven questions, and the quote. **The placement
  preview (Question 10) is a gate: no payment before the operator has seen it.**
* **Decisions** for the operator: resin-filled vias (ruling BD), U3 bought by PCBWay
  or consigned, Y1 from DigiKey or Mouser. The surface finish is no longer one: it
  is ENIG (ruling CA).
* **The first-build measurements** in `fabrication-note.md`, including U3's case
  temperature: U3 has an estimate (about 82 to 88 C junction at 70 C ambient and
  typical load) built on an assumed theta-JA, not an assessment.
