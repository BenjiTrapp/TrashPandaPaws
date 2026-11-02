# raccoon-tap — placement baseline (task 8, round 2, 2026-11-02)

The board after `tools/gen_pcb.py` was last run on it: U3 turned, every part
from tasks 5 to 7 placed, mounting added, the power plane split. Task 9 routes
this board and freezes the geometry; nothing here is routed. Later review runs
compare against this directory. `../2026-10-31-baseline/` describes a board that
no longer exists (33 footprints, U3 at 0 degrees, none of tasks 5 to 7).

This replaces the first-round baseline (58 -> 70 mm board, slots, C21 on the
bottom, 3.33 mm and all). What round 2 changed is in "Round 2" at the end.

Measured design state (SHA-256 of the analysed files):

| File | SHA-256 |
|---|---|
| `hardware/kicad/raccoon-tap.kicad_sch` | `d1bfd3ce4d9a49d1bad106be4983fa513651d9c52070a235f994bc6900d93151` |
| `hardware/kicad/raccoon-tap.kicad_pcb` | `d0d7dea15b8fea4d5a74c3829d954be61f2fca984d964c41e62fc95be05e12d2` |

![top side](placement-top.png)

`placement-bottom.png` is the bottom side: nothing on it now.

## Measured state

| Metric | Baseline (2026-10-31) | Now | Source |
|---|---|---|---|
| Footprints | 33 | 58 (all placed, none parked) | `pcb.json` |
| Board | 58 x 36 mm | **58 x 36 mm** | |
| DRC errors | 0 | **0** | `drc.rpt` |
| DRC warnings | 43 | 46 (36 `via_dangling`, 7 `silk_over_copper`, 3 `silk_overlap`) | `drc.rpt` |
| Unconnected items | 134 | 164 | `drc.rpt`; nothing is routed |
| DRC errors, zones refilled | not measured | **0** (23 warnings: those 10 silk plus 13 `isolated_copper`, the In2 islands have no vias yet; 129 unconnected) | `kicad-cli pcb drc --refill-zones` |
| ERC | 0 / 0 | 0 / 0 | `erc.rpt` |
| `check_kicad.py` | 23 failures on the stale PCB | passes | |
| U3 decoupling distance (cap to nearest U3 pad centre) | 3.56 to 7.63 mm | 1.33 to 3.57 mm | `pcb.json` |
| Buck switching loop (U6, L2, C3) | 7.9 mm2 | 7.9 mm2 | `pcb.json` |
| Hottest part | U4, 69.8 C | U4, 67.5 C | `thermal.json` |
| EMC score | 76.0 | 50.5, see below | `emc.json` |
| Zones | 3 | 17: 9 copper (In1 and bottom GND, six In2 islands, the U4 patch), 8 keepout rule areas (four per mounting hole) | `pcb.json` |

DRC progression (every change measured, per the `OPEN_QUESTIONS.md` 263-to-269
lesson):

| Run | Errors | Warnings | Unconnected |
|---|---|---|---|
| HEAD board before task 8 (stale) | 0 | 43 | 134 |
| round 1: first full placement | 3 | 53 | |
| round 1, final | 0 | 47 | 170 |
| round 2: 58 mm board, holes at 54.5, slots dropped, C21 on top | 0 | 46 | 166 |
| round 2, final: C25/R13 and U8 moved, U9 declared as a flow-through, the new U3 rule | **0** | **46** | **164** |

EMC score: 50.5 from 76.0 because the new parts are unrouted and read as ICs
by the analyzer, not because placement got worse. Four errors: `DC-001` on U8
and on U9 (it reads the two passive ESD arrays as ICs wanting a decoupling cap,
and takes C22 for U8's; the known false positive of ruling Z), `ES-002` (no GND
via by U9: there are no vias yet), `IO-001` (no filter at J2; the magnetics are
the filter, as in the baseline). Moving U8 3 mm nearer J3 made the U8 `DC-001`
worse (C22 is now 9.4 mm away) and removed `ES-001` on U9.
`PM-002` also flags J2 (courtyard 0.06 mm inside the edge, which is what a jack
at the edge is) and J3 (the plug overhangs 15.8 mm), both intended.

## U3 turned to 180 degrees

At 0 degrees the MDI pins 1 to 10 were on U3's left edge, facing the USB plug.
At 180 they are on the right edge and face J2 across an open corridor
(U3 pad edge x = 26.9 mm, first J2 pin centre x = 38.4 mm). The SuperSpeed and
USB 2.0 pins 12 to 19 are on the top edge, the supply pins on the left, the
crystal pins 35/36 on the bottom. The MDI pairs no longer wrap round the package
or cross the SuperSpeed fan-out. Y1, C19, C20, R14 and the decoupling ring moved
with it.

## The MDI pair order (rulings AJ-revised and AM)

**The problem.** U3's pins and J2's pins both run counter-clockwise round their
package, so two parts that face each other present the pairs in opposite order:
U3's east edge reads MDI3, MDI2, MDI1, MDI0 from north to south, J2's pin row
MDI0 to MDI3. Every rotation of both parts reverses it. `scratch_route_check.py`
counts crossings of straight lines from U3's eight MDI signal pads to J2's pins:

```
as the netlist has it, as placed:                  27 of 28 pin pairs cross
best legal re-assignment, straight lines:          16
J2 on the bottom side (not chosen):                 0
```

Which re-assignments are legal (ruling AJ, revised, from [RTL-DS] Table 4
section 5.4): MDI0 and MDI1 are the 10/100 pair (BI_DA, BI_DB), so MDI0 with
MDI1 may exchange, MDI2 with MDI3 may exchange, and the polarity of any pair may
turn. The two groups cannot trade places. The first round's claim that a single
layer cannot do this was wrong: the pins of J2 are through-hole and reachable
from either face, and the pairs can go round the end of the pin field.

**The route (ruling AM), shown to fit.** MDI0 and MDI1, the southern pair at U3,
go east, pass under J2's pin 10, through the gap between pin 9 and the shield
pad SH1, up the channel between J2's pin columns and its T-posts, and into pins
1 to 4 from the east; the north-going lane is the outer one, so the pairs peel
off in order and nothing crosses. Pins on the west column are reached between
two east-column pins. Dimensions (`J2` at rotation 90, origin 47.3 / 18.0):

| | |
|---|---|
| gap between pin 9's pad and SH1 | 2.71 mm (two pairs need 2.14, three 2.5) |
| channel, pin column to T-post | 3.97 mm |
| strip south of pin 10 | y 24.7 to 27.5 mm, free of parts |
| `C25` / `R13` | moved to y 29.9 mm to keep that strip free |

`scratch_route_check.py` lays it on a copy of the board and runs the DRC with
the project's rules. The run is clean (0 violations, 0 vias) in the three cases
below. In the first the netlist is as it is; the others change nets on the
scratch copy only (`netlist.yaml` is unchanged):

| | MDI0, MDI1 | MDI2, MDI3 | Needs |
|---|---|---|---|
| base | round the south end, from the east | not drawn: they reverse each other | nothing |
| **X** | round the south end | from the west, planar | J2 pins 7 to 10 re-netted: 7 = MDI3_N, 8 = MDI3_P, 9 = MDI2_N, 10 = MDI2_P (exchange and polarity, both legal) |
| **Y** | MDI0, MDI1 and MDI2 round the south end (three lanes) | MDI3 from the west | J2 pin 9 = MDI3_N, pin 10 = MDI3_P (polarity only) |

X has the margin: two lanes in a gap that needs 2.14 of 2.71 mm, pair spacing
0.63 mm. Y changes two pad nets instead of four but sends three lanes through the
gap with 0.21 mm between pairs (the stackup note asks 0.37 to 0.56 mm). **I
applied neither:** which freedom to use is the controller's, and it changes
`netlist.yaml`. After that edit the schematic is regenerated and the PCB's pad
nets follow with KiCad's Update PCB from Schematic (nothing is routed, so
nothing is lost).

**Without any netlist change** MDI0/MDI1 still go round the south end; the
MDI2/MDI3 pair order is then fixed by one pair dipping to the bottom layer
(4 vias), or, the controller's fallback, the MDI2/3 group diving under the
other (8 vias). Not routed.

**Not chosen:** J2 on the bottom side (0 crossings, but the jack then hangs
13.45 mm under the board, a mechanical decision) and a tab-down jack variant.

## Mounting

* **H1 and H2**, plated M2.5 holes (2.7 mm drill, 5.4 mm pad tied to GND) at
  (54.5, 3.5) and (54.5, 32.5), the corners furthest from the USB plug, 3.5 mm
  from both edges (the Pi 4's own edge distance), 6.5 mm outside J2's y 10 to
  26 span. A keepout ring (r 3.02 to 3.9 mm; no tracks, vias or parts, pour
  allowed) clears the screw head. They are `bom: false` components in
  `netlist.yaml` so that `check_kicad.py`'s "exactly the netlist's components"
  holds.
* **The cable-tie slots are gone, and so is the 70 mm tail.** The slots were
  4.5 to 7.9 mm beyond the jack's face, about where the plug body still is, not
  the boot, and with a tab-up jack a tie there is likely to bear on the latch.
  Showing that a tie works needs the J2 and RJ45 plug drawings, which are not in
  the repository, so no strain relief that touches the cable is claimed. What
  is there: the two screws sit 3.2 mm behind the jack's front face and 6.5 mm outside
  its width, so the pull on the cable goes into whatever the board is screwed
  to. Growth was
  released for the impedance geometry (spec 11.8), not for a mechanical tail.
* **Alignment with the Pi 4 is not achievable as written.** The Pi's holes are
  58 x 49 mm apart and all inside its 85 x 56 mm outline; this board hangs past
  the Pi's USB edge. What is aligned is the convention: M2.5, 3.5 mm from the
  edges. A 49 mm pitch would need a 56 mm tall board.
* **Lower port, tab down:** nothing on the PCB changes.

## U8, C22 and C23: the fit is clearance-only

`scratch_route_check.py` shows the SuperSpeed lanes clear every neighbour at the
rules in force. **That is all it shows.** It says nothing about impedance,
crosstalk or return paths:

* About 5 mm of each SuperSpeed pair is open (1.5 to 2 mm apart) round U8, and
  TX_P and RX_N run 0.8 mm apart, centre to centre (0.6 mm edge to edge), side by
  side through U8's 2.5 mm channel: the transmit line next to the receive line.
  The pad arrangement of a four-line SOT-23-6 forces both, and I found no
  placement that removes either. The effect of the discontinuities at 5 Gbit/s,
  and the crosstalk, are not modelled.
* **U8 is 3 mm nearer J3 than in round 1:** x 15.6 mm, 10.6 mm from J3's pad
  centres (was 13.6). The pairs are coupled between J3 and U8, so the shorter run
  mainly puts the ESD part nearer the connector; the open stretch round U8 is
  the same. Further west the TX_P line's descent into the channel runs into the
  USB 2.0 dive via at (12.2, 16.2).
* The footprint is `raccoon:SOT-23-6_SP3019_LittelfuseLand`, Littelfuse's own
  land pattern (datasheet page 5): pads 0.60 x 0.85 mm at 0.95 mm pitch, 3.33 mm
  overall (the drawing prints the span as "0.33", a digit cut off; read as 3.33,
  the only reading that fits the package table's 2.60 to 3.00 mm lead span with
  0.85 mm pads). KiCad's own SOT-23-6 leaves a 0.95 mm channel, which two lines
  of different pairs do not fit; this leaves 1.63 mm. It was checked against the
  drawing by the reviewer.
* C22 and C23 are vertical at 1.05 mm pitch, not the 0.82 mm of the note: the
  courtyard rule (an error) needs 1.0 mm between two vertical 0402s. They sit
  3.3 mm from U3's TX pads and do not lengthen the 0.6 mm neck.

## U9: D- through the channel (verified against DS4260)

[DS4260] page 1 (functional diagram) names pins 1 and 6 both I/O1 and pins 3 and
4 both I/O2; Figure 15 (PSpice model) draws each cell as in, then a series
resistor and inductor (0.11 ohm, 0.75 nH), the diode node, then out: one node
with a 1.5 nH series path between the two pins. So a line may enter on one pin
and leave on the other, or use the pad pair as the bridge.

The placement uses it. D+ goes in at pin 1 and out at pin 6. D- goes in at pin 3
and **north through the 0.95 mm channel between the two pad columns**, passing
between pins 2 and 5: 0.375 mm of clearance each side for a 0.20 mm line, against
the 0.30 mm of the Power class to GND (pin 2) and VBUS (pin 5). It comes out
north of D+, which is the order U3's pins need (D- above D+ when the pair turns
west), so the polarity reversal costs no via. Pin 4 joins by a 0.5 mm stub. The
scratch run is clean with this. The D-versus-RX crossing remains: four vias (two
at (12.2, 16.2) and (12.2, 17.1), two near U3 at (21.5, 19.75) and (22.4, 19.1)),
the pair on the bottom layer between. Total on the pair: 4, down from about 6.

The copper cannot link pins 1 and 6 for D+ (the channel is D-'s), so KiCad
would show them as an unconnected pair for ever. U9 therefore has its own
footprint, `raccoon:SOT-23-6_USBLC6-2`: KiCad's SOT-23-6 with
`(jumper_pad_groups ("1" "6") ("3" "4"))`, which tells the connectivity engine
the pads are one node. (Round 1 had the same unconnected pair.)

## The Power-class clearance at U3 (ruling AN)

U3's pads are on a 0.40 mm pitch: a track leaving a pad passes 0.20 mm from the
next pad (0.225 mm for a 0.15 mm neck), and the Power class asks 0.30 mm of
anything on a supply or GND item. `raccoon-tap.kicad_dru` now has

```
(rule "track to U3 pad on fine-pitch parts"
	(condition "A.Type == 'Track' && B.Type == 'Pad' && B.memberOfFootprint('U3')")
	(constraint clearance (min 0.2mm)))
```

0.2 mm is the signal classes' own clearance, so no track gets nearer than a
signal track already was (rulings AG and AI stand). It names tracks and U3 only,
so vias, zones and every other footprint, U8 and U9 included, keep the class
clearance; it covers a signal track against a supply pad and a supply escape
against a signal pad alike. Measured in the scratch run on the escapes of the 14
U3 signal pads: **16 violations without the rule, 0 with it**, and three
controls the rule must not clear: a track 0.19 mm from a U3 pad, a track
0.25 mm from a +1V0 pad of another footprint, a via 0.25 mm from a +1V0 pad of
U3. All three are still reported.

## Other placement work

* **Decoupling:** west column of 0402s at x = 19.75 mm, C8 (0603) on pin 20, C7
  and C13 at the north-east corner, C15, C14, C9 and C12 along the bottom either
  side of the crystal channel. C16 (pins 14 and 19, no free side) in a second
  column. C12 and C13 (AVDD10 pins 3 and 8, between MDI pairs) cannot be nearer.
* **C21** on the top side at (34.4, 18.0): the 5 mm gap west of J2's pin 6
  (MDI0/1 come in from the east, MDI2/3 at y 19.9 and below). J2's courtyard
  starts at x 36.1 and keeps it 3.3 mm from the pin; in round 1 it was 1.5 mm
  away on the bottom side, which would have meant double-sided assembly or hand
  soldering on a side with no fiducials.
* **J2** turned so the opening faces the right-hand edge, front face 0.35 mm
  inside it.
* **Buck:** U6 above U3. C3 2.7 mm under the IN pin. R5/R6 4 to 5 mm from LX and
  L2; the FB trace runs away from the switch node.
* **U4:** GND copper patch on F.Cu, 8.2 x 5.7 mm, joined to pin 2 without thermal
  relief, six vias to In1 and the bottom pour.
* **In2:** six islands: +5V (J3 and U7 corner), +5V_SW twice (a strip on the left,
  the buck's input), +1V0 (above U3), +3V3 twice (below and east of U3, the
  corridor; and R8's corner). A pre-partition: U3's pins that want +1V0 and
  +3V3 alternate round the package, so some connections will be surface tracks.
* **U3's thermal vias:** 3 x 3, tented from the back.
* **Y1:** `Crystal_SMD_3225-4Pin_3.2x2.5mm_HandSoldering`, pads 2.1 x 1.8 mm
  (ruling AC).
* **DNP:** R12 and C24 carry `dnp`, `exclude_from_pos_files` and
  `exclude_from_bom`; test pads, jumpers, holes and fiducials carry the two
  exclusions. `kicad-cli pcb export pos --smd-only` lists 41 parts, neither R12
  nor C24, and lists U3 and Y1. `check_pcb_fitting` in `check_kicad.py` keeps it
  so.
* **Three fiducials** (FID1 to FID3) at (2.5, 2.5), (2.5, 33.5), (47.0, 33.5).

## For task 9

1. **Settle the MDI2/MDI3 order**: variant X, variant Y, or the 4-via dip. X and
   Y are netlist edits (above); the A/B route round the south end is the same
   either way.
2. **Keep clear on F.Cu**: the south strip (y 24.7 to 27.5, x 31 to 40), the
   gap between J2 pin 9 and SH1, the channel x 41.7 to 45.7 up to y 12, the
   corridor between U3 and J2, the USB lane band (x 6.5 to 26.2, y 13.4 to 19.6
   and the RX approach at y 20 to 22), the crystal channel (x 23.3 to 24.7,
   y 25.7 to 29.6), U9's channel.
3. **The necks** are at most 0.15 mm wide for at most 1.0 mm from the pad
   centre; 0.6 mm clears every clearance the 0.2 mm class asks for in the scratch
   run, and the placement does not make any neck longer (the nearest feature to
   a U3 signal pad is 3.3 mm away).
4. **U9:** D- through the channel (0.2 mm line, 0.375 mm each side); keep the
   channel free of everything else; a GND trace from U9 pin 2 to J3's pad 7 along
   y = 18; VBUS via east of pin 5.
5. **USB 2.0:** four vias, the pair on the bottom layer from x 12.2 to x 21.5.
6. **U8 is a tee** with short stubs; TX_P and RX_N sit 0.8 mm apart in its
   channel; the open stretch is about 5 mm. These are to be judged, not just
   cleared.
7. **TP6 and TP7** are 18 to 21 mm from the pins they probe (the bottom edge is
   the only place they fit); low-speed, a long thin trace is fine.

## Round 2 (what changed from the first baseline)

| Finding | Done |
|---|---|
| F-1 MDI order, AJ withdrawn, AM adopted | README corrected; the planar route shown with the scratch run; two netlist variants recorded; the wrong "pair assignment is not critical" sentence in `netlist.yaml` `design_notes.mdi_pair_mapping` corrected |
| F-2 Power clearance at U3 | the rule above, verified on 14 escapes plus three controls |
| F-3 board back to 58 mm | outline 58 x 36, holes at (54.5, 3.5) and (54.5, 32.5), slots and the strain-relief claim dropped |
| F-4 C21 to the top side | (34.4, 18.0), 3.3 mm from pin 6 |
| F-5 U8 fit | recorded as clearance-only; U8 moved 3 mm nearer J3 |
| U9 channel | verified in DS4260, made possible, footprint with jumper pad groups |
| provenance of the U8 span | "3.33" now says it was read from a drawing that prints "0.33" |

## Files

| File | |
|---|---|
| `drc.rpt` | `kicad-cli pcb drc --severity-all` |
| `erc.rpt` | `kicad-cli sch erc --severity-all` |
| `schematic.json`, `pcb.json`, `cross.json`, `emc.json`, `thermal.json`, `capability_mode.json` | kicad-happy, the commands of the baseline README |
| `scratch_route_check.py` | the clearance run described above |
| `placement-top.png`, `placement-bottom.png` | the board |

Reproducing, from the repository root:

```sh
KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
KH=/opt/homebrew/bin/python3.12
R=hardware/review/2026-10-31-placement
S=vendor/kicad-happy/skills
$KIPY hardware/tools/gen_pcb.py
kicad-cli pcb drc --severity-all --output $R/drc.rpt hardware/kicad/raccoon-tap.kicad_pcb
kicad-cli sch erc --severity-all --output $R/erc.rpt hardware/kicad/raccoon-tap.kicad_sch
$KH $S/kicad/scripts/analyze_schematic.py hardware/kicad/raccoon-tap.kicad_sch --output $R/schematic.json
$KH $S/kicad/scripts/analyze_pcb.py hardware/kicad/raccoon-tap.kicad_pcb --full --schematic $R/schematic.json --stage layout --output $R/pcb.json
$KH $S/kicad/scripts/cross_analysis.py -s $R/schematic.json -p $R/pcb.json --output $R/cross.json
$KH $S/emc/scripts/analyze_emc.py -s $R/schematic.json -p $R/pcb.json --output $R/emc.json
$KH $S/kicad/scripts/analyze_thermal.py -s $R/schematic.json -p $R/pcb.json --output $R/thermal.json
$KIPY $R/scratch_route_check.py
python3 hardware/tests/check_kicad.py -v
```

`gen_pcb.py` assigns fresh UUIDs and visits the footprints in a different order
on every run, so regenerating gives a different file (same geometry, same nets).
These reports were taken from the committed board.
