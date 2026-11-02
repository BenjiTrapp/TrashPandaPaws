# raccoon-tap — placement baseline (task 8, round 3, 2026-11-02)

The board after `tools/gen_pcb.py` was last run on it: U3 turned, every part
from tasks 5 to 7 placed, mounting added, the power plane split. Task 9 routes
this board and freezes the geometry; nothing here is routed. Later review runs
compare against this directory. `../2026-10-31-baseline/` describes a board that
no longer exists (33 footprints, U3 at 0 degrees, none of tasks 5 to 7).

This replaces the earlier baselines of this task. What rounds 2 and 3 changed is
in "Rounds 2 and 3" at the end.

Measured design state (SHA-256 of the analysed files):

| File | SHA-256 |
|---|---|
| `hardware/kicad/raccoon-tap.kicad_sch` | `344164db00edf4910d6972afe34defc89f81067478801e28a34b6adfbe9f0720` |
| `hardware/kicad/raccoon-tap.kicad_pcb` | `e069ec37855ef34e7bc33985ca5f9187cf6d910df11b600575233fe471f77c0f` |

![top side](placement-top.png)

The bottom side carries no parts, so there is no bottom picture.

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
| round 2, final: C25/R13 and U8 moved, U9 declared as a flow-through, the new U3 rule | 0 | 46 | 164 |
| round 3: J2 pins 7 to 10 re-netted (ruling AQ), board and schematic regenerated | **0** | **46** | **164** |

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

## The MDI pair order (rulings AJ-revised, AM and AQ)

**The problem.** U3's pins and J2's pins both run counter-clockwise round their
package, so two parts that face each other present the pairs in opposite order:
U3's east edge reads MDI3, MDI2, MDI1, MDI0 from north to south, J2's pin row
MDI0 to MDI3. Every rotation of both parts reverses it. J2's pins are
through-hole, so a track reaches them from either face, and that is what the
route below uses.

**Which re-assignments are legal** (ruling AJ, revised; [RTL-DS] Table 4,
section 5.4): MDI0 is BI_DA and MDI1 is BI_DB, the 10/100 pairs, so they must
stay on cable pairs A and B (auto-negotiation and every 10/100 frame run on
them). MDI2 is BI_DC and MDI3 is BI_DD, and in crossover mode the PHY exchanges
them with each other. Legal: exchange MDI0 with MDI1, exchange MDI2 with MDI3,
turn the polarity of any pair; nothing across the A/B - C/D boundary.

**What the netlist now says (ruling AQ, variant X).** MDI2 and MDI3 are
exchanged on J2 and both turned. Cable pair identity comes from J2's pin notes
in `netlist.yaml` (`pair n -> cable J<k>`, k the RJ45 pin, [LPJG] sheet 1/2);
cable pairs are the 1000BASE-T ones: A = RJ45 1/2, B = 3/6, C = 4/5, D = 7/8.

| J2 pin | RJ45 pin | Cable pair | Before | After |
|---|---|---|---|---|
| 1 | 1 | A | MDI0_P | MDI0_P |
| 2 | 2 | A | MDI0_N | MDI0_N |
| 3 | 3 | B | MDI1_P | MDI1_P |
| 4 | 6 | B | MDI1_N | MDI1_N |
| 7 | 4 | C | MDI2_P | **MDI3_N** |
| 8 | 5 | C | MDI2_N | **MDI3_P** |
| 9 | 7 | D | MDI3_P | **MDI2_N** |
| 10 | 8 | D | MDI3_N | **MDI2_P** |

**Why it stays inside C/D.** Five independent pieces of evidence:

1. Pins 1 to 4 are not touched; only pins 7 to 10 change, and pins 7 to 10 reach
   RJ45 pins 4, 5, 7 and 8, which are cable pairs C and D.
2. After the change pins 7 to 10 still carry exactly MDI2 and MDI3 (two nets of
   each), and pins 1 to 4 exactly MDI0 and MDI1. No MDI net moved group.
3. Each MDI pair is whole on one cable pair (MDI3 on C, MDI2 on D) and the four
   pairs use A, B, C and D once each.
4. `mdi_group_problems` in `hardware/tests/check_fab_release.py` computes this
   from the netlist (its pin-to-RJ45 table is read from the J2 pin notes) on every
   run, and has mutation tests: moving one net, or one whole pair, across the
   boundary is reported; a pair split over two cable pairs is reported; the legal
   exchanges and polarity changes pass.
5. `scratch_route_check.py` prints the table above from the board's own pad nets
   and fails if an MDI net is outside its group.

The datasheet does not say whether the PHY detects the C/D exchange independently
of A/B. A first-build check is recorded in `netlist.yaml`
`design_notes.mdi_pair_mapping`: link at 1000 Mb/s with a straight cable and with
a crossover cable.

**The route (ruling AM), shown to fit with the nets as committed.** MDI0 and
MDI1 go east, pass under J2's pin 10, through the gap between pin 9 and the
shield pad SH1, up the channel between the pin columns and the T-posts, and into
pins 1 to 4 from the east; the north-going lane is the outer one, so the pairs
peel off in order. West-column pins are reached between two east-column pins.
MDI3 and MDI2 come from the west, MDI3 to pins 7/8 and MDI2 to pins 9/10, and no
longer cross. Dimensions (J2 at rotation 90, origin 47.3 / 18.0):

| | |
|---|---|
| gap between pin 9's pad and SH1 | 2.71 mm (the two lanes need 2.14) |
| channel, pin column to T-post | 3.97 mm |
| strip south of pin 10 | y 24.7 to 27.5 mm, free of parts |
| `C25` / `R13` | at y 29.9 mm to keep that strip free |

`scratch_route_check.py` lays SuperSpeed, USB 2.0 and all four MDI pairs on a
copy of the board and runs the DRC with the project's rules: 0 violations, no
signal net left unconnected, 0 vias in the MDI pairs, 0.63 mm between the two
wrapped pairs. Straight ratsnest lines are only an indicator (27 crossings with
the original netlist, 20 now, 16 at best for any legal assignment, 0 with J2
mirrored); the routed picture has none.

**Why not the alternatives** (ruling AQ): variant Y (MDI0 to MDI2 round the
south end, three lanes) leaves 0.21 mm between pairs against the 0.37 to 0.56 mm
of the stackup note; a dip through the bottom layer costs 4 vias and puts a
100 ohm pair over In2 (power), breaking the rule that In1 is never broken under a
pair; J2 on the bottom side and a tab-down jack were not chosen (mechanics).

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
U3. All three are still reported. `check_fab_release.py` now holds the rule in
place (`u3_track_rule_problems`): it must exist, its condition must be exactly
tracks against pads of U3 with no net or net-class restriction (so both
directions stay covered, and vias, zones and other footprints stay out), and its
minimum must be exactly 0.2 mm. Mutation tests: missing rule, scope widened to
vias or other item types, scope widened to another footprint, a net or class
restriction added to either side, minimum 0.1, 0.15 or 0.3.

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

1. **MDI:** MDI0 and MDI1 round the south end of J2's pin field and in from the
   east (outer lane to the northernmost pins); MDI3 and MDI2 from the west to pins
   7/8 and 9/10. Do not re-assign MDI nets across the A/B - C/D boundary. If the
   route proves unworkable the controller's fallback is the MDI2/3 group diving
   under the other (8 vias), which puts a 100 ohm pair over In2: judge it
   against `netlist.yaml` `stackup.rules`.
2. **Keep clear on F.Cu**: the south strip (y 24.7 to 27.5, x 31 to 40), the
   gap between J2 pin 9 and SH1, the channel x 41.7 to 45.7 up to y 12, the
   corridor between U3 and J2, the USB lane band (x 6.5 to 26.2, y 13.4 to 19.6
   and the RX approach at y 20 to 22), the crystal channel (x 23.3 to 24.7,
   y 25.7 to 29.6), U9's channel.
3. **The necks** are at most 0.15 mm wide for at most 1.0 mm from the pad
   centre; 0.6 mm clears every clearance the 0.2 mm class asks for in the
   scratch run. The rule "track to U3 pad on fine-pitch parts" (0.2 mm,
   tracks, U3 only) is what lets a track leave a pad next to a supply pad; keep
   it, it is checked.
4. **U9:** D- through the channel (0.2 mm line, 0.375 mm each side); keep the
   channel free of everything else; a GND trace from U9 pin 2 to J3's pad 7 along
   y = 18; VBUS via east of pin 5; U9 has jumper pad groups, so D+ needs no
   copper between pins 1 and 6.
5. **USB 2.0:** four vias, the pair on the bottom layer from x 12.2 to x 21.5.
   That layer's reference is In2 (power): short, 480 Mbit/s, but it is a pair over
   a power plane too; judge it.
6. **U8 is a tee** with short stubs; TX_P and RX_N sit 0.8 mm apart in its
   channel; about 5 mm of each pair is open. These are to be judged, not just
   cleared.
7. **TP6 and TP7** are 18 to 21 mm from the pins they probe (the bottom edge is
   the only place they fit); low-speed, a long thin trace is fine.
8. **First build:** 1000 Mb/s link with a straight and a crossover cable (the
   C/D exchange).

## Rounds 2 and 3 (what changed from the first baseline)

| Finding | Done |
|---|---|
| R2 F-1 MDI order (AJ withdrawn, AM adopted) | README corrected; the A/B route round the south end shown with the scratch run; the wrong "pair assignment is not critical" sentence in `netlist.yaml` corrected |
| R3 ruling AQ, variant X | `netlist.yaml` nets of MDI2/MDI3 re-netted on J2 pins 7 to 10; schematic, BOM and PCB regenerated; before/after table and the C/D proof above; `mdi_group_problems` and its tests in `check_fab_release.py` |
| R2 F-2 Power clearance at U3 | the rule, verified on 14 escapes plus three controls; R3: tested in `check_fab_release.py` |
| R2 F-3 board back to 58 mm | outline 58 x 36, holes at (54.5, 3.5) and (54.5, 32.5), slots and the strain-relief claim dropped |
| R2 F-4 C21 to the top side | (34.4, 18.0), 3.3 mm from pin 6 |
| R2 F-5 U8 | recorded as clearance-only; U8 moved 3 mm nearer J3 |
| R2 U9 channel | verified in DS4260, made possible, footprint with jumper pad groups |
| R2 provenance of the U8 span | the "3.33" now says it was read from a drawing that prints "0.33" |

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
