# raccoon-tap — findings accepted at task 10 (2026-11-03)

Every finding of the verification chain that was not fixed, with the reason.
Nothing here was made to disappear by loosening a rule: no clearance, class,
DRC rule or test threshold was changed in this task. Two groups: **A**, what
the two new ruling-BJ checks in `tests/check_fab_release.py` measure and
accept, and **B**, what the tools report.

One finding was fixed instead of accepted: the board had **no name and no
revision** on silkscreen or in its title block (found by the baseline of task 2
and by `fab_release_gate.py`, never fixed). `tools/amend_pcb.py silk_id`
(stage `silk_id` of `route_pcb.py`, so a rebuild reproduces it) put
`RACCOON TAP` and `REV 2.1-DRAFT` on `F.SilkS` in the free corner at the top
left and filled the PCB title block. The DRC gained no warning from it.

Measurements below are from `check_fab_release.py`'s probe of the committed
board (path length of a pair net outside the ±10 % differential-impedance
window, using the gap to the partner's tracks, pads and vias on the same
layer; window 81–99 Ω USB, 90–110 Ω MDI, PCBWay formula less the 8 Ω mask
offset). "As-built" means no ruling gives a figure; the committed cap only
stops it getting worse.

## A. Coupling and In1 reference (ruling BJ)

### A1 U8 straddle: TX_CONN has a granted concession of 8.0 mm of path (ruling BV)

Region `U8 straddle`. **TX_CONN: 7.99 mm (P) and 6.68 mm (N) of path** outside
the window (6.2 mm of straight-line extent, task 9 re-review M3). Ruling AS
granted "about 5 mm" as extent; ruling BV (which corrects BS's 6.5 mm) sets the
TX_CONN cap at **8.0 mm of path length**, because the conductor length, not
the extent, makes the discontinuity. The cap in `COUPLING_REGIONS` is 8.0 mm
for both nets, `kind: granted`, and the margin on TX_CONN_P is 0.01 mm.

**This is a granted concession under reservation, not an engineering target.**
The straddle is forced by U8's SOT-23-6 pad rows, and TX has no EMC iterations
left; TX_CONN's tee leaves the line 0.5-0.7 mm beyond the pads on each side
(RX tees straight at the pad), so roughly 1 mm could be recovered by re-laying
it, which is a routing change on a frozen, reviewed board and was not made.

*Verification and fall-back:* the SuperSpeed first-build check is the
verification of this concession (`lsusb -t` at 5000M, `iperf3` bidirectional
30 min at 940 Mbit/s, `dmesg` free of xHCI link errors and of a fall-back to
USB 2.0; it is also in `hardware/fab/fabrication-note.md`). **If the link
proves marginal, U8's package is the first thing to change** (a part whose pad
rows do not force the pair apart), not the pair routing.

RX at the same place: 5.31 / 5.52 mm of path against a ratchet cap of 6.0 mm
(ruling AS granted about 5 mm of extent; the 1.0 mm on top is the
implementer's allowance for path against extent and is not granted, so it is a
ratchet, A6).

### A2 U8 channel spacing between TX and RX is 0.505 mm, not 0.8 mm

Not a coupling figure, so the check does not hold it. Ruling AS was argued with
0.8 mm (4.3 h). After ruling BK moved RX_N 0.095 mm north it is 0.505 mm (2.7 h)
over 2.4 mm (x 114.65–117.09), still inside the 2–3 h of the stackup note, in
the strong-TX / weak-RX direction. The first-build check of AS covers it.

### A3 USB 2.0: about half of each net is outside the impedance window

Regions `USB 2.0 J3 to U9 crossover` (D− 10.64 mm, D+ 4.26 mm), `USB 2.0 skew
meander` (D+ 4.33 mm, on B.Cu) and `USB 2.0 layer change at U3` (0.93 / 0.74
mm). In the window: D+ 54 %, D− 51 %. As-built: no ruling quantifies it.

Why it is there: J3's D+/D− pins are 2 mm apart, so the pair spreads 1.75 mm
until it can converge; U9 is a flow-through ESD array and D+/D− cannot be
swapped, so the pair crosses between J3 and U9 (task 8); the skew meander is
what matches D+ to D− (see B-DP-001). Why it is accepted: USB 2.0 high speed
has a 500 ps minimum rise time, so 10 mm (about 60 ps) of 114 Ω line against
90 Ω is a lumped bump of reflection coefficient 0.12 that the receiver does
not resolve; ruling AR already accepted this pair for the B.Cu stretch over
In2 on the same ground. Cost if wrong: a USB 2.0 port that falls back to full
speed. First-build check: plug into a USB 2.0-only port, `lsusb -t` must show
480M, no resets in `dmesg` over 30 min of `iperf3`.

### A4 MDI: the lead-in to J2's pin columns is outside the window for 2–6.6 mm per net

Region `J2 pin lead-in`: MDI0 5.25 / 4.15 mm (N / P), MDI1 3.94 / 2.84,
MDI2 6.61 / 4.59, MDI3 4.00 / 1.97. In the window overall: MDI0 83 / 86 %,
MDI1 84 / 88 %, MDI2 50 / 58 %, MDI3 70 / 80 %. As-built: rulings AM / AQ chose
the planar route under the jack and none quantifies the spread of the pair onto
two pins 2.5 mm apart. Accepted with ruling AX's reasoning: 1000BASE-T runs at
125 MBd, the PHY cancels NEXT across pairs, and the lead-in is 7–11 % of the
lane. MDI2 is the weakest pair (50 % / 58 %): its two tracks run 1.1–2.0 mm apart
over x 34–41 to reach pins 9 and 10, which stand in two rows 2.54 mm apart. First-build check (ruling AX): link stable at 1000 Mbit/s under load,
`ethtool -S` error counters flat; with a straight and a crossover cable
(`netlist.yaml` `mdi_group` note).

### A5 In1 reference: named exceptions by position, no unexplained gap

Under every pair track on F.Cu, centre line and both edges every 0.02 mm, after
refilling the zones, there is **no point without In1 ground except**:

* each MDI track's own J2 pin: In1 has to leave a hole round the through-hole
  pin (1.04–1.18 mm along the track);
* each USB 2.0 track's own layer-change via (ruling AR), 0.5–0.7 mm per via,
  **only the four vias at (12.2, 16.2), (20.8, 18.75) for D− and (12.2, 17.1),
  (21.5, 19.15) for D+, by position (ruling BU)**. A first version exempted any
  own-net via on these nets, and a stub via planted mid-run by the task 10 review
  passed; it now fails (`test_a_stub_via_of_its_own_net_mid_run_on_usb_2_0_is_found`);
* **D− passing the In1 hole of D+'s layer-change via at (21.5, 19.15), 0.5 mm**
  (task 9 re-review M1, introduced when ruling BG moved D− south). At 480 Mbit/s
  and at the layer change itself. It is listed by position so a second
  occurrence somewhere else fails.

The tool's `GP-001` warnings on MDI2/MDI3 (93–94 % reference coverage) are this
J2 pin hole: 1.06 mm of 12.4 mm is 91 %.

### A6 Every cap names its ruling or is a ratchet (ruling BW)

`COUPLING_REGIONS` has two kinds. **Granted**, with the ruling named: `U3 neck`
(AG / AI, 1.0 mm from the pad centre), `U8 straddle` for TX_CONN (BV, 8.0 mm).
**Ratchet**, each stating "as-built ratchet, not verified against a
requirement" in the code and argued here; a cap only stops the board getting
worse:

| Region | Cap | Why it is a ratchet |
|---|---|---|
| `TX capacitor landing` | 1.4 mm | ruling BE named a fan-out of about 1 mm and no cap; measured 0.83-1.32 |
| `U8 straddle` (RX) | 6.0 mm | AS granted about 5 mm of extent; the 1.0 mm is the implementer's path allowance |
| `J3 fan-out` (RX) | 2.0 mm | BN granted 1.5 mm; the 0.5 mm is allowance |
| `J3 fan-out` (TX_CONN) | 2.7 mm | the 2.5 mm is the task 9 re-review's measurement; BE gave no figure |
| `USB 2.0 layer change at U3` | 1.2 / 1.0 mm | AR allows the layer change, not a length; measured 0.93 / 0.74 |
| `USB 2.0 J3 to U9 crossover`, `USB 2.0 skew meander` | 11.0 / 4.6, 5.0 mm | A3 |
| `J2 pin lead-in` | per net | A4 |

The floors on the share inside the window follow from these caps, so the floor
on RX and on every USB 2.0 and MDI net is a ratchet too; on TX_CONN it follows
from the BV concession plus the J3 and capacitor-landing ratchets.

## B. Tool findings

Chain output is in this directory. Ruling J: compared with the baseline by
category and rule id, not by the aggregate EMC score (76.0 then, 0 now; the
score is saturated by the 13 errors below and routing changed the decoupling
findings for layout reasons).

### B1 `fab_release_gate.py --strict`: FAIL on one check, a tool false positive

"Net count mismatch: schematic 44 vs PCB 38". The six extra nets are
`__unnamed_0` … `__unnamed_5` in `schematic.json`: six single-pin nets, one per
`no_connect` flag (U3 24, 28, 31; U4 4; U7 5; U8 5), and the schematic's
`total_no_connects` is 6. All 38 named nets are the same in schematic and PCB
(checked by name). Not fixed: the no-connect flags are correct and ERC is 0/0.
After the silkscreen fix 9 of the gate's 12 checks pass, 1 fails (this one), 2
skip (Gerbers: task 11 exports them). Ruling I: the gate does not rest on this
tool.

### B2 `VM-001` × 2 on USB2_D_P / USB2_D_N (known, ruling Z)

"5.0 V / 1.0 V domain crossing": the tool reads the ESD array U9 as a 5 V IC
talking to U3. U9 is a TVS with no supply pin on the signal path.

### B3 `GP-001` reference plane gap

* `USB2_D_N` (known false positive, ruling BO): the tool probes the wrong
  layers on this stackup; section A5 measures the real plane.
* `SHIELD`, `MDI_CT`, `ETH_LED1` (errors): not pair signals. SHIELD is the
  cable-side shield (tied to GND by C25 ∥ R13, `design_notes.shield_tie`),
  MDI_CT is a DC centre-tap bias, ETH_LED1 a DC LED drive at 1.1 mA; none
  carries a return current worth a loop.
* `MDI2/3` warnings: the J2 pin hole, A5.
* `GP-004` (51 % fill on F.Cu): the ground reference is In1; F.Cu is a signal
  layer.

### B4 `KO-001` × 12 (errors): `U3_escape` is not a keepout

The tool reads the rule area `U3_escape` as a keepout. Its block in the board
reads `(tracks allowed) (vias allowed) (pads allowed) (copperpour allowed)
(footprints allowed)`: it forbids nothing and exists only to scope ruling AU's
track clearance. The "violations" are eleven vias (nine under U3's thermal pad, one at
(121.1, 100.1), the +3V3 via at (126.8, 105.8)) and U3 itself, all inside it.

### B5 Placement and test (`PM-002` × 3, `TE-001`, `VP-001`)

* `PM-002` J2 0.1 mm from the edge: the jack's mating face is meant to sit at
  the edge. J3 courtyard 15.75 mm past the edge: J3 is the USB-A plug.
  JP1 0.65 mm from the edge: a solder jumper on a single hand-assembled board
  that is not depaneled.
* `TE-001` 2 of 31 nets: the board has the measurement points the first build
  needs (rail and inrush points); coverage as a number means nothing for a
  hand-assembled unit.
* `VP-001` U8:2 untented via in pad: ruling BA / BD. The via is tented on the
  back (`(tenting (front none) (back yes))`), `fabrication-note.md` asks for
  flux and a little more solder on this pad.

### B6 Decoupling (`DC-001` × 2, `DC-003`)

* U8 / C22 "9.3 mm": C22 is the series AC-coupling capacitor of the TX pair and
  U8 is a diode array with no supply pin.
* U9 / C1 "9.0 mm": USBLC6-2SC6's VBUS pin only senses the rail and needs no
  decoupling capacitor; C1 (1 µF on +5V) is merely the nearest one.
* C24 far from a via: C24 is DNP and is a feed-forward option across U6's
  divider (nets `+1V0_REG`, `FB_1V0`), not a decoupling capacitor.
* U3's own decoupling is not flagged. Straight-line distance from each
  capacitor's pad 1 to its U3 pin: C9 0.43, C27 1.56, C7 1.72, C10 1.91,
  C8 2.23, C15 2.62, C18 2.67, C12 2.71, C13 3.05, C11 3.33, C14 3.61, C16 3.88,
  C17 4.28 mm. Ruling BH brought C14 from 7.94 to 3.61 mm and C9 from 5.93
  to 0.43 mm; C16 and C17 are the longest now and were not re-opened. C14's
  return loop is longer than its distance (review M4).

### B7 Ground pins and I/O filtering (`IO-001`, `IO-002` × 2, `CG-AUD`)

J2 is an integrated-magnetics jack (LPJG16402AQNL: transformers, common-mode
chokes, Bob Smith termination); the filter detector cannot see inside it
(baseline noise list). "0 ground pins on J2": the jack has none; its shield is
the separate `SHIELD` net by decision. U9 (USBLC6-2SC6) has one GND pin by
package.

### B8 Outer-layer routing (`DP-004` × 16, `CK-001` × 3)

The stackup is F.Cu / In1 GND / In2 power / B.Cu with all impedance-controlled
pairs as microstrip on F.Cu over In1 (`stackup-note.md`); the inner layers
carry no signals by design. The radiation difference to stripline is real for
SuperSpeed and is not measurable without an emissions scan; recommended before
any production run. The crystal nets are 9.6 mm (XTAL1) and 4.9 / 5.0 mm (XTAL2) on F.Cu between
Y1 and U3; a crystal is not routed in a stripline.

### B9 `DP-003`, `RP-001` × 8, `DP-001`

* `DP-003` / `RP-001` USB2_D_P/N: ruling AR. The tool wants a ground via within
  1.0 mm of each layer change; the flank vias are 1.35 mm away. The re-review of
  task 9 showed the return current changes from In1 to In2 at the U9
  transition anyway. `check_fab_release.py` holds AR (one In2 boundary, both
  flank vias in the B.Cu pour and the In1 plane) and fails if a flank via goes.
* `RP-001` `ETH_LED0`, `ETH_LED1`, `LED_G_A`, `LED_Y_A`, `AVDD33_LDO`,
  `DVDD10_UPS`: DC and supply nets, not signals with a return path to stitch.
* `DP-001` "3.4 mm / 18.8 ps" on USB 2.0: raw copper. D+ passes through U9's
  flow-through pins 1→6 (2.274 mm inside the part, `USB2_U9_INTERNAL`) and both
  nets carry tee stubs into the ESD pads; `route_pcb.py` reports the signal path
  as 0.020 mm difference (task 9), and the B.Cu meander (A3) is how.

### B10 Switching (`SW-001`, `EE-001`, `EE-002`) and schematic `RS-001`

U6 is a buck converter; the tool assumes 0.5 MHz (the datasheet says 1 MHz
fixed, so there are fewer, stronger harmonics). A 5–6 mm² switching loop
(review minor) is the mitigation in the layout; an emissions scan on the first
build is the check. `RS-001` SW_1V0: the switch node, not a rail (baseline
noise list).

### B11 PCB analyser narrow tracks (`CC-002` × 20, `ETH_LED*`, `AVDD33_LDO`, `DVDD10_UPS`)

0.15 mm is the neck width of rulings AG / AI at U3's 0.4 mm pitch, at most
0.6 mm from the pad centre. At 35 µm copper that is about 3 mΩ per mm: 2 mΩ for
the longest neck on a supply of tens of milliamps.

### B12 Silkscreen (10 DRC warnings)

7 `silk_over_copper` and 3 `silk_overlap` in the DRC: the reference text of J2,
TP2 and U4 clipped by the pads of C21, C2 and C6 and J2's outline over its
shield pads. Cosmetic, known since task 9 (10 warnings then and now). The tool
also lists 41 reference designators hidden on silkscreen (all capacitors and
fiducials) and no connector labels: the operator solders from the placement
drawing and the BOM, not from the board; not changed.

### B13 Thermal: the tool's number is a placeholder

`analyze_thermal.py` assessed only U4 (Tj 67.5 °C, 0.17 W from its own assumed
105 mA load) and skipped U6 and U7 ("no load estimate"). The numbers that
carry the claim "U4 and U6 have reserve" are from `netlist.yaml`
`design_notes.rail_currents` and the datasheets, at three times the typical
current (the datasheets give no maximum):

| | load | dissipation | θJA (datasheet) | Tj at 25 °C | reserve to 125 °C |
|---|---|---|---|---|---|
| U4 AP2112K-3.3 | 0.212 A, (5.0 − 3.3) V | 0.36 W | 184 °C/W | 91 °C | 34 K (ambient limit 59 °C) |
| U4 at typical | 72 mA | 0.12 W | 184 °C/W | 47 °C | 78 K |
| U6 SY8089AAAC | 0.51 A at 1.0 V, η 0.8 assumed | 0.13 W (limit 0.6 W) | 170 °C/W | 47 °C | 78 K |

U4's 34 K is enough on a bench and thin in a closed case; the note already says
so. U3 (RTL8153B, about 0.4 W at typical) is not assessed by anything: measure
its package temperature on the first build.

### B14 Cross-analysis: `RP-002` and `PS-002` × 2 (errors), `PS-002` info

`RP-002` "ETH_LED1 crosses a gap in the GND plane on F.Cu" and `PS-002` "GND
plane has 5 disconnected islands, signals crossing: USB2_D_N, ETH_LED1":

* The GND "islands" are the board's five GND zones (F.Cu three, B.Cu one, In1
  one), counted as if they were pieces of one plane. The reference plane is the
  single solid In1 zone (section A5, no unexplained gap under any pair); the
  outer pours are tied to it with vias, which is what the DRC's 0 unconnected
  items and the absence of any `isolated_copper` warning show.
* `+3V3` (3 islands) and `+3V3_REG` (2): In2 is split into supply islands on
  purpose (task 8; the supply of a net is where its pads are). DRC finds no
  unconnected pad on any of them.
* `ETH_LED1` is a DC LED drive at about 1.1 mA that crosses an island gap of
  In2 or a pour edge on its 41 mm; there is no return current to detour.
* `USB2_D_N` crossing: the one In2 boundary of ruling AR, held by
  `check_fab_release.py` (A5, B9).

### B15 `fab_release_gate.py` skipped checks

Gerber analysis (two checks) is task 11's: the Gerbers do not exist before the
export.
