# Fabrication note: vias, solder mask, assembly

Board: `hardware/kicad/raccoon-tap.kicad_pcb` (routed, task 9). This note is
the operator's record, next to `stackup-note.md`; what PCBWay is told is the
short text (block A) under "Placing the order" in `ORDERING.md`.

Assembly split: PCBWay reflows **U3 and Y1** only; every other part is soldered
by hand with an iron and flux. A via that is open in a pad of a hand-soldered
part draws solder out of the joint, so none is left open (ruling BA).

Three parts sit on the **bottom side**, all hand-soldered: C14, C27 and C9
(0402, 100 nF), directly at the vias of U3 pins 37, 19 and 39 / 40 (rulings
BH, BK). The PCBWay
order is for one-sided assembly of U3 and Y1 on top; the bottom needs no
stencil.

## Via sizes

Every via is 0.6 / 0.3 mm (pad / drill) but two: J3 pin 1's +5V via, 0.8 /
0.4 mm (current), and U3 pin 3's +1V0 via at (28.31, 24.375) mm, **0.56 / 0.3
mm** (0.13 mm annular ring, the board's minimum; kept by the operator's decision, ruling CN, and put to
PCBWay as Question 7 of `ORDERING.md`): it sits between two MDI
pairs 1.56 mm apart and the smaller pad keeps In1's hole round it 0.11 mm from
both.

## Vias tented from the back (B.Mask covers them)

| Where | Vias | Why it is in the pad |
|---|---|---|
| U3 exposed pad (pin 41, GND) | 9, 0.6 / 0.3 mm, 3 x 3 on 1.1 mm | thermal path to In1 ([RTL-DS]); reflowed by PCBWay |
| U8 pin 2 (GND), SP3019 at (15.6, 15.86) mm from the board's top-left corner | 1, 0.6 / 0.3 mm, centred in the pad | the pin sits between the two SuperSpeed TX pads with a TX line passing on either side (ruling AS): there is no copper-free place off the pad for its via (searched on a 0.05 mm grid by `tools/route_pcb.py` stage `pad_vias`) |

Ask PCBWay for these vias to be **tented on the bottom side**. They are
already tented in the design file (`tenting back yes`; checked in the B.Mask
gerber: no opening at either place); the order should state it so that a
"vias not covered" default is not applied. The front side of these vias is
inside the pad's own mask opening by design.

For U8 pin 2 the hand-assembly note: the hole is plugged from the back by the
mask only, not filled; flux and a little extra solder on that pad.

No other via is in or touches a pad of a hand-soldered part, and every other
via keeps at least **0.1 mm of copper** from such a pad, so that a 0.1 mm mask
dam or the fab's registration tolerance cannot open it into the pad (ruling BI;
`tools/scan_board.py` checks it, U3 and Y1 excepted). All other vias follow the
board default, tented on both sides.

## First-build checks

| Check | Why |
|---|---|
| `lsusb -t` shows the adapter at 5000M; `iperf3` bidirectional for 30 min at 940 Mb/s; `dmesg` free of xHCI link errors and of a fall-back to USB 2.0 | ruling BF: pin 14's +1V0 escape runs 0.229 mm from USB3_RX_N and 0.250 mm from USB3_TX_P for up to 0.21 / 0.12 mm past the edge of U3's escape area, under the class clearance of 0.3 mm (`AU_OVERHANGS` in `tests/check_fab_release.py`) |
| link stability and error counters at 1000 Mb/s under load | ruling AX: MDI1 and MDI2 at 0.22 mm |
| `lsusb -t` at 5000M, `iperf3` bidirectional 30 min at 940 Mb/s, no xHCI link errors (same check as above) | ruling BV: the verification of the **granted concession** of 8.0 mm of path for `USB3_TX_CONN_P`'s straddle at U8 (ruling CD: the grant is that one net's; `USB3_TX_CONN_N` was granted nothing: it measures 6.68 mm and is held to its own as-built cap of 6.79 mm) (a concession under reservation, not an engineering target; `COUPLING_REGIONS` in `tests/check_fab_release.py`). **If the link proves marginal, change U8's package first** |
| U3 case temperature: IR thermometer or a thermocouple taped to the top of the package, `iperf3` bidirectional for 30 min at 940 Mb/s, room at about 25 C; expected rise 10 to 20 K; **investigate at 30 K or more** | task 11, U3 thermal (below): the estimate rests on an assumed theta-JA |

## U3 thermal

Written in task 11 because nothing else assessed U3: kicad-happy checks only U4,
and task 10 computed U4 (34 K reserve) and U6 (about 78 K) by hand. U3 is the
most heavily loaded part on the board.

**Power.** [RTL-DS] table 26, 1000 Mb/s with heavy network traffic, typical
(the datasheet gives no maximum): Icc5 0.5 mA, Icc33 70 mA, Icc10 170 mA.
P = 5 V x 0.5 mA + 3.3 V x 70 mA + 1.0 V x 170 mA = 0.0025 + 0.231 + 0.170 =
**0.40 W**, dissipated in the chip (what the pins draw is what the die turns
into heat, apart from the signal power it sends into the cable).

**Limits.** [RTL-DS] table 21 (recommended operating conditions) and table 25:
ambient 0 to 70 C, maximum junction temperature **125 C**. The datasheet gives **no theta-JA
and no theta-JC** (searched the committed copy for theta, "C/W", "thermal" and
"dissipation": no hit).

**Assumed theta-JA: 30 to 45 K/W**. This is an assumption with no source in the
repository: it is the range usual for a 5 x 5 mm QFN-40 whose exposed pad is soldered
to an internal ground plane through a via array. Here the pad is 3.6 x 3.6 mm
with 9 vias of 0.3 mm drill (3 x 3 on 1.1 mm) into a solid `In1.Cu` GND plane,
on a board of 58 x 36 mm with an `In2.Cu` plane as well.

| Dissipation | Rise (30 to 45 K/W) | Junction at 25 C ambient | Junction at 70 C ambient (datasheet limit) | Reserve to 125 C at 70 C |
|---|---|---|---|---|
| 0.40 W (typical, table 26) | 12 to 18 K | 37 to 43 C | 82 to 88 C | 37 to 43 K |
| 0.81 W (2 x typical) | 24 to 36 K | 49 to 61 C | 94 to 106 C | 19 to 31 K |
| 1.21 W (3 x typical, the envelope `netlist.yaml` sizes the rails with) | 36 to 54 K | 61 to 79 C | 106 to 124 C | 1 to 19 K |

At the typical load U3 is comfortable even at the 70 C ambient limit. At the
rail-sizing envelope of 3 x typical the pessimistic end has no reserve; that
envelope is a current budget for the regulators, not a credible power for a PHY
that is already at line rate in the typical column, but the table does not hide
it. **The result is an estimate, not an assessment of this board**: it stands or
falls with the assumed theta-JA, which only a measurement settles. It is
therefore a first-build check (last row of the table above): the top of the
package should come out 10 to 20 K above room temperature after 30 minutes at
940 Mb/s (the case-to-junction difference is small, so the case is within a few
kelvin of the junction); 30 K or more means theta-JA or the power is well
outside the assumption (at 70 C ambient that would put the junction at about
100 C or more). The enclosure's own ambient is not known and is not
estimated here.
