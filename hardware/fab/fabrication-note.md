# Fabrication note: vias, solder mask, assembly

Board: `hardware/kicad/raccoon-tap.kicad_pcb` (routed, task 9). Attach this
note to the PCBWay order together with `stackup-note.md` (task 11).

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
mm** (0.13 mm annular ring, the board's minimum): it sits between two MDI
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

