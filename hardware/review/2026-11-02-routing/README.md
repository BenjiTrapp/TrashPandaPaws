# raccoon-tap — routed (task 9, 2026-11-02)

The board after `tools/route_pcb.py` routed it (rulings AU to AZ). From here on
the board is the geometry: `tools/gen_pcb.py` refuses a routed board.

| File | |
|---|---|
| `drc.rpt` | `kicad-cli pcb drc --severity-all`: 0 errors, 0 unconnected, 10 silkscreen warnings |
| `erc.rpt` | `kicad-cli sch erc --severity-all`: 0 / 0 |
| `schematic.json`, `pcb.json`, `emc.json`, `thermal.json` | kicad-happy, the commands of `../2026-10-31-placement/README.md` |
| `u3_supply_escape_probe.py` | historical: the evidence of the two blocked rounds, for the placement of commit a974bf4 |

Ruling BA (2026-11-03): `tools/amend_pcb.py pad_vias` moved U9's VBUS via and C4's
GND via off their pads and tented U8 pin 2's in-pad GND via from the back
(`hardware/fab/fabrication-note.md`); the files here are re-taken after it.

Review 1 (2026-11-03, rulings BE to BI): `tools/amend_pcb.py coupling
decoupling via_gaps antipads split_area` re-laid USB3 TX / TX_CONN coupled with
`route_pair`, re-routed pin 14's escape, moved USB 2.0 off RX_P, put C14 and a
new C27 on B.Cu at the vias of pins 37 and 19, kept every via 0.1 mm of copper
from hand-soldered pads, and cut every F.Cu track at the edge of U3's escape
area. `tools/scan_board.py` reports via-in-pad gaps, area-edge segments, where
ruling AU still reaches past the edge, the coupled length of every pair and the
In1 antipad margins. The files here are re-taken after it.

Review 2 (2026-11-03, ruling BK): `tools/amend_pcb.py rx c9 pin3_via` moved the
AR flank via north of the USB 2.0 crossing from between RX_N and RX_P to
(19.1, 18.49), south of both, re-laid RX coupled with `route_pair`, put C9 on
B.Cu at the via of U3 pins 39 / 40, and made pin 3's +1V0 via 0.56 mm so In1's
hole round it keeps 0.1 mm from MDI1_P and MDI0_N. Files re-taken after it.

The routing report (order, EMC after each pair, lengths, vias, decoupling
distances) is in the task 9 report of the release run.
