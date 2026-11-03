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

The routing report (order, EMC after each pair, lengths, vias, decoupling
distances) is in the task 9 report of the release run.
