# Fabrication note: vias, solder mask, assembly

Board: `hardware/kicad/raccoon-tap.kicad_pcb` (routed, task 9). Attach this
note to the PCBWay order together with `stackup-note.md` (task 11).

Assembly split: PCBWay reflows **U3 and Y1** only; every other part is soldered
by hand with an iron and flux. A via that is open in a pad of a hand-soldered
part draws solder out of the joint, so none is left open (ruling BA).

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

No other via is in or touches a pad of a hand-soldered part (checked over all
vias and pads of the board after ruling BA; U3 and Y1 excepted). All other vias
follow the board default, tented on both sides.
