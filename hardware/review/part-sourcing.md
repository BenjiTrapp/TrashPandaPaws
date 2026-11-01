# Part sourcing and lifecycle, every BOM row

Checked 2026-11-01 for task 6 against DigiKey, Mouser, Newark, TME, LCSC,
manufacturer pages and aggregators (Octopart). Source of truth for the rows is
`hardware/netlist.yaml`; `hardware/bom.csv` is generated from it. **Nothing was
ordered.** U3 is treated separately in `u3-sourcing.md`.

"Lifecycle" is what the manufacturer or DigiKey says. Where only an aggregator
says it, that is stated. "Stock" is the figure on the page I read, on the day;
it moves. Prices are for one piece unless noted, in the currency the page
showed. A dash means the page did not show it and I did not guess.

## Rows

| Ref | Value | Package | Manufacturer, part number | Lifecycle | Availability / price |
|---|---|---|---|---|---|
| C1, C5 | 1 uF X5R 25 V 10 % | 0603 | Yageo CC0603KRX5R8BB105 | Active (DigiKey) | DigiKey, Mouser, TME list it; stock and price not captured |
| C2, C7, C9-C18, C21-C23 | 100 nF X7R 50 V 10 % | 0603 | Yageo CC0603KRX7R9BB104 | Active (DigiKey) | DigiKey stock about 4.0 million; EUR 0.10 to 0.145 each |
| C3 | 10 uF X5R 16 V 10 % | 0805 | Samsung CL21A106KOQNNNE | Active (DigiKey, DiGi-Electronics) | stock and price not captured |
| C4 | 22 uF X5R 6.3 V 20 % | 0805 | Samsung CL21A226MQQNNNE | Active (DigiKey) | stock and price not captured |
| C6 | 10 uF X5R 10 V 10 % | 0603 | Samsung CL10A106KP8NNNC | Active (DigiKey) | DigiKey lead time 61 weeks quoted; stock not captured |
| C8 | 2.2 uF X5R 16 V 10 % | 0603 | Samsung CL10A225KO8NNNC | Active (DigiKey) | DigiKey stock 213,560; $0.11 |
| C19, C20 | 27 pF C0G 50 V 5 % | 0603 | Yageo CC0603JRNPO9BN270 | Active (DigiKey) | DigiKey 4,946; Mouser in stock $0.10 |
| C25 | 1 nF X7R 2 kV 10 % | 1206 | KEMET C1206C102KGRACTU | Active (DigiKey) | stock and price not captured |
| C26 | 27 nF X7R 50 V 10 % | 0603 | Yageo CC0603KRX7R9BB273 | Active (DigiKey) | stock and price not captured |
| C24 (DNP) | pad only; 10 pF C0G if fitted | 0603 | Yageo CC0603JRNPO9BN100 | Active (family); DigiKey stock 12,319 | EUR 0.10; **a stocked starting point, not a design value** |
| R5 | 10.0 k 1 % | 0603 | Yageo RC0603FR-0710KL | Active (DigiKey) | ~95,000 at one dealer, $0.088; widely stocked |
| R6 | 15.0 k 1 % | 0603 | Yageo RC0603FR-0715KL | Active (Newark, Yageo spec sheet) | widely stocked |
| R7, R8 | 1 k (1 % part) | 0603 | Yageo RC0603FR-071KL | Active (DigiKey) | widely stocked |
| R11 | 2.49 k 1 % | 0603 | Yageo RC0603FR-072K49L | Active (DigiKey) | lead time 22 weeks quoted if not in stock |
| R14 | 0 ohm | 0603 | Yageo RC0603JR-070RL | Active (DigiKey) | DigiKey 8.86 million; rated 1 A |
| R12 (DNP) | 0 ohm, do not fit | 0603 | Yageo RC0603JR-070RL | Active | as R14 |
| R13 | 1 M 5 % | 1206 | Yageo RC1206JR-071ML | Active (DigiKey) | stock and price not captured |
| L2 | 2.2 uH, 2.7 A, Isat 3.3 A | 3225 (1210) | TDK TFM322512ALMA2R2MTAA | Active (DigiKey) | stock and price not captured |
| U3 | RTL8153B | QFN-40-EP 5x5 | Realtek RTL8153B-VB-CG | no EOL notice found | **see `u3-sourcing.md`**: LCSC C2802072, stock 3,330, $3.56 each at 1 pc |
| U4 | AP2112K-3.3 | SOT-23-5 | Diodes Inc AP2112K-3.3TRG1 | Active (DigiKey) | stock and price not captured |
| U6 | SY8089AAAC | SOT-23-5 | Silergy SY8089AAAC | **NRND per Octopart** (see below) | LCSC C78988 22,935 in stock at $0.15 (5+); Octopart: 95,000 and 223,000 at distributors, about EUR 0.06 to 0.07 |
| U7 | TPS22810 | SOT-23-6 | Texas Instruments TPS22810DBVR | released (TI product page) | Mouser 143,660 (EUR 1.06); TI direct $0.492 (1 to 99); DigiKey 15,164 on one site, "backorder, 16-Nov-2026" on another |
| U8 | SP3019-04HTG | SOT-23-6L | Littelfuse SP3019-04HTG | **Active** (Littelfuse page) | DigiKey $1.05 (3,000: $0.214); Mouser 12,116; Newark $1.03; Farnell $1.06 |
| U9 | USBLC6-2SC6 | SOT-23-6L | STMicroelectronics USBLC6-2SC6 | **Active, volume production** (ST page) | DigiKey 92,412 on ST's page; about $0.12 to $0.19 |
| Y1 | 25 MHz, CL 18 pF | 3225 | Abracon ABM8-25.000MHZ-D2Y-T | Active (DigiKey) | DigiKey 27,729, $0.884 at 10; Mouser 9,289 |
| J2 | LPJG16402AQNL | THT | LINK-PP LPJG16402AQNL | no flag found | link-pp.com and l-p.com only: 5,000 in stock at $3.44 plus $29.47 shipping. **Not found at DigiKey or Mouser.** |
| J3 | 692112030100 | SMT right-angle | Wuerth Elektronik 692112030100 | no flag found | DigiKey 7,997, $3.68 at 10; Newark $3.48 |
| TP1-TP7, JP1, JP2 | bare pads | - | none: left out of the BOM | - | nothing to buy |

## Findings of the lifecycle sweep

The sweep covered all 27 BOM lines, not only the new ones.

1. **SP3012-04HTG, the first low-capacitance ESD array I found, is obsolete.**
   Littelfuse marks it "Obsolete, replaced by SP3019-04HTG"; DigiKey says "no
   longer manufactured". Several aggregators still list stock as "active".
   Replaced by SP3019-04HTG (0.3 pF typ against 0.5 pF).
2. **Three Murata parts I would have picked first are not orderable for a new
   design.** GRM188R71C104KA01D (100 nF, 16 V, 0603) is Obsolete at DigiKey,
   EOL at Octopart, "Not suitable for new design" at Anglia.
   GRM188R61A225KE34D (2.2 uF, 10 V) is EOL, last-time-buy 2021. GRM1885C1H270JA01D
   (27 pF C0G) is "Not for new designs". The Yageo and Samsung parts in the BOM
   replace them.
3. **CL10A105KA8NNNC (Samsung 1 uF, 25 V) shows "Discontinued at DigiKey" on
   one DigiKey page and "Active" on another.** That is DigiKey's stocking, not
   necessarily Samsung's. Avoided; the Yageo CC0603KRX5R8BB105 is used.
4. **U6 SY8089AAAC, an existing row, is "NRND" on Octopart (updated about a
   month before this check).** Silergy's own page was not reachable. LCSC and
   distributors hold well over 100,000 pieces, so a five-board build is not at
   risk; a later production run might be. The netlist and footprint are not
   changed for it. If Silergy's NRND notice is confirmed, the cure is a
   different buck in SOT-23-5 with the same pin-out and a new feedback
   divider; that is a design task, not a BOM edit.
5. **TPS22918 was replaced by TPS22810 during this task.** The TPS22918 is
   Active and well characterised at 5 V, but its absolute maximum on VIN is
   6 V and a hot-plugged USB rail can ring above that. TPS22810 is rated
   20 V absolute maximum. See `netlist.yaml` design_notes.vbus_inrush.
6. **J2 has a single source.** LINK-PP's own shop (or its l-p.com channel) is
   the only place I found it. The operator solders J2 by hand, so PCBWay does
   not need it, but a stock-out there stops the build. No lifecycle problem was
   found.

## Hand-solderability

Every part except U3 is either leaded (SOT-23-5/-6 for the five other ICs,
the through-hole and SMT connectors) or a two-terminal chip with visible
pads: 0603 and larger passives, and the 3225 inductor with its terminations on
the short sides. Leadless low-capacitance ESD parts were rejected for this
reason (`netlist.yaml` design_notes.esd_protection).

Not checked: Y1, the 3225 crystal, has its four pads on the underside. Whether
that is comfortable with an iron and flux was not tested. It is the package the
earlier tasks chose, and the brief names U3 as the only exception to
hand-solderability, so this is a question for the layout task (generous
side-extending pads, or a crystal with visible terminations), not decided here.

## Open items for a person

- Download the Littelfuse SP3019 datasheet by hand and commit it with an md5
  (`netlist.yaml` header, `[SP3019]`). Scripted download of it was refused.
- Download the Wuerth 692112030100 datasheet by hand (ruling U, task 11).
- Get a PCBWay quote for U3-only assembly (`u3-sourcing.md`).
- Check stock and price for the lines marked "not captured" on the day of
  ordering; they are all commodity parts with an Active listing.
