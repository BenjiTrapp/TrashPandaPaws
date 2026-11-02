# U3 (RTL8153B-VB-CG) sourcing

Checked 2026-11-01 for task 6. **Nothing was ordered and no quote was
requested.** Everything below is from public web pages; where a number could
not be obtained it says so. Ruling AC (task 6 review) adds Y1 to the parts
PCBWay places; see the section on it below.

## Verdict

**PCBWay can place U3 and very probably can buy it, but only if the BOM names
where to buy it. It does not need to be consigned.** Mouser and DigiKey, the
distributors PCBWay names first, show no listing for this part in any search I
ran; the part is sold through Realtek's own channel and through LCSC. PCBWay's
own page says it buys from "distributors you recommend". Name LCSC `C2802072`
in the BOM remarks and the stock position is fine (3,330 pcs at LCSC on
2026-11-01). Consigning (about 8 pcs bought by the operator) is the fallback if
PCBWay's quote comes back "cannot source" or at a price that is silly.

**The cost of PCBWay assembling U3 (and Y1) on 5 boards could not be established,
and cannot be until task 11.** PCBWay publishes no fee schedule; the price
appears only after a BOM and Gerbers are uploaded to its quoting system, and
those do not exist before the board is routed. "Why the surcharge is blank, and
what task 11 must obtain" lists the nine things to get from the quote; the
quote request text is at the end.

## Why PCBWay has to place U3 at all

U3 is QFN-40 with an exposed pad, 0.4 mm pitch, 5 x 5 mm
(`Package_DFN_QFN:QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm`). The operator solders
with an iron and flux: no stencil, no hot air. A 0.4 mm leadless part with a
ground pad under it cannot be soldered that way. U3 is the one deliberate
exception to the hand-solderable rule. PCBWay also places Y1 (ruling AC, below).

## Where the part can be bought

| Channel | What I found | Stock / price | Trust |
|---|---|---|---|
| **LCSC** `C2802072` (Realtek, QFN-40-EP 5x5) | live product endpoint `wmsc.lcsc.com/ftps/wm/product/detail?productCode=C2802072` | stock 3,330; 1 pc $3.5645, 10 pcs $3.0346, 30 pcs $2.7203, 100 pcs $2.3056, 490 pcs $2.1591, 980 pcs $2.0933. Search pages the same day showed 4,702 to 5,279 in stock, from $2.09. | LCSC lists the manufacturer as REALTEK. Whether LCSC is a franchised Realtek distributor was not verified. It is the same warehouse family as JLCPCB. |
| Mouser, DigiKey, Arrow, Farnell/Newark | no listing found in searches for the exact part number | - | - |
| Realtek | `realtek.com/products/communications-network-ics/item/rtl8153b-vb-cg` exists. It is a product page; how to buy (sales contact / regional distributor) was not followed up. | - | manufacturer |
| Brokers (UppConn "quote on request", PCBX $3.21, DigiPart $3.68, IC-Components, eBay $6.95 plus shipping) | listings only | unverified | **treat as unverified and possibly relabelled stock; do not use for a part that is hard to replace** |

## What PCBWay says about sourcing

From `pcbway.com/pcb_prototype/Electronic_Components.html` and its help
centre, 2026-11-01:

- Four options: PCBWay supplies everything from authorised distributors;
  PCBWay buys from distributors **you recommend**; you consign everything
  ("kitted"); or a combination.
- Named partners: Digi-Key, Mouser, Farnell element14, Arrow, Avnet, "and some
  reliable local electronic suppliers". Local suppliers are their first choice
  for stock, 5-7 business days, 7-10 with customs clearance.
- "No substitutes will be used without getting your approval."
- "Can we buy components from a specific supplier or provide a link? Yes,
  please remark the supplier name or include the link in the BOM."
- If you pick the supplier: "we won't guarantee the quality of components."
- Their unit prices include shipping, customs, procurement labour and spare
  parts for assembly losses, so they run above the distributor price.
- PCBWay sells no components on their own.
- Consigned parts: markings on every package matching the BOM; a small excess
  (1 to 5 pieces by total quantity) for expensive parts such as ICs; parts not
  on a reel must be on one continuous strip of tape.

## Cost for 5 boards

| Item | Amount | Basis |
|---|---|---|
| U3 parts, if consigned | 8 pcs (5 + 3 spare) from LCSC: 8 x $3.5645 = **$28.52**, or 10 pcs at $3.0346 = **$30.35** | LCSC price breaks above; plus shipping and import VAT to wherever the parts go. LCSC ships within China cheaply. |
| U3 parts, if PCBWay buys | not knowable | PCBWay quotes it back to you; expect LCSC price plus handling. |
| Y1 parts | 7 pcs (5 + 2 spare) at DigiKey's $0.884 (10-piece price) = about $6.2 | DigiKey page text; if PCBWay buys, its own price |
| PCBWay fee for a two-part (U3 + Y1) partial assembly | **not quoted, not obtainable before task 11** | see the section on why. Fixed items to expect: assembly setup / engineering, a stencil for the one SMD side, placement of 2 positions x 5, shipping of the assembled boards. |
| Order-of-magnitude anchors | $142 for 10 boards, 81 parts, 50 unique ([contextualelectronics forum](https://forum.contextualelectronics.com/t/pcbway-assembly-service-my-experience/2541)); $490 assembly fee quoted on a complex job ([EEVblog](https://www.eevblog.com/forum/manufacture/turnkey-assembly-costs-price-check/)) | anecdotes from other boards, years apart. They bracket complex jobs; they do not price a two-part job. Do not budget from them. |

## Lead time

- U3 from LCSC: in stock (3,330), so the part is not the long pole. LCSC and
  PCBWay are both in Shenzhen/Guangdong, so a consigned shipment is a domestic
  one. LCSC's own dispatch time was not looked up.
- If PCBWay buys: PCBWay's sourcing page says local suppliers are its first
  choice, "about 5-7 business days" to obtain components, "7-10 business
  days if customs clearance takes too long". That is PCBWay's statement for
  parts it has to bring in, not a figure for this part.
- Assembly lead time on top of that: **not published** (see below).

## Why the surcharge is blank, and what task 11 must obtain

PCBWay's assembly price is produced only by its quoting system after a BOM
and Gerber files are uploaded to an account; the public pages carry no fee
schedule, and the figures people quote (the two anecdotes above) are for
complex boards. I could not get a number without placing an inquiry, and
requesting a quote for a board that is not routed yet would be a wrong
number anyway: the BOM, CPL and Gerbers do not exist until tasks 8 to 11 are
done. So the surcharge is not "unknown because nobody looked"; it is
unobtainable until task 11 has a fabrication package. Task 11 must obtain,
from the quote, in writing:

1. The assembly setup / engineering fee for a **two-unique-part** partial
   assembly (U3 and Y1, see below), 5 boards.
2. The stencil fee, and whether the stencil is one-sided.
3. The placement fee for 2 positions x 5 boards.
4. Whether X-ray inspection of the exposed-pad QFN is included or charged.
5. The U3 and Y1 part cost as PCBWay will charge it, and the spare quantity
   it adds for placement losses.
6. Whether it accepts LCSC `C2802072` as the named source for U3 (and says so
   before ordering if it cannot).
7. Its assembly lead time, and its sourcing lead time for each part.
8. The shipping option and cost for the assembled boards (PCBWay ships them
   in a panel unless told otherwise).
9. Any minimum-order or "partial assembly" surcharge.

## What is unknown

1. All nine items above.
2. Lifecycle of the RTL8153B-VB-CG at Realtek. LCSC still sells it and
   Realtek's product page is up; no EOL notice was found, none was looked for
   at Realtek's customer portal.
3. Authenticity of LCSC stock for this part beyond LCSC's own listing.

## Y1 goes to PCBWay as well (ruling AC)

The crystal Y1 (Abracon ABM8-25.000MHZ-D2Y-T, 3225, four pads under the body)
is not comfortable to solder with an iron, and the ABM8 was checked point by
point against [RTL-DS] table 23, so it stays. Task 11 therefore puts **U3 and
Y1** into PCBWay's partial assembly. Y1 is stocked at DigiKey (27,729, $0.884
at 10) and Mouser (9,289), both of which PCBWay names as its first
international sources, so it needs no special arrangement: list it with its
part number and manufacturer. Task 8 draws it with an extended-pad footprint
for hand rework.

## Quote request to send (text for task 11, not sent)

> Partial assembly, 5 boards, one side. Place **only** U3 (RTL8153B-VB-CG,
> QFN-40 5x5 mm, 0.4 mm pitch, exposed pad) and Y1 (Abracon
> ABM8-25.000MHZ-D2Y-T, 3225 crystal). All other positions stay empty, the
> customer solders them. Please source U3 from **LCSC part C2802072**
> (Realtek RTL8153B-VB-CG) and Y1 from DigiKey or Mouser by part number.
> Please quote the nine items listed in our request: setup/engineering fee,
> stencil, placement, X-ray of the QFN, part cost and the spare quantity you
> add, lead times, shipping. If you cannot source U3 from LCSC, tell us before
> ordering; we can consign 8 pieces on a continuous cut-tape strip.

## For task 11

- The CPL and the assembly BOM for PCBWay contain **U3 and Y1 only**. Every
  other row is hand-fitted by the operator, and R12 and C24 are DNP (see
  `hardware/bom.csv`, column Populate).
- Put `C2802072` and the supplier name "LCSC" in the BOM line for U3.
- Keep U3's pin 1 and its orientation marked on the silkscreen; a QFN cannot
  be reworked by hand.
