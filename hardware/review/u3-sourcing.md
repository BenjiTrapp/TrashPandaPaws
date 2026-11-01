# U3 (RTL8153B-VB-CG) sourcing

Checked 2026-11-01 for task 6. **Nothing was ordered and no quote was
requested.** Everything below is from public web pages; where a number could
not be obtained it says so.

## Verdict

**PCBWay can place U3 and very probably can buy it, but only if the BOM names
where to buy it. It does not need to be consigned.** Mouser and DigiKey, the
distributors PCBWay names first, show no listing for this part in any search I
ran; the part is sold through Realtek's own channel and through LCSC. PCBWay's
own page says it buys from "distributors you recommend". Name LCSC `C2802072`
in the BOM remarks and the stock position is fine (3,330 pcs at LCSC on
2026-11-01). Consigning (about 8 pcs bought by the operator) is the fallback if
PCBWay's quote comes back "cannot source" or at a price that is silly.

**The cost of PCBWay assembling only U3 on 5 boards could not be established.**
PCBWay publishes no fee schedule for assembly; the price appears only after a
BOM and Gerbers are uploaded to its instant quote, which needs an account and
was not done. See "What is unknown" below; the quote request text is at the end.

## Why PCBWay has to place U3 at all

U3 is QFN-40 with an exposed pad, 0.4 mm pitch, 5 x 5 mm
(`Package_DFN_QFN:QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm`). The operator solders
with an iron and flux: no stencil, no hot air. A 0.4 mm leadless part with a
ground pad under it cannot be soldered that way. U3 is the one deliberate
exception to the hand-solderable rule, and the only part PCBWay places.

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
| PCBWay fee for a one-part assembly | **not quoted** | needs the instant quote with BOM and Gerbers. Fixed items to expect: assembly setup / engineering, a stencil for the one SMD side, placement of 1 part x 5, shipping of the assembled boards. |
| Order-of-magnitude anchors | $142 for 10 boards, 81 parts, 50 unique ([contextualelectronics forum](https://forum.contextualelectronics.com/t/pcbway-assembly-service-my-experience/2541)); $490 assembly fee quoted on a complex job ([EEVblog](https://www.eevblog.com/forum/manufacture/turnkey-assembly-costs-price-check/)) | anecdotes from other boards, years apart. They bracket complex jobs; they do not price a one-part job. Do not budget from them. |

## What is unknown

1. PCBWay's fee for a U3-only assembly of 5 boards (setup, stencil, placement).
2. Whether PCBWay will accept `C2802072`/LCSC as the named source, or prefers
   its own local supplier for this part. It says yes in general.
3. Whether PCBWay requires X-ray inspection of the exposed-pad QFN and charges
   for it. It publishes X-ray as a capability; whether it is included for a
   QFN is not stated.
4. Lifecycle of the RTL8153B-VB-CG at Realtek. LCSC still sells it and
   Realtek's product page is up; no EOL notice was found, none was looked for
   at Realtek's customer portal.
5. Authenticity of LCSC stock for this part beyond LCSC's own listing.

## Quote request to send (text for task 11, not sent)

> Partial assembly, 5 boards, one side. Place **only** U3 (RTL8153B-VB-CG,
> QFN-40 5x5 mm, 0.4 mm pitch, exposed pad); all other positions stay empty,
> the customer solders them. Please source U3 from **LCSC part C2802072**
> (Realtek RTL8153B-VB-CG). Please quote: assembly setup/engineering, stencil,
> placement, X-ray inspection of the QFN if it is not included, part cost and
> the spare quantity you add for placement losses. If you cannot source it
> from LCSC, tell us before ordering; we can consign 8 pieces on a continuous
> cut-tape strip.

## For task 11

- The CPL and the assembly BOM for PCBWay contain **U3 only**. Every other
  row is hand-fitted by the operator, and R12 and C24 are DNP (see
  `hardware/bom.csv`, column Populate).
- Put `C2802072` and the supplier name "LCSC" in the BOM line for U3.
- Keep U3's pin 1 and its orientation marked on the silkscreen; a QFN cannot
  be reworked by hand.
