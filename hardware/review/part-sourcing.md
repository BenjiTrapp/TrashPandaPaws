# Part sourcing and lifecycle, every BOM row

Checked 2026-11-01 for task 6 against DigiKey, Mouser, Newark, TME, LCSC,
manufacturer pages and aggregators (Octopart). Source of truth for the rows is
`hardware/netlist.yaml`; `hardware/bom.csv` is generated from it. **Nothing was
ordered.** U3 is treated separately in `u3-sourcing.md`.

**How "Lifecycle" was read.** DigiKey, Mouser, Newark, TME, Octopart, Littelfuse,
ST and TI product pages refuse scripted access (HTTP 403 or a challenge page).
Every lifecycle and stock entry below was therefore read from the text that a
web search returned for that page (a search-result snippet), not from the page
itself. The marks: **[S]** search-result text of the vendor page; **[D]**
a datasheet I downloaded and read; **[A]** an aggregator only (Octopart,
resellers). "Listed" means the part appears in distributor results with no
obsolescence flag and the word Active did not appear in what I saw. A person
ordering should open the pages; nothing here is a substitute for that. "Stock" is the figure on the page I read, on the day;
it moves. Prices are for one piece unless noted, in the currency the page
showed. A dash means the page did not show it and I did not guess.

## Rows

| Ref | Value | Package | Manufacturer, part number | Lifecycle | Availability and price (1 piece unless stated) |
|---|---|---|---|---|---|
| C1, C5 | 1 uF X5R 25 V 10 % | 0603 | Yageo CC0603KRX5R8BB105 | Active [S: DigiKey] | Mouser in stock, $0.14; Newark $0.152 |
| C2, C21 | 100 nF X7R 50 V 10 % | 0603 | Yageo CC0603KRX7R9BB104 | Active [S: DigiKey] | DigiKey about 3.88 million, $0.10 (1), $0.016 (1,000) |
| C7, C9-C18, C22, C23 | 100 nF X7R 50 V 10 % | **0402** | Yageo CC0402KRX7R9BB104 | listed [S: DigiKey]; Yageo spec sheet exists | DigiKey 1.13 to 1.17 million; price at 1 not captured (the 16 V sibling CC0402KRX7R7BB104 is $0.10 at 1) |
| C3 | 10 uF X5R 16 V 10 % | 0805 | Samsung CL21A106KOQNNNE | Active [S: DigiKey, DiGi-Electronics] | DigiKey 345,000, $0.17; Newark/element14 list it |
| C4 | 22 uF X5R 6.3 V 20 % | 0805 | Yageo CC0805MKX5R5BB226 | Active [S: DigiKey] | DigiKey 182,800, $0.50; 24-week lead time quoted when not in stock. **Changed from Samsung CL21A226MQQNNNE, which one DigiKey page showed at stock 0** |
| C6 | 10 uF X5R 10 V 10 % | 0603 | Yageo CC0603KRX5R6BB106 | listed [S: DigiKey, Mouser, Newark] | DigiKey 5.53 million, $0.035 shown (quantity break not captured). **Changed, see "Blocker" below** |
| C8 | 2.2 uF X5R 16 V 10 % | 0603 | Samsung CL10A225KO8NNNC | Active [S: DigiKey] | DigiKey 213,560, $0.11 |
| C19, C20 | 27 pF C0G 50 V 5 % | **0402** | Yageo CC0402JRNPO9BN270 | listed [S: DigiKey]; reseller price INR 1.32 | stock at DigiKey **not captured**: the same family's CC0402FRNPO9BN270 showed 4,935 and a 16-week lead time. Watch item |
| C24 (DNP) | pad only; 10 pF C0G if fitted | 0603 | Yageo CC0603JRNPO9BN100 | listed [S: DigiKey] | DigiKey 12,319; EUR 0.10. **A stocked starting point, not a design value** |
| C25 | 1 nF X7R 2 kV 10 % | 1206 | KEMET C1206C102KGRACTU | Active [S: DigiKey] | TME in stock, $0.26; Newark $1.41; Distrelec in stock |
| C26 | 27 nF X7R 50 V 10 % | 0603 | Yageo CC0603KRX7R9BB273 | Active [S: DigiKey] | DigiKey 40,326, $0.14 (from a substitute listing); resellers 20,000 to 32,000 |
| R5 | 10.0 k 1 % | 0603 | Yageo RC0603FR-0710KL | Active [S: DigiKey] | one dealer 95,000 at $0.088; family at DigiKey $0.10 (1) |
| R6 | 15.0 k 1 % | 0603 | Vishay Dale CRCW060315K0FKEA | listed [S: DigiKey, Farnell] | DigiKey 209,682 to 252,679, $0.11 to $0.16 (1), $0.0097 (5,000). **Changed from Yageo RC0603FR-0715KL, which DigiKey quotes with a 24-week lead time** |
| R7, R8 | 1 k (1 % part) | 0603 | Yageo RC0603FR-071KL | Active [S: DigiKey] | listed at DigiKey and Mouser; **stock and price not captured** (family $0.10 at 1) |
| R11 | 2.49 k 1 % | 0603 | Yageo RC0603FR-072K49L | Active [S: DigiKey] | DigiKey 209,679 to 226,171, $0.10 |
| R13 | 1 M 5 % | 1206 | Yageo RC1206JR-071ML | Active [S: DigiKey AU] | Mouser in stock $0.10; Farnell $0.022 (10); DigiKey $0.0099 (5,000) |
| R14 | 0 ohm | **0402** | Yageo RC0402JR-070RL | listed [S: DigiKey, Mouser, Farnell] | DigiKey 1.44 to 11.4 million, $0.10; Mouser 10.86 million; Farnell 19.6 million |
| R12 (DNP) | 0 ohm, do not fit | 0603 | Yageo RC0603JR-070RL | Active [S: DigiKey] | DigiKey 8.86 million (the same part as R14's 0603 sibling); rated 1 A |
| L2 | 2.2 uH, 2.7 A, Isat 3.3 A | 3225 (1210) | TDK TFM322512ALMA2R2MTAA | Active [S: DigiKey] | DigiKey 7,645 to 8,608, $0.61 (CAD page) / INR 39; Mouser $0.79 (1), $0.653 (10) but "notify me when in stock"; TDK's own page 3,250; TTI 14-week lead time at 2,000 |
| U3 | RTL8153B | QFN-40-EP 5x5 | Realtek RTL8153B-VB-CG | no EOL notice found | **`u3-sourcing.md`**: LCSC C2802072, live stock 3,330, $3.56 (1), $3.03 (10) |
| U4 | AP2112K-3.3 | SOT-23-5 | Diodes Inc AP2112K-3.3TRG1 | Active [S: DigiKey] | DigiKey 408,880, $0.28 (1); Mouser 233,121, EUR 0.232 |
| U6 | SY8089AAAC | SOT-23-5 | Silergy SY8089AAAC | **NRND [A: Octopart, updated about a month before this check]**; Silergy's page not reached | LCSC C78988 22,935 at $0.15 (5+); Octopart: 95,000 and 223,000 at distributors |
| U7 | TPS22810 | SOT-23-6 | Texas Instruments TPS22810DBVR | released [S: TI product page] | TI direct $0.492 (1 to 99); Mouser 143,660, EUR 1.06; DigiKey 15,164 on one site, "backorder, 16-Nov-2026" on another |
| U8 | SP3019-04HTG | SOT-23-6L | Littelfuse SP3019-04HTG | Active [S: Littelfuse page] | DigiKey 14,092, $1.05 (1), $0.214 (3,000); Mouser 12,116; Newark $1.03; Farnell $1.06 |
| U9 | USBLC6-2SC6 | SOT-23-6L | STMicroelectronics USBLC6-2SC6 | Active, volume production [S: ST page] | DigiKey 92,412 per ST's page; $0.12 to $0.19 (Octopart, exact break not captured) |
| Y1 | 25 MHz, CL 18 pF | 3225 | Abracon ABM8-25.000MHZ-D2Y-T | Active [S: DigiKey] | DigiKey 27,729, $0.884 (10); Mouser 9,289; Abracon 28,720 at $0.56 |
| J2 | LPJG16402AQNL | THT | LINK-PP LPJG16402AQNL | no flag found [A] | link-pp.com / l-p.com only: 5,000 in stock at $3.44 plus $29.47 shipping. **Not found at DigiKey or Mouser** |
| J3 | 692112030100 | SMT right-angle | Wuerth Elektronik 692112030100 | no flag found [S: DigiKey, Newark] | DigiKey 7,997, $3.68 (10); Newark $3.48 |
| TP1-TP7, JP1, JP2 | bare pads | - | none: left out of the BOM | - | nothing to buy |

### Blocker found and removed: C6

The first choice for C6, Samsung CL10A106KP8NNNC (10 uF, 10 V, 0603), was shown
by DigiKey with a **61-week lead time** and no stock. For a five-board build
that is a blocker, not a cost. Replaced by Yageo CC0603KRX5R6BB106 (same
value, rating, dielectric and case; DigiKey 5.53 million in stock). The
Murata GRM188R61A106KE69D, the other obvious candidate, was rejected: one
vendor lists it as removed from Murata's database. A 10 uF in 0603 at 3.3 V
loses part of its value to DC bias; C6 only needs 1 uF for U4's stability
([AP-DS]), so the replacement is not critical.

The same Samsung 61-week figure appeared on several other Samsung CL pages;
it is DigiKey's quote for items it does not hold. C3 and C8 do have stock at
DigiKey (345,000 and 213,560) and stay Samsung.

## Findings of the lifecycle sweep

The sweep covered all 28 BOM lines, not only the new ones. All of its evidence is search-result text (marks above), not the vendor pages.

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
3. **A Samsung 61-week lead time hid a blocker.** See "Blocker found and
   removed: C6" above; C6 and R6 were changed because of lead times, C4 because
   of one zero-stock page.
3a. **CL10A105KA8NNNC (Samsung 1 uF, 25 V) shows "Discontinued at DigiKey" on
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

Every part except U3 (and Y1, below) is either leaded (SOT-23-5/-6 for the
five other ICs, the through-hole and SMT connectors) or a two-terminal chip
with visible pads: 0402 and larger passives, and the 3225 inductor with its
terminations on the short sides. Leadless low-capacitance ESD parts were
rejected for this reason (`netlist.yaml` design_notes.esd_protection). The
0402 parts (C7, C9-C18, C19, C20, C22, C23, R14) are there on purpose: spec
5.1 keeps U3's decoupling and the crystal load capacitors small and close, and
the SuperSpeed AC-coupling pair stays 0402 for signal integrity (a 0603 pad on
a 90 ohm pair is a larger discontinuity, sits beside U8, and the two legs must
stay symmetric). They are hand-solderable with care; they are not the easy
parts. C8 is 0603 as a recorded deviation from 5.1 (2.2 uF in 0402 loses too
much to DC bias).

### Y1, the 3225 crystal (ruling AC)

Y1 has four pads on its underside and is not comfortable with an iron. It
stays: the ABM8 was checked point by point against [RTL-DS] table 23. The
mitigation is two-sided, and both halves must happen:

1. **Task 11 adds Y1 to PCBWay's partial assembly alongside U3.** PCBWay then
   places two parts, not one (see `u3-sourcing.md`). Y1 is stocked at the
   distributors PCBWay names first (DigiKey 27,729, Mouser 9,289), so it needs
   no special sourcing.
2. **Task 8 draws Y1 with an extended-pad footprint** (pads lengthened beyond
   the body), so that a crystal that is misplaced or has to be replaced after
   assembly can be reworked by hand at all.

## Open items for a person

- Download the Wuerth 692112030100 datasheet by hand (ruling U, task 11).
- Obtain a PCBWay quote for U3 + Y1 assembly (`u3-sourcing.md`, "What task 11
  must obtain").
- Open the vendor pages for the lines marked "not captured" or "listed" on the
  day of ordering: R7/R8 stock, C19/C20 stock, C7-C18 price. All commodity
  parts.
- Confirm U6's NRND status with Silergy.
- Closed in the fix round: the SP3019 datasheet (committed, md5
  54393f118f8c7b7301cd09a710708d61), and the TI documents.
