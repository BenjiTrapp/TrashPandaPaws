# U3 (RTL8153B-VB-CG) pinout verdict

**Verdict: `belegt` (established).** All 40 pin numbers and the exposed pad
(pin 41) are taken from Realtek's own datasheet, as found in three
copies of the PDF. Every pin agrees across all three copies, and each one
matches `hardware/netlist.yaml` as of commit `7e2c564`.

The gate (spec §5.3) concludes at **Stage 1**: the datasheet itself was
obtained. Stage 2 (two independent secondary sources) was not needed, and
Stage 3 (halt) does not apply. No pin in this document is inferred.

Date: 2026-11-01. Task 3 of the raccoon-tap fabrication plan.

## 1. Sources

All three files are in `hardware/datasheets/`.

| Key | File | Rev | MD5 | Pages |
|---|---|---|---|---|
| **[DS14]** | `RTL8153B-VB-CG_rev1.4_lcsc-datasheet.pdf` | 1.4, 16 March 2018 | `ada97c6b3441cbea983d8c8e2dbac259` | 34 |
| [DS14b] | `RTL8153B-VB-CG_rev1.4_oneyac.pdf` | 1.4, 16 March 2018 | `7dad2ab144f08ad97bcc18a8358b9a97` | 35 |
| [DS10] | `RTL8153B-VB-CG_rev1.0_elecfans.pdf` | 1.0, 27 January 2016 | `da71cc8baf23e63b442aea97f042f3fc` | 33 |

**Checking the part and variant.** The cover page of each file reads
`RTL8153B-VB-CG`, "Integrated 10/100/1000M Ethernet Controller for USB 3.0
Applications", `Track ID: JATR-8275-15`. That is the exact document the
`netlist.yaml` header cites as `[RTL-DS]`, "rev 1.4, Track ID JATR-8275-15".
Figure 1 shows the 40-pin package marked `RTL8153B`. This is the VB variant in
QFN-40. It is not the RTL8153VC in QFN-48 used by Olimex.

**How independent are the copies?** Not very, and this matters less than it
might seem. All three carry the same distribution watermark ("CONFIDENTIAL for
Haoliyuan Electronic (shenzhen) Co., Ltd"). The two rev 1.4 files have the
same PDF creation date (2018-03-07). They are one Realtek document, re-hosted
by different sites, and [DS14b] adds a "Downloaded From Oneyac.com" stamp.
These are not independent witnesses in the Stage 2 sense. They do not need to
be. This is the primary manufacturer source, and Stage 1 asks for exactly
that. The extra copies are useful in a different way: they show the text
extracted the same way from two separately hosted files, and that the pin
numbers did not change between rev 1.0 and rev 1.4.

**Revision note.** In [DS14], the cover page, the revision history and pages
i–iv say "Rev. 1.4". The body page footers from printed page 4 on still say
"Rev. 1.3". The revision history explains why: rev 1.4 (2018/03/16) only
"Revised section 5.6 Regulator and Reference Pins, page 6 (REGOUT and ENSWREG
descriptions)", so the body footers were never updated. This has no effect on
pin numbers. Rev 1.0 has the same numbers for all 41 pins.

**Where things are in [DS14]** (printed page / PDF page):

| Content | Printed page | PDF page |
|---|---|---|
| §4 Figure 1 "Pin Assignments" (package drawing, pins 1–40) | 4 | 10 |
| §5 Tables 1–3 (Power Mgmt, SPI Flash, EEPROM) | 5 | 11 |
| §5 Tables 4–6 (Transceiver, Clock, Regulator and Reference) | 6 | 12 |
| §5 Tables 7–9 (LED, Power and Ground, GPIO) | 7 | 13 |
| §5 Table 10 (USB Interface); §5.11 Table 11 (Shared Pin Modes) | 8 | 14 |

A render of Figure 1 from [DS14] PDF page 10 is committed as
`hardware/datasheets/RTL8153B-VB-CG_rev1.4_fig1_pin_assignments.png`.

## 2. How each pin was established

Each pin is supported by two separate kinds of evidence inside [DS14]:

1. **The §5 pin-description tables**, parsed by machine. Running
   `python3 hardware/datasheets/crosscheck_u3_pinout.py` from the repo root
   runs `pdftotext -raw` on all three PDFs and builds a pin → symbol map from
   §5 Tables 1–10 of each. It then requires all of the following:
   - every pin 1–41 appears in every PDF;
   - the three maps are identical;
   - no PDF and no netlist entry contains a pin outside 1–41;
   - the `netlist.yaml` name for each pin is one of the datasheet symbols for
     that pin;
   - a pin carries more than one symbol only if the datasheet's own §5.11
     Table 11 lists it as shared.

   The script exits 0 only if every condition holds. Running it with
   `--selftest` feeds it seven deliberately corrupted inputs: a pin moved in
   one PDF, a pin moved the same way in all PDFs, a lost row, a lost wrapped
   continuation line, a stray extra symbol, two netlist pins swapped, and a
   netlist pin 42. It requires every one of them to fail. All seven do (see
   `.superpowers/sdd/2026-10-31-raccoon-tap-fab-release/task-3-report.md`).
2. **Figure 1, read by eye.** I rendered the page and read pins 1–40 off the
   package drawing. They match the tables for every pin. Figure 1 does not
   number the exposed pad, so pin 41 rests on Table 8 alone.

`OPEN_QUESTIONS.md` 3b gives this as the reason the power pins were left open:
"the pin-assignment figure did not extract cleanly from the PDF". That is true
of the figure, because the raw text extraction of Figure 1 is scrambled. It is
not true of the tables. Table 8 extracts as clean rows. The figure has now also
been read directly from the rendered page, as 3b asked.

## 3. Pin table

Column guide:

- **Datasheet symbol(s):** every symbol [DS14] §5 gives for that pin.
- **netlist.yaml name:** the value at `components.U3.pins.<n>.name` in commit
  `7e2c564`.
- **[DS14] §5 row:** the table number and the row exactly as `pdftotext -raw`
  prints it (Symbol, Type, Pin No).
- **Fig. 1:** the label printed next to that pin number in Figure 1.

[DS14b] and [DS10] give the same numbers for every row (crosscheck output).
**★** marks the nine critical supply and regulator signals from spec §7.4 and
`OPEN_QUESTIONS.md` 3b.

| Pin | Datasheet symbol(s) | netlist.yaml name | [DS14] §5 row (verbatim) | Fig. 1 | Status |
|---:|---|---|---|---|---|
| 1 | MDIP0 | MDIP0 | Table 4: `MDIP0 IO 1` | MDIP0 | ✅ |
| 2 | MDIN0 | MDIN0 | Table 4: `MDIN0 IO 2` | MDIN0 | ✅ |
| 3 ★ | AVDD10 | AVDD10 | Table 8: `AVDD10 P 3, 8, 37` "Analog 1.0V Power Supply." | AVDD10 | ✅ |
| 4 | MDIP1 | MDIP1 | Table 4: `MDIP1 IO 4` | MDIP1 | ✅ |
| 5 | MDIN1 | MDIN1 | Table 4: `MDIN1 IO 5` | MDIN1 | ✅ |
| 6 | MDIP2 | MDIP2 | Table 4: `MDIP2 IO 6` | MDIP2 | ✅ |
| 7 | MDIN2 | MDIN2 | Table 4: `MDIN2 IO 7` | MDIN2 | ✅ |
| 8 ★ | AVDD10 | AVDD10 | Table 8: `AVDD10 P 3, 8, 37` | AVDD10 | ✅ |
| 9 | MDIP3 | MDIP3 | Table 4: `MDIP3 IO 9` | MDIP3 | ✅ |
| 10 | MDIN3 | MDIN3 | Table 4: `MDIN3 IO 10` | MDIN3 | ✅ |
| 11 ★ | AVDD33 | AVDD33 | Table 8: `AVDD33 P 11, 20, 39, 40` "Analog 3.3V Power Supply." (the list wraps over two lines in the PDF) | AVDD33 | ✅ |
| 12 | U3SSTXN | U3SSTXN | Table 10: `U3SSTXN O 12` | U3SSTXN | ✅ |
| 13 | U3SSTXP | U3SSTXP | Table 10: `U3SSTXP O 13` | U3SSTXP | ✅ |
| 14 | U3VDD10 | U3VDD10 | Table 8: `U3VDD10 P 14` "USB 3.0 1.0V Power Supply." | U3VDD10 | ✅ |
| 15 | U3SSRXN | U3SSRXN | Table 10: `U3SSRXN I 15` | U3SSRXN | ✅ |
| 16 | U3SSRXP | U3SSRXP | Table 10: `U3SSRXP I 16` | U3SSRXP | ✅ |
| 17 | U2DM | U2DM | Table 10: `U2DM IO 17` | U2DM | ✅ |
| 18 | U2DP | U2DP | Table 10: `U2DP IO 18` | U2DP | ✅ |
| 19 | U2VDD10 | U2VDD10 | Table 8: `U2VDD10 P 19` "USB 2.0/USB 1.1 1.0V Power Supply." | U2VDD10 | ✅ |
| 20 ★ | AVDD33 | AVDD33 | Table 8: `AVDD33 P 11, 20, 39, 40`; also Table 6: `AVDD33 P 20` "Linear Regulator (LDO) 3.3V Output." (see §5) | AVDD33 | ✅ |
| 21 ★ | VDD5 | VDD5 | Table 8: `VDD5 P 21` "Analog 5.0V Power Supply." | VDD5 | ✅ |
| 22 ★ | DVDD10_UPS | DVDD10_UPS | Table 8: `DVDD10_UPS P 22` "Digital 1.0V Uninterruptible Power Supply."; also Table 6: `DVDD10_UPS P 22` "Linear Regulator (LDO) 1.0V Output." (see §5) | DVDD10_UPS | ✅ |
| 23 ★ | DVDD33 | DVDD33 | Table 8: `DVDD33 P 23, 33` "Digital 3.3V Power Supply." | DVDD33 | ✅ |
| 24 | EEDO, GPIO, LANWAKEB, LED2, SPISDO | LED2 | Table 7: `LED2 O 24`; Table 1: `LANWAKEB D 24`; Table 2: `SPISDO I 24`; Table 3: `EEDO I 24`; Table 9: `GPIO IO 24`; Table 11 lists pin 24 as shared | EEDO/LED2/SPISDO/LANWAKEB/GPIO | ✅ shared, see §4 |
| 25 | EEDI, ENSWREG, SPISDI | ENSWREG | Table 6: `ENSWREG I 25`; Table 2: `SPISDI O 25`; Table 3: `EEDI IO 25`; Table 11 lists pin 25 as shared | EEDI/SPISDI/ENSWREG | ✅ shared, see §4 |
| 26 | VDDREG33 | VDDREG33 | Table 6: `VDDREG33 P 26` "Digital 3.3V Power Supply for Switching/LDO Regulator." | VDDREG33 | ✅ |
| 27 | VDDREG5 | VDDREG5 | Table 6: `VDDREG5 P 27` "Digital 5V Power Supply for Switching/LDO Regulator." | VDDREG5 | ✅ |
| 28 ★ | REGOUT | REGOUT | Table 6: `REGOUT O 28` "Switching/LDO Regulator 1.0V Output." | REGOUT | ✅ |
| 29 ★ | GND | GND | Table 8: `GND P 29` "Ground."; also Table 6: `GND P 29` "Switching/LDO Regulator GND." | GND | ✅ |
| 30 | EESK, LED1, SPISCK | LED1 | Table 7: `LED1 O 30`; Table 2: `SPISCK O 30`; Table 3: `EESK O 30`; Table 11 lists pin 30 as shared | EESK/LED1/SPISCK | ✅ shared, see §4 |
| 31 | EECS | EECS | Table 3: `EECS O 31` | EECS | ✅ |
| 32 | LED0, SPICSB | LED0 | Table 7: `LED0 O 32`; Table 2: `SPICSB O 32`; Table 11 lists pin 32 as shared | LED0/SPICSB | ✅ shared, see §4 |
| 33 ★ | DVDD33 | DVDD33 | Table 8: `DVDD33 P 23, 33` | DVDD33 | ✅ |
| 34 ★ | DVDD10 | DVDD10 | Table 8: `DVDD10 P 34` "Digital 1.0V Power Supply." | DVDD10 | ✅ |
| 35 | CKXTAL1 | CKXTAL1 | Table 5: `CKXTAL1 I 35` | CKXTAL1 | ✅ |
| 36 | CKXTAL2 | CKXTAL2 | Table 5: `CKXTAL2 IO 36` | CKXTAL2 | ✅ |
| 37 ★ | AVDD10 | AVDD10 | Table 8: `AVDD10 P 3, 8, 37` | AVDD10 | ✅ |
| 38 ★ | RSET | RSET | Table 6: `RSET I 38` "Reference (External Resistor Reference)." | RSET | ✅ |
| 39 ★ | AVDD33 | AVDD33 | Table 8: `AVDD33 P 11, 20, 39, 40` | AVDD33 | ✅ |
| 40 ★ | AVDD33 | AVDD33 | Table 8: `AVDD33 P 11, 20, 39, 40` | AVDD33 | ✅ |
| 41 ★ | GND | GND | Table 8: `GND P 41` "Ground (Exposed Pad)." | not drawn (pad not numbered in Fig. 1) | ✅ |

### The nine critical signals, grouped

| Signal | Pins | [DS14] source |
|---|---|---|
| `AVDD10` | 3, 8, 37 | Table 8 row `AVDD10 P 3, 8, 37`; Fig. 1 |
| `AVDD33` | 11, 20, 39, 40 | Table 8 row `AVDD33 P 11, 20, 39, 40`; Table 6 row `AVDD33 P 20`; Fig. 1 |
| `DVDD10` | 34 | Table 8 row `DVDD10 P 34`; Fig. 1 |
| `DVDD33` | 23, 33 | Table 8 row `DVDD33 P 23, 33`; Fig. 1 |
| `VDD5` | 21 | Table 8 row `VDD5 P 21`; Fig. 1 |
| `REGOUT` | 28 | Table 6 row `REGOUT O 28`; Fig. 1 |
| `DVDD10_UPS` | 22 | Table 8 row `DVDD10_UPS P 22`; Table 6 row `DVDD10_UPS P 22`; Fig. 1 |
| `RSET` | 38 | Table 6 row `RSET I 38`; Fig. 1 |
| `GND` | 29, 41 | Table 8 rows `GND P 29` and `GND P 41` "(Exposed Pad)"; Table 6 row `GND P 29`; Fig. 1 (29 only) |

All nine have a source you can look up. **None of them is missing a pin
number.**

## 4. Multi-function pins (24, 25, 30, 32): expected, not a mismatch

The datasheet lists every function a shared pin can have. `netlist.yaml`
names only the function this design uses, and keeps the full label in its
`shared:` field. The check for these pins is therefore "the netlist name is one
of the datasheet symbols", not "the names are equal".

| Pin | Datasheet symbols | netlist `name` | netlist `shared` | Fig. 1 label |
|---:|---|---|---|---|
| 24 | EEDO, GPIO, LANWAKEB, LED2, SPISDO | LED2 | `EEDO/LED2/SPISDO/LANWAKEB/GPIO` | `EEDO/LED2/SPISDO/LANWAKEB/GPIO` |
| 25 | EEDI, ENSWREG, SPISDI | ENSWREG | `EEDI/SPISDI/ENSWREG` | `EEDI/SPISDI/ENSWREG` |
| 30 | EESK, LED1, SPISCK | LED1 | `EESK/LED1/SPISCK` | `EESK/LED1/SPISCK` |
| 32 | LED0, SPICSB | LED0 | `LED0/SPICSB` | `LED0/SPICSB` |

Table 11 (§5.11) also lists pin 31 (EECS) as shared. However, pin 31 has only
one symbol in Tables 1–10, so the netlist and datasheet use the same name
there. Table 11 calls pin 25 `EEDI/SPIDI` without ENSWREG. ENSWREG on pin 25
comes from Table 6 (`ENSWREG I 25`, "Power-On Latch Pin") and Table 3 Note 2
("Pin 25 is power-on latch pin for ENSWREG"), and Figure 1 shows it.

## 5. Not a pin-number question, but Task 5 should know

Table 6 (Regulator and Reference Pins) describes **pin 20 (`AVDD33`)** as
"Linear Regulator (LDO) 3.3V Output" and **pin 22 (`DVDD10_UPS`)** as "Linear
Regulator (LDO) 1.0V Output", each with "designed for RTL8153B-VB internal use
only". Table 8 lists the same pins as power supplies. `netlist.yaml` types both
as `power_in`. **The pin numbers are not in question.** Both tables give 20 and
22. What is open is the electrical role of these pins: whether 20 and 22 should
be driven from outside, or only decoupled. This verdict does not settle that.
It is noted here so that Task 5 does not miss it when it goes through the power
pins.

## 6. Contradiction resolved: `design-guide.md` §2.1 vs `OPEN_QUESTIONS.md` 3b

**The contradiction.** `hardware/OPEN_QUESTIONS.md` item 3b says the power and
regulator pin positions (`AVDD10`, `AVDD33`, `DVDD10`, `DVDD33`, `VDD5`,
`REGOUT`, `DVDD10_UPS`, `RSET`, `GND`) "are not yet confirmed" and "must be
read off the datasheet figure directly before the symbol is finalised. Do not
infer them." `hardware/design-guide.md` §2.1 still gives all of them a number
under the heading "Verified pinout".

**Resolution: §2.1 is correct.** Every number §2.1 gives for these nine signals
matches [DS14] §5 Table 8 / Table 6 and Figure 1:

| Signal | §2.1 | [DS14] |
|---|---|---|
| AVDD10 | 3, 8, 37 | 3, 8, 37 |
| AVDD33 | 11, 20, 39, 40 | 11, 20, 39, 40 |
| DVDD10 | 34 | 34 |
| DVDD33 | 23, 33 | 23, 33 |
| VDD5 | 21 | 21 |
| REGOUT | 28 | 28 |
| DVDD10_UPS | 22 | 22 |
| RSET | 38 | 38 |
| GND | 29, 41 (pad) | 29, 41 (pad) |

§2.1's other pins also match [DS14]: 40 of 40 plus the pad. `netlist.yaml`,
which follows §2.1, agrees on all 41 (crosscheck).

**Why this closes the matter.** 3b raised a doubt about where the numbers came
from, not about specific wrong values. It said the figure had not extracted
cleanly, so the numbers had not been checked against a source. That doubt is
now settled from the primary source, in two ways that do not depend on each
other:

1. the §5 tables, which extract as clean rows and agree across three copies
   and two revisions;
2. Figure 1, read from the rendered page as 3b asked.

§2.1 was never used as evidence. It was only compared against the datasheet.
So 3b's instruction "Do not infer them" has been followed: nothing was
inferred, and the numbers were read from the source. 3b's warning no longer
applies. It should be marked resolved, with a pointer to this document, when
Task 12 updates the documentation. This document does not edit
`OPEN_QUESTIONS.md` or `design-guide.md`.

**Not resolved here.** This document settles pin **numbers** only. These
remain open and depend on the same datasheet:

- the role of pins 20 and 22 (§5 above);
- the RSET resistor value (`netlist.yaml` `design_notes.rset`);
- the ENSWREG / 1.0 V rail choice (`OPEN_QUESTIONS.md` 3f);
- LED current direction ([RTL-DS] 6.2);
- the outdated DVDD12 reference.

## 7. For Task 5: how to use this document

- To check a pin number in `netlist.yaml` → `components.U3.pins`, compare
  against the **Pin** and **Datasheet symbol(s)** columns in §3. A
  `netlist.yaml` name must be one of the listed symbols. For pins 24, 25, 30
  and 32 it is the function the design uses (§4).
- To check the netlist again by machine after editing it, run
  `python3 hardware/datasheets/crosscheck_u3_pinout.py` from the repo root.
  Exit status 0 with `result: ALL 41 PINS AGREE` means the pin list still
  matches all three PDFs. Run it with `--selftest` to confirm the check can
  still detect errors.
- The crosscheck compares pin **names and numbers** only. It does not check
  the `type:` fields, nets, or anything outside `U3.pins`.
