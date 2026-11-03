# Deferred minor findings of tasks 1 to 9, for the whole-branch review

The ledger holds 35 lines marked `minor (deferred` (the controller counted 32),
plus the minors of the two task 9 reviews. All are collected here once, with a
proposed disposition: **R** resolved (here or earlier), **T11** / **T12** owned by
that task, **S** substantive (touches what the board is or what a document
claims about a source), **D** documentation wording. Nothing in this list stops
the board being ordered; S1 and S2 need a decision.

## Substantive

| # | Where | Finding |
|---|---|---|
| S1 | task 6, `netlist.yaml:1291-1292` (U8 `source`) | **Provenance error.** U8's ESD rating is cited as "+/-10 kV contact / +/-15 kV air IEC 61000-4-2" against the committed SP3019 PDF, whose page 1 says "+22 kV / -10 kV contact, +22 kV / -10 kV air". The claim is more conservative than the part, but the citation is wrong, which is the failure mode that cost this project time before. Fix in `netlist.yaml`, regenerate. (USBLC6 at line 1330 reads "8 kV contact / 15 kV air": check against DS4260 in the same pass.) |
| S2 | task 5, `netlist.yaml` (crystal `drive_level`) | The threshold is arithmetically inconsistent: C0 3 pF + CL_total about 21 pF is 24 pF, which gives about 1.06 V p-p, not the 1.2 V p-p in the note (13 % high in volts, 28 % in power); and it is measured at the CKXTAL1 node, whose shunt capacitance is about 31 pF, so the real limit is nearer 0.8-0.9 V p-p. A first-build measurement item, not a layout one. |
| S3 | task 6 | `[SLYT118]` quoted words "some form of VBUS surge current limiting" are not in the document (it says "Larger capacitors can be used if inrush limiting is provided"): a paraphrase marked as a quotation. |
| S4 | task 7, `scratch_drc_check.py` | The pass criterion counts neck-to-pad violations only, not neck-to-other-track. Superseded in effect by the rule area and `AU_OVERHANGS`; confirm nothing else relies on it. |
| S5 | task 8 | The impedance of the B.Cu USB 2.0 stretch over the 0.6 mm In2 gap is not calculated (the gap raises it, the pour 0.3 mm away lowers it). Covered by accepted finding A3 (480 Mbit/s) and the first-build check, not by a number. |
| S6 | task 9 review 1 | `route_grid.py` produced saw-tooth (146 of 181 DVDD10_UPS segments under 0.08 mm) and 33-35 mm stub lines to TP6 / TP7; the buck return U6.2 to C3.2 is 0.3 mm wide under the body, loop about 5-6 mm². Layout quality, no rule broken; the loop is the thing to check in an emissions scan. |
| S7 | task 9 re-review M4, M6 | C14's return loop is longer than its distance (nearest GND via 3.17 mm from C14 pad 2; a GND via at C14.2 would shorten it). The 0.56 / 0.3 mm via has a 0.13 mm annular ring: ask PCBWay about the ring, not only list the size (T11). |
| S8 | task 9 re-review M2, M3 | TX to RX spacing in U8's channel is 0.505 mm, TX_CONN's straddle is 6.2 mm of extent: recorded as accepted findings A2 and A1 here. Update ruling AS's risk record to these figures. |

## Resolved

| # | Where | Finding | How |
|---|---|---|---|
| R1 | task 9 re-review M5 | `hardware/kicad/~raccoon-tap.kicad_pro.lck` committed | Removed from the index, `*.lck` added to `.gitignore` (this task). |
| R2 | task 8 | No suite test that the USB 2.0 return vias exist | `check_fab_release.py` holds ruling AR: one In2 boundary, a GND via on each side of the crossing standing in the B.Cu pour and in the In1 plane, with a mutation test. There are two flank vias now, not four. |
| R3 | task 5 | `test_missing_footprint_fails` only failed because of the footprint count difference to the stale PCB | Re-verified on the routed board: the unmutated board has no connectivity failure, the C21 to C99 rename produces exactly the "PCB has exactly the N netlist components" failure. |
| R4 | task 9 re-review M1, M7 | USB2_D_N over D+'s antipad hidden by `reference_gaps()` exempting the partner's holes; coupling reported at "0.6 mm or more" understates the out-of-window length | The new checks exempt only a track's own hole and the one named D- over D+ via; coupling is judged by the impedance window. |
| R5 | task 2 | README does not say task 10 compares by category and finding id, not the 76.0 aggregate | Done in this directory's `README.md`. |
| R6 | task 1 | Tooling note lists `route_pcb.py` as a KIPY user before it existed | It exists now. |

## Documentation (task 12 unless marked)

| # | Where | Finding |
|---|---|---|
| D1 | task 1 | Examples in the tooling note write to `/tmp` instead of `$TMPDIR`. |
| D2 | task 1 | The note names `str \| None`; the real failure site is `list \| None` in `sexp_parser.py:115`. |
| D3 | task 2 | Baseline README: point 11 counted as "found" though a coincidence; process noise in a project document; `analyze_schematic.py ~line 8743` reference is brittle; trust section does not say ERC 0 / DRC 0 are equally blind to points 1-10; committed JSONs hold absolute `/Users/<operator>` paths (so do the ones in this directory); Tj 69.8 °C in the header table lacks "U4 only, placeholder"; the point 12 table row has line breaks that break GFM rendering (README lines 139-147); "built-in defaults" is a little stronger than the probe shows. |
| D4 | task 3 | Table 11 cross-check regex is brittle (closes fine today); the verdict points at a `.superpowers/` path that is not permanent, does not say `extract_datasheet.py` was replaced (so there is no `extracted/*.json` with a quality score), the `.gitattributes` proof has no control group, and "Realtek does not publish this datasheet" has no source. |
| D5 | task 4 | `check_kicad.py:41-42` docstring promises a `KNOWN_GAPS` procedure the code does not have, plus an orphaned PoE comment at :66-67; tests hard-wire board facts (3 zones, 33 components, zone-mutation text patterns) that drift now the PCB is hand-maintained; `test_net_name_missing_from_netlist_fails` overlaps `test_pad_on_unknown_net_name_fails`. |
| D6 | task 6 | `netlist.yaml:638-641` `feed_forward` still says the SY8089 datasheet is not in `hardware/datasheets`; `design_notes.esd_protection` has "U8 PIN MAP, PROVENANCE" spliced into the "LAYOUT (for tasks 8 and 9)" line; `bom.csv` still lists Y1 as an ordinary hand-assembly row (T11: mark it as PCBWay's). |
| D7 | task 7 | "Only entries 1-3 of 112 are 1OZ/1OZ" is unsupported (only 1-3 are excerpted); "it shortens the neck that is needed" for outer-end routing was never measured ("may shorten"); the 111.9 Ω as-built disclosure does not say that is about +24 % (USB3) and +12 % (MDI) outside the ±10 % window; the PCBWay excerpt "after printing three times or more the impedance no longer changes" is not covered by the table (open item 1 should say three or more); `stackup-note.md` neck wording (ruling AI, from pad centre) for task 12. |
| D8 | task 8 | "The only reading that fits" for the 0.33 / 3.33 mm span is a little strong (the disclosure itself is honest). |
| D9 | task 9 review 1 | Routing order deviates from the plan (low speed before supplies); the claim "the only place AU applies outside the area" is wrong (7 more overhangs of 0.03-0.22 mm, now bounded by `AU_OVERHANGS` and ruling BQ); `route_pcb.py:1014` dead code; the README below the board images still describes the HAT (65 × 56 mm, 2 layers); ruling BM's "parking spot" pattern for C27 to be documented in `gen_pcb.py` and the placement README. |
