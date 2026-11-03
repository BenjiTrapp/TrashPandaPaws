# raccoon-tap — pre-routing analysis baseline (2026-10-31)

This directory records what the `raccoon-tap` board (4-layer USB 3.0 to Gigabit
Ethernet adapter) looked like to automated review **before** the fabrication
push: fully placed, **zero routed tracks**. Later review runs are compared
against it. Nothing here modifies the design.

Measured design state (SHA-256 of the analysed files, also embedded in
`schematic.json` / `pcb.json` under `inputs.source_hashes`):

| File | SHA-256 |
|---|---|
| `hardware/kicad/raccoon-tap.kicad_sch` | `229f53c3af072502c8a704d84e78a2eaf4885462465e24b82364286f14c236c6` |
| `hardware/kicad/raccoon-tap.kicad_pcb` | `b19ab3fbf800c633db42e86e3f9f661ce089e10e63f6fa09532e575cd261b69a` |

Repository HEAD when measured: `488a952`.

The analyzers write the absolute path of the file they were given into
`inputs.source_files` and as the keys of `inputs.source_hashes`. As first
committed, `schematic.json` and `pcb.json` (and the same files in the later
review directories) therefore carried the operator's home directory. They now
carry the repository-relative form (`hardware/kicad/raccoon-tap.kicad_pcb`):
`hardware/tools/relativize_paths.py` removed the repository-root prefix and
nothing else (18 occurrences in 10 files; every number, finding and hash is
byte-identical), and `hardware/tools/run_kicad_happy.sh` runs the analyzers
and applies it, so a run on another machine yields the same files. The
commands below are the analyzers' own; use the script for anything that is to
be committed.

**How later runs compare against this baseline.** By finding category and rule
id (for example `RT-001`, `DC-003`, `PM-002`), not by the aggregate EMC score of
76.0: that score came from a run in which only 5 of 18 categories could run, so
a later score is not like-for-like (see the EMC caveat below). The routed run's
`../2026-11-03-routed/README.md` is laid out that way.

## Files

| File | Producer |
|---|---|
| `schematic.json` | `kicad/scripts/analyze_schematic.py` |
| `pcb.json` | `kicad/scripts/analyze_pcb.py --full --stage layout` |
| `cross.json` | `kicad/scripts/cross_analysis.py` |
| `emc.json` | `emc/scripts/analyze_emc.py` (target: FCC Part 15 Class B) |
| `thermal.json` | `kicad/scripts/analyze_thermal.py` |
| `erc.rpt` | `kicad-cli sch erc --severity-all` |
| `drc.rpt` | `kicad-cli pcb drc --severity-all` |
| `capability_mode.json` | written by the analyzers: records that datasheet extraction was unavailable and LLM review disabled |

## Reproducing

From the repository root, with the interpreters documented in
`hardware/OPEN_QUESTIONS.md` (`### kicad-happy`); `KH` is Homebrew Python 3.12.

```sh
R=hardware/review/2026-10-31-baseline
S=vendor/kicad-happy/skills
KH=/opt/homebrew/bin/python3.12
$KH $S/kicad/scripts/analyze_schematic.py hardware/kicad/raccoon-tap.kicad_sch --output $R/schematic.json
$KH $S/kicad/scripts/analyze_pcb.py hardware/kicad/raccoon-tap.kicad_pcb --full --schematic $R/schematic.json --stage layout --output $R/pcb.json
$KH $S/kicad/scripts/cross_analysis.py -s $R/schematic.json -p $R/pcb.json --output $R/cross.json
$KH $S/emc/scripts/analyze_emc.py -s $R/schematic.json -p $R/pcb.json --output $R/emc.json
$KH $S/kicad/scripts/analyze_thermal.py -s $R/schematic.json -p $R/pcb.json --output $R/thermal.json
kicad-cli sch erc --severity-all --output $R/erc.rpt hardware/kicad/raccoon-tap.kicad_sch
kicad-cli pcb drc --severity-all --output $R/drc.rpt hardware/kicad/raccoon-tap.kicad_pcb
```

## Metrics

| Metric | Value | Source / note |
|---|---|---|
| Footprints | 33 | `pcb.json` statistics; 32 SMD + 1 through-hole (J2) |
| Track segments | 0 | `pcb.json` statistics |
| Vias | 41 | 40 on GND, 1 on SHIELD; all through vias 0.6/0.3 mm; all dangling, see below |
| Zones | 3 | GND on B.Cu, GND on In1.Cu, +3V3 on In2.Cu; none filled yet |
| Unconnected items | 134 | `drc.rpt`; expected, board is unrouted |
| DRC errors | 0 | `drc.rpt` violation list holds no error-severity entries |
| DRC warnings | 43 | 41 `via_dangling`, 2 `silk_over_copper` (J2 shield pads) |
| ERC errors | 0 | `erc.rpt` (0 warnings); **with four checks ignored**, see caveats |
| EMC risk score | 76.0 / 100 | 0 = worst, 100 = best; 29 findings (2 error, 22 warning, 5 info); see caveat |
| Highest junction temperature | 69.8 °C | **U4 only, placeholder load** (AP2112K-3.3 LDO, assumed 105 mA, 25 °C ambient); U3 not modelled; see caveat |
| Schematic analyzer findings | 27 | 2 error, 3 warning, 22 info |
| PCB analyzer findings | 51 | 28 error, 1 warning, 22 info (26 of the errors are `RT-001` unrouted nets) |
| Cross-analysis findings | 0 | 6 of 10 checks ran, 4 skipped for lack of tracks |
| Thermal score | 100 / 100 | 1 of 2 candidate parts assessed |

The 41 dangling vias and 134 unconnected items are the direct consequence of an
unrouted board. They are not defects and should fall to zero once routing is
done; any value other than zero after routing is a real finding.

The one DRC detail worth reading is that the 134 unconnected items are written
to `drc.rpt` with "error" severity but are counted separately from the 43
violations, which is why "DRC errors" is 0 and "unconnected items" is 134.

### Caveats on individual numbers

- **Zones = 3.** `pcbnew` (`len(list(board.Zones()))`) and the analyzer both
  say 3. Counting the string `(zone` in the board file by text gives 4, because
  `(zone_connect 2)` also matches; do not count zones that way.
- **EMC score 76.0 comes from a partly blind run.** Only 5 of the 18 EMC check
  categories ran (ground plane, decoupling, I/O filtering, emission estimate,
  switching). Everything that needs copper (return paths, crosstalk,
  differential-pair skew, PDN, board edge) was skipped. The tool's own
  regulatory-coverage table rates radiated-emission coverage as "minimal".
  Twenty of the 22 warnings are `DC-003` ("decoupling cap far from via"), which
  measures distance to the nearest via on a board that has no tracks yet; they
  say little about the final layout. Expect the score to move when tracks exist.
- **Highest Tj 69.8 °C covers one part only.** Of two candidates the thermal
  analyzer assessed U4 and skipped U6 (below its minimum dissipation). U3, the
  RTL8153B, which dissipates the most, was not modelled at all. The U4 figure
  rests on an assumed 105 mA load (the schematic power budget uses 10 mA) and
  the default Tj,max of 125 °C. Treat it as a placeholder, not a thermal sign-off.
- **ERC 0 means "0 with four checks disabled".** `erc.rpt` ends with an
  `** Ignored checks:` block naming: *Global label only appears once in the
  schematic*, *Four connection points are joined together*, *SPICE model issue*,
  and *Assigned footprint doesn't match footprint filters*. These are not set
  in the project: `hardware/kicad/raccoon-tap.kicad_pro` has no `erc` section at
  all (its `rule_severities` entries belong to DRC), so they are most
  likely KiCad 10's built-in default severities. Consistent with that,
  `kicad-cli sch erc` on a copy of the schematic with no project file ignores
  the same four; that run does not rule out a KiCad user-level configuration
  on this machine, which was not inspected. To
  see what they would say, a scratch copy of the project was given an `erc`
  section setting those four to `error`; `kicad-cli` then reported "Ignored
  checks: None" and still 0 violations, so on today's schematic the ignored
  checks hide nothing. That result is for this schematic only; it is not
  recorded in a committed file. The footprint-filter check is silent here
  for a further reason: no symbol in `raccoon.kicad_sym` or the schematic
  defines `ki_fp_filters`, so there is nothing for it to compare.
- **Datasheet-backed checks did not run.** `capability_mode.json` shows
  `datasheet_extraction: unavailable`, datasheet coverage 0 %, and no schematic
  finding is `datasheet_backed`. The component lifecycle audit was not run
  (needs network and distributor API keys). `ngspice` is not installed; none of
  the five analyses above depend on it, so nothing degraded from that, but the
  SPICE simulation skill is unavailable.

## What the toolkit found on its own — and what it missed

The list of known open issues (design-spec §7.4 of the fabrication-release
plan) has **12 entries**. Each was searched for in the analyzer output before
anything was changed.

Verdict key: **found** = a finding names the problem; **partial** = a finding
shows a symptom or part of it, without diagnosing it; **missed** = no finding
touches it; **coincidental** = a finding fires, but for a reason unrelated to
the defect, so it is not counted as found.

| # | Known issue | Verdict | Evidence |
|---|---|---|---|
| 1 | U3 supply/regulator pin numbers unconfirmed (`3b`) | **missed** | No finding about U3 pin assignment. `ic_pin_analysis` simply takes the pin names and numbers from the schematic symbol as given. The only related output is the generic `DS-001` (error): "No datasheets directory found and no BOM parts have MPNs. Review is a consistency check only — manufacturer specs cannot be verified." The tool is honest that it cannot check this, but does not point at U3. |
| 2 | 21 µF bulk on VBUS vs the 10 µF USB limit | **missed — and actively reassuring** | The tool computes the right number (`usb_compliance…vbus_capacitance_detail.total_uf = 21.2`) and then reports `"vbus_capacitance": "pass"`. The check (in `analyze_schematic.py`, the code that sets `conn_checks["checks"]["vbus_capacitance"]`) only has a *lower* bound (warns below 1 µF); there is no upper bound. `inrush_analysis` covers only the regulator outputs (U4, U6), not VBUS. |
| 3 | No ESD protection on D+/D− and the SuperSpeed pairs | **found** | `EP-AUD-j3` (info): "ESD audit J3 (generic): none coverage", `unprotected_nets` = USB2_D_N, USB2_D_P, USB3_RX_N, USB3_RX_P, USB3_TX_N, USB3_TX_P. `EP-AUD-j2` (info) says the same for the RJ45. `UC-002:j3` (warning): "No ESD/TVS protection on VBUS at J3". `emc:IO-001:j3` (error): "no ferrite bead, CM choke, or ESD protection within 25mm". Severity is under-weighted: the audit itself is only "info". |
| 4 | USB-A SSTX/SSRX host/device naming (`usb3_crossover`) | **missed** | The only crossover check in the toolkit is the UART TX→RX one. J3 is even mis-classified as a UART debug connector in `test_coverage` (its USB3 TX/RX nets are listed under category `uart`). |
| 5 | Differential-pair width/spacing are placeholders (`3g`) | **missed** | `pcb.json` reads the net classes (MDI 0.18/0.25 mm, USB3 0.20/0.20 mm) and reports `design_rule_compliance.compliant: true`. No impedance calculation. `emc.json` `board_info.has_stackup: false` records that no stackup is known, but no finding raises it. |
| 6 | In2 is one solid +3V3 plane, must be split into +5V/+3V3/+1V0 islands | **partial (incidental)** | `RT-001` flags `+5V` ("Unrouted net +5V (12 pads)") and `+1V0` ("Unrouted net +1V0 (16 pads)") but not `+3V3`, because the single full-board +3V3 zone on In2 counts as routing for it. That is the right signal for the wrong reason: the same `RT-001` fires for every other net and will go quiet as soon as any copper touches those nets, whether or not an island exists. Do not rely on it after routing. |
| 7 | J2 orientation: RJ45 opening must face the board edge | **missed** | No finding. J2 is at (148, 96) mm, rotation 180°, courtyard to x = 156.2 mm against a board edge at 158 mm; the tool does not evaluate mating-face direction. (The one placement-vs-edge check, `PM-002`, fired on J3, see noise below.) |
| 8 | `SHIELD` net decision (direct GND vs 1 nF ∥ 1 MΩ) | **partial** | The consequence is visible: `connector_ground_audit` (warning) "Connector J2 has no ground pins (16 pins)", `emc:IO-002:j2` (warning) "Insufficient ground pins on J2", and `EP-AUD-j2` lists `SHIELD` among the unprotected nets. The cause — that `SHIELD` is a separate net with only J2's SH1/SH2 on it while J3's shell is tied to `GND` — is never stated, and the recommendation ("Add ground pin(s)") presumes the answer to the open design decision. |
| 9 | Y1: no crystal selected, placeholder footprint, C19/C20 `TBD` | **partial** | `SS-001` and `missing_mpn` list Y1 among the 33 parts without an MPN. Nothing about the placeholder footprint. The load-cap check takes the 39 pF values at face value: `DO-DET-y1` "Crystal load cap Y1 = 22.5pF", `in_typical_range: true`. The `TBD` status lives in `netlist.yaml`, which the toolkit does not read, so the tool signs off a placeholder. |
| 10 | LED polarity assumption (`led_polarity`) | **missed** | No finding mentions the LED nets (`ETH_LED0/1`, `LED_G_A`, `LED_Y_A`) beyond listing them as unrouted (`RT-001`) and unprotected (`EP-AUD-j2`). |
| 11 | BOM: 10 of 19 lines have no part number | **coincidental** (not counted as found) | `SS-001:c1` (error): "Sourcing blocker: BOM has <50% MPN coverage (0/17 unique parts). Board is not pre-fab ready." `DS-001` (error), `bom_lock.status: fail`. The tool reports 0 MPNs because the MPNs live in `netlist.yaml`/`bom.csv`, not in the schematic's symbol fields, so it would say the same for a BOM with every number filled in. It did not find the ten lines that lack one; it found that it cannot see MPNs at all. |
| 12 | U3 footprint `QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm` resolves in the installed library | **missed** | The analyzer reads the copy embedded in the board file; it does not look the footprint up in a library. Separately (not a toolkit result): the file exists at `…/KiCad.app/Contents/SharedSupport/footprints/Package_DFN_QFN.pretty/QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm.kicad_mod`, and `kicad-cli pcb drc` reports "Found 0 Footprint errors". ERC's silence on the filter check (*Assigned footprint doesn't match footprint filters* is one of the four ignored checks, see caveats) says nothing about this item: that check compares a footprint against a symbol's `ki_fp_filters` (none are defined here), not against the library. The check that does test resolution is `footprint_link_issues`, which is not ignored: the real ERC run raised nothing for U3's `Package_DFN_QFN:QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm`, and in the no-project probe it fired only for J2's unconfigured `raccoon` library, never for U3, so the check was live and U3's link resolved. The analyzer's `TV-001` (U3 thermal vias 9/9) shows it parsed the embedded footprint correctly. |

**Score: 1 found outright (3), 3 partial (6, 8, 9), 7 missed (1, 2, 4, 5, 7, 10, 12), 1 coincidental (11, not counted).**

### What this means for trusting the toolkit

- The toolkit is **good at what can be read off the topology**: missing ESD
  parts, missing MPNs, unrouted nets, tombstoning, thermal-via counts. Where it
  reports these it is deterministic and the numbers check out.
- It is **blind to everything that needs a datasheet, a stackup or domain
  intent**: pin assignments, USB host/device naming, impedance, LED polarity,
  mating-face orientation, plane partitioning. A clean toolkit report on these
  is *absence of a check*, not evidence of correctness.
- It can be **actively wrong in the reassuring direction**: item 2 (21 µF VBUS
  passes) and item 9 (placeholder crystal caps "in typical range").
  A `pass` in the toolkit output must not be read as a sign-off for any of the
  twelve items above without a human check against the datasheet.
- Items 1, 2, 4, 5, 7, 10 and 12 need to be verified by direct inspection, not
  by re-running the toolkit and waiting for a finding.
- **The same holds for KiCad's own ERC and DRC.** "ERC 0, DRC 0" says nothing
  about items 1 to 10 either: ERC checks the schematic's internal consistency
  (it cannot know a pin number is wrong against a datasheet) and DRC checks
  geometry against rules (it cannot know a pair should be 90 Ω). A zero from
  either is the absence of a check, exactly as for the toolkit.

### Noise to expect when reading later reports

- `PM-002:j3` (error) "J3 courtyard overhangs board edge by 15.75mm": J3 is a
  plug that is meant to protrude, so this is intended. Unless the board outline
  changes it will keep firing.
- `RS-001:sw_1v0` (warning) "SW_1V0 has no declared source": SW_1V0 is the
  U6 switch node, not a rail.
- `emc:IO-001` (error) for J2: the RJ45 has integrated magnetics; the filter
  detector cannot see them.
- `design_intent.detection_signals` says "5-layer board detected"; the board has
  four copper layers (F.Cu, In1.Cu, In2.Cu, B.Cu).
- `power_budget` assumes 10 mA per IC, `thermal` assumes 105 mA for U4; the two
  disagree and neither is from a datasheet.

### Genuine findings that are not on the known-issue list

- `FD-001` (error): no fiducials on F.Cu with 32 SMD parts and fine-pitch QFN;
  assembly needs at least three.
- `silkscreen`: no board name and no revision marking; J2/J3 unlabelled.
- `pcb.json` `vias.via_analysis.via_in_pad`: nine 0.3 mm through vias sit in
  U3's exposed pad. The analyzer rates the thermal-via count adequate (`TV-001`,
  9/9) but raises nothing about open via-in-pad and solder wicking; whether the
  fab will fill or tent them is a fabrication-data decision.
- `TE-001` (warning): 0 of 25 signal nets have test points.
