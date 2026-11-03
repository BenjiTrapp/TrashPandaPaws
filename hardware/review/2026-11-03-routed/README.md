# raccoon-tap — verification of the routed board (task 10, 2026-11-03)

The chain that decides whether the board may be ordered, run on commit
`192cf12` plus this task's changes. Nothing was ordered.

Design files analysed (SHA-256):

| File | SHA-256 |
|---|---|
| `hardware/kicad/raccoon-tap.kicad_pcb` | `0f309dab5a1cfcf0e0f163f1aa0cdc70a7fec1a031040b2d25a5e4372c9f9d25` |
| `hardware/kicad/raccoon-tap.kicad_sch` | `1a05a336e41eed85213eccd75a8c79f16cbdf1d4915e4478cecb11761f0864ef` |

## What the gate rests on

**KiCad's ERC and DRC plus the repo's own checks** (rulings I, P, C):
`hardware/tests/run_design_checks.sh` runs all of them and exits 0 only if all
pass. kicad-happy is supplementary: in task 2 it found 1 of 12 known defects
unaided, and its capacitance check passed 21.2 µF on a 10 µF limit. The
ruling-BJ checks compare net labels and geometry, so the DRC stays in the gate
for shorts and unconnected items.

| Check | Result | File |
|---|---|---|
| `kicad-cli pcb drc --severity-all` | **0 errors, 0 unconnected**, 10 silkscreen warnings (7 `silk_over_copper`, 3 `silk_overlap`, unchanged since task 9) | `drc.rpt`; with `--refill-zones`: `drc-refilled.rpt`, same |
| `kicad-cli sch erc --severity-all` | **0 violations** | `erc.rpt` |
| `check_netlist.py` | exit 0, 0 warnings | `check_netlist.out` |
| `check_kicad.py` (incl. `check_pcb_connectivity(pcb, netlist, report)`, ruling N) | exit 0 | `check_kicad.out` |
| `test_check_kicad.py` | 27 tests OK | |
| `check_fab_release.py` | **131 tests OK** (109 before; 22 new, see below) | `check_fab_release.out` |
| `tools/rebuild_check.py` | 1136 of 1136 items identical (tracks, vias, footprints, zones, silkscreen text) | `run_design_checks.out` |
| `run_design_checks.sh` | all of the above | `run_design_checks.out` |

## The two checks the DRC cannot do (ruling BJ)

Both live in `hardware/tests/check_fab_release.py`, measured on the committed
board by `hardware/tests/board_probe.py` under KiCad's Python and judged in the
test file. They need pcbnew; without it they **error**, they do not skip.

* **In1 continuity.** Zones refilled in memory, then every F.Cu pair track walked
  along its centre line and both edges every 0.02 mm; each point must have In1
  GND under it. The only allowed exceptions are named in `IN1_EXCEPTIONS`: a
  MDI track's own J2 pin hole, a USB 2.0 track's own layer-change via, and
  D− over the hole of D+'s via at (21.5, 19.15) (0.5 mm). Everything else, and
  any exception over its length cap, fails. Ruling AR (one In2 boundary, flank
  vias in the B.Cu pour and the In1 plane) is held as well.
* **Pair coupling.** For every pair net, every 0.05 mm, the edge gap to the
  partner's copper (track, pad or via, same layer) gives the as-built
  differential impedance with the project's own PCBWay port less the 8 Ω mask
  offset. Length outside ±10 % of the target must lie in a **named region with a
  cap** (`COUPLING_REGIONS`: ruling AG/AI necks, BE capacitor landing and TX_CONN
  straddle, AS/BN for RX, and as-built caps where no ruling gives a figure),
  anything in no region may total 0.3 mm, and the share of each net inside the
  window must stay above a floor that follows from its caps.

`mutation_evidence.py` / `mutation-evidence.txt` show both failing. On the
**real** boards from git: 732475b (the board review 1 of task 9 found at TX 0 %
coupled, RX 28 %, USB 2.0 over D+'s antipad) fails with 27 coupling and 17 In1
messages; 584ece4 (RX still 28 %) fails with 10; b13cff9 (ruling BK) passes. On
planted defects: a 0.45 mm shift of RX_N leaves it 15 % inside the window; a
hole in In1 under each of the 16 pair nets is found on every one; a +3V3 via
0.52 mm beside RX_P (touching nothing) is found by its antipad; removing the AR
flank via fails ruling AR. With both judging functions replaced by
`lambda: []` all 10 mutation tests fail (24 failing assertions with sub-tests).

## kicad-happy, supplementary

Run with `KH=/opt/homebrew/bin/python3.12`, stage `pre_fab` (commands as in
`../2026-10-31-baseline/README.md`): `schematic.json`, `pcb.json`, `cross.json`,
`emc.json`, `thermal.json`, `fab_release_gate.json` / `.txt` (`--strict`).

**The gate FAILs strictly, on one check, a tool false positive**: net count
schematic 44 vs PCB 38; the six extra nets are the six `no_connect` flags
(accepted-findings B1). 9 of 12 checks pass, 2 skip (Gerbers: task 11). Before
the silkscreen fix it also failed on the missing board name and revision.

The three known false positives are present as expected (2 × `VM-001`, 1 ×
`GP-001` on USB2_D_N, ruling BO). Every other finding is argued in
**`accepted-findings.md`**: 1 fixed (board name and revision on silkscreen and
in the title block, `amend_pcb.py silk_id`), 5 coupling and reference
findings A1-A5 and 15 groups of tool findings accepted, none by changing a rule.

## Against the task 2 baseline (ruling J: by category and rule id)

| | Baseline 2026-10-31 (unrouted) | Now |
|---|---|---|
| Footprints / track segments / vias / zones | 33 / 0 / 41 / 3 | 59 / 934 / 123 / 18 (9 copper, 9 rule areas) |
| Unconnected items | 134 | **0** |
| DRC errors / warnings | 0 / 43 (41 dangling vias, 2 silk) | **0** / 10 (silk) |
| ERC | 0 / 0 | 0 / 0 |
| PCB analyser findings | 51 (28 err, 1 warn, 22 info; 26 are `RT-001` unrouted) | 71 (14 err, 23 warn, 34 info): `KO-001` × 12, `PM-002` × 2 err, `CC-002` × 20 |
| Cross-analysis | 0 findings, 6 of 10 checks | 4 (3 err), 8 of 10 checks: `RP-002`, `PS-002` × 3 |
| Thermal | 100, U4 69.8 °C (placeholder load) | 100, U4 67.5 °C (placeholder load); real figures in accepted B13 |
| EMC | 76.0, 29 findings, 5 of 18 categories ran | 0.0, 50 findings, 8 categories: not like-for-like |

EMC by rule id (baseline → now): `DC-003` 20 → 1, `IO-001` 2 → 1, `IO-002` 1 → 2,
`GP-001` 1 info → 8 (4 errors), `DP-001` 0 → 1, `DP-003` 0 → 2, `DP-004` 0 → 16,
`RP-001` 0 → 8, `CK-001` 0 → 3, `DC-001` 0 → 2, `GP-004` 0 → 1; `SW-001`,
`EE-001`, `EE-002` unchanged. Everything new needs copper, which the baseline
did not have, so the checks could not run; the decoupling-distance findings
fell from 20 to 1 because routing gave the capacitors real vias. The score of
0 is the 13 errors saturating it, not a measure.

The twelve known defects of task 2, with the evidence this run can show (the
ledger has the history of each fix):

| # | Item | Evidence now |
|---|---|---|
| 1 | U3 pin numbers | `u3-pinout-verdict.md`; `datasheets/crosscheck_u3_pinout.py` against the committed datasheet |
| 2 | VBUS capacitance vs 10 µF | `check_fab_release.py` VBUS test and the gated-rail inrush model |
| 3 | ESD on D+/D− and SuperSpeed | U8 and U9 on the board |
| 4 | USB-A SSTX/SSRX naming | `netlist.yaml` `design_notes.usb3_crossover` (ruling U) |
| 5 | Diff-pair geometry | `check_no_placeholder_geometry`, and now measured on the board (coupling check) |
| 6 | In2 split into islands | six In2 zones in the board; the tool's `PS-002` reads them as a split (B14) |
| 7 | J2 orientation | `PM-002` fires on J2's edge distance as expected (B5) |
| 8 | `SHIELD` net | decided 2026-11-01: C25 ∥ R13 to GND (`design_notes.shield_tie`) |
| 9 | Y1 | ABM8, C19 / C20 0402 (rulings W, AC) |
| 10 | LED polarity | `led_polarity` note; a first-build item |
| 11 | BOM part numbers | gate: all components have MPNs (43 of 43) |
| 12 | U3 footprint resolves | DRC "0 Footprint errors" |

## Deferred minors

`deferred-minors.md` collects the 35 deferred lines of tasks 1-8 and the minors
of the task 9 reviews for the whole-branch review, with a disposition each.
Two need a decision: the U8 ESD-rating citation (S1) and the crystal drive-level
arithmetic (S2).

## Reproducing

```sh
hardware/tests/run_design_checks.sh            # the gate
KH=/opt/homebrew/bin/python3.12 S=vendor/kicad-happy/skills R=hardware/review/2026-11-03-routed
$KH $S/kicad/scripts/analyze_schematic.py hardware/kicad/raccoon-tap.kicad_sch --output $R/schematic.json
$KH $S/kicad/scripts/analyze_pcb.py hardware/kicad/raccoon-tap.kicad_pcb --full --schematic $R/schematic.json --stage pre_fab --output $R/pcb.json
$KH $S/kicad/scripts/cross_analysis.py -s $R/schematic.json -p $R/pcb.json --output $R/cross.json
$KH $S/emc/scripts/analyze_emc.py -s $R/schematic.json -p $R/pcb.json --output $R/emc.json
$KH $S/kicad/scripts/analyze_thermal.py -s $R/schematic.json -p $R/pcb.json --output $R/thermal.json
$KH $S/kicad/scripts/fab_release_gate.py -s $R/schematic.json -p $R/pcb.json -t $R/thermal.json -e $R/emc.json --strict --text
python3 $R/mutation_evidence.py
```
