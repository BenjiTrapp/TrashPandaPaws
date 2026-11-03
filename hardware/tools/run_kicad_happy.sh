#!/bin/bash
# Raccoon Tap - run the kicad-happy analyzers into a review directory, and make
# the output machine-independent.
#
# The analyzers (vendor/kicad-happy, third-party, not edited here) record the
# absolute path of their inputs. relativize_paths.py rewrites that to the
# repository-relative form, so the same board analysed on two machines yields
# the same files and the committed ones do not carry anyone's home directory.
# Do not run the analyzers by hand into a directory you are going to commit.
#
# Usage: hardware/tools/run_kicad_happy.sh OUT_DIR [layout|pre_fab]
#   OUT_DIR  relative to the repository root, e.g. hardware/review/2026-11-03-routed
#   KH       Python with kicad-happy's dependencies; default /opt/homebrew/bin/python3.12
#
# Writes schematic.json, pcb.json, cross.json, emc.json, thermal.json (and the
# capability_mode.json the analyzers leave beside them) into OUT_DIR.

set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$TOOLS_DIR/../.." && pwd)"
KH="${KH:-/opt/homebrew/bin/python3.12}"
S="vendor/kicad-happy/skills"
R="${1:?usage: run_kicad_happy.sh OUT_DIR [layout|pre_fab]}"
STAGE="${2:-pre_fab}"

cd "$REPO"
mkdir -p "$R"
"$KH" $S/kicad/scripts/analyze_schematic.py hardware/kicad/raccoon-tap.kicad_sch --output "$R/schematic.json"
"$KH" $S/kicad/scripts/analyze_pcb.py hardware/kicad/raccoon-tap.kicad_pcb --full --schematic "$R/schematic.json" --stage "$STAGE" --output "$R/pcb.json"
"$KH" $S/kicad/scripts/cross_analysis.py -s "$R/schematic.json" -p "$R/pcb.json" --output "$R/cross.json"
"$KH" $S/emc/scripts/analyze_emc.py -s "$R/schematic.json" -p "$R/pcb.json" --output "$R/emc.json"
"$KH" $S/kicad/scripts/analyze_thermal.py -s "$R/schematic.json" -p "$R/pcb.json" --output "$R/thermal.json"

python3 "$TOOLS_DIR/relativize_paths.py" "$R"/*.json
