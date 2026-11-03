#!/bin/bash
# Raccoon Tap - design checks (desktop). Decides whether the board may be ordered.
#
# Not hardware/tests/run_all.sh: that is the on-device runner for the drop-box
# (sudo, first boot, bridge transparency, C2 beacon) and has no business gating
# a fabrication release (ruling C).
#
# The gate is KiCad's own DRC and ERC plus the repo's own checks. kicad-happy
# (ruling I) is supplementary and is not run here: it found 1 of 12 known
# defects unaided, and its capacitance check has no upper bound. The ruling BJ
# checks in check_fab_release.py (In1 ground under every pair, pair coupling)
# compare net labels and geometry, so KiCad's DRC stays in the gate for shorts
# and unconnected items (ruling P).
#
# Usage: hardware/tests/run_design_checks.sh [--skip-rebuild]
#   KIPY       KiCad's Python (pcbnew); default is the macOS app bundle
#   KICAD_CLI  kicad-cli; default is the one on PATH, else the app bundle
#
# Exit 0 only if every check passed. Takes about 2 minutes (the rebuild is a third).

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
HW="$(dirname "$TESTS_DIR")"
KIPY="${KIPY:-/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3}"
KICAD_CLI="${KICAD_CLI:-$(command -v kicad-cli || echo /Applications/KiCad/KiCad.app/Contents/MacOS/kicad-cli)}"
PCB="$HW/kicad/raccoon-tap.kicad_pcb"
SCH="$HW/kicad/raccoon-tap.kicad_sch"
SKIP_REBUILD=0
[ "${1:-}" = "--skip-rebuild" ] && SKIP_REBUILD=1

PASS=0
FAIL=0
FAILED=()
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

run() {
    local name="$1"
    shift
    echo "=== $name"
    if "$@"; then
        PASS=$((PASS + 1)); echo "--- PASS  $name"
    else
        FAIL=$((FAIL + 1)); FAILED+=("$name"); echo "--- FAIL  $name"
    fi
}

kicad_drc() {
    "$KICAD_CLI" pcb drc --severity-all --format json --output "$TMP/drc.json" "$PCB" >/dev/null || return 1
    python3 - "$TMP/drc.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
sev = {}
for v in d["violations"]:
    sev[v["severity"]] = sev.get(v["severity"], 0) + 1
unconnected = len(d["unconnected_items"])
kinds = ", ".join(sorted({v["type"] for v in d["violations"] if v["severity"] == "warning"}))
print(f"DRC: {sev.get('error', 0)} errors, {unconnected} unconnected, {sev.get('warning', 0)} warnings ({kinds})")
sys.exit(0 if sev.get("error", 0) == 0 and unconnected == 0 else 1)
EOF
}

kicad_erc() {
    "$KICAD_CLI" sch erc --severity-all --format json --output "$TMP/erc.json" "$SCH" >/dev/null || return 1
    python3 - "$TMP/erc.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
n = sum(len(s["violations"]) for s in d["sheets"])
print(f"ERC: {n} violations (errors and warnings)")
sys.exit(0 if n == 0 else 1)
EOF
}

run "kicad-cli pcb drc  (0 errors, 0 unconnected)" kicad_drc
run "kicad-cli sch erc  (0 violations)" kicad_erc
run "check_netlist.py" python3 "$TESTS_DIR/check_netlist.py"
run "check_kicad.py (incl. check_pcb_connectivity)" python3 "$TESTS_DIR/check_kicad.py"
run "test_check_kicad.py" python3 -m unittest "$TESTS_DIR/test_check_kicad.py"
run "check_fab_release.py (incl. In1 continuity and pair coupling, ruling BJ)" python3 "$TESTS_DIR/check_fab_release.py"
if [ "$SKIP_REBUILD" = 1 ]; then
    echo "=== rebuild_check.py skipped (--skip-rebuild)"
else
    run "rebuild_check.py (gen_pcb + route_pcb reproduce the committed board)" "$KIPY" "$HW/tools/rebuild_check.py"
fi

echo
echo "design checks: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
    printf '  failed: %s\n' "${FAILED[@]}"
    exit 1
fi
exit 0
