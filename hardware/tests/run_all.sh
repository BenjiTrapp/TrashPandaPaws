#!/bin/bash
# Raccoon HAT v1 — Test Runner
# Executes all on-device tests and produces a summary report.
# Usage: sudo ./run_all.sh [--report <file>] [--skip <test>]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT=""
SKIP=""
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_WARN=0
TOTAL_SKIP=0
RESULTS=()

usage() {
    echo "Usage: sudo $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --report <file>   Write results to file (default: stdout only)"
    echo "  --skip <tests>    Comma-separated test names to skip"
    echo "  --list            List available tests and exit"
    echo "  --help            Show this help"
    exit 0
}

# On-device tests in recommended execution order
TESTS=(
    "firstboot_test.sh|First Boot Validation|Checks image provisioning and system readiness"
    "smoke_test.sh|Hardware Smoke Test|USB enumeration, NICs, power rails, GPIO"
    "power_test.sh|Power & Thermal|Voltage, current, temperature under load"
    "throughput_test.sh|Ethernet Throughput|iperf3 TCP/UDP bandwidth through HAT"
    "bridge_transparency_test.sh|Bridge Transparency|Traffic passes unmodified through bridge"
    "nac_bypass_test.sh|802.1X NAC Bypass|EAPOL forwarding, MAC cloning readiness"
    "cover_identity_test.sh|Cover Identity|Hostname, MAC OUI, HTTP branding, ports"
    "sniffer_capture_test.sh|Sniffer / Capture|PCAP capture, rotation, BPF filters"
    "c2_beacon_test.sh|C2 Beacon|C2 connectivity, TLS, beacon process"
    "ssh_tunnel_test.sh|SSH Reverse Tunnel|Keys, tunnel persistence, hardening"
)

while [ $# -gt 0 ]; do
    case "$1" in
        --report)  REPORT="$2"; shift 2 ;;
        --skip)    SKIP="$2"; shift 2 ;;
        --list)
            echo "Available tests:"
            for entry in "${TESTS[@]}"; do
                IFS='|' read -r file title desc <<< "$entry"
                printf "  %-32s %s\n" "$file" "$desc"
            done
            echo
            echo "External (run from another machine):"
            printf "  %-32s %s\n" "opsec_scan.sh <ip>" "Stealth scan from network perspective"
            echo
            echo "Manual:"
            printf "  %-32s %s\n" "continuity_check.md" "Multimeter checks before first power-on"
            exit 0
            ;;
        --help|-h) usage ;;
        *)         echo "Unknown option: $1"; usage ;;
    esac
done

# ── Header ──
echo "╔═══════════════════════════════════════════════════════╗"
echo "║         Raccoon HAT v1 — Full Test Suite              ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo
echo "  Host:     $(hostname)"
echo "  Kernel:   $(uname -r)"
echo "  Date:     $(date -Iseconds)"
echo "  Platform: $(cat /proc/device-tree/model 2>/dev/null | tr -d '\0' || uname -m)"
echo

# ── Check root ──
if [ "$(id -u)" -ne 0 ]; then
    echo "WARNING: Not running as root — some tests will fail."
    echo "         Re-run with: sudo $0"
    echo
fi

# ── Run tests ──
run_test() {
    local file="$1" title="$2" desc="$3"
    local test_path="$SCRIPT_DIR/$file"

    # Skip check
    if echo ",$SKIP," | grep -qi ",$file,"; then
        printf "  [\033[36mSKIP\033[0m]  %s\n" "$title"
        RESULTS+=("SKIP|$title|skipped by user")
        ((TOTAL_SKIP++))
        return
    fi

    if [ ! -x "$test_path" ]; then
        if [ -f "$test_path" ]; then
            chmod +x "$test_path"
        else
            printf "  [\033[33mWARN\033[0m]  %s — file not found\n" "$title"
            RESULTS+=("WARN|$title|file not found")
            ((TOTAL_WARN++))
            return
        fi
    fi

    echo "┌─────────────────────────────────────────────"
    echo "│ $title"
    echo "│ $desc"
    echo "└─────────────────────────────────────────────"

    local start_time end_time duration exit_code
    start_time=$(date +%s)

    # Capture output and exit code
    local output
    output=$("$test_path" 2>&1) || true
    exit_code=${PIPESTATUS[0]:-$?}

    end_time=$(date +%s)
    duration=$((end_time - start_time))

    echo "$output"
    echo

    # Parse result counts from output
    local t_pass t_warn t_fail
    t_pass=$(echo "$output" | grep -oP '\d+(?= OK)' | tail -1 || echo 0)
    t_warn=$(echo "$output" | grep -oP '\d+(?= WARN)' | tail -1 || echo 0)
    t_fail=$(echo "$output" | grep -oP '\d+(?= FAIL)' | tail -1 || echo 0)

    TOTAL_PASS=$((TOTAL_PASS + ${t_pass:-0}))
    TOTAL_WARN=$((TOTAL_WARN + ${t_warn:-0}))
    TOTAL_FAIL=$((TOTAL_FAIL + ${t_fail:-0}))

    local status
    if [ "$exit_code" -eq 0 ]; then
        status="PASS"
    else
        status="FAIL"
    fi

    RESULTS+=("$status|$title|${t_pass:-0} OK / ${t_warn:-0} WARN / ${t_fail:-0} FAIL (${duration}s)")
}

for entry in "${TESTS[@]}"; do
    IFS='|' read -r file title desc <<< "$entry"
    run_test "$file" "$title" "$desc"
done

# ── Summary ──
echo
echo "╔═══════════════════════════════════════════════════════╗"
echo "║                    Test Summary                       ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo
printf "  %-30s  %s\n" "TEST" "RESULT"
echo "  ────────────────────────────────────────────────────"

for res in "${RESULTS[@]}"; do
    IFS='|' read -r status title detail <<< "$res"
    case "$status" in
        PASS) color="\033[32m" ;;
        FAIL) color="\033[31m" ;;
        SKIP) color="\033[36m" ;;
        *)    color="\033[33m" ;;
    esac
    printf "  ${color}%-6s\033[0m %-24s %s\n" "$status" "$title" "$detail"
done

echo
echo "  ════════════════════════════════════════════════"
printf "  Total checks: \033[32m%d OK\033[0m / \033[33m%d WARN\033[0m / \033[31m%d FAIL\033[0m / \033[36m%d SKIP\033[0m\n" \
    "$TOTAL_PASS" "$TOTAL_WARN" "$TOTAL_FAIL" "$TOTAL_SKIP"
echo

# ── Reminders ──
echo "  Not included (run separately):"
echo "    • opsec_scan.sh <ip>      — run from an EXTERNAL machine"
echo "    • continuity_check.md     — manual multimeter checks"
echo

# ── Report file ──
if [ -n "$REPORT" ]; then
    {
        echo "Raccoon HAT v1 — Test Report"
        echo "Date: $(date -Iseconds)"
        echo "Host: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo
        printf "%-8s %-26s %s\n" "STATUS" "TEST" "DETAIL"
        echo "──────────────────────────────────────────────────────────"
        for res in "${RESULTS[@]}"; do
            IFS='|' read -r status title detail <<< "$res"
            printf "%-8s %-26s %s\n" "$status" "$title" "$detail"
        done
        echo
        printf "Total: %d OK / %d WARN / %d FAIL / %d SKIP\n" \
            "$TOTAL_PASS" "$TOTAL_WARN" "$TOTAL_FAIL" "$TOTAL_SKIP"
    } > "$REPORT"
    echo "  Report written to: $REPORT"
    echo
fi

# ── Exit code ──
if [ "$TOTAL_FAIL" -gt 0 ]; then
    exit 1
else
    exit 0
fi
