#!/bin/bash
# Raccoon HAT v1 — C2 Beacon Connectivity Test
# Verifies the implant can reach its C2 server and that the beacon
# process is running, authenticated, and not leaking traffic.
# Usage: sudo ./c2_beacon_test.sh [c2_host]

set -euo pipefail

CONFIG="/opt/raccoon/configs/raccoon.yaml"
C2_HOST="${1:-}"

if [ -z "$C2_HOST" ] && [ -f "$CONFIG" ]; then
    C2_HOST=$(grep -oP 'c2_server:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "")
fi
if [ -z "$C2_HOST" ]; then
    echo "Usage: sudo $0 <c2_host_or_ip>"
    echo "  Or set c2_server in $CONFIG"
    exit 1
fi

C2_PORT=$(grep -oP 'c2_port:\s*\K\d+' "$CONFIG" 2>/dev/null || echo "443")

PASS=0
FAIL=0
WARN=0

result() {
    local label="$1" status="$2"
    case "$status" in
        OK)   printf "  [\033[32mOK\033[0m]   %s\n" "$label"; ((PASS++)) ;;
        FAIL) printf "  [\033[31mFAIL\033[0m] %s\n" "$label"; ((FAIL++)) ;;
        WARN) printf "  [\033[33mWARN\033[0m] %s\n" "$label"; ((WARN++)) ;;
    esac
}

echo "╔═══════════════════════════════════════════════╗"
echo "║   Raccoon HAT v1 — C2 Beacon Test              ║"
echo "╚═══════════════════════════════════════════════╝"
echo
echo "C2 target: $C2_HOST:$C2_PORT"
echo

# ── DNS resolution ──
echo "── DNS Resolution ──"
resolved=$(dig +short "$C2_HOST" 2>/dev/null | head -1 || echo "")
if [ -n "$resolved" ]; then
    result "Resolved $C2_HOST → $resolved" OK
else
    if echo "$C2_HOST" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
        result "C2 is an IP address (no DNS needed)" OK
        resolved="$C2_HOST"
    else
        result "Cannot resolve $C2_HOST" FAIL
    fi
fi

# ── TCP connectivity ──
echo "── TCP Connectivity ──"
if timeout 5 bash -c "echo >/dev/tcp/$C2_HOST/$C2_PORT" 2>/dev/null; then
    result "TCP connection to $C2_HOST:$C2_PORT succeeded" OK
else
    result "Cannot reach $C2_HOST:$C2_PORT" FAIL
fi

# ── TLS verification ──
echo "── TLS ──"
if command -v openssl &>/dev/null; then
    tls_info=$(echo | timeout 5 openssl s_client -connect "$C2_HOST:$C2_PORT" -servername "$C2_HOST" 2>/dev/null || echo "")
    if echo "$tls_info" | grep -q "Verify return code: 0"; then
        result "TLS certificate valid" OK
    elif echo "$tls_info" | grep -q "BEGIN CERTIFICATE"; then
        result "TLS handshake OK but certificate not verified (self-signed?)" WARN
    else
        result "TLS handshake failed" FAIL
    fi

    # Check for certificate pinning config
    if [ -f "/opt/raccoon/certs/c2_pin.pem" ] || [ -f "/opt/raccoon/certs/c2_ca.pem" ]; then
        result "Certificate pin/CA file present" OK
    else
        result "No certificate pin file — consider adding for MITM protection" WARN
    fi
else
    result "openssl not installed — skipping TLS check" WARN
fi

# ── Beacon process ──
echo "── Beacon Process ──"
beacon_procs=$(pgrep -af "beacon\|c2_client\|raccoon.*beacon" 2>/dev/null || echo "")
if [ -n "$beacon_procs" ]; then
    pid=$(echo "$beacon_procs" | head -1 | awk '{print $1}')
    result "Beacon process running (PID $pid)" OK

    # Check process uptime
    if [ -d "/proc/$pid" ]; then
        start_time=$(stat -c %Y "/proc/$pid" 2>/dev/null || echo 0)
        now=$(date +%s)
        uptime_sec=$((now - start_time))
        uptime_min=$((uptime_sec / 60))
        result "Beacon uptime: ${uptime_min}m" OK
    fi
else
    result "No beacon process found" FAIL
    echo "    Expected: python3 -m c2.beacon or similar"
fi

# ── Beacon interval verification ──
echo "── Beacon Timing ──"
beacon_interval=$(grep -oP 'beacon_interval:\s*\K\d+' "$CONFIG" 2>/dev/null || echo "")
if [ -n "$beacon_interval" ]; then
    result "Configured beacon interval: ${beacon_interval}s" OK
    if [ "$beacon_interval" -lt 10 ]; then
        result "Interval < 10s — very aggressive, increases detection risk" WARN
    fi
else
    result "Beacon interval not configured (using default)" WARN
fi

# Check jitter config
jitter=$(grep -oP 'beacon_jitter:\s*\K[\d.]+' "$CONFIG" 2>/dev/null || echo "")
if [ -n "$jitter" ]; then
    result "Jitter configured: ${jitter}" OK
else
    result "No jitter configured — beacon is predictable" WARN
fi

# ── Outbound traffic analysis ──
echo "── Outbound Traffic ──"
CAPFILE="/tmp/c2_beacon_$$.pcap"
echo "  Capturing C2 traffic for 30 seconds..."
timeout 30 tcpdump -i any -c 50 "host $C2_HOST and port $C2_PORT" -w "$CAPFILE" 2>/dev/null &
TCPDUMP_PID=$!
wait "$TCPDUMP_PID" 2>/dev/null || true

if [ -f "$CAPFILE" ]; then
    pkt_count=$(tcpdump -r "$CAPFILE" 2>/dev/null | wc -l || echo 0)
    if [ "$pkt_count" -gt 0 ]; then
        result "Captured $pkt_count C2 packets in 30s" OK

        # Check for plaintext leaks
        plaintext=$(tcpdump -r "$CAPFILE" -A 2>/dev/null | grep -ci "raccoon\|implant\|beacon" || echo 0)
        if [ "$plaintext" -gt 0 ]; then
            result "Plaintext keywords found in C2 traffic!" FAIL
        else
            result "No plaintext keywords in traffic (encrypted)" OK
        fi
    else
        result "No C2 traffic captured in 30s — beacon may be idle" WARN
    fi
    rm -f "$CAPFILE"
else
    result "Traffic capture failed" WARN
fi

# ── No unexpected outbound connections ──
echo "── Connection Audit ──"
other_conns=$(ss -tnp 2>/dev/null | grep -v "127.0.0.1" | grep -v "$C2_HOST" | grep "ESTAB" | grep -v "sshd" || echo "")
if [ -n "$other_conns" ]; then
    count=$(echo "$other_conns" | wc -l)
    result "$count unexpected outbound connections" WARN
    echo "$other_conns" | head -5 | while read -r line; do
        echo "    $line"
    done
else
    result "No unexpected outbound connections" OK
fi

# ── Kill switch / dead-man check ──
echo "── Kill Switch ──"
if grep -q "kill_switch\|dead_man\|self_destruct" "$CONFIG" 2>/dev/null; then
    result "Kill switch configured in config" OK
else
    result "No kill switch configured" WARN
fi

# ── Summary ──
echo
echo "────────────────────────────────────"
printf "Results: \033[32m%d OK\033[0m / \033[33m%d WARN\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
