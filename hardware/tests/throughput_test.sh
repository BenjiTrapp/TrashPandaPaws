#!/bin/bash
# Raccoon HAT v1 — Ethernet Throughput Test
# Measures bridge throughput between eth0 and the HAT's RTL8153B port.
# Requires iperf3 installed: apt install iperf3
# Usage: sudo ./throughput_test.sh [target_ip] [duration_seconds]

set -euo pipefail

TARGET="${1:-127.0.0.1}"
DURATION="${2:-10}"
LOGFILE="/tmp/raccoon_throughput_$(date +%Y%m%d_%H%M%S).log"

echo "╔════════════════════════════════════════════╗"
echo "║   Raccoon HAT v1 — Throughput Test         ║"
echo "╚════════════════════════════════════════════╝"
echo

if ! command -v iperf3 &>/dev/null; then
    echo "ERROR: iperf3 not installed. Run: apt install iperf3"
    exit 1
fi

# Detect HAT interface
ETH1=""
for iface in eth1 enx* usb0; do
    if ip link show "$iface" &>/dev/null; then
        ETH1="$iface"
        break
    fi
done

if [ -z "$ETH1" ]; then
    echo "ERROR: No second Ethernet interface found (HAT not detected)"
    exit 1
fi

echo "Interfaces:"
echo "  Primary:   eth0"
echo "  HAT (USB): $ETH1"
echo "  Target:    $TARGET"
echo "  Duration:  ${DURATION}s per direction"
echo "  Log:       $LOGFILE"
echo

# Show link info
for iface in eth0 "$ETH1"; do
    speed=$(ethtool "$iface" 2>/dev/null | grep -oP 'Speed: \K.*' || echo "unknown")
    echo "  $iface link speed: $speed"
done
echo

# Start iperf3 server in background (if testing loopback)
SERVER_PID=""
if [ "$TARGET" = "127.0.0.1" ]; then
    iperf3 -s -D -1 2>/dev/null
    SERVER_PID=$!
    sleep 1
fi

# ── TCP Upload ──
echo "── TCP Upload (client → target) ──"
iperf3 -c "$TARGET" -t "$DURATION" -f m 2>&1 | tee -a "$LOGFILE" | tail -4
echo

# ── TCP Download ──
if [ "$TARGET" = "127.0.0.1" ]; then
    iperf3 -s -D -1 2>/dev/null
    sleep 1
fi
echo "── TCP Download (target → client, reverse) ──"
iperf3 -c "$TARGET" -t "$DURATION" -f m -R 2>&1 | tee -a "$LOGFILE" | tail -4
echo

# ── UDP Jitter ──
if [ "$TARGET" = "127.0.0.1" ]; then
    iperf3 -s -D -1 2>/dev/null
    sleep 1
fi
echo "── UDP Jitter Test (100Mbps target) ──"
iperf3 -c "$TARGET" -t "$DURATION" -u -b 100M -f m 2>&1 | tee -a "$LOGFILE" | tail -5
echo

# ── Bidirectional ──
if [ "$TARGET" != "127.0.0.1" ]; then
    echo "── Bidirectional (simultaneous) ──"
    iperf3 -c "$TARGET" -t "$DURATION" -f m --bidir 2>&1 | tee -a "$LOGFILE" | tail -6
    echo
fi

# Cleanup
[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true

# ── Parse results ──
echo "────────────────────────────────────"
echo "Results saved to: $LOGFILE"

tcp_bw=$(grep -oP '\d+(\.\d+)? Mbits/sec.*sender' "$LOGFILE" | head -1 | grep -oP '[\d.]+' | head -1 || echo "?")
echo "Peak TCP throughput: ${tcp_bw} Mbps"

if [ "${tcp_bw%.*}" -ge 900 ] 2>/dev/null; then
    printf "\033[32mPASS\033[0m: Near-line-rate GbE throughput\n"
elif [ "${tcp_bw%.*}" -ge 500 ] 2>/dev/null; then
    printf "\033[33mWARN\033[0m: Throughput below expected (>900 Mbps)\n"
else
    printf "\033[31mFAIL\033[0m: Low throughput — check USB/Ethernet connection\n"
fi
