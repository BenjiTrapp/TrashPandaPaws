#!/bin/bash
# Raccoon HAT v1 — 802.1X NAC Bypass Test
# Verifies the implant can forward EAPOL frames and perform
# MAC/IP cloning for network access behind 802.1X.
# Usage: sudo ./nac_bypass_test.sh

set -euo pipefail

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
echo "║   Raccoon HAT v1 — 802.1X NAC Bypass Test     ║"
echo "╚═══════════════════════════════════════════════╝"
echo

# ── Prerequisites ──
echo "── Prerequisites ──"
for tool in ebtables iptables tcpdump bridge; do
    if command -v "$tool" &>/dev/null; then
        result "$tool installed" OK
    else
        result "$tool missing (required for NAC bypass)" FAIL
    fi
done

# ── Bridge EAPOL forwarding ──
echo "── EAPOL Forwarding Config ──"

# Check group_fwd_mask (bit 0 = STP, bit 3 = EAPOL 01:80:c2:00:00:03)
fwd_mask=$(cat /sys/class/net/br0/bridge/group_fwd_mask 2>/dev/null || echo "0")
fwd_mask_dec=$((fwd_mask))

if [ $((fwd_mask_dec & 8)) -ne 0 ]; then
    result "group_fwd_mask includes EAPOL (bit 3 set): $fwd_mask" OK
else
    result "group_fwd_mask=$fwd_mask — EAPOL bit not set" FAIL
    echo "    Fix: echo 8 > /sys/class/net/br0/bridge/group_fwd_mask"
fi

# Check ebtables for EAPOL pass-through
eapol_rules=$(ebtables -L 2>/dev/null | grep -ci "0x888e" || echo 0)
if [ "$eapol_rules" -gt 0 ]; then
    result "ebtables has $eapol_rules EAPOL (0x888e) rules" OK
else
    result "No ebtables EAPOL rules configured" WARN
fi

# ── EAPOL frame capture test ──
echo "── EAPOL Frame Detection ──"
CAPFILE="/tmp/eapol_test_$$.pcap"
echo "  Listening for EAPOL frames for 15 seconds..."
timeout 15 tcpdump -i br0 -c 5 "ether proto 0x888e" -w "$CAPFILE" 2>/dev/null &
TCPDUMP_PID=$!
wait "$TCPDUMP_PID" 2>/dev/null || true

if [ -f "$CAPFILE" ]; then
    eapol_count=$(tcpdump -r "$CAPFILE" 2>/dev/null | wc -l || echo 0)
    if [ "$eapol_count" -gt 0 ]; then
        result "Captured $eapol_count EAPOL frames — downstream device authenticating" OK
    else
        result "No EAPOL frames seen (device may already be authenticated)" WARN
    fi
    rm -f "$CAPFILE"
else
    result "EAPOL capture failed" WARN
fi

# ── Downstream host discovery ──
echo "── Downstream Host Discovery ──"

# Check ARP table for hosts on downstream interface
ETH1=""
for iface in eth1 enx* usb0; do
    if ip link show "$iface" &>/dev/null; then
        ETH1="$iface"
        break
    fi
done

if [ -n "$ETH1" ]; then
    # Passive: look at bridge FDB for learned MACs
    fdb_entries=$(bridge fdb show br br0 2>/dev/null | grep -v permanent | grep -v "self" | head -5)
    if [ -n "$fdb_entries" ]; then
        result "Learned MACs on bridge:" OK
        echo "$fdb_entries" | while read -r line; do
            echo "    $line"
        done
    else
        result "No learned MACs on bridge (no downstream traffic yet)" WARN
    fi

    # Check if we can see the downstream device's traffic
    downstream_mac=$(bridge fdb show br br0 dev "$ETH1" 2>/dev/null | grep -v permanent | head -1 | awk '{print $1}' || echo "")
    if [ -n "$downstream_mac" ]; then
        result "Downstream device MAC: $downstream_mac" OK
    else
        result "Cannot identify downstream device MAC" WARN
    fi
fi

# ── MAC cloning readiness ──
echo "── MAC Cloning ──"
if ip link set dev br0 address 00:00:00:00:00:00 2>/dev/null; then
    ip link set dev br0 address "$(cat /sys/class/net/br0/address)"
    result "Can change br0 MAC address (macchanger ready)" OK
else
    result "Cannot change br0 MAC — needs NET_ADMIN capability" FAIL
fi

# ── IP forwarding ──
echo "── IP Forwarding ──"
ip_fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
if [ "$ip_fwd" = "1" ]; then
    result "IP forwarding enabled" OK
else
    result "IP forwarding disabled — NAC bypass active mode won't work" FAIL
fi

# ── ebtables L2 rewrite capability ──
echo "── L2 Rewrite ──"
if ebtables -L 2>/dev/null | grep -qi "snat\|dnat\|SNAT\|DNAT"; then
    result "ebtables NAT rules present for MAC rewriting" OK
else
    result "No ebtables NAT rules — L2 rewrite not yet configured" WARN
    echo "    (This is normal before NAC bypass activation)"
fi

# ── iptables L3 rewrite capability ──
echo "── L3 Rewrite ──"
nat_rules=$(iptables -t nat -L 2>/dev/null | grep -c "SNAT\|MASQUERADE" || echo 0)
if [ "$nat_rules" -gt 0 ]; then
    result "iptables NAT rules present for IP rewriting" OK
else
    result "No iptables NAT rules — L3 rewrite not yet configured" WARN
fi

# ── Summary ──
echo
echo "────────────────────────────────────"
printf "Results: \033[32m%d OK\033[0m / \033[33m%d WARN\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
