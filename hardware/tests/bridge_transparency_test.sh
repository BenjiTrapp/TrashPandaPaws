#!/bin/bash
# Raccoon HAT v1 — Bridge Transparency Test
# Verifies the Ethernet bridge passes traffic without modification.
# The implant must be inline between two hosts or connected to a switch.
# Usage: sudo ./bridge_transparency_test.sh <downstream_ip>

set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: sudo $0 <downstream_device_ip>"
    echo "  The downstream device must be reachable through the bridge."
    exit 1
fi

PASS=0
FAIL=0

result() {
    local label="$1" status="$2"
    case "$status" in
        OK)   printf "  [\033[32mOK\033[0m]   %s\n" "$label"; ((PASS++)) ;;
        FAIL) printf "  [\033[31mFAIL\033[0m] %s\n" "$label"; ((FAIL++)) ;;
    esac
}

echo "╔═══════════════════════════════════════════════╗"
echo "║   Raccoon HAT v1 — Bridge Transparency Test    ║"
echo "╚═══════════════════════════════════════════════╝"
echo
echo "Target: $TARGET"
echo

# ── Bridge exists and has both interfaces ──
echo "── Bridge Status ──"
if ip link show br0 &>/dev/null; then
    result "Bridge br0 exists" OK
    members=$(bridge link show 2>/dev/null | grep "master br0" | awk '{print $2}' | tr '\n' ' ')
    if echo "$members" | grep -q "eth0" && echo "$members" | grep -qE "eth1|enx"; then
        result "Bridge has both interfaces: $members" OK
    else
        result "Bridge missing interfaces (has: $members)" FAIL
    fi
else
    result "Bridge br0 not found" FAIL
    echo "Cannot continue without bridge. Exiting."
    exit 1
fi

# ── ICMP pass-through ──
echo "── ICMP Pass-Through ──"
if ping -c 3 -W 2 "$TARGET" &>/dev/null; then
    latency=$(ping -c 5 -W 2 "$TARGET" 2>/dev/null | tail -1 | grep -oP 'rtt.*= \K[\d.]+' || echo "?")
    result "Ping to $TARGET: ${latency}ms avg" OK
    if [ "${latency%.*}" -lt 5 ] 2>/dev/null; then
        result "Latency < 5ms (bridge adds minimal delay)" OK
    else
        result "Latency ${latency}ms — bridge may be adding delay" FAIL
    fi
else
    result "Cannot ping $TARGET through bridge" FAIL
fi

# ── TTL preservation ──
echo "── TTL Preservation ──"
ttl=$(ping -c 1 -W 2 "$TARGET" 2>/dev/null | grep -oP 'ttl=\K\d+' || echo 0)
if [ "$ttl" -gt 0 ]; then
    result "TTL from $TARGET: $ttl (bridge must not decrement)" OK
else
    result "Could not read TTL" FAIL
fi

# ── MAC address forwarding ──
echo "── MAC Forwarding ──"
arp_mac=$(arp -n "$TARGET" 2>/dev/null | grep -oP '([0-9a-f]{2}:){5}[0-9a-f]{2}' || echo "")
if [ -n "$arp_mac" ]; then
    result "Downstream MAC visible: $arp_mac" OK
else
    result "Cannot see downstream device MAC" FAIL
fi

# ── No IP address on bridge interfaces ──
echo "── Interface Isolation ──"
for iface in eth0 eth1; do
    ip_on_iface=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' || echo "")
    if [ -z "$ip_on_iface" ]; then
        result "$iface has no IP (correct for bridge member)" OK
    else
        result "$iface has IP $ip_on_iface (should be on br0 only)" FAIL
    fi
done

# ── EAPOL forwarding (802.1X) ──
echo "── EAPOL Forwarding ──"
eapol_rule=$(ebtables -L 2>/dev/null | grep -c "0x888e" || echo 0)
bridge_eapol=$(cat /sys/class/net/br0/bridge/group_fwd_mask 2>/dev/null || echo 0)
if [ "$bridge_eapol" != "0" ] || [ "$eapol_rule" -gt 0 ]; then
    result "EAPOL forwarding enabled (group_fwd_mask=$bridge_eapol)" OK
else
    result "EAPOL forwarding not configured — 802.1X bypass won't work" FAIL
fi

# ── Packet capture verification ──
echo "── Packet Integrity (tcpdump sample) ──"
CAPFILE="/tmp/bridge_test_$$.pcap"
timeout 5 tcpdump -i br0 -c 20 -w "$CAPFILE" host "$TARGET" 2>/dev/null &
TCPDUMP_PID=$!
ping -c 5 -W 1 "$TARGET" &>/dev/null
wait "$TCPDUMP_PID" 2>/dev/null || true

if [ -f "$CAPFILE" ]; then
    pkt_count=$(tcpdump -r "$CAPFILE" 2>/dev/null | wc -l || echo 0)
    if [ "$pkt_count" -ge 5 ]; then
        result "Captured $pkt_count packets on bridge — traffic flowing" OK
    else
        result "Only $pkt_count packets captured — check bridge config" FAIL
    fi
    rm -f "$CAPFILE"
else
    result "tcpdump capture failed" FAIL
fi

# ── No iptables interference ──
echo "── Firewall Check ──"
fwd_policy=$(iptables -L FORWARD 2>/dev/null | head -1 | grep -oP '\(policy \K\w+' || echo "unknown")
if [ "$fwd_policy" = "ACCEPT" ]; then
    result "FORWARD policy: ACCEPT" OK
else
    result "FORWARD policy: $fwd_policy (may block bridge traffic)" FAIL
fi

fwd_rules=$(iptables -L FORWARD 2>/dev/null | grep -c "DROP\|REJECT" || echo 0)
if [ "$fwd_rules" -eq 0 ]; then
    result "No DROP/REJECT rules in FORWARD chain" OK
else
    result "$fwd_rules DROP/REJECT rules found — may interfere" FAIL
fi

# ── Summary ──
echo
echo "────────────────────────────────────"
printf "Results: \033[32m%d OK\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$FAIL"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
