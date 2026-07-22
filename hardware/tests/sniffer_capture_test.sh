#!/bin/bash
# Raccoon HAT v1 — Sniffer / PCAP Capture Test
# Verifies the implant can passively capture traffic on the bridge,
# write PCAPs, rotate files, and exfiltrate captures.
# Usage: sudo ./sniffer_capture_test.sh

set -euo pipefail

CONFIG="/opt/raccoon/configs/raccoon.yaml"
CAPTURE_DIR=$(grep -oP 'capture_dir:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "/opt/raccoon/captures")

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
echo "║   Raccoon HAT v1 — Sniffer / Capture Test      ║"
echo "╚═══════════════════════════════════════════════╝"
echo
echo "Capture dir: $CAPTURE_DIR"
echo

# ── Prerequisites ──
echo "── Prerequisites ──"
for tool in tcpdump tshark; do
    if command -v "$tool" &>/dev/null; then
        result "$tool installed" OK
    else
        result "$tool not found" WARN
    fi
done

if command -v dumpcap &>/dev/null; then
    result "dumpcap available (ring buffer support)" OK
else
    result "dumpcap not found (tcpdump fallback OK)" WARN
fi

# ── Capture directory ──
echo "── Capture Storage ──"
if [ -d "$CAPTURE_DIR" ]; then
    result "Capture directory exists: $CAPTURE_DIR" OK

    # Check permissions
    if [ -w "$CAPTURE_DIR" ]; then
        result "Capture directory is writable" OK
    else
        result "Capture directory not writable" FAIL
    fi

    # Check available disk space
    avail_mb=$(df -m "$CAPTURE_DIR" 2>/dev/null | tail -1 | awk '{print $4}')
    if [ "${avail_mb:-0}" -ge 500 ]; then
        result "Available space: ${avail_mb}MB (>500MB)" OK
    elif [ "${avail_mb:-0}" -ge 100 ]; then
        result "Available space: ${avail_mb}MB (low — consider cleanup)" WARN
    else
        result "Available space: ${avail_mb:-?}MB (critically low)" FAIL
    fi

    # Check for existing captures
    pcap_count=$(find "$CAPTURE_DIR" -name "*.pcap" -o -name "*.pcapng" 2>/dev/null | wc -l || echo 0)
    pcap_size=$(du -sh "$CAPTURE_DIR" 2>/dev/null | awk '{print $1}' || echo "?")
    result "Existing captures: $pcap_count files ($pcap_size total)" OK
else
    result "Capture directory missing: $CAPTURE_DIR" FAIL
    mkdir -p "$CAPTURE_DIR" 2>/dev/null && result "Created $CAPTURE_DIR" OK || result "Cannot create $CAPTURE_DIR" FAIL
fi

# ── Promiscuous mode ──
echo "── Promiscuous Mode ──"
for iface in br0 eth0 eth1; do
    if ip link show "$iface" &>/dev/null; then
        flags=$(ip link show "$iface" 2>/dev/null | head -1)
        if echo "$flags" | grep -q "PROMISC"; then
            result "$iface is in promiscuous mode" OK
        else
            result "$iface not promiscuous — enable with: ip link set $iface promisc on" WARN
        fi
    fi
done

# ── Live capture test ──
echo "── Live Capture Test ──"
TEST_PCAP="$CAPTURE_DIR/test_capture_$$.pcap"

# Capture 10 seconds of traffic
echo "  Capturing for 10 seconds on br0..."
timeout 10 tcpdump -i br0 -c 100 -w "$TEST_PCAP" 2>/dev/null &
TCPDUMP_PID=$!
sleep 2
# Generate some traffic to capture
ping -c 3 -W 1 8.8.8.8 &>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

if [ -f "$TEST_PCAP" ]; then
    file_size=$(stat -c %s "$TEST_PCAP" 2>/dev/null || echo 0)
    if [ "$file_size" -gt 24 ]; then
        pkt_count=$(tcpdump -r "$TEST_PCAP" 2>/dev/null | wc -l || echo 0)
        result "Captured $pkt_count packets (${file_size} bytes)" OK
    else
        result "Capture file empty or header only" FAIL
    fi

    # Verify PCAP is valid
    if command -v capinfos &>/dev/null; then
        if capinfos "$TEST_PCAP" &>/dev/null; then
            result "PCAP file is valid (capinfos OK)" OK
        else
            result "PCAP file may be corrupted" FAIL
        fi
    fi

    rm -f "$TEST_PCAP"
else
    result "Capture file not created" FAIL
fi

# ── BPF filter test ──
echo "── BPF Filters ──"
TEST_BPF="$CAPTURE_DIR/test_bpf_$$.pcap"

# Test common filters compile correctly
for filter in "tcp port 80" "udp port 53" "not arp" "host 10.0.0.1 and tcp" "ether proto 0x888e"; do
    if timeout 2 tcpdump -i br0 -c 0 -d "$filter" &>/dev/null; then
        result "BPF compiles: '$filter'" OK
    else
        result "BPF fails: '$filter'" FAIL
    fi
done

# ── File rotation ──
echo "── File Rotation ──"
max_size=$(grep -oP 'capture_max_size:\s*\K\S+' "$CONFIG" 2>/dev/null || echo "")
max_files=$(grep -oP 'capture_max_files:\s*\K\d+' "$CONFIG" 2>/dev/null || echo "")

if [ -n "$max_size" ]; then
    result "Max capture size configured: $max_size" OK
else
    result "No capture size limit — disk may fill up" WARN
fi

if [ -n "$max_files" ]; then
    result "Max capture files configured: $max_files" OK
else
    result "No file count limit configured" WARN
fi

# Test ring buffer (dumpcap)
if command -v dumpcap &>/dev/null; then
    TEST_RING="$CAPTURE_DIR/test_ring_$$.pcapng"
    if timeout 5 dumpcap -i br0 -b filesize:100 -b files:3 -a duration:3 -w "$TEST_RING" &>/dev/null; then
        ring_files=$(ls "${TEST_RING}"* 2>/dev/null | wc -l || echo 0)
        result "Ring buffer works (dumpcap created $ring_files files)" OK
        rm -f "${TEST_RING}"* 2>/dev/null
    else
        result "Ring buffer test failed" WARN
    fi
fi

# ── Credential capture filters ──
echo "── Protocol Filters ──"
if command -v tshark &>/dev/null; then
    # Test tshark can parse protocols
    for proto in http dns ftp smtp pop imap; do
        if tshark -G protocols 2>/dev/null | grep -qi "^$proto"; then
            result "tshark supports $proto dissection" OK
        else
            result "tshark missing $proto dissector" WARN
        fi
    done
fi

# ── Sniffer process ──
echo "── Sniffer Process ──"
sniffer_procs=$(pgrep -af "sniffer\|tcpdump.*-w\|dumpcap\|tshark.*-w" 2>/dev/null || echo "")
if [ -n "$sniffer_procs" ]; then
    result "Active capture process found:" OK
    echo "$sniffer_procs" | head -3 | while read -r line; do
        echo "    $line"
    done
else
    result "No active capture process (sniffer not running)" WARN
fi

# ── Capture encryption ──
echo "── Capture Security ──"
if command -v gpg &>/dev/null; then
    result "gpg available for capture encryption" OK
else
    result "gpg not installed — captures stored in cleartext" WARN
fi

encrypt_config=$(grep -i "encrypt_captures\|capture_encrypt" "$CONFIG" 2>/dev/null || echo "")
if [ -n "$encrypt_config" ]; then
    result "Capture encryption configured" OK
else
    result "No capture encryption configured — OPSEC risk if device seized" WARN
fi

# ── Summary ──
echo
echo "────────────────────────────────────"
printf "Results: \033[32m%d OK\033[0m / \033[33m%d WARN\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
