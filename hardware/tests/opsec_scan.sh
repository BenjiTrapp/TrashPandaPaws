#!/bin/bash
# Raccoon HAT v1 — OPSEC / Stealth Verification
# Scans the implant from the network perspective to verify it is not
# detectable as anything other than its cover device.
# Run from an EXTERNAL machine on the same network, NOT on the implant.
# Usage: ./opsec_scan.sh <implant_ip>

set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <implant_ip>"
    echo "  Run this from a SEPARATE machine on the same LAN."
    exit 1
fi

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
echo "║   Raccoon HAT v1 — OPSEC Scan                 ║"
echo "║   Run from external machine, NOT the implant   ║"
echo "╚═══════════════════════════════════════════════╝"
echo
echo "Target: $TARGET"
echo

# ── Nmap port scan ──
echo "── Port Scan (nmap) ──"
if command -v nmap &>/dev/null; then
    SCAN_FILE="/tmp/raccoon_opsec_$$.xml"
    nmap -sS -sU -p- --top-ports 1000 -O --osscan-guess -oX "$SCAN_FILE" "$TARGET" 2>/dev/null

    # Check for unexpected ports
    open_tcp=$(nmap -sS --top-ports 1000 "$TARGET" 2>/dev/null | grep "open" | grep "tcp" || true)
    open_udp=$(nmap -sU --top-ports 100 "$TARGET" 2>/dev/null | grep "open" | grep "udp" || true)

    echo "  Open TCP ports:"
    echo "$open_tcp" | while read -r line; do
        port=$(echo "$line" | awk '{print $1}' | cut -d/ -f1)
        case "$port" in
            80|443) result "  TCP $port — expected for cover HTTP" OK ;;
            5060)   result "  TCP $port — SIP (Cisco cover)" OK ;;
            9100)   result "  TCP $port — PJL (HP cover)" OK ;;
            515)    result "  TCP $port — LPD (HP cover)" OK ;;
            631)    result "  TCP $port — IPP (HP cover)" OK ;;
            23)     result "  TCP $port — Telnet (HP cover)" OK ;;
            22)     result "  TCP $port — SSH exposed! Should be localhost only" FAIL ;;
            *)      result "  TCP $port — unexpected open port" WARN ;;
        esac
    done

    # OS detection
    os_guess=$(grep -oP 'name="\K[^"]+' "$SCAN_FILE" 2>/dev/null | head -1 || echo "")
    if [ -n "$os_guess" ]; then
        if echo "$os_guess" | grep -qi "linux\|raspberry\|debian\|parrot"; then
            result "OS fingerprint reveals Linux: '$os_guess'" FAIL
        else
            result "OS fingerprint: '$os_guess' (not Linux)" OK
        fi
    else
        result "OS fingerprint inconclusive (good — harder to identify)" OK
    fi

    rm -f "$SCAN_FILE"
else
    result "nmap not installed — skipping port scan" WARN
fi

# ── SSH exposure ──
echo "── SSH Exposure ──"
if timeout 3 bash -c "echo >/dev/tcp/$TARGET/22" 2>/dev/null; then
    ssh_banner=$(timeout 3 bash -c "cat </dev/tcp/$TARGET/22" 2>/dev/null | head -1 || echo "")
    result "SSH port 22 reachable from network — should be localhost only" FAIL
    if echo "$ssh_banner" | grep -qi "OpenSSH\|dropbear"; then
        result "SSH banner: '$ssh_banner' (leaks info)" FAIL
    fi
else
    result "SSH port 22 not reachable from network (correct)" OK
fi

# ── HTTP fingerprinting ──
echo "── HTTP Fingerprinting ──"
if command -v curl &>/dev/null; then
    headers=$(curl -sI "http://$TARGET/" 2>/dev/null || echo "")

    # Server header
    server=$(echo "$headers" | grep -i "^Server:" | tr -d '\r' || echo "")
    if echo "$server" | grep -qi "python\|flask\|werkzeug\|gunicorn\|cherrypy\|uvicorn"; then
        result "Server header reveals Python: $server" FAIL
    elif echo "$server" | grep -qi "apache\|nginx\|lighttpd"; then
        result "Server header: $server (plausible)" OK
    elif [ -z "$server" ]; then
        result "No Server header (good — less info leaked)" OK
    else
        result "Server header: $server" OK
    fi

    # X-Powered-By
    powered=$(echo "$headers" | grep -i "^X-Powered-By:" | tr -d '\r' || echo "")
    if [ -n "$powered" ]; then
        result "X-Powered-By header present: $powered" FAIL
    else
        result "No X-Powered-By header" OK
    fi

    # Check for Python traceback on error pages
    error_page=$(curl -s "http://$TARGET/nonexistent_$(date +%s)" 2>/dev/null || echo "")
    if echo "$error_page" | grep -qi "traceback\|werkzeug\|flask\|python"; then
        result "Error page leaks Python framework info" FAIL
    else
        result "Error page clean (no framework info)" OK
    fi
fi

# ── TTL analysis ──
echo "── TTL Analysis ──"
ttl=$(ping -c 1 -W 2 "$TARGET" 2>/dev/null | grep -oP 'ttl=\K\d+' || echo 0)
if [ "$ttl" -eq 64 ]; then
    result "TTL=64 (default Linux — could match many devices)" WARN
elif [ "$ttl" -eq 128 ]; then
    result "TTL=128 (Windows — unusual for cover device)" WARN
elif [ "$ttl" -eq 255 ]; then
    result "TTL=255 (Cisco IOS — matches Cisco cover)" OK
else
    result "TTL=$ttl" OK
fi

# ── DNS reverse lookup ──
echo "── DNS ──"
rdns=$(dig -x "$TARGET" +short 2>/dev/null || echo "")
if [ -n "$rdns" ]; then
    if echo "$rdns" | grep -qi "raspberry\|parrot\|linux\|raccoon"; then
        result "Reverse DNS reveals identity: $rdns" FAIL
    else
        result "Reverse DNS: $rdns" OK
    fi
else
    result "No reverse DNS entry (neutral)" OK
fi

# ── mDNS / Avahi ──
echo "── mDNS / Avahi ──"
if command -v avahi-browse &>/dev/null; then
    mdns_services=$(timeout 5 avahi-browse -at 2>/dev/null | grep "$TARGET" || echo "")
    if echo "$mdns_services" | grep -qi "ssh\|sftp\|workstation\|linux"; then
        result "mDNS advertises Linux services" FAIL
    elif [ -n "$mdns_services" ]; then
        result "mDNS services: $(echo "$mdns_services" | head -3)" WARN
    else
        result "No mDNS services from target (good)" OK
    fi
fi

# ── ARP MAC OUI check ──
echo "── MAC OUI ──"
target_mac=$(arp -n "$TARGET" 2>/dev/null | grep -oP '([0-9a-f]{2}:){5}[0-9a-f]{2}' || echo "")
if [ -n "$target_mac" ]; then
    oui=$(echo "$target_mac" | cut -d: -f1-3)
    case "$oui" in
        00:1b:d5) result "MAC OUI $oui = Cisco (matches Cisco cover)" OK ;;
        00:1e:0b) result "MAC OUI $oui = HP (matches HP cover)" OK ;;
        b8:27:eb|dc:a6:32|e4:5f:01|d8:3a:dd)
            result "MAC OUI $oui = Raspberry Pi Foundation — BLOWN!" FAIL ;;
        *)  result "MAC OUI $oui — verify it matches cover vendor" WARN ;;
    esac
else
    result "Cannot determine target MAC" WARN
fi

# ── Summary ──
echo
echo "════════════════════════════════════"
printf "Results: \033[32m%d OK\033[0m / \033[33m%d WARN\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo "OPSEC FAILURES detected — the implant may be identifiable."
    exit 1
else
    echo "No critical OPSEC issues found."
    exit 0
fi
