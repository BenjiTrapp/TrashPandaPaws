#!/bin/bash
# Raccoon HAT v1 — Cover Identity Verification Test
# Validates that the device's cover identity is consistent and convincing.
# Tests hostname, MAC prefix, HTTP responses, and open ports.
# Usage: sudo ./cover_identity_test.sh [cisco_phone|hp_printer]

set -euo pipefail

CONFIG="/opt/raccoon/configs/raccoon.yaml"
MODE="${1:-}"

if [ -z "$MODE" ]; then
    if [ -f "$CONFIG" ]; then
        MODE=$(grep -oP 'device_mode:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "")
    fi
    if [ -z "$MODE" ]; then
        echo "Usage: sudo $0 <cisco_phone|hp_printer>"
        exit 1
    fi
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
echo "║   Raccoon HAT v1 — Cover Identity Test         ║"
echo "╚═══════════════════════════════════════════════╝"
echo
echo "Active cover mode: $MODE"
echo

# ── Hostname ──
echo "── Hostname ──"
actual_hostname=$(hostname)
if [ "$MODE" = "cisco_phone" ]; then
    if echo "$actual_hostname" | grep -qP '^SEP[0-9A-F]{12}$'; then
        result "Hostname '$actual_hostname' matches Cisco SEP format" OK
    else
        result "Hostname '$actual_hostname' does not match SEPxxxxxxxxxxxx" FAIL
    fi
elif [ "$MODE" = "hp_printer" ]; then
    if echo "$actual_hostname" | grep -qi 'HP-LaserJet\|HP-'; then
        result "Hostname '$actual_hostname' matches HP format" OK
    else
        result "Hostname '$actual_hostname' does not match HP-* format" FAIL
    fi
fi

# ── MAC Address Prefix ──
echo "── MAC Address ──"
for iface in eth0 br0; do
    mac=$(ip link show "$iface" 2>/dev/null | grep -oP 'link/ether \K[0-9a-f:]+' || continue)
    if [ -z "$mac" ]; then continue; fi

    mac_prefix=$(echo "$mac" | cut -d: -f1-3)
    if [ "$MODE" = "cisco_phone" ]; then
        expected="00:1b:d5"
    else
        expected="00:1e:0b"
    fi

    if [ "$mac_prefix" = "$expected" ]; then
        result "$iface MAC prefix $mac_prefix matches $MODE OUI" OK
    else
        result "$iface MAC prefix $mac_prefix does not match expected $expected" FAIL
    fi
done

# ── HTTP Cover Response ──
echo "── HTTP Cover Server ──"
if command -v curl &>/dev/null; then
    http_code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:80/ 2>/dev/null || echo "000")
    if [ "$http_code" != "000" ]; then
        result "HTTP server responding (status $http_code)" OK
    else
        result "HTTP server not responding on port 80" FAIL
    fi

    http_body=$(curl -s http://127.0.0.1:80/ 2>/dev/null || echo "")

    if [ "$MODE" = "cisco_phone" ]; then
        if echo "$http_body" | grep -qi "cisco"; then
            result "HTTP response contains 'Cisco' branding" OK
        else
            result "HTTP response missing 'Cisco' branding" FAIL
        fi
        if echo "$http_body" | grep -qi "7960\|IP Phone"; then
            result "HTTP response references IP Phone model" OK
        else
            result "HTTP response missing phone model reference" FAIL
        fi
    elif [ "$MODE" = "hp_printer" ]; then
        if echo "$http_body" | grep -qi "hp\|hewlett"; then
            result "HTTP response contains HP branding" OK
        else
            result "HTTP response missing HP branding" FAIL
        fi
        if echo "$http_body" | grep -qi "LaserJet\|M478"; then
            result "HTTP response references printer model" OK
        else
            result "HTTP response missing printer model reference" FAIL
        fi
    fi

    # Check server header is not leaking Python/Flask
    server_header=$(curl -sI http://127.0.0.1:80/ 2>/dev/null | grep -i "^Server:" || echo "")
    if echo "$server_header" | grep -qi "python\|flask\|werkzeug\|gunicorn"; then
        result "Server header leaks Python framework: $server_header" FAIL
    else
        result "Server header clean: ${server_header:-<none>}" OK
    fi
else
    result "curl not installed — skipping HTTP tests" WARN
fi

# ── Expected Ports Open ──
echo "── Port Profile ──"
if [ "$MODE" = "cisco_phone" ]; then
    expected_ports=(80 5060 10000)
    unexpected_ports=(9100 515 631 161 23)
elif [ "$MODE" = "hp_printer" ]; then
    expected_ports=(80 9100 515 631 161 23)
    unexpected_ports=(5060 10000)
fi

for port in "${expected_ports[@]}"; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        result "Port $port open (expected for $MODE)" OK
    else
        result "Port $port closed (should be open for $MODE)" FAIL
    fi
done

for port in "${unexpected_ports[@]}"; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        result "Port $port open (should NOT be open in $MODE)" FAIL
    else
        result "Port $port closed (correct — not part of $MODE)" OK
    fi
done

# ── No Raccoon/implant strings in HTTP ──
echo "── OPSEC Check ──"
http_full=$(curl -s http://127.0.0.1:80/ 2>/dev/null || echo "")
for keyword in "raccoon" "implant" "TrashPanda" "pentest" "ParrotOS"; do
    if echo "$http_full" | grep -qi "$keyword"; then
        result "HTTP leaks keyword '$keyword'" FAIL
    fi
done
result "No implant keywords in HTTP response" OK

# Check process names
if ps aux 2>/dev/null | grep -v grep | grep -qi "raccoon\|implant"; then
    result "Process name contains 'raccoon'/'implant' — visible in ps" WARN
else
    result "No identifying process names visible" OK
fi

# ── SNMP (HP printer only) ──
if [ "$MODE" = "hp_printer" ]; then
    echo "── SNMP ──"
    if command -v snmpget &>/dev/null; then
        sys_descr=$(snmpget -v2c -c public 127.0.0.1 1.3.6.1.2.1.1.1.0 2>/dev/null | grep -oP 'STRING: \K.*' || echo "")
        if echo "$sys_descr" | grep -qi "HP\|LaserJet"; then
            result "SNMP sysDescr matches HP printer" OK
        elif [ -n "$sys_descr" ]; then
            result "SNMP responds but sysDescr wrong: $sys_descr" FAIL
        else
            result "SNMP not responding" FAIL
        fi
    else
        result "snmpget not installed — skipping SNMP test" WARN
    fi
fi

# ── SIP (Cisco phone only) ──
if [ "$MODE" = "cisco_phone" ]; then
    echo "── SIP ──"
    if ss -ulnp 2>/dev/null | grep -q ":5060 "; then
        result "SIP port 5060 listening (UDP)" OK
    else
        result "SIP port 5060 not listening" FAIL
    fi
fi

# ── Summary ──
echo
echo "────────────────────────────────────"
printf "Results: \033[32m%d OK\033[0m / \033[33m%d WARN\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
