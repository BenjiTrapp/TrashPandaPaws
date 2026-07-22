#!/bin/bash
# Raccoon HAT v1 — Hardware Smoke Test
# Run on the Raspberry Pi after the HAT is connected and powered via PoE.
# Usage: sudo ./smoke_test.sh

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

echo "╔══════════════════════════════════════════╗"
echo "║   Raccoon HAT v1 — Hardware Smoke Test   ║"
echo "╚══════════════════════════════════════════╝"
echo

# ── USB Enumeration ──
echo "── USB Enumeration ──"
if lsusb 2>/dev/null | grep -q "0bda:8153"; then
    result "RTL8153B detected (0bda:8153)" OK
else
    result "RTL8153B not found on USB bus" FAIL
fi

# ── Network Interfaces ──
echo "── Network Interfaces ──"
ETH1=""
for iface in eth1 enx* usb0; do
    if ip link show "$iface" &>/dev/null; then
        ETH1="$iface"
        break
    fi
done

if [ -n "$ETH1" ]; then
    result "Second Ethernet interface: $ETH1" OK
else
    result "No second Ethernet interface found" FAIL
fi

if ip link show eth0 &>/dev/null; then
    result "Primary Ethernet (eth0) present" OK
else
    result "Primary Ethernet (eth0) missing" FAIL
fi

# ── Link Status ──
echo "── Link Status ──"
for iface in eth0 ${ETH1:-}; do
    [ -z "$iface" ] && continue
    carrier=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null || echo 0)
    speed=$(ethtool "$iface" 2>/dev/null | grep -oP 'Speed: \K[0-9]+' || echo 0)
    if [ "$carrier" = "1" ]; then
        if [ "$speed" -ge 1000 ]; then
            result "$iface: link up @ ${speed}Mbps" OK
        else
            result "$iface: link up but only ${speed}Mbps (expected 1000)" WARN
        fi
    else
        result "$iface: no link" WARN
    fi
done

# ── Bridge ──
echo "── Bridge Configuration ──"
if ip link show br0 &>/dev/null; then
    members=$(bridge link show 2>/dev/null | grep -c "master br0" || echo 0)
    if [ "$members" -ge 2 ]; then
        result "Bridge br0 with $members members" OK
    else
        result "Bridge br0 exists but only $members member(s)" WARN
    fi
else
    result "Bridge br0 not configured (expected for tap mode)" WARN
fi

# ── Power Rails (if INA219 or sysfs hwmon available) ──
echo "── Power Rails ──"
hwmon_found=false
for hwmon in /sys/class/hwmon/hwmon*/; do
    name=$(cat "${hwmon}name" 2>/dev/null || continue)
    if [ "$name" = "ina219" ] || [ "$name" = "ina226" ]; then
        hwmon_found=true
        voltage=$(cat "${hwmon}in1_input" 2>/dev/null || echo 0)
        voltage_v=$(echo "scale=2; $voltage / 1000" | bc 2>/dev/null || echo "?")
        if [ "$voltage" -gt 4500 ] && [ "$voltage" -lt 5500 ]; then
            result "5V rail: ${voltage_v}V" OK
        else
            result "5V rail: ${voltage_v}V (out of range 4.5-5.5V)" FAIL
        fi
    fi
done
if ! $hwmon_found; then
    result "No power monitor (INA219) detected — measure manually" WARN
fi

# ── GPIO Header ──
echo "── GPIO ──"
if [ -d /sys/class/gpio ] || [ -d /sys/bus/platform/drivers/pinctrl-bcm2835 ]; then
    result "GPIO subsystem available" OK
else
    result "GPIO subsystem not found" WARN
fi

# ── SPI Flash (W25Q16 via RTL8153B, not directly accessible) ──
echo "── Firmware ──"
if [ -n "$ETH1" ]; then
    driver=$(ethtool -i "$ETH1" 2>/dev/null | grep -oP 'driver: \K.*' || echo "unknown")
    fw=$(ethtool -i "$ETH1" 2>/dev/null | grep -oP 'firmware-version: \K.*' || echo "unknown")
    result "Driver: $driver, FW: $fw" OK
fi

# ── Temperature ──
echo "── Thermal ──"
cpu_temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0)
cpu_temp_c=$((cpu_temp / 1000))
if [ "$cpu_temp_c" -lt 70 ]; then
    result "CPU temp: ${cpu_temp_c}°C" OK
elif [ "$cpu_temp_c" -lt 80 ]; then
    result "CPU temp: ${cpu_temp_c}°C (warm)" WARN
else
    result "CPU temp: ${cpu_temp_c}°C (throttling likely)" FAIL
fi

# ── Summary ──
echo
echo "────────────────────────────────────"
printf "Results: \033[32m%d OK\033[0m / \033[33m%d WARN\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo "Some tests FAILED — check hardware connections."
    exit 1
elif [ "$WARN" -gt 0 ]; then
    echo "All critical tests passed, some warnings."
    exit 0
else
    echo "All tests passed."
    exit 0
fi
