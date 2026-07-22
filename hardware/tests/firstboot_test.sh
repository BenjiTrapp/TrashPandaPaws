#!/bin/bash
# Raccoon HAT v1 — First Boot Validation Test
# Verifies the SD card image was provisioned correctly and all
# components are in place for first deployment.
# Run ONCE after flashing the image and booting the device.
# Usage: sudo ./firstboot_test.sh

set -euo pipefail

CONFIG="/opt/raccoon/configs/raccoon.yaml"

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
echo "║   Raccoon HAT v1 — First Boot Validation       ║"
echo "╚═══════════════════════════════════════════════╝"
echo
echo "Date: $(date)"
echo "Kernel: $(uname -r)"
echo "Hostname: $(hostname)"
echo

# ── Hardware identification ──
echo "── Hardware ──"
model=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0' || echo "unknown")
if echo "$model" | grep -qi "Raspberry Pi 4"; then
    result "Platform: $model" OK
else
    result "Platform: $model (expected Raspberry Pi 4)" WARN
fi

mem_total=$(free -m | awk '/Mem:/{print $2}')
if [ "$mem_total" -ge 3500 ]; then
    result "RAM: ${mem_total}MB (4GB+)" OK
elif [ "$mem_total" -ge 1800 ]; then
    result "RAM: ${mem_total}MB (2GB — 4GB recommended)" WARN
else
    result "RAM: ${mem_total}MB (insufficient)" FAIL
fi

# ── Filesystem ──
echo "── Filesystem ──"
root_avail=$(df -m / | tail -1 | awk '{print $4}')
if [ "$root_avail" -ge 2000 ]; then
    result "Root filesystem: ${root_avail}MB free" OK
else
    result "Root filesystem: ${root_avail}MB free (low)" WARN
fi

# Check if filesystem was expanded
root_size=$(df -m / | tail -1 | awk '{print $2}')
if [ "$root_size" -ge 7000 ]; then
    result "Filesystem expanded (${root_size}MB)" OK
else
    result "Filesystem only ${root_size}MB — may need raspi-config expand" WARN
fi

# ── Required directories ──
echo "── Directory Structure ──"
for dir in /opt/raccoon /opt/raccoon/configs /opt/raccoon/modules /opt/raccoon/logs; do
    if [ -d "$dir" ]; then
        result "$dir exists" OK
    else
        result "$dir missing" FAIL
    fi
done

# Capture directory
capture_dir=$(grep -oP 'capture_dir:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "/opt/raccoon/captures")
if [ -d "$capture_dir" ]; then
    result "$capture_dir exists" OK
else
    result "$capture_dir missing (creating)" WARN
    mkdir -p "$capture_dir" 2>/dev/null
fi

# ── Config file ──
echo "── Configuration ──"
if [ -f "$CONFIG" ]; then
    result "Main config exists: $CONFIG" OK

    # Validate YAML syntax
    if command -v python3 &>/dev/null; then
        if python3 -c "import yaml; yaml.safe_load(open('$CONFIG'))" 2>/dev/null; then
            result "YAML syntax valid" OK
        else
            result "YAML syntax error in config" FAIL
        fi
    fi

    # Check device_mode is set
    device_mode=$(grep -oP 'device_mode:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "")
    if [ -n "$device_mode" ]; then
        result "device_mode: $device_mode" OK
    else
        result "device_mode not set in config" FAIL
    fi
else
    result "Config file missing: $CONFIG" FAIL
fi

# ── Python environment ──
echo "── Python ──"
if command -v python3 &>/dev/null; then
    py_version=$(python3 --version 2>&1)
    result "$py_version" OK
else
    result "python3 not found" FAIL
fi

if command -v pip3 &>/dev/null; then
    result "pip3 available" OK
else
    result "pip3 not found" WARN
fi

# Check required Python modules
for module in yaml scapy netifaces requests pyroute2; do
    if python3 -c "import $module" 2>/dev/null; then
        result "Python module: $module" OK
    else
        result "Python module missing: $module" FAIL
    fi
done

# ── Required system packages ──
echo "── System Packages ──"
for pkg in bridge-utils ebtables iptables tcpdump iproute2 macchanger; do
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        result "Package: $pkg" OK
    else
        result "Package missing: $pkg" FAIL
    fi
done

# Optional but recommended
for pkg in autossh iperf3 stress-ng nmap tshark; do
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        result "Optional package: $pkg" OK
    else
        result "Optional package missing: $pkg" WARN
    fi
done

# ── Network interfaces ──
echo "── Network Interfaces ──"
# Built-in Ethernet
if ip link show eth0 &>/dev/null; then
    result "eth0 (built-in) present" OK
else
    result "eth0 not found" FAIL
fi

# USB Ethernet (RTL8153B HAT)
hat_iface=""
for iface in eth1 enx* usb0; do
    if ip link show "$iface" &>/dev/null 2>&1; then
        hat_iface="$iface"
        break
    fi
done
if [ -n "$hat_iface" ]; then
    result "HAT USB Ethernet: $hat_iface" OK
else
    result "No USB Ethernet found (HAT not detected?)" FAIL
fi

# USB device check
if lsusb 2>/dev/null | grep -q "0bda:8153"; then
    result "RTL8153B USB device detected (0bda:8153)" OK
else
    result "RTL8153B not found on USB bus" FAIL
fi

# ── Systemd services ──
echo "── Services ──"
for svc in raccoon raccoon-bridge raccoon-cover; do
    if systemctl list-unit-files 2>/dev/null | grep -q "$svc"; then
        if systemctl is-enabled "$svc" 2>/dev/null | grep -q "enabled"; then
            result "Service $svc: enabled" OK
        else
            result "Service $svc: exists but not enabled" WARN
        fi
    else
        result "Service $svc: not installed" WARN
    fi
done

# ── SSH keys ──
echo "── SSH Keys ──"
ssh_dir="/opt/raccoon/.ssh"
if [ -d "$ssh_dir" ]; then
    result "SSH directory exists" OK
    key_files=$(find "$ssh_dir" -name "id_*" -not -name "*.pub" 2>/dev/null | wc -l)
    if [ "$key_files" -gt 0 ]; then
        result "Found $key_files SSH private key(s)" OK
    else
        result "No SSH keys generated yet" WARN
    fi
else
    result "SSH directory missing: $ssh_dir" WARN
fi

# ── MAC address not default ──
echo "── MAC Address ──"
for iface in eth0 br0; do
    mac=$(ip link show "$iface" 2>/dev/null | grep -oP 'link/ether \K[0-9a-f:]+' || continue)
    oui=$(echo "$mac" | cut -d: -f1-3)
    case "$oui" in
        b8:27:eb|dc:a6:32|e4:5f:01|d8:3a:dd|2c:cf:67)
            result "$iface MAC $mac — default RPi OUI (must change before deploy)" FAIL ;;
        *)
            result "$iface MAC $mac (non-RPi OUI)" OK ;;
    esac
done

# ── Hostname not default ──
echo "── Hostname ──"
hn=$(hostname)
if echo "$hn" | grep -qi "raspberry\|parrot\|kali\|linux"; then
    result "Hostname '$hn' reveals OS identity — must change" FAIL
else
    result "Hostname: $hn" OK
fi

# ── Time sync ──
echo "── Time ──"
if timedatectl 2>/dev/null | grep -q "synchronized: yes"; then
    result "NTP synchronized" OK
elif systemctl is-active systemd-timesyncd &>/dev/null; then
    result "Time sync service running" OK
else
    result "Time not synchronized — logs will have wrong timestamps" WARN
fi

# ── Kernel modules ──
echo "── Kernel Modules ──"
for mod in bridge br_netfilter 8021q; do
    if lsmod 2>/dev/null | grep -q "^$mod"; then
        result "Module loaded: $mod" OK
    else
        if modprobe "$mod" 2>/dev/null; then
            result "Module loaded (on demand): $mod" OK
        else
            result "Module unavailable: $mod" WARN
        fi
    fi
done

# ── Disable unnecessary services ──
echo "── Unnecessary Services ──"
for svc in bluetooth avahi-daemon cups; do
    if systemctl is-active "$svc" 2>/dev/null | grep -q "active"; then
        result "$svc running — should be disabled for OPSEC" WARN
    else
        result "$svc not running" OK
    fi
done

# ── Write first-boot marker ──
MARKER="/opt/raccoon/.firstboot_done"
if [ ! -f "$MARKER" ]; then
    echo "$(date -Iseconds) firstboot_test passed=$PASS failed=$FAIL warned=$WARN" > "$MARKER"
    result "First-boot marker written" OK
else
    prev=$(cat "$MARKER" | head -1)
    result "Device was already validated: $prev" WARN
fi

# ── Summary ──
echo
echo "════════════════════════════════════"
printf "Results: \033[32m%d OK\033[0m / \033[33m%d WARN\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"
echo

if [ "$FAIL" -gt 0 ]; then
    echo "FIRST BOOT VALIDATION FAILED — fix issues before deploying."
    exit 1
elif [ "$WARN" -gt 3 ]; then
    echo "Validation passed with warnings — review before deploying."
    exit 0
else
    echo "Device ready for deployment."
    exit 0
fi
