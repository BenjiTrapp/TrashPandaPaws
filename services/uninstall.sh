#!/bin/bash
# Raccoon Implant — Complete service and persistence removal
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[!] Must run as root (sudo)"
    exit 1
fi

echo "[*] Removing Raccoon Implant services and persistence"

# systemd services
for svc in raccoon-implant raccoon-beacon raccoon-watchdog raccoon-macspoof raccoon-beacon-check; do
    systemctl stop "${svc}.service" 2>/dev/null || true
    systemctl disable "${svc}.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/${svc}.service"
done

# systemd timer
systemctl stop raccoon-beacon-check.timer 2>/dev/null || true
systemctl disable raccoon-beacon-check.timer 2>/dev/null || true
rm -f /etc/systemd/system/raccoon-beacon-check.timer

systemctl daemon-reload

# crontab
(crontab -l 2>/dev/null | grep -v "beacon_standalone") | crontab - 2>/dev/null || true

# rc.local
if [ -f /etc/rc.local ]; then
    sed -i '/beacon_standalone/d' /etc/rc.local
fi

# udev rules
rm -f /etc/udev/rules.d/99-raccoon-beacon.rules
rm -f /etc/udev/rules.d/99-raccoon-promisc.rules
udevadm control --reload-rules 2>/dev/null || true

# PID file
rm -f /tmp/.raccoon_beacon.pid

echo "[+] All services and persistence removed"
