#!/bin/bash
# Raccoon Implant — Service installation
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Must run as root (sudo)${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo -e "${YELLOW}[*] Installing Raccoon Implant services${NC}"

# ── Preflight: a config that would be refused ──
# Warn and carry on rather than stop. The fix is an edit to the config, which
# the services read at their next start, so nothing here needs re-running; and
# a device installed but not enabled would fail after the next reboot just as
# silently, in a different place.
KEY_CHECK=0
bash "${SCRIPT_DIR}/check_beacon_key.sh" || KEY_CHECK=$?

# ── Core services ──
echo -e "${GREEN}[+] Installing systemd units${NC}"
cp "${SCRIPT_DIR}/raccoon-implant.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/raccoon-beacon.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/raccoon-watchdog.service" /etc/systemd/system/

# ── The gsocket carrier: copied, never enabled ──
# The team server's side of c2.fallback.gsocket, for a host that wants a
# carrier without the 📡 panel. It is put in place here because this script
# is the only thing in the repository that installs units, and left disabled
# on purpose: a carrier joins the Global Socket Relay Network, a third party,
# and nothing should join one because an installer ran. It also needs a
# secret file this script cannot invent -- see /etc/raccoon/gsocket.env in
# the unit, and the GSRN section of docs/LISTENERS.md.
#
# A drop-box needs no unit for this leg at all: the beacon starts its own
# gs-netcat child, lazily, and restarts it itself.
cp "${SCRIPT_DIR}/raccoon-gsocket.service" /etc/systemd/system/

systemctl daemon-reload

systemctl enable raccoon-implant.service
systemctl enable raccoon-beacon.service
systemctl enable raccoon-watchdog.service

echo -e "${GREEN}[+] Core services enabled${NC}"

# ── Beacon persistence (multi-layer) ──
echo -e "${GREEN}[+] Installing beacon persistence${NC}"
if [ -x "${PROJECT_DIR}/software/setup/persist.sh" ]; then
    bash "${PROJECT_DIR}/software/setup/persist.sh"
else
    chmod +x "${PROJECT_DIR}/software/setup/persist.sh"
    bash "${PROJECT_DIR}/software/setup/persist.sh"
fi

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  All services installed${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
if [ "$KEY_CHECK" -ne 0 ]; then
    echo -e "${RED}[!] Not ready to call back: set c2.encryption_key in /opt/raccoon/configs/raccoon.yaml first (see the warning above).${NC}"
    echo ""
fi
echo -e "${YELLOW}Management:${NC}"
echo "  sudo systemctl start raccoon-implant    # full implant"
echo "  sudo systemctl start raccoon-beacon     # beacon only"
echo "  sudo systemctl status raccoon-implant"
echo "  sudo systemctl status raccoon-beacon"
echo "  sudo journalctl -u raccoon-implant -f"
echo ""
echo -e "${YELLOW}raccoon-gsocket is installed and deliberately not enabled:${NC}"
echo "  It is the team server's side of the gsocket C2 leg, and starting it"
echo "  dials the Global Socket Relay Network — a third party. An implant"
echo "  needs no unit for that leg; the beacon runs its own gs-netcat child."
echo "  Read the GSRN section of docs/LISTENERS.md first, then on a team"
echo "  server: write /etc/raccoon/gsocket.env (0600) and"
echo "  sudo systemctl enable --now raccoon-gsocket"
echo ""
echo -e "${YELLOW}After reboot, the beacon starts automatically via:${NC}"
echo "  1. systemd raccoon-beacon.service"
echo "  2. crontab @reboot"
echo "  3. rc.local"
echo "  4. udev network trigger"
echo "  5. systemd timer watchdog (every 5 min)"
echo ""
