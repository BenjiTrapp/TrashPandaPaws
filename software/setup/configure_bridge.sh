#!/bin/bash
# Raccoon Implant — Network bridge configuration for ParrotOS
# Creates a persistent bridge between eth0 (upstream) and eth1 (downstream).
# ParrotOS uses NetworkManager by default — this script configures both
# NetworkManager (nmcli) and ifupdown as fallback.
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Must run as root (sudo)${NC}"
    exit 1
fi

UPSTREAM="${1:-eth0}"
DOWNSTREAM="${2:-eth1}"
BRIDGE="br0"

echo -e "${YELLOW}[*] Configuring bridge: ${BRIDGE}${NC}"
echo -e "${YELLOW}    Upstream:   ${UPSTREAM} (from switch / PoE)${NC}"
echo -e "${YELLOW}    Downstream: ${DOWNSTREAM} (to target device)${NC}"

# Verify interfaces exist
for iface in "$UPSTREAM" "$DOWNSTREAM"; do
    if ! ip link show "$iface" &>/dev/null; then
        echo -e "${RED}[!] Interface ${iface} not found${NC}"
        echo "    Available interfaces:"
        ip -brief link show | grep -v lo
        exit 1
    fi
done

# ── Method 1: NetworkManager (ParrotOS default) ──
if command -v nmcli &>/dev/null && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    echo -e "${GREEN}[+] Configuring via NetworkManager${NC}"

    # Remove existing connections for these interfaces
    for iface in "$UPSTREAM" "$DOWNSTREAM" "$BRIDGE"; do
        nmcli connection delete "$iface" 2>/dev/null || true
        nmcli connection delete "bridge-${iface}" 2>/dev/null || true
        nmcli connection delete "bridge-slave-${iface}" 2>/dev/null || true
    done

    # Create bridge
    nmcli connection add type bridge \
        ifname "$BRIDGE" \
        con-name "$BRIDGE" \
        bridge.stp no \
        bridge.forward-delay 0 \
        ipv4.method auto \
        ipv6.method disabled \
        connection.autoconnect yes

    # Add upstream as bridge slave
    nmcli connection add type bridge-slave \
        ifname "$UPSTREAM" \
        con-name "bridge-slave-${UPSTREAM}" \
        master "$BRIDGE" \
        connection.autoconnect yes

    # Add downstream as bridge slave
    nmcli connection add type bridge-slave \
        ifname "$DOWNSTREAM" \
        con-name "bridge-slave-${DOWNSTREAM}" \
        master "$BRIDGE" \
        connection.autoconnect yes

    # Set promiscuous mode
    ip link set "$UPSTREAM" promisc on 2>/dev/null || true
    ip link set "$DOWNSTREAM" promisc on 2>/dev/null || true

    # Activate
    nmcli connection up "$BRIDGE" 2>/dev/null || true

    echo -e "${GREEN}[+] NetworkManager bridge configured and activated${NC}"

else
    # ── Method 2: ifupdown fallback ──
    echo -e "${YELLOW}[!] NetworkManager not active, using ifupdown${NC}"

    echo -e "${GREEN}[+] Writing /etc/network/interfaces.d/raccoon-bridge${NC}"
    cat > /etc/network/interfaces.d/raccoon-bridge <<EOF
# Raccoon Implant — Transparent Ethernet Bridge
# Bridges ${UPSTREAM} (upstream/PoE) and ${DOWNSTREAM} (downstream/target)

auto ${UPSTREAM}
iface ${UPSTREAM} inet manual
    up ip link set \$IFACE up promisc on
    down ip link set \$IFACE down promisc off

auto ${DOWNSTREAM}
iface ${DOWNSTREAM} inet manual
    up ip link set \$IFACE up promisc on
    down ip link set \$IFACE down promisc off

auto ${BRIDGE}
iface ${BRIDGE} inet dhcp
    bridge_ports ${UPSTREAM} ${DOWNSTREAM}
    bridge_stp off
    bridge_fd 0
    bridge_maxwait 0
    up ip link set ${BRIDGE} promisc on
EOF

    # Prevent dhcpcd from managing bridge members
    if systemctl is-active --quiet dhcpcd 2>/dev/null; then
        echo -e "${GREEN}[+] Configuring dhcpcd to ignore bridge members${NC}"
        if ! grep -q "denyinterfaces ${UPSTREAM}" /etc/dhcpcd.conf 2>/dev/null; then
            cat >> /etc/dhcpcd.conf <<EOF

# Raccoon Implant — bridge members managed separately
denyinterfaces ${UPSTREAM}
denyinterfaces ${DOWNSTREAM}
EOF
        fi
    fi

    echo -e "${GREEN}[+] ifupdown bridge configuration written${NC}"
fi

# ── Persist promiscuous mode via udev rule ──
echo -e "${GREEN}[+] Creating udev rule for persistent promiscuous mode${NC}"
cat > /etc/udev/rules.d/99-raccoon-promisc.rules <<EOF
ACTION=="add", SUBSYSTEM=="net", KERNEL=="${UPSTREAM}", RUN+="/sbin/ip link set %k promisc on"
ACTION=="add", SUBSYSTEM=="net", KERNEL=="${DOWNSTREAM}", RUN+="/sbin/ip link set %k promisc on"
EOF
udevadm control --reload-rules 2>/dev/null || true

echo ""
echo -e "${GREEN}[+] Bridge configuration complete${NC}"
echo ""
echo -e "${YELLOW}To activate now (if not already active):${NC}"
if command -v nmcli &>/dev/null; then
    echo "  sudo nmcli connection up ${BRIDGE}"
else
    echo "  sudo ifup ${BRIDGE}"
fi
echo ""
echo -e "${YELLOW}Verify with:${NC}"
echo "  brctl show"
echo "  ip addr show ${BRIDGE}"
echo ""
