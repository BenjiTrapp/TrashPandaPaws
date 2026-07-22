#!/bin/bash
# Raccoon HAT v1 — SSH Reverse Tunnel Test
# Verifies remote access via SSH reverse tunnel is working,
# persistent, and not leaking identity.
# Usage: sudo ./ssh_tunnel_test.sh [ssh_server]

set -euo pipefail

CONFIG="/opt/raccoon/configs/raccoon.yaml"
SSH_SERVER="${1:-}"

if [ -z "$SSH_SERVER" ] && [ -f "$CONFIG" ]; then
    SSH_SERVER=$(grep -oP 'ssh_server:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "")
fi
if [ -z "$SSH_SERVER" ]; then
    echo "Usage: sudo $0 <ssh_jump_server>"
    echo "  Or set ssh_server in $CONFIG"
    exit 1
fi

SSH_PORT=$(grep -oP 'ssh_port:\s*\K\d+' "$CONFIG" 2>/dev/null || echo "22")
REVERSE_PORT=$(grep -oP 'reverse_port:\s*\K\d+' "$CONFIG" 2>/dev/null || echo "")
SSH_USER=$(grep -oP 'ssh_user:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "raccoon")
SSH_KEY=$(grep -oP 'ssh_key:\s*"\K[^"]+' "$CONFIG" 2>/dev/null || echo "/opt/raccoon/.ssh/id_ed25519")

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
echo "║   Raccoon HAT v1 — SSH Reverse Tunnel Test     ║"
echo "╚═══════════════════════════════════════════════╝"
echo
echo "SSH server: $SSH_USER@$SSH_SERVER:$SSH_PORT"
echo "Reverse port: ${REVERSE_PORT:-not configured}"
echo

# ── SSH client ──
echo "── SSH Client ──"
if command -v ssh &>/dev/null; then
    ssh_version=$(ssh -V 2>&1 | head -1)
    result "SSH client: $ssh_version" OK
else
    result "SSH client not installed" FAIL
    exit 1
fi

if command -v autossh &>/dev/null; then
    result "autossh installed (persistent tunnels)" OK
else
    result "autossh not found — tunnel may not auto-reconnect" WARN
fi

# ── SSH key ──
echo "── SSH Key ──"
if [ -f "$SSH_KEY" ]; then
    result "SSH key exists: $SSH_KEY" OK

    # Check permissions
    key_perms=$(stat -c %a "$SSH_KEY" 2>/dev/null || echo "???")
    if [ "$key_perms" = "600" ] || [ "$key_perms" = "400" ]; then
        result "Key permissions: $key_perms (correct)" OK
    else
        result "Key permissions: $key_perms (should be 600)" FAIL
    fi

    # Check key type
    key_type=$(ssh-keygen -l -f "$SSH_KEY" 2>/dev/null | awk '{print $4}' || echo "unknown")
    if echo "$key_type" | grep -qi "ED25519\|ECDSA"; then
        result "Key type: $key_type" OK
    elif echo "$key_type" | grep -qi "RSA"; then
        key_bits=$(ssh-keygen -l -f "$SSH_KEY" 2>/dev/null | awk '{print $1}' || echo 0)
        if [ "$key_bits" -ge 4096 ]; then
            result "Key type: RSA-$key_bits (OK but ED25519 preferred)" OK
        else
            result "Key type: RSA-$key_bits (weak — use ED25519)" WARN
        fi
    else
        result "Key type: $key_type" WARN
    fi

    # No passphrase (required for unattended use)
    if ssh-keygen -y -P "" -f "$SSH_KEY" &>/dev/null; then
        result "Key has no passphrase (correct for unattended tunnel)" OK
    else
        result "Key has passphrase — tunnel cannot auto-start" FAIL
    fi
else
    result "SSH key not found: $SSH_KEY" FAIL
fi

# ── known_hosts ──
echo "── Known Hosts ──"
known_hosts="/opt/raccoon/.ssh/known_hosts"
if [ -f "$known_hosts" ]; then
    if grep -q "$SSH_SERVER" "$known_hosts" 2>/dev/null; then
        result "Server fingerprint in known_hosts" OK
    else
        result "Server $SSH_SERVER not in known_hosts — first connect will prompt" WARN
    fi
else
    result "known_hosts file missing" WARN
fi

# ── TCP connectivity to SSH server ──
echo "── Server Connectivity ──"
if timeout 5 bash -c "echo >/dev/tcp/$SSH_SERVER/$SSH_PORT" 2>/dev/null; then
    result "TCP to $SSH_SERVER:$SSH_PORT reachable" OK
else
    result "Cannot reach $SSH_SERVER:$SSH_PORT" FAIL
fi

# ── Active tunnel check ──
echo "── Active Tunnel ──"
tunnel_procs=$(pgrep -af "ssh.*-R\|autossh" 2>/dev/null | grep -v grep || echo "")
if [ -n "$tunnel_procs" ]; then
    result "Active SSH tunnel process found:" OK
    echo "$tunnel_procs" | head -3 | while read -r line; do
        echo "    $line"
    done

    # Check if reverse port is bound
    if [ -n "$REVERSE_PORT" ]; then
        if ss -tlnp 2>/dev/null | grep -q ":$REVERSE_PORT "; then
            result "Reverse port $REVERSE_PORT is bound locally" OK
        else
            result "Reverse port $REVERSE_PORT not bound locally (bound on server side)" OK
        fi
    fi
else
    result "No active SSH tunnel process" WARN
fi

# ── Tunnel persistence (systemd / cron) ──
echo "── Tunnel Persistence ──"
if systemctl is-enabled raccoon-tunnel 2>/dev/null | grep -q "enabled"; then
    result "raccoon-tunnel systemd service enabled" OK
    if systemctl is-active raccoon-tunnel 2>/dev/null | grep -q "active"; then
        result "raccoon-tunnel service running" OK
    else
        result "raccoon-tunnel service not running" FAIL
    fi
elif crontab -l 2>/dev/null | grep -q "autossh\|ssh.*-R"; then
    result "Tunnel restart configured via crontab" OK
else
    result "No tunnel persistence mechanism found (systemd/cron)" WARN
fi

# ── SSH config hardening ──
echo "── SSH Config ──"
ssh_config="/opt/raccoon/.ssh/config"
if [ -f "$ssh_config" ]; then
    result "SSH config file exists" OK

    # Check for keepalive
    if grep -qi "ServerAliveInterval" "$ssh_config" 2>/dev/null; then
        interval=$(grep -oP 'ServerAliveInterval\s+\K\d+' "$ssh_config" || echo "?")
        result "ServerAliveInterval: ${interval}s" OK
    else
        result "No ServerAliveInterval — tunnel may drop silently" WARN
    fi

    if grep -qi "ServerAliveCountMax" "$ssh_config" 2>/dev/null; then
        result "ServerAliveCountMax configured" OK
    fi

    # Check for OPSEC settings
    if grep -qi "StrictHostKeyChecking" "$ssh_config" 2>/dev/null; then
        result "StrictHostKeyChecking configured" OK
    fi
else
    result "No SSH config file at $ssh_config" WARN
fi

# ── OPSEC: SSH not exposed locally ──
echo "── OPSEC ──"
if ss -tlnp 2>/dev/null | grep -qP ":22\s.*0\.0\.0\.0"; then
    result "SSH port 22 listening on 0.0.0.0 — should be localhost only" FAIL
elif ss -tlnp 2>/dev/null | grep -qP ":22\s.*127\.0\.0\.1"; then
    result "SSH port 22 listening on localhost only (correct)" OK
elif ss -tlnp 2>/dev/null | grep -q ":22 "; then
    result "SSH port 22 listening — check bind address" WARN
else
    result "SSH port 22 not listening (tunnel-only access)" OK
fi

# Check SSH banner
sshd_config="/etc/ssh/sshd_config"
if [ -f "$sshd_config" ]; then
    if grep -qi "^Banner" "$sshd_config" 2>/dev/null; then
        result "SSH banner configured — may leak info" WARN
    else
        result "No SSH banner (good)" OK
    fi

    if grep -qi "^PasswordAuthentication.*no" "$sshd_config" 2>/dev/null; then
        result "Password auth disabled (key-only)" OK
    else
        result "Password auth may be enabled" WARN
    fi
fi

# ── Summary ──
echo
echo "────────────────────────────────────"
printf "Results: \033[32m%d OK\033[0m / \033[33m%d WARN\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
