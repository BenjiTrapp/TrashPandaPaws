#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  Raccoon C2 Team Server — Launcher (Linux/macOS)
# ──────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PY="$SCRIPT_DIR/server.py"

# ── Colors ──
R='\033[1;31m'    # Red (bold)
G='\033[1;32m'    # Green (bold)
Y='\033[1;33m'    # Yellow (bold)
C='\033[1;36m'    # Cyan (bold)
W='\033[1;37m'    # White (bold)
D='\033[0;90m'    # Dim
N='\033[0m'       # Reset

# ── Defaults ──
# HOST/PORT are the beacon socket and stay reachable from the network;
# the operator GUI and API get their own socket, loopback by default.
PORT="${PORT:-8443}"
HOST="${HOST:-0.0.0.0}"
OPERATOR_PORT="${OPERATOR_PORT:-8444}"
OPERATOR_HOST="${OPERATOR_HOST:-127.0.0.1}"
# The data directory the server is given; it keeps the operator token in
# $DATA_DIR/operator-token (mode 0600) and this launcher names the path.
DATA_DIR="$HOME/.raccoon-c2"
KEY=""
KEY_ORIGIN=""
TOKEN=""
SSL=""
CERT=""
CERTKEY=""
INTERACTIVE=""

# ── Parse args ──
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)       PORT="$2"; shift 2;;
        --host)       HOST="$2"; shift 2;;
        --operator-port) OPERATOR_PORT="$2"; shift 2;;
        --operator-host) OPERATOR_HOST="$2"; shift 2;;
        --key)        KEY="$2"; KEY_ORIGIN="passed with --key"; shift 2;;
        --token)      TOKEN="$2"; shift 2;;
        --ssl)        SSL="--ssl"; shift;;
        --cert)       CERT="$2"; shift 2;;
        --certkey)    CERTKEY="$2"; shift 2;;
        --interactive|-i) INTERACTIVE="1"; shift;;
        -h|--help)
            echo "Usage: $0 [--port 8443] [--host 0.0.0.0] [--operator-port 8444] [--operator-host 127.0.0.1] [--key <b64>] [--token <str>] [--ssl] [--cert <file>] [--certkey <file>] [-i|--interactive]"
            echo "  --host/--port: the beacon socket. --operator-host/--operator-port: the GUI and API."
            echo "  The key and token may instead come from RACCOON_KEY and RACCOON_TOKEN; a flag wins over its"
            echo "  variable. Prefer the variables: arguments are visible to every user in ps. The server is"
            echo "  handed both in its environment, never on its command line."
            exit 0;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

# Flag first, then the environment (the order the server and agent/config.py use).
if [[ -z "$KEY" && -n "${RACCOON_KEY:-}" ]]; then
    KEY="$RACCOON_KEY"
    KEY_ORIGIN="from RACCOON_KEY"
fi
if [[ -z "$TOKEN" && -n "${RACCOON_TOKEN:-}" ]]; then
    TOKEN="$RACCOON_TOKEN"
fi

# ── Banner ──
clear 2>/dev/null || true
echo ""
echo -e "${R}    ██████╗  █████╗  ██████╗ ██████╗ ██████╗  ██████╗ ███╗   ██╗${N}"
echo -e "${R}    ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔═══██╗████╗  ██║${N}"
echo -e "${R}    ██████╔╝███████║██║     ██║     ██║   ██║██║   ██║██╔██╗ ██║${N}"
echo -e "${R}    ██╔══██╗██╔══██║██║     ██║     ██║   ██║██║   ██║██║╚██╗██║${N}"
echo -e "${R}    ██║  ██║██║  ██║╚██████╗╚██████╗╚██████╔╝╚██████╔╝██║ ╚████║${N}"
echo -e "${R}    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝${N}"
echo ""
echo -e "${D}     ██████╗██████╗    ████████╗███████╗ █████╗ ███╗   ███╗${N}"
echo -e "${D}    ██╔════╝╚════██╗   ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║${N}"
echo -e "${W}    ██║      █████╔╝      ██║   █████╗  ███████║██╔████╔██║${N}"
echo -e "${D}    ██║     ██╔═══╝       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║${N}"
echo -e "${D}    ╚██████╗███████╗      ██║   ███████╗██║  ██║██║ ╚═╝ ██║${N}"
echo -e "${D}     ╚═════╝╚══════╝      ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝${N}"
echo ""
echo -e "${D}    ─────────────────────────────────────────────────────────${N}"
echo -e "${R}     🦝 T R A S H   P A N D A   P A W S${N}"
echo -e "${D}    ─────────────────────────────────────────────────────────${N}"
echo ""

# ── Pre-flight checks ──
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [[ -z "$PYTHON" ]]; then
    echo -e "${R}  [✗] Python not found${N}"
    exit 1
fi

PYVER=$($PYTHON --version 2>&1)
echo -e "${G}  [✓]${N} ${W}Python${N}        ${D}$PYVER${N}"

# ── Virtual environment ──
VENV_DIR="$SCRIPT_DIR/.venv"

if [[ ! -f "$VENV_DIR/bin/python" ]]; then
    echo -e "${C}  [*]${N} ${W}Creating venv${N} ${D}$VENV_DIR${N}"
    $PYTHON -m venv "$VENV_DIR"
    if [[ $? -ne 0 ]]; then
        echo -e "${R}  [✗] Failed to create venv${N}"
        exit 1
    fi
fi

PYTHON="$VENV_DIR/bin/python"
echo -e "${G}  [✓]${N} ${W}Venv${N}          ${D}$VENV_DIR${N}"

# ── Dependencies (pip) ──
$PYTHON -m pip install --upgrade pip --quiet 2>/dev/null || true

PIP_PKGS="flask cryptography impacket ldap3 lsassy"

MISSING=""
for pkg in $PIP_PKGS; do
    if ! $PYTHON -c "import $pkg" 2>/dev/null; then
        MISSING="$MISSING $pkg"
    fi
done

if [[ -n "$MISSING" ]]; then
    echo -e "${C}  [*]${N} ${W}Installing${N}    ${D}$MISSING${N}"
    for pkg in $MISSING; do
        if ! $PYTHON -m pip install "$pkg" --quiet 2>/dev/null; then
            echo -e "${Y}  [!]${N} ${W}$pkg${N} ${Y}install failed (skipped)${N}"
        fi
    done
fi

# ── NetExec (pipx, installed from GitHub) ──
if ! command -v pipx &>/dev/null; then
    echo ""
    echo -ne "${Y}  [?]${N} ${W}pipx is required for NetExec. Install pipx now?${N} ${D}[Y/n]${N} "
    read -r ANSWER
    if [[ -z "$ANSWER" || "$ANSWER" =~ ^[yYjJ] ]]; then
        echo -e "${C}  [*]${N} ${W}Installing${N}    ${D}pipx${N}"
        $PYTHON -m pip install pipx --quiet 2>/dev/null
        $PYTHON -m pipx ensurepath 2>/dev/null
        PIPX_BIN=$($PYTHON -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>/dev/null)
        if [[ -n "$PIPX_BIN" ]] && ! command -v pipx &>/dev/null; then
            export PATH="$PIPX_BIN:$PATH"
        fi
        if command -v pipx &>/dev/null; then
            echo -e "${G}  [✓]${N} ${W}pipx${N}          ${D}installed${N}"
        else
            echo -e "${Y}  [!]${N} ${W}pipx${N}          ${Y}install failed${N}"
        fi
    fi
fi
if command -v pipx &>/dev/null && ! command -v nxc &>/dev/null; then
    echo -e "${C}  [*]${N} ${W}Installing${N}    ${D}netexec (pipx)${N}"
    pipx install git+https://github.com/Pennyw0rth/NetExec 2>/dev/null || \
        echo -e "${Y}  [!]${N} ${W}netexec${N} ${Y}install failed (skipped)${N}"
fi

# ── Version display ──
_pkg_ver() {
    local ver
    ver=$($PYTHON -c "import importlib.metadata; print(importlib.metadata.version('$1'))" 2>/dev/null)
    if [[ -z "$ver" ]]; then
        echo -e "${Y}  [!]${N} ${W}$2${N}${Y}not installed${N}"
    else
        echo -e "${G}  [✓]${N} ${W}$2${N}${D}$ver${N}"
    fi
}

_pkg_ver flask        "Flask         "
_pkg_ver cryptography "Cryptography  "
_pkg_ver impacket     "Impacket      "
_pkg_ver ldap3        "ldap3         "
_pkg_ver lsassy       "Lsassy        "

NXC_VER=$(nxc --version 2>/dev/null || true)
if [[ -n "$NXC_VER" ]]; then
    echo -e "${G}  [✓]${N} ${W}NetExec       ${N}${D}$NXC_VER${N}"
else
    echo -e "${Y}  [!]${N} ${W}NetExec       ${N}${Y}not installed (requires pipx)${N}"
fi

# ── Interactive configuration ──
if [[ -n "$INTERACTIVE" ]] || { [[ -z "$KEY" ]] && [[ -t 0 ]]; }; then
    echo ""
    echo -e "${D}  ─────────────────────────────────────────────${N}"
    echo -e "${Y}  Server Configuration${N}"
    echo -e "${D}  ─────────────────────────────────────────────${N}"
    echo ""

    echo -ne "  ${C}Beacon listen host${N} ${D}[${HOST}]${N}: "
    read -r INPUT
    [[ -n "$INPUT" ]] && HOST="$INPUT"

    echo -ne "  ${C}Beacon listen port${N} ${D}[${PORT}]${N}: "
    read -r INPUT
    [[ -n "$INPUT" ]] && PORT="$INPUT"

    PROTO="http"
    [[ -n "$SSL" ]] && PROTO="https"

    echo ""
    echo -e "${D}  ─────────────────────────────────────────────${N}"
    echo -e "${Y}  Encryption${N}"
    echo -e "${D}  ─────────────────────────────────────────────${N}"
    echo ""
    echo -e "  ${W}Use AES-256-GCM encryption for beacon comms?${N}"
    echo -e "  ${D}Agents must use the same key to communicate.${N}"
    echo ""
    echo -e "  ${C}[1]${N} ${W}Generate a random key (default)${N}"
    echo -e "  ${C}[2]${N} ${W}Enter a key manually (base64)${N}"
    echo ""
    echo -ne "  ${Y}Choice${N} ${D}[1]${N}${W}: ${N}"
    read -r INPUT

    case "${INPUT:-1}" in
        1)
            KEY=$($PYTHON -c "
import base64, os
k = os.urandom(32)
print(base64.b64encode(k).decode())
")
            echo ""
            echo -e "  ${G}[✓]${N} ${W}Generated random AES-256-GCM key${N}"
            echo -e "  ${C}${KEY}${N}"
            echo -e "  ${R}  ⚠  Save this key — agents need it to connect!${N}"
            KEY_ORIGIN="generated for this run"
            ;;
        2)
            echo ""
            echo -ne "  ${Y}Key${N} ${D}(base64 AES-256-GCM, 32 bytes)${N}${W}: ${N}"
            read -r INPUT
            if [[ -n "$INPUT" ]]; then
                KEY="$INPUT"
                KEY_ORIGIN="entered by hand"
                echo -e "  ${G}[✓]${N} ${W}Using provided key${N}"
            fi
            ;;
        *)
            echo -e "  ${R}[✗]${N} ${W}Choose 1 or 2${N}"
            exit 1
            ;;
    esac

    echo ""
    echo -ne "  ${C}Operator token${N} ${D}[random]${N}: "
    read -r INPUT
    [[ -n "$INPUT" ]] && TOKEN="$INPUT"

    echo ""
fi

# ── Generate token if not set ──
if [[ -z "$TOKEN" ]]; then
    TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))" 2>/dev/null || openssl rand -base64 24 | tr -d '=/+' | head -c 32)
fi

# ── The key is required: there is no default and none is derived ──
PROTO="http"
[[ -n "$SSL" ]] && PROTO="https"

if [[ -z "$KEY" ]]; then
    echo -e "  ${R}[✗]${N} ${W}No encryption key. The server will not start without one.${N}"
    echo -e "  ${D}Pass --key <base64>, or run interactively and generate one:${N}"
    echo -e "  ${D}python3 -c \"import os,base64; print(base64.b64encode(os.urandom(32)).decode())\"${N}"
    exit 1
fi

ENC_KEY_B64="$KEY"
KEY_TYPE="${KEY_ORIGIN} (AES-256-GCM)"

# Enough to tell two keys apart, nowhere near enough to help guess one.
ENC_KEY_PREVIEW="${ENC_KEY_B64:0:6}..."
TOKEN_FILE="$DATA_DIR/operator-token"
# Shown as ~/..., which is what fits in the box.
TILDE='~'
TOKEN_FILE_SHOWN="${TOKEN_FILE/#$HOME/$TILDE}"

echo ""
echo -e "${D}  ┌──────────────────────────────────────────────────────┐${N}"
echo -e "${D}  │${N}  ${W}Server Configuration${N}                                 ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"

LISTEN_STR="${PROTO}://${HOST}:${PORT}"
GUI_STR="${PROTO}://${OPERATOR_HOST}:${OPERATOR_PORT}"
PAD_L=$((38 - ${#LISTEN_STR}))
PAD_G=$((38 - ${#GUI_STR}))
[[ $PAD_L -lt 0 ]] && PAD_L=0
[[ $PAD_G -lt 0 ]] && PAD_G=0

echo -e "${D}  │${N}  ${C}Beacons${N}      ${W}${LISTEN_STR}${N}$(printf '%*s' $PAD_L '')${D}│${N}"
echo -e "${D}  │${N}  ${C}GUI${N}          ${W}${GUI_STR}${N}$(printf '%*s' $PAD_G '')${D}│${N}"

PAD_K=$((38 - ${#KEY_TYPE}))
[[ $PAD_K -lt 0 ]] && PAD_K=0
KEY_COLOR="$G"
echo -e "${D}  │${N}  ${C}Encryption${N}   ${KEY_COLOR}${KEY_TYPE}${N}$(printf '%*s' $PAD_K '')${D}│${N}"

echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}  ${Y}Operator Token (for GUI login), in this file:${N}        ${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
PAD_T=$((52 - ${#TOKEN_FILE_SHOWN}))
[[ $PAD_T -lt 0 ]] && PAD_T=0
echo -e "${D}  │${N}  ${G}${TOKEN_FILE_SHOWN}${N}$(printf '%*s' $PAD_T '')${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}  ${Y}Encryption Key (agents need the whole of it):${N}        ${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
PAD_E=$((52 - ${#ENC_KEY_PREVIEW}))
[[ $PAD_E -lt 0 ]] && PAD_E=0
echo -e "${D}  │${N}  ${C}${ENC_KEY_PREVIEW}${N}$(printf '%*s' $PAD_E '')${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  └──────────────────────────────────────────────────────┘${N}"
echo ""
if [[ "$OPERATOR_PORT" != "$PORT" && ( "$OPERATOR_HOST" == 127.* || "$OPERATOR_HOST" == "localhost" || "$OPERATOR_HOST" == "::1" ) ]]; then
    echo -e "${D}  The GUI is loopback only. From another machine:${N}"
    echo -e "${D}  ssh -L ${OPERATOR_PORT}:${OPERATOR_HOST}:${OPERATOR_PORT} <user>@<this-host>, then open ${PROTO}://localhost:${OPERATOR_PORT}${N}"
    echo ""
fi
echo -e "${D}  Press Ctrl+C to stop the server${N}"
echo ""

# ── Build command ──
# The key and token are not in it: arguments are readable by every user in
# ps and /proc/<pid>/cmdline. They go in the environment at launch, below.
CMD=("$PYTHON" "$SERVER_PY" "--host" "$HOST" "--port" "$PORT"
     "--operator-host" "$OPERATOR_HOST" "--operator-port" "$OPERATOR_PORT"
     "--data-dir" "$DATA_DIR")
[[ -n "$SSL" ]]        && CMD+=("--ssl")
[[ -n "$CERT" ]]       && CMD+=("--cert" "$CERT")
[[ -n "$CERTKEY" ]]    && CMD+=("--certkey" "$CERTKEY")

# ── Optional: the autonomous agent service ──
#
# A question, never a default. The C2 has to start exactly the way it does
# today for someone who has no model configured, and this whole block is
# skipped unless it is answered yes or AGENT_START is already set.
#
# The agent runs as a separate process (design section 7) so that a model
# that stalls cannot hold up beacon handling. It binds loopback; the C2
# reads AGENT_URL to find it.
AGENT_START="${AGENT_START:-}"
AGENT_BIND_HOST="${AGENT_BIND_HOST:-127.0.0.1}"
AGENT_BIND_PORT="${AGENT_BIND_PORT:-8099}"

if [[ -z "$AGENT_START" && -t 0 ]]; then
    echo ""
    echo -ne "${Y}  [?]${N} ${W}Start the autonomous agent service as well?${N} ${D}[y/N]${N} "
    read -r ANSWER
    [[ "$ANSWER" =~ ^[yYjJ] ]] && AGENT_START="1"
fi

AGENT_PID=""
if [[ -n "$AGENT_START" ]]; then
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    export AGENT_URL="http://${AGENT_BIND_HOST}:${AGENT_BIND_PORT}"
    # The agent authenticates to the C2 with the operator token, so it gets
    # the one this launcher just decided on rather than a second copy that
    # could drift.
    export RACCOON_TOKEN="$TOKEN"
    # The operator socket: the agent drives the operator API.
    export AGENT_C2_URL="${PROTO}://127.0.0.1:${OPERATOR_PORT}"
    if [[ -z "${AGENT_PROVIDER:-}" || -z "${AGENT_MODEL:-}" ]]; then
        echo -e "${Y}  [!]${N} ${W}Agent${N}         ${Y}AGENT_PROVIDER and AGENT_MODEL are not set;${N}"
        echo -e "      ${D}the service starts and reports itself unavailable in the GUI.${N}"
    fi
    echo -e "${C}  [*]${N} ${W}Starting agent${N} ${D}${AGENT_URL}${N}"
    ( cd "$REPO_ROOT" && "$PYTHON" -m software.agent \
        --bind-host "$AGENT_BIND_HOST" --bind-port "$AGENT_BIND_PORT" \
        >> "$SCRIPT_DIR/agent.log" 2>&1 ) &
    AGENT_PID=$!
    # Stopped with the server, so Ctrl+C does not leave it holding the port
    # and a lowered beacon interval behind.
    trap '[[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" 2>/dev/null || true' EXIT INT TERM
    echo -e "${G}  [✓]${N} ${W}Agent${N}         ${D}pid $AGENT_PID, log $SCRIPT_DIR/agent.log${N}"
    echo ""
fi

# ── Launch ──
# Only the server gets the key: the agent above never needed it.
RACCOON_KEY="$KEY" RACCOON_TOKEN="$TOKEN" exec "${CMD[@]}"
