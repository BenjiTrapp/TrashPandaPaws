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
PORT="${PORT:-8443}"
HOST="${HOST:-0.0.0.0}"
KEY=""
DERIVE_KEY=""
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
        --key)        KEY="$2"; shift 2;;
        --derive-key) DERIVE_KEY="$2"; shift 2;;
        --token)      TOKEN="$2"; shift 2;;
        --ssl)        SSL="--ssl"; shift;;
        --cert)       CERT="$2"; shift 2;;
        --certkey)    CERTKEY="$2"; shift 2;;
        --interactive|-i) INTERACTIVE="1"; shift;;
        -h|--help)
            echo "Usage: $0 [--port 8443] [--host 0.0.0.0] [--key <b64>] [--derive-key <str>] [--token <str>] [--ssl] [--cert <file>] [--certkey <file>] [-i|--interactive]"
            exit 0;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

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
$PYTHON -m pip install --upgrade pip --quiet 2>/dev/null

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

NXC_VER=$(nxc --version 2>/dev/null)
if [[ -n "$NXC_VER" ]]; then
    echo -e "${G}  [✓]${N} ${W}NetExec       ${N}${D}$NXC_VER${N}"
else
    echo -e "${Y}  [!]${N} ${W}NetExec       ${N}${Y}not installed (requires pipx)${N}"
fi

# ── Interactive configuration ──
if [[ -n "$INTERACTIVE" ]] || { [[ -z "$KEY" ]] && [[ -z "$DERIVE_KEY" ]] && [[ -t 0 ]]; }; then
    echo ""
    echo -e "${D}  ─────────────────────────────────────────────${N}"
    echo -e "${Y}  Server Configuration${N}"
    echo -e "${D}  ─────────────────────────────────────────────${N}"
    echo ""

    echo -ne "  ${C}Listen host${N} ${D}[${HOST}]${N}: "
    read -r INPUT
    [[ -n "$INPUT" ]] && HOST="$INPUT"

    echo -ne "  ${C}Listen port${N} ${D}[${PORT}]${N}: "
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
    echo -e "  ${C}[1]${N} ${W}Auto-generate a random key${N}"
    echo -e "  ${C}[2]${N} ${W}Enter a key manually (base64)${N}"
    echo -e "  ${C}[3]${N} ${W}Derive from callback URL (default)${N}"
    echo ""
    echo -ne "  ${Y}Choice${N} ${D}[3]${N}${W}: ${N}"
    read -r INPUT

    case "${INPUT:-3}" in
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
            ;;
        2)
            echo ""
            echo -ne "  ${Y}Key${N} ${D}(base64 AES-256-GCM, 32 bytes)${N}${W}: ${N}"
            read -r INPUT
            if [[ -n "$INPUT" ]]; then
                KEY="$INPUT"
                echo -e "  ${G}[✓]${N} ${W}Using provided key${N}"
            else
                echo -e "  ${Y}[!]${N} ${W}No key entered — falling back to default derivation${N}"
            fi
            ;;
        3|"")
            echo -e "  ${D}[i]${N} ${W}Using default key: SHA256(\":\")${N}"
            ;;
        *)
            echo -e "  ${D}[i]${N} ${W}Using default key: SHA256(\":\")${N}"
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

# ── Compute the actual encryption key for display ──
PROTO="http"
[[ -n "$SSL" ]] && PROTO="https"

if [[ -n "$KEY" ]]; then
    ENC_KEY_B64="$KEY"
    KEY_TYPE="explicit (AES-256-GCM)"
elif [[ -n "$DERIVE_KEY" ]]; then
    ENC_KEY_B64=$($PYTHON -c "
import hashlib, base64
k = hashlib.sha256('${DERIVE_KEY}'.encode()).digest()
print(base64.b64encode(k).decode())
")
    KEY_TYPE="derived from --derive-key"
else
    CALLBACK="${PROTO}://${HOST}:${PORT}/api/v1/beacon"
    ENC_KEY_B64=$($PYTHON -c "
import hashlib, base64
k = hashlib.sha256(':'.encode()).digest()
print(base64.b64encode(k).decode())
")
    KEY_TYPE="DEFAULT — SHA256(\":\")"
fi

ENC_KEY_PREVIEW="${ENC_KEY_B64:0:32}..."

echo ""
echo -e "${D}  ┌──────────────────────────────────────────────────────┐${N}"
echo -e "${D}  │${N}  ${W}Server Configuration${N}                                 ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"

LISTEN_STR="${PROTO}://${HOST}:${PORT}"
GUI_STR="${PROTO}://localhost:${PORT}"
PAD_L=$((38 - ${#LISTEN_STR}))
PAD_G=$((38 - ${#GUI_STR}))
[[ $PAD_L -lt 0 ]] && PAD_L=0
[[ $PAD_G -lt 0 ]] && PAD_G=0

echo -e "${D}  │${N}  ${C}Listen${N}       ${W}${LISTEN_STR}${N}$(printf '%*s' $PAD_L '')${D}│${N}"
echo -e "${D}  │${N}  ${C}GUI${N}          ${W}${GUI_STR}${N}$(printf '%*s' $PAD_G '')${D}│${N}"

PAD_K=$((38 - ${#KEY_TYPE}))
[[ $PAD_K -lt 0 ]] && PAD_K=0
KEY_COLOR="$R"
[[ -n "$KEY" || -n "$DERIVE_KEY" ]] && KEY_COLOR="$G"
echo -e "${D}  │${N}  ${C}Encryption${N}   ${KEY_COLOR}${KEY_TYPE}${N}$(printf '%*s' $PAD_K '')${D}│${N}"

echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}  ${Y}Operator Token (for GUI login):${N}                      ${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
PAD_T=$((52 - ${#TOKEN}))
[[ $PAD_T -lt 0 ]] && PAD_T=0
echo -e "${D}  │${N}  ${G}${TOKEN}${N}$(printf '%*s' $PAD_T '')${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}  ${Y}Encryption Key (for agent registration):${N}             ${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
PAD_E=$((52 - ${#ENC_KEY_B64}))
[[ $PAD_E -lt 0 ]] && PAD_E=0
echo -e "${D}  │${N}  ${C}${ENC_KEY_B64}${N}$(printf '%*s' $PAD_E '')${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  └──────────────────────────────────────────────────────┘${N}"
echo ""
echo -e "${D}  Press Ctrl+C to stop the server${N}"
echo ""

# ── Build command ──
CMD=("$PYTHON" "$SERVER_PY" "--host" "$HOST" "--port" "$PORT" "--token" "$TOKEN")
[[ -n "$KEY" ]]        && CMD+=("--key" "$KEY")
[[ -n "$DERIVE_KEY" ]] && CMD+=("--derive-key" "$DERIVE_KEY")
[[ -n "$SSL" ]]        && CMD+=("--ssl")
[[ -n "$CERT" ]]       && CMD+=("--cert" "$CERT")
[[ -n "$CERTKEY" ]]    && CMD+=("--certkey" "$CERTKEY")

# ── Launch ──
exec "${CMD[@]}"
