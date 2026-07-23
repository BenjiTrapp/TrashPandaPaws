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

# Check dependencies
MISSING=""
for pkg in flask cryptography; do
    if ! $PYTHON -c "import $pkg" 2>/dev/null; then
        MISSING="$MISSING $pkg"
    fi
done

if [[ -n "$MISSING" ]]; then
    echo -e "${Y}  [!]${N} ${W}Installing${N}    ${D}$MISSING${N}"
    $PYTHON -m pip install $MISSING --quiet 2>/dev/null
fi

echo -e "${G}  [✓]${N} ${W}Flask${N}         ${D}$($PYTHON -c "import importlib.metadata; print(importlib.metadata.version('flask'))")${N}"
echo -e "${G}  [✓]${N} ${W}Cryptography${N}  ${D}$($PYTHON -c "import importlib.metadata; print(importlib.metadata.version('cryptography'))")${N}"

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
    echo -e "${Y}  Encryption Key${N}"
    echo -e "${D}  ─────────────────────────────────────────────${N}"
    echo ""
    echo -e "  ${W}Enter a base64 AES-256-GCM key.${N}"
    echo -e "  ${D}Agents must use the same key to communicate.${N}"
    echo ""
    echo -e "  ${D}Leave blank to auto-derive from:${N}"
    echo -e "  ${C}SHA256(\"${PROTO}://${HOST}:${PORT}/api/v1/beacon:\")${N}"
    echo ""
    echo -ne "  ${Y}Key${N} ${D}(base64 or Enter to derive)${N}${W}: ${N}"
    read -r INPUT

    if [[ -n "$INPUT" ]]; then
        KEY="$INPUT"
    fi

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
