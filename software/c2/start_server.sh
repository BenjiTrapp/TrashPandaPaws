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
        -h|--help)
            echo "Usage: $0 [--port 8443] [--host 0.0.0.0] [--key <b64>] [--derive-key <str>] [--token <str>] [--ssl] [--cert <file>] [--certkey <file>]"
            exit 0;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

# ── Generate token if not set ──
if [[ -z "$TOKEN" ]]; then
    TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))" 2>/dev/null || openssl rand -base64 24 | tr -d '=/+' | head -c 32)
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

# ── Key info ──
KEY_TYPE="DEFAULT (insecure!)"
[[ -n "$KEY" ]] && KEY_TYPE="explicit (AES-256-GCM)"
[[ -n "$DERIVE_KEY" ]] && KEY_TYPE="derived from callback:domain"

PROTO="http"
[[ -n "$SSL" ]] && PROTO="https"

echo ""
echo -e "${D}  ┌──────────────────────────────────────────────────────┐${N}"
echo -e "${D}  │${N}  ${W}Server Configuration${N}                                 ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  │${N}  ${C}Listen${N}       ${W}${PROTO}://${HOST}:${PORT}${N}$(printf '%*s' $((26 - ${#PROTO} - ${#HOST} - ${#PORT})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}GUI${N}          ${W}${PROTO}://localhost:${PORT}${N}$(printf '%*s' $((28 - ${#PROTO} - ${#PORT})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}Encryption${N}   ${W}${KEY_TYPE}${N}$(printf '%*s' $((32 - ${#KEY_TYPE})) '')${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}  ${Y}Operator Token (for GUI access):${N}                     ${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  │${N}  ${G}${TOKEN}${N}$(printf '%*s' $((40 - ${#TOKEN})) '')${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}  ${Y}Beacon registration key derivation:${N}                  ${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
if [[ -n "$KEY" ]]; then
echo -e "${D}  │${N}  ${W}--key ${KEY:0:20}...${N}$(printf '%*s' $((27 - 20)) '')${D}│${N}"
elif [[ -n "$DERIVE_KEY" ]]; then
echo -e "${D}  │${N}  ${W}--derive-key ${DERIVE_KEY:0:24}...${N}$(printf '%*s' $((18 - 24)) '')${D}│${N}"
else
echo -e "${D}  │${N}  ${R}⚠  No key set — using SHA256(\":\")${N}                  ${D}│${N}"
echo -e "${D}  │${N}  ${D}  Use --key <b64> or --derive-key <str>${N}             ${D}│${N}"
fi
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
