#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  Raccoon C2 — Test Agent Registration
# ──────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Colors ──
R='\033[1;31m'
G='\033[1;32m'
Y='\033[1;33m'
C='\033[1;36m'
W='\033[1;37m'
D='\033[0;90m'
N='\033[0m'

# ── Defaults ──
HOST="127.0.0.1"
PORT="8443"
KEY="${RACCOON_KEY:-}"
INTERVAL="5"
JITTER="10"
USE_SSL=""

# ── Parse args ──
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)     HOST="$2"; shift 2;;
        --port)     PORT="$2"; shift 2;;
        --key)      KEY="$2"; shift 2;;
        --interval) INTERVAL="$2"; shift 2;;
        --jitter)   JITTER="$2"; shift 2;;
        --ssl)      USE_SSL="--ssl"; shift;;
        -h|--help)
            echo "Usage: $0 [--host 127.0.0.1] [--port 8443] [--key <b64>] [--interval 5] [--jitter 10] [--ssl]"
            echo ""
            echo "The key may instead come from RACCOON_KEY; --key wins when both are set. Prefer the"
            echo "variable: arguments are visible to every user in ps. If neither is set you are"
            echo "prompted for it. A key is required."
            exit 0;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

# ── Banner ──
echo ""
echo -e "${R}    ╔══════════════════════════════════════════════╗${N}"
echo -e "${R}    ║${N}  ${W}🦝 Raccoon C2 — Test Agent${N}                   ${R}║${N}"
echo -e "${R}    ╚══════════════════════════════════════════════╝${N}"
echo ""

# ── Python check ──
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
echo -e "${G}  [✓]${N} ${W}Python${N}   ${D}$($PYTHON --version 2>&1)${N}"

# ── Prompt for key if not set ──
if [[ -z "$KEY" ]]; then
    echo ""
    PROTO="http"
    [[ -n "$USE_SSL" ]] && PROTO="https"
    CALLBACK="${PROTO}://${HOST}:${PORT}/api/v1/beacon"

    echo -e "${D}  ─────────────────────────────────────────────${N}"
    echo -e "${Y}  Encryption Key${N}"
    echo -e "${D}  ─────────────────────────────────────────────${N}"
    echo ""
    echo -e "  ${W}Enter a base64 AES-256-GCM key.${N}"
    echo -e "  ${D}This must match the key the server was started with.${N}"
    echo ""
    echo -ne "  ${Y}Key${N} ${D}(base64)${N}${W}: ${N}"
    read -rs KEY
    echo ""

    if [[ -z "$KEY" ]]; then
        echo -e "  ${R}[✗]${N} ${W}A key is required; there is no default.${N}"
        echo -e "  ${D}Use the key the server was started with, or generate one for both:${N}"
        echo -e "  ${D}python3 -c \"import os,base64; print(base64.b64encode(os.urandom(32)).decode())\"${N}"
        exit 1
    fi
    echo -e "  ${G}[✓]${N} ${W}Using explicit key${N}"
fi

# ── Display config ──
PROTO="http"
[[ -n "$USE_SSL" ]] && PROTO="https"

echo ""
echo -e "${D}  ─────────────────────────────────────────────${N}"
echo -e "${W}  Agent Configuration${N}"
echo -e "${D}  ─────────────────────────────────────────────${N}"
echo -e "  ${C}Server${N}     ${W}${PROTO}://${HOST}:${PORT}${N}"
echo -e "  ${C}Interval${N}   ${W}${INTERVAL}s${N} ${D}(jitter ${JITTER}%)${N}"
echo -e "  ${C}Key${N}        ${W}${KEY:0:6}...${N}"
echo -e "${D}  ─────────────────────────────────────────────${N}"
echo ""
echo -e "${G}  [▶]${N} ${W}Starting beacon...${N}"
echo -e "${D}  Press Ctrl+C to stop${N}"
echo ""

# ── Launch ──
cd "$REPO_ROOT"

CMD=("$PYTHON" "$SCRIPT_DIR/test_add_agent.py"
     "--host" "$HOST"
     "--port" "$PORT"
     "--interval" "$INTERVAL"
     "--jitter" "$JITTER")
[[ -n "$USE_SSL" ]] && CMD+=("--ssl")

# The key goes in the environment, not the arguments: ps shows those to
# every user.
RACCOON_KEY="$KEY" exec "${CMD[@]}"
