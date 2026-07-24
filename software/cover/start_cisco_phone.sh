#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  Raccoon — Cisco Phone Cover Identity Launcher
#  Starts the Cisco IP Phone 7960 cover standalone.
# ──────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="${PROJECT_ROOT}/configs/raccoon.yaml"

# ── Colors ──
R='\033[1;31m'
G='\033[1;32m'
Y='\033[1;33m'
C='\033[1;36m'
W='\033[1;37m'
D='\033[0;90m'
N='\033[0m'

# ── Defaults ──
HTTP_PORT="${HTTP_PORT:-80}"
SIP_PORT="${SIP_PORT:-5060}"
RTP_PORT="${RTP_PORT:-10000}"
HOSTNAME="${HOSTNAME:-SEP001BD5A1B2C3}"
CONFIG=""

# ── Parse args ──
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config|-c)    CONFIG="$2"; shift 2;;
        --http-port)    HTTP_PORT="$2"; shift 2;;
        --sip-port)     SIP_PORT="$2"; shift 2;;
        --rtp-port)     RTP_PORT="$2"; shift 2;;
        --hostname)     HOSTNAME="$2"; shift 2;;
        -h|--help)
            echo "Usage: $0 [--config <yaml>] [--http-port 80] [--sip-port 5060] [--rtp-port 10000] [--hostname <name>]"
            exit 0;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

# ── Banner ──
clear 2>/dev/null || true
echo ""
echo -e "${G}    ╔═╗╦╔═╗╔═╗╔═╗${N}"
echo -e "${G}    ║  ║╚═╗║  ║ ║${N}"
echo -e "${G}    ╚═╝╩╚═╝╚═╝╚═╝${N}"
echo ""
echo -e "${D}    ─────────────────────────────────────────────────────────${N}"
echo -e "${C}     📞 Cisco IP Phone 7960 — Cover Identity${N}"
echo -e "${D}    ─────────────────────────────────────────────────────────${N}"
echo -e "${D}     Part of${N} ${R}🦝 T R A S H   P A N D A   P A W S${N}"
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
echo -e "${G}  [✓]${N} ${W}Python${N}          ${D}$PYVER${N}"

# ── Virtual environment ──
VENV_DIR="$PROJECT_ROOT/software/.venv"

if [[ ! -f "$VENV_DIR/bin/python" ]]; then
    echo -e "${C}  [*]${N} ${W}Creating venv${N}   ${D}$VENV_DIR${N}"
    $PYTHON -m venv "$VENV_DIR"
fi

PYTHON="$VENV_DIR/bin/python"
echo -e "${G}  [✓]${N} ${W}Venv${N}            ${D}$VENV_DIR${N}"

# ── Dependencies ──
$PYTHON -m pip install --upgrade pip --quiet 2>/dev/null || true

REQUIRED_PKGS="pyyaml netifaces scapy"
MISSING=""
for pkg in $REQUIRED_PKGS; do
    if ! $PYTHON -c "import ${pkg//-/_}" 2>/dev/null; then
        MISSING="$MISSING $pkg"
    fi
done

if [[ -n "$MISSING" ]]; then
    echo -e "${C}  [*]${N} ${W}Installing${N}      ${D}$MISSING${N}"
    $PYTHON -m pip install $MISSING --quiet 2>/dev/null || true
fi

# ── Resolve config ──
if [[ -n "$CONFIG" ]]; then
    CONFIG_FILE="$CONFIG"
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${Y}  [!]${N} ${W}Config not found:${N} ${D}$CONFIG_FILE${N}"
    echo -e "${Y}  [!]${N} ${W}Using defaults${N}"
    CONFIG_FILE=""
fi

if [[ -n "$CONFIG_FILE" ]]; then
    echo -e "${G}  [✓]${N} ${W}Config${N}          ${D}$CONFIG_FILE${N}"
fi

# ── Port check ──
_check_port() {
    local port=$1 name=$2
    if command -v ss &>/dev/null; then
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo -e "${Y}  [!]${N} ${W}${name}${N} ${Y}port ${port} already in use${N}"
            return 1
        fi
    elif command -v lsof &>/dev/null; then
        if lsof -iTCP:"${port}" -sTCP:LISTEN &>/dev/null; then
            echo -e "${Y}  [!]${N} ${W}${name}${N} ${Y}port ${port} already in use${N}"
            return 1
        fi
    fi
    return 0
}

PORTS_OK=true
_check_port "$HTTP_PORT" "HTTP" || PORTS_OK=false
_check_port "$SIP_PORT" "SIP" || PORTS_OK=false

if [[ "$PORTS_OK" == "false" ]]; then
    echo ""
    echo -e "${Y}  [!]${N} ${W}Some ports are in use. Cover may not start all services.${N}"
    echo -e "${D}      Use --http-port / --sip-port to override.${N}"
    echo ""
fi

# ── Summary ──
echo ""
echo -e "${D}  ┌──────────────────────────────────────────────────────┐${N}"
echo -e "${D}  │${N}  ${W}Cisco Phone Cover Identity${N}                             ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  │${N}  ${C}Hostname${N}     ${W}${HOSTNAME}${N}$(printf '%*s' $((34 - ${#HOSTNAME})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}Model${N}        ${W}Cisco IP Phone 7960${N}                  ${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  │${N}  ${C}HTTP${N}         ${W}:${HTTP_PORT}${N}$(printf '%*s' $((39 - ${#HTTP_PORT})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}SIP${N}          ${W}:${SIP_PORT}${N}$(printf '%*s' $((39 - ${#SIP_PORT})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}RTP${N}          ${W}:${RTP_PORT}${N}$(printf '%*s' $((39 - ${#RTP_PORT})) '')${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  └──────────────────────────────────────────────────────┘${N}"
echo ""
echo -e "${D}  Press Ctrl+C to stop${N}"
echo ""

# ── Build command ──
CMD=("$PYTHON" "-c" "
import sys, os
sys.path.insert(0, '${PROJECT_ROOT}')
os.chdir('${PROJECT_ROOT}')

import yaml
from software.cover.cisco_phone import CiscoCover

config_path = '${CONFIG_FILE}'
if config_path:
    with open(config_path) as f:
        config = yaml.safe_load(f)
else:
    config = {
        'device_mode': 'cisco_phone',
        'cover': {
            'enabled': True,
            'cisco_phone': {
                'hostname': '${HOSTNAME}',
                'model': 'Cisco IP Phone 7960',
                'firmware': 'P0S3-08-12-00',
                'mac_prefix': '00:1b:d5',
                'http_port': ${HTTP_PORT},
                'sip_port': ${SIP_PORT},
                'rtp_port': ${RTP_PORT},
            }
        },
        'logging': {'log_dir': '/tmp/raccoon/logs', 'console_level': 'INFO', 'file_level': 'DEBUG'}
    }

config['device_mode'] = 'cisco_phone'
cisco_cfg = config.get('cover', {}).get('cisco_phone', {})
cisco_cfg['http_port'] = int('${HTTP_PORT}')
cisco_cfg['sip_port'] = int('${SIP_PORT}')
cisco_cfg['rtp_port'] = int('${RTP_PORT}')
cisco_cfg['hostname'] = '${HOSTNAME}'

import logging, signal
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s %(message)s')

cover = CiscoCover(config)
cover.start()

def shutdown(sig, frame):
    print()
    logging.getLogger('raccoon.cover').info('Shutting down Cisco Phone cover...')
    cover.stop()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

import time
while True:
    time.sleep(1)
")

# ── Launch ──
exec "${CMD[@]}"
