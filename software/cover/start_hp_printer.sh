#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  Raccoon — HP Printer Cover Identity Launcher
#  Starts the HP Color LaserJet Pro MFP M478 cover standalone.
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
PJL_PORT="${PJL_PORT:-9100}"
LPD_PORT="${LPD_PORT:-515}"
IPP_PORT="${IPP_PORT:-631}"
SNMP_PORT="${SNMP_PORT:-161}"
TELNET_PORT="${TELNET_PORT:-23}"
HOSTNAME="${HOSTNAME:-HP-LaserJet-M478}"
CONFIG=""

# ── Parse args ──
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config|-c)    CONFIG="$2"; shift 2;;
        --http-port)    HTTP_PORT="$2"; shift 2;;
        --pjl-port)     PJL_PORT="$2"; shift 2;;
        --lpd-port)     LPD_PORT="$2"; shift 2;;
        --ipp-port)     IPP_PORT="$2"; shift 2;;
        --snmp-port)    SNMP_PORT="$2"; shift 2;;
        --telnet-port)  TELNET_PORT="$2"; shift 2;;
        --hostname)     HOSTNAME="$2"; shift 2;;
        -h|--help)
            echo "Usage: $0 [--config <yaml>] [--http-port 80] [--pjl-port 9100] [--lpd-port 515] [--ipp-port 631] [--snmp-port 161] [--telnet-port 23] [--hostname <name>]"
            exit 0;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

# ── Banner ──
clear 2>/dev/null || true
echo ""
echo -e "${W}    ╦ ╦╔═╗  ╦  ╔═╗╔═╗╔═╗╦═╗ ╦╔═╗╔╦╗${N}"
echo -e "${W}    ╠═╣╠═╝  ║  ╠═╣╚═╗║╣ ╠╦╝ ║║╣  ║ ${N}"
echo -e "${W}    ╩ ╩╩    ╩═╝╩ ╩╚═╝╚═╝╩╚═╚╝╚═╝ ╩ ${N}"
echo ""
echo -e "${D}    ─────────────────────────────────────────────────────────${N}"
echo -e "${C}     🖨  HP Color LaserJet Pro MFP M478 — Cover Identity${N}"
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
_check_port "$PJL_PORT" "PJL/JetDirect" || PORTS_OK=false
_check_port "$SNMP_PORT" "SNMP" || PORTS_OK=false

if [[ "$PORTS_OK" == "false" ]]; then
    echo ""
    echo -e "${Y}  [!]${N} ${W}Some ports are in use. Cover may not start all services.${N}"
    echo -e "${D}      Use --http-port / --pjl-port / --snmp-port to override.${N}"
    echo ""
fi

# ── Summary ──
echo ""
echo -e "${D}  ┌──────────────────────────────────────────────────────┐${N}"
echo -e "${D}  │${N}  ${W}HP Printer Cover Identity${N}                              ${D}│${N}"
echo -e "${D}  ├──────────────────────────────────────────────────────┤${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  │${N}  ${C}Hostname${N}     ${W}${HOSTNAME}${N}$(printf '%*s' $((34 - ${#HOSTNAME})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}Model${N}        ${W}HP Color LaserJet Pro MFP M478fdw${N}   ${D}│${N}"
echo -e "${D}  │${N}                                                      ${D}│${N}"
echo -e "${D}  │${N}  ${C}HTTP${N}         ${W}:${HTTP_PORT}${N}$(printf '%*s' $((39 - ${#HTTP_PORT})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}PJL/9100${N}     ${W}:${PJL_PORT}${N}$(printf '%*s' $((39 - ${#PJL_PORT})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}LPD${N}          ${W}:${LPD_PORT}${N}$(printf '%*s' $((39 - ${#LPD_PORT})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}IPP/CUPS${N}     ${W}:${IPP_PORT}${N}$(printf '%*s' $((39 - ${#IPP_PORT})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}SNMP${N}         ${W}:${SNMP_PORT}${N}$(printf '%*s' $((39 - ${#SNMP_PORT})) '')${D}│${N}"
echo -e "${D}  │${N}  ${C}Telnet${N}       ${W}:${TELNET_PORT}${N}$(printf '%*s' $((39 - ${#TELNET_PORT})) '')${D}│${N}"
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
from software.cover.hp_printer import HPPrinterCover

config_path = '${CONFIG_FILE}'
if config_path:
    with open(config_path) as f:
        config = yaml.safe_load(f)
else:
    config = {
        'device_mode': 'hp_printer',
        'cover': {
            'enabled': True,
            'hp_printer': {
                'hostname': '${HOSTNAME}',
                'model': 'HP Color LaserJet Pro MFP M478fdw',
                'firmware': '2411C_001.2434A',
                'mac_prefix': '00:1e:0b',
                'http_port': ${HTTP_PORT},
                'pjl_port': ${PJL_PORT},
                'lpd_port': ${LPD_PORT},
                'ipp_port': ${IPP_PORT},
                'snmp_port': ${SNMP_PORT},
                'telnet_port': ${TELNET_PORT},
            }
        },
        'logging': {'log_dir': '/tmp/raccoon/logs', 'console_level': 'INFO', 'file_level': 'DEBUG'}
    }

config['device_mode'] = 'hp_printer'
hp_cfg = config.get('cover', {}).get('hp_printer', {})
hp_cfg['http_port'] = int('${HTTP_PORT}')
hp_cfg['pjl_port'] = int('${PJL_PORT}')
hp_cfg['lpd_port'] = int('${LPD_PORT}')
hp_cfg['ipp_port'] = int('${IPP_PORT}')
hp_cfg['snmp_port'] = int('${SNMP_PORT}')
hp_cfg['telnet_port'] = int('${TELNET_PORT}')
hp_cfg['hostname'] = '${HOSTNAME}'

import logging, signal
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s %(message)s')

cover = HPPrinterCover(config)
cover.start()

def shutdown(sig, frame):
    print()
    logging.getLogger('raccoon.cover').info('Shutting down HP Printer cover...')
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
