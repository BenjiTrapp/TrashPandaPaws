#!/bin/bash
set -e

R='\033[1;31m'
G='\033[1;32m'
Y='\033[1;33m'
C='\033[1;36m'
W='\033[1;37m'
D='\033[0;90m'
N='\033[0m'

echo ""
echo -e "${R}    ██████╗  █████╗  ██████╗ ██████╗ ██████╗  ██████╗ ███╗   ██╗${N}"
echo -e "${R}    ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔═══██╗████╗  ██║${N}"
echo -e "${R}    ██████╔╝███████║██║     ██║     ██║   ██║██║   ██║██╔██╗ ██║${N}"
echo -e "${R}    ██╔══██╗██╔══██║██║     ██║     ██║   ██║██║   ██║██║╚██╗██║${N}"
echo -e "${R}    ██║  ██║██║  ██║╚██████╗╚██████╗╚██████╔╝╚██████╔╝██║ ╚████║${N}"
echo -e "${R}    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝${N}"
echo ""
echo -e "${D}    ─────────────────────────────────────────────────────────${N}"
echo -e "${R}     🦝 T R A S H   P A N D A   P A W S   [Docker]${N}"
echo -e "${D}    ─────────────────────────────────────────────────────────${N}"
echo ""

# Tool versions
echo -e "${G}  [✓]${N} ${W}Python${N}        ${D}$(python3 --version 2>&1)${N}"
echo -e "${G}  [✓]${N} ${W}Flask${N}         ${D}$(python3 -c 'import importlib.metadata; print(importlib.metadata.version("flask"))')${N}"
echo -e "${G}  [✓]${N} ${W}Impacket${N}      ${D}$(python3 -c 'import importlib.metadata; print(importlib.metadata.version("impacket"))')${N}"
echo -e "${G}  [✓]${N} ${W}NetExec${N}       ${D}$(nxc --version 2>/dev/null || echo 'installed')${N}"
echo -e "${G}  [✓]${N} ${W}Lsassy${N}        ${D}$(python3 -c 'import importlib.metadata; print(importlib.metadata.version("lsassy"))')${N}"
echo -e "${G}  [✓]${N} ${W}RelayKing${N}     ${D}$(python3 /opt/RelayKing/relayking.py --version 2>/dev/null || echo 'installed')${N}"
echo -e "${G}  [✓]${N} ${W}Responder${N}     ${D}$(python3 /opt/Responder/Responder.py --version 2>/dev/null || echo 'installed')${N}"
echo ""

PORT="${RACCOON_PORT:-8443}"
HOST="${RACCOON_HOST:-0.0.0.0}"
DATA="${RACCOON_DATA:-/data/raccoon-c2}"

CMD=(python3 /opt/raccoon-c2/server.py
    --host "$HOST"
    --port "$PORT"
    --data-dir "$DATA"
)

[ -n "$RACCOON_KEY" ]        && CMD+=(--key "$RACCOON_KEY")
[ -n "$RACCOON_DERIVE_KEY" ] && CMD+=(--derive-key "$RACCOON_DERIVE_KEY")
[ -n "$RACCOON_TOKEN" ]      && CMD+=(--token "$RACCOON_TOKEN")
[ -n "$RACCOON_SSL" ]        && CMD+=(--ssl)
[ -n "$RACCOON_CERT" ]       && CMD+=(--cert "$RACCOON_CERT")
[ -n "$RACCOON_CERTKEY" ]    && CMD+=(--certkey "$RACCOON_CERTKEY")

# Pass through any extra args
CMD+=("$@")

echo -e "${D}  ┌──────────────────────────────────────────────┐${N}"
echo -e "${D}  │${N}  ${C}Listen${N}   ${W}http://${HOST}:${PORT}${N}"
echo -e "${D}  │${N}  ${C}Data${N}     ${W}${DATA}${N}"
echo -e "${D}  │${N}  ${C}Tools${N}    ${W}impacket nxc lsassy relayking responder nmap${N}"
echo -e "${D}  └──────────────────────────────────────────────┘${N}"
echo ""

exec "${CMD[@]}"
