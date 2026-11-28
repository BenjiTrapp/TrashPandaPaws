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
#
# `_tool` reports what is actually there. The three lines below used to
# read `$(nxc --version 2>/dev/null || echo 'installed')`, which printed
# the word "installed" under a green tick for a tool that was absent --
# it claimed NetExec in an image deliberately built without it. A banner
# that cannot be wrong is worth more than one that is always green.
_tool() {
  # $1 label, $2 command that must be on PATH, $3.. how to ask for a version
  if ! command -v "$2" >/dev/null 2>&1; then
    printf "%b  [ ]%b %b%-13s%b %bnot installed%b\n" "$D" "$N" "$W" "$1" \
      "$N" "$D" "$N"
    return
  fi
  # The version is dug out, not trusted. Measured: `relayking --version`
  # exits 1 and prints six lines of ASCII art before the version, and
  # `responder --version` prints nothing at all -- so a plain `cmd | head
  # -1 || echo unknown` showed an empty string for both, because head
  # exits 0 whatever it read. Pull the first version-shaped token out of
  # the output, strip the colour codes, and say "installed" when there is
  # none rather than printing a blank.
  local out ver
  out="$("${@:3}" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')"
  ver="$(printf '%s' "$out" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
  printf "%b  [✓]%b %b%-13s%b %b%s%b\n" "$G" "$N" "$W" "$1" "$N" "$D" \
    "${ver:-installed}" "$N"
}

_pymod() {
  # $1 label, $2 distribution name. The three module lines below used to
  # print a hardcoded green tick beside this, so an absent package would
  # have read "[✓] Lsassy not installed" -- the same defect as the one
  # above, left in place by the first version of this fix.
  local ver
  ver="$(python3 -c "import importlib.metadata as m; print(m.version('$2'))" \
    2>/dev/null)"
  if [ -n "$ver" ]; then
    printf "%b  [✓]%b %b%-13s%b %b%s%b\n" "$G" "$N" "$W" "$1" "$N" "$D" \
      "$ver" "$N"
  else
    printf "%b  [ ]%b %b%-13s%b %bnot installed%b\n" "$D" "$N" "$W" "$1" \
      "$N" "$D" "$N"
  fi
}

echo -e "${G}  [✓]${N} ${W}Python${N}        ${D}$(python3 --version 2>&1)${N}"
_pymod "Flask" flask
_pymod "Impacket" impacket
_tool "NetExec" nxc nxc --version
_pymod "Lsassy" lsassy
_tool "RelayKing" relayking python3 /opt/RelayKing/relayking.py --version
_tool "Responder" responder python3 /opt/Responder/Responder.py --version
echo ""

# RACCOON_HOST/PORT: the beacon socket. RACCOON_OPERATOR_HOST/PORT: the GUI
# and API, loopback by default -- with network_mode: host that is the host's
# loopback, so the GUI is reached on this machine or over an SSH tunnel.
PORT="${RACCOON_PORT:-8443}"
HOST="${RACCOON_HOST:-0.0.0.0}"
OPERATOR_PORT="${RACCOON_OPERATOR_PORT:-8444}"
OPERATOR_HOST="${RACCOON_OPERATOR_HOST:-127.0.0.1}"
DATA="${RACCOON_DATA:-/data/raccoon-c2}"

CMD=(python3 -m software.c2.server
    --host "$HOST"
    --port "$PORT"
    --operator-host "$OPERATOR_HOST"
    --operator-port "$OPERATOR_PORT"
    --data-dir "$DATA"
)

# RACCOON_KEY and RACCOON_TOKEN are deliberately not turned into arguments:
# the server reads them from the environment it inherits, and an argument is
# visible to every user in ps -- on the host too, which shares its PID
# namespace with its containers. With no key the server refuses and says how
# to make one; there is no default and nothing is derived.
[ -n "$RACCOON_SSL" ]        && CMD+=(--ssl)
[ -n "$RACCOON_CERT" ]       && CMD+=(--cert "$RACCOON_CERT")
[ -n "$RACCOON_CERTKEY" ]    && CMD+=(--certkey "$RACCOON_CERTKEY")

# Pass through any extra args
CMD+=("$@")

echo -e "${D}  ┌──────────────────────────────────────────────┐${N}"
echo -e "${D}  │${N}  ${C}Beacons${N}  ${W}http://${HOST}:${PORT}${N}"
echo -e "${D}  │${N}  ${C}GUI${N}      ${W}http://${OPERATOR_HOST}:${OPERATOR_PORT}${N}"
echo -e "${D}  │${N}  ${C}Data${N}     ${W}${DATA}${N}"
# Built from what is on PATH, not from a list written once. The fixed
# list claimed `nxc` in an image that had none.
_present=""
for _t in nmap nxc responder relayking xfreerdp xfreerdp3 vncviewer; do
  command -v "$_t" >/dev/null 2>&1 && _present="${_present} ${_t}"
done
python3 -c "import impacket" 2>/dev/null && _present="${_present} impacket"
python3 -c "import lsassy" 2>/dev/null && _present="${_present} lsassy"
echo -e "${D}  │${N}  ${C}Tools${N}   ${W}${_present# }${N}"
# Who this is, because the image's default user is `raccoon` and two of
# the tools above need raw sockets. An operator who dropped the
# `user: "0:0"` line from docker-compose.yml would otherwise find out
# from Responder failing, which says nothing about why.
if [ "$(id -u)" = "0" ]; then
  echo -e "${D}  │${N}  ${C}User${N}    ${W}root${N} ${D}(Responder and nmap -sS can use NET_RAW)${N}"
else
  echo -e "${D}  │${N}  ${C}User${N}    ${W}$(id -un)${N} ${Y}— not root: Responder and nmap -sS cannot open raw sockets${N}"
fi
echo -e "${D}  └──────────────────────────────────────────────┘${N}"
echo ""

exec "${CMD[@]}"
