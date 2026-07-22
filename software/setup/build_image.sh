#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  TrashPandaPaws — Image Builder
#
#  Builds a ready-to-boot SD card / eMMC image from your workstation.
#  Downloads ParrotOS ARM64, injects Raccoon software + config,
#  enables headless SSH, and optionally flashes to a target device.
#
#  Runs on: Linux, macOS, WSL2
#  Requires: wget, unxz/xz, losetup (or hdiutil on macOS), rsync
#
#  Usage:
#    sudo ./build_image.sh                     # build image only
#    sudo ./build_image.sh /dev/sdX            # build + flash to SD
#    sudo ./build_image.sh /dev/sdX --config raccoon.yaml
#    sudo ./build_image.sh --no-flash          # explicit: image only
#    sudo ./build_image.sh --clean             # remove cached downloads
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

# ── Paths ──

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/.build"
CACHE_DIR="${BUILD_DIR}/cache"
MOUNT_DIR="${BUILD_DIR}/mnt"
OUTPUT_DIR="${BUILD_DIR}/output"

# ── ParrotOS Image ──
# Update this URL when a new ParrotOS ARM64 release is published.
# Check: https://parrotsec.org/download/ → Raspberry Pi → ARM64
PARROT_VERSION="6.2"
PARROT_IMAGE_URL="https://download.parrot.sh/parrot/iso/${PARROT_VERSION}/Parrot-home-${PARROT_VERSION}_arm64.img.xz"
PARROT_IMAGE_FILE="parrot-arm64-${PARROT_VERSION}.img.xz"
PARROT_IMAGE_RAW="parrot-arm64-${PARROT_VERSION}.img"

# ── Defaults ──
TARGET_DEVICE=""
CUSTOM_CONFIG=""
NO_FLASH=false
CLEAN=false
WIFI_SSID=""
WIFI_PSK=""
FIRST_BOOT_USER="raccoon"
FIRST_BOOT_PASS="trashpanda"

# ── Parse arguments ──

usage() {
    echo "TrashPandaPaws — Image Builder"
    echo ""
    echo "Usage: sudo $0 [/dev/sdX] [OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  /dev/sdX              Target device to flash (SD card reader)"
    echo ""
    echo "Options:"
    echo "  --config FILE         Custom raccoon.yaml to inject"
    echo "  --wifi SSID:PSK       Configure WiFi for headless first boot"
    echo "  --user USER:PASS      First-boot credentials (default: raccoon:trashpanda)"
    echo "  --no-flash            Build image only, don't flash"
    echo "  --clean               Remove cached downloads and exit"
    echo "  --help                Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo $0 /dev/sdb                         # flash to SD card"
    echo "  sudo $0 /dev/sdb --wifi MyNet:secret123   # with WiFi"
    echo "  sudo $0 --no-flash                        # image only → .build/output/"
    echo "  sudo $0 /dev/sdb --config /path/to/my-raccoon.yaml"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        /dev/*)
            TARGET_DEVICE="$1"
            shift ;;
        --config)
            CUSTOM_CONFIG="$2"
            shift 2 ;;
        --wifi)
            IFS=':' read -r WIFI_SSID WIFI_PSK <<< "$2"
            shift 2 ;;
        --user)
            IFS=':' read -r FIRST_BOOT_USER FIRST_BOOT_PASS <<< "$2"
            shift 2 ;;
        --no-flash)
            NO_FLASH=true
            shift ;;
        --clean)
            CLEAN=true
            shift ;;
        --help|-h)
            usage ;;
        *)
            err "Unknown argument: $1"
            usage ;;
    esac
done

# ── Preflight checks ──

if [ "$EUID" -ne 0 ]; then
    err "Must run as root (sudo)"
    exit 1
fi

if [ "$CLEAN" = true ]; then
    info "Cleaning build cache"
    rm -rf "$BUILD_DIR"
    log "Done"
    exit 0
fi

# Check required tools
for cmd in wget xz losetup mount umount rsync parted mkfs.ext4; do
    if ! command -v "$cmd" &>/dev/null; then
        # macOS uses hdiutil instead of losetup
        if [ "$cmd" = "losetup" ] && command -v hdiutil &>/dev/null; then
            continue
        fi
        err "Missing required tool: $cmd"
        echo "  Install with: sudo apt install $(echo "$cmd" | sed 's/mkfs.ext4/e2fsprogs/; s/parted/parted/')"
        exit 1
    fi
done

if [ -n "$CUSTOM_CONFIG" ] && [ ! -f "$CUSTOM_CONFIG" ]; then
    err "Config file not found: $CUSTOM_CONFIG"
    exit 1
fi

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   TrashPandaPaws — Image Builder          ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"

mkdir -p "$CACHE_DIR" "$MOUNT_DIR" "$OUTPUT_DIR"

# ── Step 1: Download ParrotOS ──

info "Step 1/6: ParrotOS ARM64 image"

if [ -f "${CACHE_DIR}/${PARROT_IMAGE_RAW}" ]; then
    log "Using cached image: ${PARROT_IMAGE_RAW}"
else
    if [ -f "${CACHE_DIR}/${PARROT_IMAGE_FILE}" ]; then
        log "Using cached download: ${PARROT_IMAGE_FILE}"
    else
        log "Downloading ParrotOS ${PARROT_VERSION} ARM64..."
        wget -q --show-progress -O "${CACHE_DIR}/${PARROT_IMAGE_FILE}" "$PARROT_IMAGE_URL"
    fi

    log "Decompressing image (this takes a minute)..."
    xz -dk "${CACHE_DIR}/${PARROT_IMAGE_FILE}"
    mv "${CACHE_DIR}/${PARROT_IMAGE_FILE%.xz}" "${CACHE_DIR}/${PARROT_IMAGE_RAW}"
fi

# ── Step 2: Create working copy ──

info "Step 2/6: Preparing working copy"

WORK_IMAGE="${OUTPUT_DIR}/trashpandapaws-${PARROT_VERSION}.img"
cp "${CACHE_DIR}/${PARROT_IMAGE_RAW}" "$WORK_IMAGE"

# Expand image by 1GB for Raccoon software + dependencies
log "Expanding image by 1GB..."
truncate -s +1G "$WORK_IMAGE"

# ── Step 3: Mount image ──

info "Step 3/6: Mounting image partitions"

cleanup() {
    log "Cleaning up mounts..."
    sync 2>/dev/null || true
    umount "${MOUNT_DIR}/boot" 2>/dev/null || true
    umount "${MOUNT_DIR}/rootfs/proc" 2>/dev/null || true
    umount "${MOUNT_DIR}/rootfs/sys" 2>/dev/null || true
    umount "${MOUNT_DIR}/rootfs/dev/pts" 2>/dev/null || true
    umount "${MOUNT_DIR}/rootfs/dev" 2>/dev/null || true
    umount "${MOUNT_DIR}/rootfs" 2>/dev/null || true
    [ -n "${LOOP_DEV:-}" ] && losetup -d "$LOOP_DEV" 2>/dev/null || true
}
trap cleanup EXIT

LOOP_DEV=$(losetup -fP --show "$WORK_IMAGE")
log "Loop device: ${LOOP_DEV}"

# Wait for partitions to appear
sleep 1
partprobe "$LOOP_DEV" 2>/dev/null || true
sleep 1

# Detect partitions (typically p1 = boot/fat32, p2 = rootfs/ext4)
BOOT_PART="${LOOP_DEV}p1"
ROOT_PART="${LOOP_DEV}p2"

if [ ! -b "$ROOT_PART" ]; then
    err "Could not find rootfs partition at ${ROOT_PART}"
    err "Available partitions:"
    ls -la "${LOOP_DEV}"* 2>/dev/null || true
    exit 1
fi

# Expand rootfs partition to fill available space
log "Expanding rootfs partition..."
parted -s "$LOOP_DEV" resizepart 2 100%
e2fsck -f -y "$ROOT_PART" || true
resize2fs "$ROOT_PART"

# Mount
mkdir -p "${MOUNT_DIR}/boot" "${MOUNT_DIR}/rootfs"
mount "$ROOT_PART" "${MOUNT_DIR}/rootfs"
mount "$BOOT_PART" "${MOUNT_DIR}/boot" 2>/dev/null || warn "No separate boot partition"

log "Image mounted at ${MOUNT_DIR}/rootfs"

# ── Step 4: Inject Raccoon software ──

info "Step 4/6: Injecting TrashPandaPaws"

ROOTFS="${MOUNT_DIR}/rootfs"
RACCOON_DIR="${ROOTFS}/opt/raccoon"

# Create directory structure
mkdir -p "${RACCOON_DIR}"/{captures,logs,bin}

# Copy software
log "Copying software..."
rsync -a --exclude='__pycache__' --exclude='*.pyc' \
    "${PROJECT_DIR}/software/" "${RACCOON_DIR}/software/"

# Copy configs (custom or default)
mkdir -p "${RACCOON_DIR}/configs"
if [ -n "$CUSTOM_CONFIG" ]; then
    log "Using custom config: ${CUSTOM_CONFIG}"
    cp "$CUSTOM_CONFIG" "${RACCOON_DIR}/configs/raccoon.yaml"
else
    cp "${PROJECT_DIR}/configs/raccoon.yaml" "${RACCOON_DIR}/configs/raccoon.yaml"
fi

# Copy services
rsync -a "${PROJECT_DIR}/services/" "${RACCOON_DIR}/services/"

# Copy setup scripts
rsync -a "${PROJECT_DIR}/software/setup/" "${RACCOON_DIR}/software/setup/"
chmod +x "${RACCOON_DIR}/software/setup/"*.sh

# Copy requirements
cp "${PROJECT_DIR}/software/requirements.txt" "${RACCOON_DIR}/software/"

log "Software injected into /opt/raccoon/"

# ── Step 5: Configure first-boot ──

info "Step 5/6: Configuring headless first boot"

# 5a. Enable SSH on first boot
log "Enabling SSH..."
touch "${MOUNT_DIR}/boot/ssh" 2>/dev/null || \
    touch "${ROOTFS}/boot/ssh" 2>/dev/null || true

# Also enable via systemd (belt and suspenders)
if [ -d "${ROOTFS}/etc/systemd/system/multi-user.target.wants" ]; then
    ln -sf /lib/systemd/system/ssh.service \
        "${ROOTFS}/etc/systemd/system/multi-user.target.wants/ssh.service" 2>/dev/null || true
fi

# 5b. Create user (write into /etc/shadow, /etc/passwd, /etc/group)
log "Creating user: ${FIRST_BOOT_USER}"
HASHED_PASS=$(openssl passwd -6 "$FIRST_BOOT_PASS")

# Append user if not exists
if ! grep -q "^${FIRST_BOOT_USER}:" "${ROOTFS}/etc/passwd" 2>/dev/null; then
    echo "${FIRST_BOOT_USER}:x:1001:1001:TrashPandaPaws:/home/${FIRST_BOOT_USER}:/bin/bash" \
        >> "${ROOTFS}/etc/passwd"
    echo "${FIRST_BOOT_USER}:${HASHED_PASS}:19700:0:99999:7:::" \
        >> "${ROOTFS}/etc/shadow"
    echo "${FIRST_BOOT_USER}:x:1001:" \
        >> "${ROOTFS}/etc/group"
    mkdir -p "${ROOTFS}/home/${FIRST_BOOT_USER}"

    # Add to sudo group
    sed -i "/^sudo:/s/$/${FIRST_BOOT_USER},/" "${ROOTFS}/etc/group" 2>/dev/null || true
    # Remove trailing comma if first member
    sed -i 's/,:$//' "${ROOTFS}/etc/group" 2>/dev/null || true
fi

# Also set root password for emergency access
ROOT_HASH=$(openssl passwd -6 "$FIRST_BOOT_PASS")
sed -i "s|^root:[^:]*:|root:${ROOT_HASH}:|" "${ROOTFS}/etc/shadow" 2>/dev/null || true

# 5c. WiFi configuration (optional)
if [ -n "$WIFI_SSID" ] && [ -n "$WIFI_PSK" ]; then
    log "Configuring WiFi: ${WIFI_SSID}"

    # wpa_supplicant config
    mkdir -p "${ROOTFS}/etc/wpa_supplicant"
    cat > "${ROOTFS}/etc/wpa_supplicant/wpa_supplicant.conf" <<WPAEOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=DE

network={
    ssid="${WIFI_SSID}"
    psk="${WIFI_PSK}"
    key_mgmt=WPA-PSK
}
WPAEOF
    chmod 600 "${ROOTFS}/etc/wpa_supplicant/wpa_supplicant.conf"

    # Also create NetworkManager connection (ParrotOS default)
    mkdir -p "${ROOTFS}/etc/NetworkManager/system-connections"
    cat > "${ROOTFS}/etc/NetworkManager/system-connections/raccoon-wifi.nmconnection" <<NMEOF
[connection]
id=raccoon-wifi
type=wifi
autoconnect=true

[wifi]
ssid=${WIFI_SSID}
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
psk=${WIFI_PSK}

[ipv4]
method=auto

[ipv6]
method=disabled
NMEOF
    chmod 600 "${ROOTFS}/etc/NetworkManager/system-connections/raccoon-wifi.nmconnection"
fi

# 5d. Create first-boot provisioning script
log "Creating first-boot provisioning service..."
cat > "${ROOTFS}/opt/raccoon/first-boot.sh" <<'FBEOF'
#!/bin/bash
# TrashPandaPaws — First boot provisioning
# Runs once on first boot, then disables itself.
set -e

exec > /var/log/raccoon-first-boot.log 2>&1
echo "=== TrashPandaPaws first boot: $(date) ==="

export DEBIAN_FRONTEND=noninteractive

# Wait for network
echo "[+] Waiting for network..."
for i in $(seq 1 30); do
    if ping -c1 -W2 8.8.8.8 &>/dev/null; then
        echo "[+] Network is up"
        break
    fi
    sleep 2
done

# Update packages
echo "[+] Updating packages..."
apt-get update -qq

# Install dependencies
echo "[+] Installing dependencies..."
apt-get install -y -qq \
    python3-pip python3-venv python3-scapy \
    bridge-utils tcpdump iptables ebtables arptables nftables \
    ethtool net-tools macchanger autossh x11vnc xvfb \
    libpcap-dev portaudio19-dev dnsutils

# Python venv
echo "[+] Setting up Python environment..."
python3 -m venv /opt/raccoon/venv --system-site-packages
/opt/raccoon/venv/bin/pip install --upgrade pip -q
/opt/raccoon/venv/bin/pip install -r /opt/raccoon/software/requirements.txt -q

# Permissions
chown -R root:root /opt/raccoon
chmod 700 /opt/raccoon/captures /opt/raccoon/logs

# Network config
echo "[+] Configuring network..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.d/99-raccoon.conf
echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.d/99-raccoon.conf
echo "net.bridge.bridge-nf-call-iptables=0" >> /etc/sysctl.d/99-raccoon.conf
echo "net.bridge.bridge-nf-call-ip6tables=0" >> /etc/sysctl.d/99-raccoon.conf
echo "net.bridge.bridge-nf-call-arptables=0" >> /etc/sysctl.d/99-raccoon.conf
sysctl -p /etc/sysctl.d/99-raccoon.conf 2>/dev/null || true

# Load bridge module on boot
echo "br_netfilter" > /etc/modules-load.d/raccoon-bridge.conf

# Hostname from config
CFG=/opt/raccoon/configs/raccoon.yaml
COVER=$(grep -oP 'device_mode:\s*"\K[^"]+' "$CFG" 2>/dev/null || echo "cisco_phone")
HOSTNAME=$(awk -v mode="$COVER" '
    $0 ~ "^  " mode ":" { in_section=1; next }
    in_section && /^  [a-z]/ && $0 !~ "^    " { in_section=0 }
    in_section && /hostname:/ { gsub(/.*hostname:\s*"?|".*/, ""); print; exit }
' "$CFG" 2>/dev/null)
[ -n "$HOSTNAME" ] && hostnamectl set-hostname "$HOSTNAME"
echo "[+] Hostname: $(hostname)"

# Disable noisy services
for svc in avahi-daemon cups bluetooth ModemManager; do
    systemctl disable "$svc" 2>/dev/null || true
    systemctl stop "$svc" 2>/dev/null || true
done

# Install systemd services
echo "[+] Installing services..."
cp /opt/raccoon/services/raccoon-implant.service /etc/systemd/system/
cp /opt/raccoon/services/raccoon-beacon.service /etc/systemd/system/
cp /opt/raccoon/services/raccoon-watchdog.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable raccoon-implant.service
systemctl enable raccoon-beacon.service
systemctl enable raccoon-watchdog.service

# MAC spoof service
cat > /etc/systemd/system/raccoon-macspoof.service <<'MACEOF'
[Unit]
Description=TrashPandaPaws — MAC Address Spoof
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '\
  CFG=/opt/raccoon/configs/raccoon.yaml; \
  COVER=$(grep -oP "device_mode:\s*\"\K[^\"]*" $CFG 2>/dev/null || echo cisco_phone); \
  PREFIX=$(awk -v m="$COVER" "\$0 ~ \"^  \"m\":\" {s=1; next} s && /^  [a-z]/ && \$0 !~ \"^    \" {s=0} s && /mac_prefix:/ {gsub(/.*mac_prefix:\s*\"?|\".*/, \"\"); print; exit}" $CFG 2>/dev/null); \
  [ -z "$PREFIX" ] && PREFIX="00:1b:d5"; \
  UPSTREAM=$(grep -oP "upstream_iface:\s*\"\K[^\"]*" $CFG 2>/dev/null || echo eth0); \
  DOWNSTREAM=$(grep -oP "downstream_iface:\s*\"\K[^\"]*" $CFG 2>/dev/null || echo eth1); \
  ip link set $UPSTREAM down 2>/dev/null; \
  macchanger -m ${PREFIX}:$(openssl rand -hex 3 | sed "s/\(..\)/\1:/g;s/:$//") $UPSTREAM 2>/dev/null; \
  ip link set $UPSTREAM up 2>/dev/null; \
  ip link set $DOWNSTREAM down 2>/dev/null; \
  macchanger -m ${PREFIX}:$(openssl rand -hex 3 | sed "s/\(..\)/\1:/g;s/:$//") $DOWNSTREAM 2>/dev/null; \
  ip link set $DOWNSTREAM up 2>/dev/null; \
'

[Install]
WantedBy=network-pre.target
MACEOF
systemctl daemon-reload
systemctl enable raccoon-macspoof.service

# Disable first-boot service (run only once)
systemctl disable raccoon-first-boot.service
rm -f /etc/systemd/system/raccoon-first-boot.service

echo ""
echo "=== TrashPandaPaws first boot complete: $(date) ==="
echo "=== Rebooting to activate MAC spoof + services ==="
reboot
FBEOF
chmod +x "${ROOTFS}/opt/raccoon/first-boot.sh"

# Create systemd service for first-boot
cat > "${ROOTFS}/etc/systemd/system/raccoon-first-boot.service" <<SVCEOF
[Unit]
Description=TrashPandaPaws — First Boot Provisioning
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/raccoon/first-boot.sh

[Service]
Type=oneshot
ExecStart=/opt/raccoon/first-boot.sh
RemainAfterExit=no
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
SVCEOF

# Enable the first-boot service
ln -sf /etc/systemd/system/raccoon-first-boot.service \
    "${ROOTFS}/etc/systemd/system/multi-user.target.wants/raccoon-first-boot.service" 2>/dev/null || true

log "First-boot provisioning configured"

# ── Step 6: Finalize ──

info "Step 6/6: Finalizing image"

# Sync and unmount
sync
umount "${MOUNT_DIR}/boot" 2>/dev/null || true
umount "${ROOTFS}" 2>/dev/null || true
losetup -d "$LOOP_DEV" 2>/dev/null || true
LOOP_DEV=""

IMAGE_SIZE=$(du -h "$WORK_IMAGE" | cut -f1)
log "Image ready: ${WORK_IMAGE} (${IMAGE_SIZE})"

# ── Flash to device ──

if [ -n "$TARGET_DEVICE" ] && [ "$NO_FLASH" = false ]; then
    echo ""
    info "Flashing to ${TARGET_DEVICE}"

    # Safety check
    if [ ! -b "$TARGET_DEVICE" ]; then
        err "${TARGET_DEVICE} is not a block device"
        exit 1
    fi

    # Show device info
    echo ""
    warn "Target device:"
    lsblk "$TARGET_DEVICE" 2>/dev/null || fdisk -l "$TARGET_DEVICE" 2>/dev/null || true
    echo ""
    warn "ALL DATA ON ${TARGET_DEVICE} WILL BE DESTROYED!"
    echo ""
    read -r -p "Type 'YES' to confirm flash: " CONFIRM
    if [ "$CONFIRM" != "YES" ]; then
        err "Aborted"
        exit 1
    fi

    # Unmount any mounted partitions
    for part in "${TARGET_DEVICE}"*; do
        umount "$part" 2>/dev/null || true
    done

    log "Writing image (this takes several minutes)..."
    dd if="$WORK_IMAGE" of="$TARGET_DEVICE" bs=4M status=progress conv=fsync
    sync

    log "Flash complete!"
fi

# ── Summary ──

echo ""
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  TrashPandaPaws image build complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo ""
echo "  Image:      ${WORK_IMAGE}"
echo "  Size:       ${IMAGE_SIZE}"
echo "  OS:         ParrotOS ${PARROT_VERSION} ARM64"
echo "  User:       ${FIRST_BOOT_USER} / ${FIRST_BOOT_PASS}"
if [ -n "$WIFI_SSID" ]; then
echo "  WiFi:       ${WIFI_SSID}"
fi
echo ""
echo -e "${YELLOW}First boot sequence:${NC}"
echo "  1. Insert SD card into Raspberry Pi 4"
echo "  2. Connect Ethernet (upstream to PoE switch)"
echo "  3. Power on — first boot takes ~5 minutes"
echo "     (installs deps, configures services, then reboots)"
echo "  4. After reboot, the implant is fully operational"
echo ""
echo -e "${YELLOW}Access:${NC}"
echo "  SSH:  ssh ${FIRST_BOOT_USER}@<pi-ip>"
echo "  Root: ssh root@<pi-ip>  (same password)"
echo ""
if [ -z "$TARGET_DEVICE" ] || [ "$NO_FLASH" = true ]; then
echo -e "${YELLOW}To flash manually:${NC}"
echo "  sudo dd if=${WORK_IMAGE} of=/dev/sdX bs=4M status=progress"
echo "  # or use Raspberry Pi Imager → 'Use custom'"
echo ""
fi
echo -e "${CYAN}Logs from first-boot provisioning:${NC}"
echo "  journalctl -u raccoon-first-boot"
echo "  cat /var/log/raccoon-first-boot.log"
echo ""
