#!/usr/bin/env bash
# Mount a forensic image read-only inside WSL (or any Linux): E01 (via ewfmount), raw/dd, or VHDX
# (via qemu-nbd), with partition and LVM handling. Prints the exact mount and the command to undo it.
# Gumshoe itself never mounts anything; this is the examiner's explicit step, logged by `gumshoe verify`.
#
#   sudo setup/wsl/mount_image.sh /mnt/d/case/Webserver.E01            # mounts at /mnt/evidence
#   sudo setup/wsl/mount_image.sh --umount                             # undo
#   sudo setup/wsl/mount_image.sh image.E01 --part 6                   # choose a partition explicitly
#   sudo setup/wsl/mount_image.sh image.E01 --lv VulnOSv2-vg/root      # choose a logical volume explicitly
set -euo pipefail
TARGET=/mnt/evidence; EWF=/mnt/ewf; PART=""; LV=""; IMG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --umount) IMG=UMOUNT;; --target) TARGET="$2"; shift;; --part) PART="$2"; shift;; --lv) LV="$2"; shift;;
    *) IMG="$1";;
  esac; shift
done
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
STATE=/run/gumshoe-mount.state

if [ "$IMG" = "UMOUNT" ]; then
  [ -f "$STATE" ] || { echo "nothing recorded in $STATE"; exit 1; }
  # shellcheck disable=SC1090
  . "$STATE"
  umount "$TARGET" 2>/dev/null && echo "unmounted $TARGET"
  [ -n "${VG:-}" ] && vgchange -an "$VG" >/dev/null 2>&1 && echo "deactivated VG $VG"
  [ -n "${LOOPDEV:-}" ] && kpartx -d "$LOOPDEV" >/dev/null 2>&1 && losetup -d "$LOOPDEV" 2>/dev/null && echo "released $LOOPDEV"
  [ -n "${NBD:-}" ] && qemu-nbd --disconnect "$NBD" >/dev/null 2>&1 && echo "disconnected $NBD"
  mountpoint -q "$EWF" && fusermount -u "$EWF" 2>/dev/null && echo "unmounted $EWF"
  rm -f "$STATE"; exit 0
fi
[ -n "$IMG" ] && [ -f "$IMG" ] || { echo "usage: $0 <image.E01|image.dd|image.vhdx> [--part N] [--lv VG/LV] [--target DIR] | --umount"; exit 1; }
mkdir -p "$TARGET" "$EWF"
LOOPDEV=""; NBD=""; VG=""; RAW=""

case "${IMG,,}" in
  *.e01)
    command -v ewfmount >/dev/null || { echo "ewfmount missing: apt install ewf-tools"; exit 1; }
    echo "== ewfinfo (acquisition hashes; compare with gumshoe verify / case paperwork)"; ewfinfo "$IMG" | grep -iE "MD5|SHA|Acquisition date|Examiner|Case" || true
    mountpoint -q "$EWF" || ewfmount "$IMG" "$EWF"
    RAW="$EWF/ewf1";;
  *.vhdx|*.vhd|*.vmdk|*.qcow2)
    command -v qemu-nbd >/dev/null || { echo "qemu-nbd missing: apt install qemu-utils"; exit 1; }
    modprobe nbd max_part=16; NBD=/dev/nbd0
    qemu-nbd --read-only --connect="$NBD" "$IMG"; sleep 1; RAW="$NBD";;
  *) RAW="$IMG";;
esac

echo "== partitions"; mmls "$RAW" 2>/dev/null || fdisk -l "$RAW" 2>/dev/null || true
if [ -z "$NBD" ]; then
  LOOPDEV=$(losetup --find --show --read-only "$RAW")
  kpartx -av "$LOOPDEV" >/dev/null 2>&1 || true
fi
sleep 1
DEV=""
if [ -n "$LV" ]; then
  VG="${LV%%/*}"; vgchange -ay "$VG" >/dev/null; DEV="/dev/$LV"
elif [ -n "$PART" ]; then
  if [ -n "$NBD" ]; then DEV="${NBD}p${PART}"; else DEV="/dev/mapper/$(basename "$LOOPDEV")p${PART}"; fi
else
  # prefer an LVM root LV; else the largest ext4/xfs partition
  if pvs --noheadings 2>/dev/null | grep -qE "$(basename "${LOOPDEV:-$NBD}")"; then
    VG=$(pvs --noheadings -o vg_name 2>/dev/null | grep -v '^\s*$' | head -1 | tr -d ' ')
    vgchange -ay "$VG" >/dev/null
    DEV=$(lvs --noheadings -o lv_path "$VG" 2>/dev/null | tr -d ' ' | grep -iE "root" | head -1)
    [ -z "$DEV" ] && DEV=$(lvs --noheadings -o lv_path,lv_size --units b "$VG" | sort -k2 -n | tail -1 | awk '{print $1}')
  else
    DEV=$(lsblk -nrpo NAME,FSTYPE,SIZE -b "${LOOPDEV:-$NBD}" 2>/dev/null | awk '$2=="ext4"||$2=="xfs"{print $3, $1}' | sort -n | tail -1 | awk '{print $2}')
    [ -z "$DEV" ] && DEV=$(ls /dev/mapper/$(basename "${LOOPDEV:-x}")p* 2>/dev/null | head -1)
  fi
fi
[ -n "$DEV" ] && [ -e "$DEV" ] || { echo "could not pick a filesystem; use --part N or --lv VG/LV (see the listing above)"; exit 1; }
FST=$(blkid -o value -s TYPE "$DEV" 2>/dev/null || echo "")
OPTS="ro,noatime,noexec,nosuid"
case "$FST" in ext4|ext3) OPTS="$OPTS,noload";; xfs) OPTS="$OPTS,norecovery";; esac
mount -t "${FST:-auto}" -o "$OPTS" "$DEV" "$TARGET"
cat > "$STATE" <<EOF
TARGET=$TARGET
EWF=$EWF
LOOPDEV=$LOOPDEV
NBD=$NBD
VG=$VG
EOF
echo "== mounted $DEV ($FST) at $TARGET with $OPTS"
grep " $TARGET " /proc/mounts
echo "next: gumshoe init --mount $TARGET ...   then   gumshoe verify"
echo "undo: sudo $0 --umount"
