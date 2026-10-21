#!/usr/bin/env bash
# Mount a forensic image read-only inside WSL (or any Linux): E01 (via ewfmount), raw/dd/img, or
# VHDX/VMDK/qcow2 (via qemu-nbd), with partition and LVM handling. Prints what it picked and how to undo it.
# Gumshoe itself never mounts anything; this is the examiner's explicit step, logged by `gumshoe verify`.
#
#   mount_image /mnt/d/case/Webserver.E01              # mounts the root filesystem at /mnt/evidence
#   mount_image image.raw --part 2                      # choose a partition explicitly
#   mount_image image.raw --lv VulnOSv2-vg/root         # choose a logical volume explicitly
#   mount_image image.raw --part 1 --at /www            # add a 2nd volume on top of the mounted root
#   mount_image data.raw --lv datavg/www --at /www      # (same image or another one; e.g. a data disk at /www)
#   mount_image --umount                                # undo everything
#
# Read-only at every layer: the loop device is read-only, LVM is told to activate the volume group
# read-only (and only to look at the image's own devices), and the filesystem is mounted
# ro,noload/norecovery so no journal replay touches the image.
# Works without udev (WSL has none): LVM is run with udev_rules/udev_sync off and the device nodes are
# created by vgmknodes/dmsetup instead.
set -uo pipefail
TARGET=/mnt/evidence; EWF=/mnt/ewf; PART=""; LV=""; IMG=""; AT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --umount) IMG=UMOUNT;; --target) TARGET="$2"; shift;; --part) PART="$2"; shift;; --lv) LV="$2"; shift;; --at) AT="$2"; shift;;
    -h|--help) sed -n 2,13p "$0"; exit 0;;
    *) IMG="$1";;
  esac; shift
done
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
STATE=/run/gumshoe-mount.state
die(){ echo "ERROR: $*"; exit "${2:-1}"; }

# LVM: no udev needed, scan only our loop/nbd devices (never the examiner's disks), activate read-only
lvm_cfg(){
  local ro=""; [ -n "${1:-}" ] && ro="read_only_volume_list=[\"$1\"]"
  echo "devices{obtain_device_list_from_udev=0 use_devicesfile=0 filter=[\"a|^/dev/loop[0-9]+p?[0-9]*\$|\",\"a|^/dev/mapper/loop[0-9]+p[0-9]+\$|\",\"a|^/dev/nbd[0-9]+p?[0-9]*\$|\",\"r|.*|\"]} activation{udev_sync=0 udev_rules=0 verify_udev_operations=0 $ro} global{use_lvmlockd=0} log{silent=0}"
}
lvmc(){ lvm "$@" --config "$(lvm_cfg "${VG:-}")"; }

if [ "$IMG" = "UMOUNT" ]; then
  if [ -f "$STATE" ]; then
    # shellcheck disable=SC1090
    . "$STATE"
  else
    echo "no mount recorded in $STATE; cleaning up whatever an earlier attempt left behind"
  fi
  # -R: anything mounted on top of the target (a second volume at $TARGET/www, say) goes first
  umount -R "$TARGET" 2>/dev/null && echo "unmounted $TARGET" || { umount "$TARGET" 2>/dev/null && echo "unmounted $TARGET"; }
  for m in $(awk -v t="$TARGET/" 'index($2,t)==1{print $2}' /proc/mounts | sort -r); do umount "$m" 2>/dev/null && echo "unmounted $m"; done
  # every VG that lives on our loop/nbd devices (the filter keeps the examiner's own disks out of it)
  for vg in ${VG:-} $(lvm vgs --noheadings -o vg_name --config "$(lvm_cfg)" 2>/dev/null); do
    VG="$vg"; lvmc vgchange -an "$vg" >/dev/null 2>&1 && echo "deactivated VG $vg"
  done
  for l in ${LOOPDEV:-} $(losetup -ln 2>/dev/null | awk '{print $1}'); do
    [ -e "$l" ] || continue
    kpartx -d "$l" >/dev/null 2>&1
    losetup -d "$l" 2>/dev/null && echo "released $l"
  done
  for n in ${NBD:-} /dev/nbd0 /dev/nbd1; do [ -e "$n" ] && qemu-nbd --disconnect "$n" >/dev/null 2>&1 && echo "disconnected $n"; done
  for e in "$EWF" /mnt/ewf /mnt/ewf2; do mountpoint -q "$e" 2>/dev/null && fusermount -u "$e" 2>/dev/null && echo "unmounted $e"; done
  rm -f "$STATE"; exit 0
fi
[ -n "$IMG" ] && [ -f "$IMG" ] || { echo "usage: $0 <image.E01|image.raw|image.dd|image.vhdx> [--part N] [--lv VG/LV] [--target DIR] [--at /www] | --umount"; exit 1; }
MOUNT_AT="$TARGET"; SAME_IMAGE=0; MAIN_LOOP=""; MAIN_NBD=""; MAIN_PARTS=""
if [ -n "$AT" ]; then
  # an additional volume on top of the mounted root: the original server's /www (data disk), /home, /var/lib/mysql ...
  [ -f "$STATE" ] || die "nothing is mounted yet: mount the root volume first, then add a volume with --at"
  # shellcheck disable=SC1090
  . "$STATE"
  [ -n "$PART$LV" ] || die "--at needs --part N or --lv VG/LV to say which volume goes there"
  MOUNT_AT="$TARGET/${AT#/}"
  [ -d "$MOUNT_AT" ] || die "$MOUNT_AT does not exist on the mounted root: the mount point must exist there (it did on the original server, see its /etc/fstab)"
  mountpoint -q "$MOUNT_AT" && die "$MOUNT_AT is already a mount point"
  if [ -n "${IMAGE:-}" ] && [ "$(readlink -f "$IMG")" = "$(readlink -f "$IMAGE")" ]; then
    SAME_IMAGE=1; MAIN_LOOP="$LOOPDEV"; MAIN_NBD="$NBD"; MAIN_PARTS="$PARTS"
    echo "== same image as the mounted root: reusing its devices"
  else
    EWF=/mnt/ewf2
  fi
else
  [ -f "$STATE" ] && die "something is already mounted by this script (see $STATE); run: $0 --umount   (or press Unmount in the UI). To add a volume on top of it use --at /dir"
  mountpoint -q "$TARGET" && die "$TARGET is already a mount point; unmount it first"
fi
mkdir -p "$TARGET" "$EWF"
LOOPDEV=""; NBD=""; VG=""; RAW=""; PARTS="none"

if [ "$SAME_IMAGE" = 1 ]; then
  LOOPDEV="$MAIN_LOOP"; NBD="$MAIN_NBD"; PARTS="$MAIN_PARTS"; RAW="${LOOPDEV:-$NBD}"
else
case "${IMG,,}" in
  *.e01|*.ex01)
    command -v ewfmount >/dev/null || die "ewfmount missing (apt install ewf-tools)"
    echo "== ewfinfo (acquisition hashes; compare with gumshoe verify / case paperwork)"
    ewfinfo "$IMG" 2>/dev/null | grep -iE "MD5|SHA|Acquisition date|Examiner|Case|Evidence" || true
    mountpoint -q "$EWF" || ewfmount "$IMG" "$EWF" || die "ewfmount failed"
    RAW="$EWF/ewf1";;
  *.vhdx|*.vhd|*.vmdk|*.qcow2)
    command -v qemu-nbd >/dev/null || die "qemu-nbd missing (apt install qemu-utils)"
    modprobe nbd max_part=16 2>/dev/null || true
    [ -e /dev/nbd0 ] || die "no /dev/nbd0: this kernel has no nbd module (WSL: use wsl --mount --vhd on the Windows side, or convert to raw with qemu-img)"
    NBD=/dev/nbd0; [ -n "$AT" ] && NBD=/dev/nbd1
    qemu-nbd --read-only --connect="$NBD" "$IMG" || die "qemu-nbd failed"
    sleep 1; RAW="$NBD";;
  *) RAW="$IMG";;
esac
fi

echo "== partitions"
mmls "$RAW" 2>/dev/null || fdisk -l "$RAW" 2>/dev/null || echo "(no partition table: treating the image as one filesystem or one PV)"

if [ -z "$NBD" ] && [ "$SAME_IMAGE" = 0 ]; then
  # 1st choice: the kernel scans the partitions (no device-mapper, no udev needed); fallback: kpartx maps
  LOOPDEV=$(losetup --find --show --read-only -P "$RAW" 2>/dev/null) || LOOPDEV=$(losetup --find --show --read-only "$RAW") || die "losetup failed"
  for _ in 1 2 3 4 5; do ls "${LOOPDEV}"p* >/dev/null 2>&1 && break; sleep 0.5; done
  if ls "${LOOPDEV}"p* >/dev/null 2>&1; then PARTS="kernel"
  elif command -v kpartx >/dev/null && kpartx -av "$LOOPDEV" >/dev/null 2>&1 && ls /dev/mapper/"$(basename "$LOOPDEV")"p* >/dev/null 2>&1; then PARTS="kpartx"
  fi
fi
BASE="${LOOPDEV:-$NBD}"
part_dev(){  # partition N -> device node
  if [ -n "$NBD" ]; then echo "${NBD}p$1"
  elif [ "$PARTS" = "kpartx" ]; then echo "/dev/mapper/$(basename "$LOOPDEV")p$1"
  else echo "${LOOPDEV}p$1"; fi
}
list_parts(){ ls "${BASE}"p* /dev/mapper/"$(basename "$BASE")"p* 2>/dev/null || true; }
echo "== block devices"; lsblk -o NAME,SIZE,FSTYPE,TYPE,RO "$BASE" 2>/dev/null || true

save_state(){  # %q: paths with spaces survive being sourced back
  if [ -n "$AT" ]; then printf 'EXTRA_%s=%q\n' "$(date +%s)" "$MOUNT_AT|$IMG|$LOOPDEV|$NBD|$VG" >> "$STATE"
  else printf 'TARGET=%q\nEWF=%q\nLOOPDEV=%q\nNBD=%q\nVG=%q\nPARTS=%q\nIMAGE=%q\n' "$TARGET" "$EWF" "$LOOPDEV" "$NBD" "$VG" "$PARTS" "$IMG" > "$STATE"; fi
}
cleanup_fail(){ save_state; echo "   (devices left attached so you can inspect them; undo with: $0 --umount)"; }

activate_vg(){  # $1 = VG; sets nothing, exits non-zero on failure with the real LVM message shown
  local vg="$1" out
  VG="$vg"
  if out=$(lvmc vgchange -ay "$vg" 2>&1); then echo "$out" | sed 's/^/   /'
  else
    echo "$out" | sed 's/^/   lvm: /'
    if echo "$out" | grep -qiE "partial|missing"; then
      echo "   VG is partial (a PV is missing from the image); activating what is there, read-only"
      out=$(lvmc vgchange -ay --activationmode partial "$vg" 2>&1) && echo "$out" | sed 's/^/   /' || { echo "$out" | sed 's/^/   lvm: /'; return 5; }
    else return 5; fi
  fi
  # device nodes without udev
  lvmc vgmknodes "$vg" >/dev/null 2>&1 || true
  dmsetup mknodes >/dev/null 2>&1 || true
  return 0
}
lv_dev(){  # VG/LV -> an existing device node (symlink, dm name, or /dev/dm-N)
  local vglv="$1" vg lv d
  vg="${vglv%%/*}"; lv="${vglv#*/}"
  for d in "/dev/$vg/$lv" "/dev/mapper/${vg//-/--}-${lv//-/--}"; do [ -e "$d" ] && { echo "$d"; return; }; done
  d=$(dmsetup info -c --noheadings -o major,minor "${vg//-/--}-${lv//-/--}" 2>/dev/null | tr -d ' ')
  [ -n "$d" ] && [ -e "/dev/block/$d" ] && { echo "/dev/block/$d"; return; }
  echo ""
}

DEV=""
if [ -n "$LV" ]; then
  activate_vg "${LV%%/*}" || { cleanup_fail; die "LVM activation failed (see the lvm: lines above)" 5; }
  DEV=$(lv_dev "$LV"); [ -n "$DEV" ] || { cleanup_fail; die "logical volume $LV not found after activation (lvs: $(lvmc lvs --noheadings -o lv_path "${LV%%/*}" 2>&1 | tr -s ' \n' ' '))"; }
elif [ -n "$PART" ]; then
  DEV=$(part_dev "$PART"); [ -e "$DEV" ] || { cleanup_fail; die "partition $PART ($DEV) does not exist; partitions seen: $(list_parts | tr '\n' ' ')"; }
else
  # an LVM PV on any of our devices? prefer its root LV; otherwise the largest ext4/xfs/btrfs partition
  PVOUT=$(lvm pvs --noheadings -o pv_name,vg_name --config "$(lvm_cfg)" 2>/dev/null | awk '$1 ~ /loop|nbd/' || true)
  if [ -n "$PVOUT" ]; then
    echo "== LVM physical volumes in the image"; echo "$PVOUT" | sed 's/^/   /'
    VGNAME=$(echo "$PVOUT" | awk '$2!=""{print $2; exit}')
    [ -n "$VGNAME" ] || { cleanup_fail; die "a PV was found but it belongs to no readable volume group (orphan PV or damaged metadata); try --part N for a plain partition" 5; }
    activate_vg "$VGNAME" || { cleanup_fail; die "LVM activation failed (see the lvm: lines above)" 5; }
    echo "== logical volumes"
    LVLIST=$(lvmc lvs --noheadings -o lv_path,lv_size,lv_attr --units b "$VGNAME" 2>/dev/null | awk '{print $1, $2, $3}')
    echo "$LVLIST" | sed 's/^/   /'
    # root-looking names first, then the largest LV carrying a filesystem (not swap)
    for cand in $(echo "$LVLIST" | awk '{print $1}' | grep -iE '/(root|rootfs|lv_root|ubuntu-lv|system|sys|centos-root|rhel-root)$'; echo "$LVLIST" | sort -k2 -n -r | awk '{print $1}'); do
      d=$(lv_dev "${cand#/dev/}"); [ -n "$d" ] || continue
      t=$(blkid -o value -s TYPE "$d" 2>/dev/null || true)
      case "$t" in ext2|ext3|ext4|xfs|btrfs) DEV="$d"; break;; esac
    done
    [ -n "$DEV" ] || { cleanup_fail; die "no logical volume with a mountable filesystem; use --lv VG/LV (nodes: $(ls /dev/mapper 2>/dev/null | tr '\n' ' '))"; }
  else
    best=0
    for d in $(list_parts) "$BASE"; do
      [ -e "$d" ] || continue
      t=$(blkid -o value -s TYPE "$d" 2>/dev/null || true)
      case "$t" in ext2|ext3|ext4|xfs|btrfs) sz=$(blockdev --getsize64 "$d" 2>/dev/null || echo 0); [ "$sz" -gt "$best" ] && { best=$sz; DEV="$d"; };; esac
    done
    [ -n "$DEV" ] || { cleanup_fail; die "no ext/xfs/btrfs filesystem found on $(list_parts "$BASE" | tr '\n' ' ') $BASE; use --part N (listing above) or --lv VG/LV"; }
  fi
fi
FST=$(blkid -o value -s TYPE "$DEV" 2>/dev/null || echo "")
OPTS="ro,noatime,noexec,nosuid"
case "$FST" in ext4|ext3) OPTS="$OPTS,noload";; xfs) OPTS="$OPTS,norecovery";; esac
if ! out=$(mount -t "${FST:-auto}" -o "$OPTS" "$DEV" "$MOUNT_AT" 2>&1); then
  echo "$out"; cleanup_fail; die "mount of $DEV (${FST:-unknown fs}) failed" 32
fi
save_state
echo "== mounted $DEV ($FST) at $MOUNT_AT with $OPTS"
grep " $MOUNT_AT " /proc/mounts
if [ -n "$AT" ]; then echo "next: run Collect (or Re-analyze) again so the added volume is read"
else echo "next: create the case in the UI (mount root $TARGET), then Verify"; fi
echo "undo: $0 --umount"
