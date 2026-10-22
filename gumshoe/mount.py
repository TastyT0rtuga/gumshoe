"""Read-only checks and mount guidance. Gumshoe never mounts anything itself;
it verifies that what you mounted is read-only and tells you the commands."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional


def _proc_mounts() -> list[tuple[str, str, str, str]]:
    out = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    out.append((parts[0], parts[1], parts[2], parts[3]))
    except OSError:
        pass
    return out


def find_mount(path: Path) -> Optional[tuple[str, str, str, str]]:
    """Longest-prefix match of `path` against /proc/mounts."""
    p = str(Path(path).resolve())
    best = None
    for dev, mp, fstype, opts in _proc_mounts():
        if p == mp or p.startswith(mp.rstrip("/") + "/"):
            if best is None or len(mp) > len(best[1]):
                best = (dev, mp, fstype, opts)
    return best


def holder_of(image_path) -> dict:
    """How the filesystem holding the image *file* is mounted (the drvfs share or drive, a loop device's backing
    folder): recorded with the read-only check so the custody record says what is and is not guaranteed. The
    evidence filesystem inside the image is what Gumshoe mounts read-only (checked below); the drive the image
    file sits on is whatever Windows gave the distro - usually read-write - and nothing in Gumshoe writes there."""
    if not image_path:
        return {}
    try:
        m = find_mount(Path(str(image_path)).parent)
    except OSError:
        m = None
    if not m:
        return {"path": str(image_path), "mountpoint": None, "readonly": None}
    dev, mp, fstype, opts = m
    return {"path": str(image_path), "mountpoint": mp, "fstype": fstype, "options": opts, "readonly": "ro" in set(opts.split(","))}


def check_readonly(mount_root: Path, mode: str) -> dict:
    """Returns {ok, reason, details}. On Linux in mount mode the mountpoint
    must carry the `ro` option. In export mode we only check the folder is
    present and warn if it is writable."""
    root = Path(mount_root)
    if not root.exists():
        return {"ok": False, "reason": f"evidence root does not exist: {root}", "details": {}}
    if mode == "export" or not sys.platform.startswith("linux"):
        writable = os.access(root, os.W_OK)
        return {
            "ok": True,
            "reason": "export mode: folder present" + (" (folder is writable; consider setting it read-only)" if writable else ""),
            "details": {"writable": writable},
        }
    m = find_mount(root)
    if not m:
        return {"ok": False, "reason": "no mountpoint covers the evidence root; is the image mounted?", "details": {}}
    dev, mp, fstype, opts = m
    optset = set(opts.split(","))
    ro = "ro" in optset
    details = {"device": dev, "mountpoint": mp, "fstype": fstype, "options": opts,
               "noload": "noload" in optset, "noexec": "noexec" in optset}
    if mp in ("/",):
        return {"ok": False, "reason": "evidence root resolves to the host root filesystem, not a mounted image",
                "details": details}
    if not ro:
        return {"ok": False, "reason": f"mount {mp} is NOT read-only (options: {opts})", "details": details}
    return {"ok": True, "reason": f"{mp} ({fstype}) mounted read-only", "details": details}


MOUNT_HELP = """\
Mounting the image read-only (Windows 11 host, WSL2 analysis distro)

A) Recommended: Arsenal Image Mounter -> wsl --mount
   1. Arsenal Image Mounter -> Mount image -> tick "Read only". Note the PhysicalDrive number
      Windows assigns (Disk Management shows it).
   2. Admin PowerShell:
        wsl --mount \\\\.\\PHYSICALDRIVE<n> --bare
   3. Inside WSL:
        lsblk                                   # find the new /dev/sdX and its partitions
        sudo mkdir -p /mnt/evidence
        sudo mount -o ro,noload,noexec,nosuid /dev/sdX<p> /mnt/evidence
        grep ' /mnt/evidence ' /proc/mounts     # must show 'ro'
      (LVM inside the image: sudo vgscan && sudo vgchange -ay, then mount the LV the same way.)
   4. gumshoe verify --case <CASE>              # refuses to continue unless the mount is ro

B) No virtual-disk bridge: ewfmount inside WSL
        sudo mkdir -p /mnt/ewf /mnt/evidence
        ewfmount /mnt/d/case/server.E01 /mnt/ewf
        sudo fdisk -l /mnt/ewf/ewf1             # partition start sector -> offset = start * 512
        sudo mount -o ro,noload,noexec,nosuid,offset=<bytes> /mnt/ewf/ewf1 /mnt/evidence
   Raw/dd image: skip ewfmount and use the dd file in place of /mnt/ewf/ewf1.

C) No WSL: FTK Imager -> Export Files (whole tree) + Export File List (CSV)
        gumshoe init ... --mode export --mount D:\\Cases\\CASE\\export

Unmounting:   sudo umount /mnt/evidence ; (A) wsl --unmount \\\\.\\PHYSICALDRIVE<n>
"""
