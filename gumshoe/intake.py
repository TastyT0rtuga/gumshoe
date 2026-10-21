"""The hopper: drop anything, get a case.

`gumshoe intake <path>` takes whatever an examiner has - an E01, a raw/dd/img (any name, no extension
needed), a VHDX/VMDK/qcow2, a zip/7z/gz/xz/tar of an image or of a file tree, a folder that is an
extracted file system, a folder holding the disk images of one server (drive-scsi0 + drive-scsi1 ...)
- and does the right thing with it:

  detect      by content, not by file name (magic bytes; inside archives too)
  extract     archives into the analysis distro (fast ext4, never onto the evidence share)
  mount       disk images read-only through setup/wsl/mount_image.sh (partitions, LVM, udev-less)
  assemble    when the original server kept /www, /home, /var/lib/mysql ... on a second disk, the image
              holding it is found by UUID/label/device order from the root's /etc/fstab and mounted on top
  case        created with the item's name, the examiner, the image path(s) and a note of what was done
  verify      read-only check; every image hashed (and compared with a hash file lying next to it)
  collect     tools + MariaDB review + normalize; optionally the deep run afterwards

Everything is logged as `[intake] ...` lines (the UI's progress bar reads them) and written to
<case>/intake.json, which `gumshoe remount` replays after a reboot.
"""
from __future__ import annotations

import bz2
import gzip
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Optional

from .case import Case, project_root

# extracted disk images go to <work>/images, file trees to <work>/trees; <work> is /opt/dfir (inside the
# distro) unless the examiner pointed it at another drive in the settings (C: full)
DEFAULT_WORK = Path("/opt/dfir")
HOPPER_WIN = r"C:\DFIR\hopper"
HOPPER = Path("/mnt/c/DFIR/hopper")
DEFAULT_TARGET = "/mnt/evidence"
STATE_FILE = Path("/run/gumshoe-mount.state")
SNIFF_BYTES = 128 * 1024
Log = Callable[[str], None]


def mount_script() -> Path:
    return project_root() / "setup" / "wsl" / "mount_image.sh"


# --------------------------------------------------------------------------- detection
def sniff_bytes(head: bytes) -> dict[str, Any]:
    """What a blob is, from its first 128 KiB. kind: ewf | disk | vmdisk | archive | unsupported | unknown."""
    h = head
    if h[:8] == b"EVF\x09\x0d\x0a\xff\x00":
        return {"kind": "ewf", "format": "E01"}
    if h[:8] == b"EVF2\r\n\x81\x00":
        return {"kind": "ewf", "format": "Ex01"}
    if h[:8] == b"LVF\x09\x0d\x0a\xff\x00" or h[:8] == b"LVF2\r\n\x81\x00":
        return {"kind": "unsupported", "format": "L01 logical evidence file (export its contents with FTK Imager, then drop the folder)"}
    if h[:8] == b"vhdxfile":
        return {"kind": "vmdisk", "format": "vhdx"}
    if h[:8] == b"conectix":
        return {"kind": "vmdisk", "format": "vhd"}
    if h[:4] == b"KDMV":
        return {"kind": "vmdisk", "format": "vmdk"}
    if h[:21] == b"# Disk DescriptorFile":
        return {"kind": "vmdisk", "format": "vmdk-descriptor"}
    if h[:4] == b"QFI\xfb":
        return {"kind": "vmdisk", "format": "qcow2"}
    if b"VirtualBox Disk Image" in h[:64]:
        return {"kind": "vmdisk", "format": "vdi"}
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return {"kind": "archive", "format": "zip"}
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return {"kind": "archive", "format": "7z"}
    if h[:2] == b"\x1f\x8b":
        return {"kind": "archive", "format": "gz"}
    if h[:3] == b"BZh" and h[3:4].isdigit():
        return {"kind": "archive", "format": "bz2"}
    if h[:6] == b"\xfd7zXZ\x00":
        return {"kind": "archive", "format": "xz"}
    if h[:4] == b"\x28\xb5\x2f\xfd":
        return {"kind": "unsupported", "format": "zstd (no zstd tool in the bundle; decompress it on Windows first)"}
    if h[:7] == b"Rar!\x1a\x07\x00" or h[:8] == b"Rar!\x1a\x07\x01\x00":
        return {"kind": "unsupported", "format": "rar (extract it with 7-Zip on Windows, then drop the result)"}
    if h[257:262] == b"ustar":
        return {"kind": "archive", "format": "tar"}
    if h[:4] == b"MSCF":
        return {"kind": "unsupported", "format": "cab"}
    # disks and bare file systems
    if h[512:520] == b"EFI PART":
        return {"kind": "disk", "format": "gpt"}
    if len(h) >= 512 and h[510:512] == b"\x55\xaa":
        if h[3:11] == b"NTFS    ":
            return {"kind": "disk", "format": "ntfs (bare)"}
        if h[82:87] == b"FAT32" or h[54:57] == b"FAT":
            return {"kind": "disk", "format": "fat (bare)"}
        types = [h[446 + 16 * i + 4] for i in range(4)]
        if any(types):
            return {"kind": "disk", "format": "mbr" + (" (protective gpt)" if 0xEE in types else "")}
        return {"kind": "disk", "format": "boot sector"}
    if len(h) >= 1024 + 58 and h[1024 + 56:1024 + 58] == b"\x53\xef":
        return {"kind": "disk", "format": "ext (bare)"}
    if h[:4] == b"XFSB":
        return {"kind": "disk", "format": "xfs (bare)"}
    if len(h) > 0x10048 and h[0x10040:0x10048] == b"_BHRfS_M":
        return {"kind": "disk", "format": "btrfs (bare)"}
    for n in range(4):
        if h[512 * n:512 * n + 8] == b"LABELONE":
            return {"kind": "disk", "format": "lvm pv (bare)"}
    if len(h) >= 4096 and h[4096 - 10:4096] in (b"SWAPSPACE2", b"SWAP-SPACE"):
        return {"kind": "unsupported", "format": "swap"}
    return {"kind": "unknown", "format": ""}


def _head(path: Path, n: int = SNIFF_BYTES) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _seven_zip() -> Optional[str]:
    return shutil.which("7zz") or shutil.which("7z") or shutil.which("7za")


def _zip_members(path: Path) -> list[tuple[str, int]]:
    with zipfile.ZipFile(path) as z:
        return [(i.filename, i.file_size) for i in z.infolist() if not i.is_dir()]


def _sevenz_members(path: Path) -> list[tuple[str, int]]:
    exe = _seven_zip()
    if not exe:
        return []
    out = subprocess.run([exe, "l", "-slt", "-ba", str(path)], capture_output=True, text=True, errors="replace").stdout
    members, cur = [], {}
    for line in out.splitlines() + [""]:
        if not line.strip():
            if cur.get("Path") and cur.get("Folder", "-") != "+" and cur.get("Attributes", "").find("D") < 0:
                members.append((cur["Path"], int(cur.get("Size") or 0)))
            cur = {}
            continue
        if " = " in line:
            k, v = line.split(" = ", 1)
            cur[k.strip()] = v.strip()
    return members


def _archive_inner_head(path: Path, fmt: str, member: Optional[str]) -> bytes:
    """First bytes of what is inside an archive (one member, or the stream)."""
    try:
        if fmt == "zip" and member:
            with zipfile.ZipFile(path) as z, z.open(member) as m:
                return m.read(SNIFF_BYTES)
        if fmt == "gz":
            with gzip.open(path, "rb") as g:
                return g.read(SNIFF_BYTES)
        if fmt == "bz2":
            with bz2.open(path, "rb") as g:
                return g.read(SNIFF_BYTES)
        if fmt == "xz":
            with lzma.open(path, "rb") as g:
                return g.read(SNIFF_BYTES)
        if fmt == "7z" and member and _seven_zip():
            p = subprocess.Popen([_seven_zip(), "e", "-so", str(path), member], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            data = p.stdout.read(SNIFF_BYTES) if p.stdout else b""
            p.kill()
            p.wait()
            return data
    except Exception:  # noqa: BLE001 - a damaged archive is reported, not raised
        return b""
    return b""


def _gz_name(path: Path) -> str:
    """Original file name stored in a gzip header (FNAME), if any."""
    try:
        with open(path, "rb") as f:
            h = f.read(10)
            if len(h) < 10 or h[:2] != b"\x1f\x8b":
                return ""
            flg = h[3]
            if flg & 4:
                xlen = int.from_bytes(f.read(2), "little")
                f.read(xlen)
            if flg & 8:
                name = b""
                while True:
                    c = f.read(1)
                    if not c or c == b"\x00":
                        break
                    name += c
                return name.decode("utf-8", "replace")
    except OSError:
        pass
    return ""


def sniff(path: Path) -> dict[str, Any]:
    """Everything the hopper wants to know about one dropped item (file or folder)."""
    path = Path(path)
    info: dict[str, Any] = {"path": str(path), "name": path.name, "kind": "unknown", "format": "", "size": 0, "notes": []}
    if path.is_dir():
        return _sniff_dir(path, info)
    if not path.is_file():
        info["kind"] = "missing"
        return info
    info["size"] = path.stat().st_size
    head = _head(path)
    s = sniff_bytes(head)
    info.update(s)
    if info["kind"] == "unknown" and info["size"] < 4096:
        info["kind"] = "unsupported"
        info["format"] = "too small to be an image or an archive"
        return info
    # split raw (FTK Imager .001/.002 ...): the first segment looks like a disk, siblings continue it
    m = re.match(r"^(.*)\.(\d{3})$", path.name)
    if m and info["kind"] == "disk" and m.group(2) in ("000", "001"):
        sibs = sorted(p for p in path.parent.glob(m.group(1) + ".[0-9][0-9][0-9]") if p.is_file())
        if len(sibs) > 1:
            info["kind"] = "split"
            info["segments"] = [str(p) for p in sibs]
            info["size"] = sum(p.stat().st_size for p in sibs)
            info["format"] = f"split raw, {len(sibs)} segments"
    if info["kind"] == "archive":
        _sniff_archive(path, info)
    if info["kind"] == "unknown":
        info["notes"].append("not a disk image, archive or E01 that I recognise (first bytes: " + head[:16].hex() + ")")
    return info


def _sniff_archive(path: Path, info: dict[str, Any]) -> None:
    fmt = info["format"]
    members: list[tuple[str, int]] = []
    inner: dict[str, Any] = {}
    member: Optional[str] = None
    if fmt == "zip":
        try:
            members = _zip_members(path)
        except zipfile.BadZipFile as e:
            info["kind"] = "unsupported"
            info["format"] = f"damaged zip ({e})"
            return
    elif fmt == "7z":
        if not _seven_zip():
            info["kind"] = "unsupported"
            info["format"] = "7z (7-Zip is not installed in the distro; the update's debs folder adds it, or extract on Windows)"
            return
        members = _sevenz_members(path)
    if members:
        total = sum(sz for _, sz in members)
        member, big = max(members, key=lambda t: t[1])
        info["members"] = len(members)
        info["uncompressed"] = total
        if big >= 8 * 2**20 and big >= 0.9 * total:
            inner = sniff_bytes(_archive_inner_head(path, fmt, member))
            if inner.get("kind") in ("disk", "ewf", "vmdisk"):
                info["contains"] = "image"
                info["member"] = member
                info["inner"] = inner
                info["notes"].append(f"{fmt} holding one disk image: {member} ({big / 2**30:.1f} GB)")
                return
        info["contains"] = "tree"
        info["notes"].append(f"{fmt} with {len(members)} files ({total / 2**30:.1f} GB unpacked)")
        return
    if fmt in ("gz", "bz2", "xz"):
        inner = sniff_bytes(_archive_inner_head(path, fmt, None))
        info["inner"] = inner
        if inner.get("kind") in ("disk", "ewf", "vmdisk"):
            info["contains"] = "image"
            info["member"] = _gz_name(path) if fmt == "gz" else ""
            info["notes"].append(f"{fmt}-compressed disk image" + (f" ({info['member']})" if info["member"] else ""))
        elif inner.get("format") == "tar":
            info["contains"] = "tree"
            info["notes"].append(f"compressed tar ({fmt})")
        else:
            info["contains"] = "tree" if inner.get("kind") == "unknown" else "image"
            info["notes"].append(f"{fmt}-compressed data (inner content {inner.get('kind')})")
        return
    if fmt == "tar":
        info["contains"] = "tree"
        info["notes"].append("tar archive")


_ROOTFS_HINTS = ("etc/passwd", "etc/os-release", "usr/lib/os-release")
_PARTIAL_HINTS = {"home directory": (".bash_history", ".bashrc", ".bash_profile", ".profile"),
                  "MariaDB/MySQL data directory": ("ibdata1", "aria_log_control", "mysql_upgrade_info", "ib_logfile0"),
                  "web root": ("index.php", "wp-config.php", "index.html"),
                  "aaPanel tree": ("server/panel", "wwwroot")}


def _sniff_dir(path: Path, info: dict[str, Any]) -> dict[str, Any]:
    try:
        entries = sorted(path.iterdir(), key=lambda p: p.name.lower())
    except OSError as e:
        info["kind"] = "unsupported"
        info["format"] = f"cannot read folder: {e}"
        return info
    if any((path / h).is_file() for h in _ROOTFS_HINTS):
        info["kind"] = "tree"
        info["format"] = "Linux root file system (extracted)"
        info["notes"].append("an extracted copy: owners and change times are not what they were on the server; the image itself is better evidence")
        return info
    # a folder of images (one server's disks, plus hash files and reports)
    items, skipped = [], []
    for e in entries:
        if e.is_file() and e.stat().st_size >= 8 * 2**20:
            s = sniff(e)
            if s["kind"] in ("disk", "ewf", "vmdisk", "split") or (s["kind"] == "archive" and s.get("contains") == "image"):
                items.append(s)
            elif s["kind"] == "archive":
                skipped.append(f"{e.name} (archive of files, not a disk - drop it on its own if it needs analysing)")
    if items:
        # one entry per split set
        seen, uniq = set(), []
        for s in items:
            key = tuple(s.get("segments") or [s["path"]])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(s)
        info["kind"] = "set"
        info["items"] = uniq
        info["size"] = sum(s["size"] for s in uniq)
        kinds = ", ".join(f"{Path(s['path']).name} ({s['kind']} {s.get('format', '')})".strip() for s in uniq)
        info["format"] = f"{len(uniq)} disk image(s): {kinds}"
        for sk in skipped:
            info["notes"].append("skipped " + sk)
        hashes = [e.name for e in entries if e.is_file() and e.stat().st_size < 64 * 1024 and re.search(r"hash|sha|md5|sum", e.name, re.I)]
        if hashes:
            info["hash_files"] = hashes
            info["notes"].append("hash file(s) next to the images will be compared: " + ", ".join(hashes))
        return info
    info["kind"] = "tree"
    what = [label for label, hints in _PARTIAL_HINTS.items() if any((path / h).exists() for h in hints)]
    info["format"] = ("partial export: " + ", ".join(what)) if what else "folder of files (no Linux root layout)"
    info["notes"].append("analysed as an export folder: the tools that need a whole system (UAC's persistence checks, the panel reader) "
                         "will find less here than on a disk image")
    return info


def scan_hopper(hopper: Path = HOPPER) -> list[dict[str, Any]]:
    """Every item lying in the hopper, with what it is."""
    out = []
    if not hopper.is_dir():
        return out
    for e in sorted(hopper.iterdir(), key=lambda p: p.name.lower()):
        if e.name.startswith((".", "~$")) or e.name.lower() in ("desktop.ini", "thumbs.db", "readme.txt"):
            continue
        try:
            out.append(sniff(e))
        except Exception as ex:  # noqa: BLE001
            out.append({"path": str(e), "name": e.name, "kind": "unsupported", "format": f"could not inspect: {ex}", "size": 0, "notes": []})
    return out


# --------------------------------------------------------------------------- helpers
def _run(cmd: list[str], log: Log, timeout: Optional[int] = None, env: Optional[dict] = None) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    out = (p.stdout or "") + (p.stderr or "")
    for line in out.rstrip().splitlines():
        log("   " + line)
    return p.returncode, out


def _free_gb(path: Path) -> float:
    p = path
    while not p.exists() and p != p.parent:
        p = p.parent
    return shutil.disk_usage(p).free / 2**30


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def safe_case_id(name: str) -> str:
    base = re.sub(r"\.(zip|7z|gz|tgz|xz|txz|bz2|tbz2|tar|raw|dd|img|e01|ex01|vhdx|vhd|vmdk|qcow2|vdi|001)$", "", name, flags=re.I)
    base = re.sub(r"\.(tar|raw|dd|img)$", "", base, flags=re.I)
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-._") or "case"
    return base[:48]


def unique_case_id(cases_root: Path, base: str) -> str:
    cid, n = base, 1
    while (cases_root / cid / "case.json").exists():
        n += 1
        cid = f"{base}-{n}"
    return cid


def mounted_now() -> dict[str, str]:
    """What the mount helper currently has mounted (its state file), as a dict."""
    if not STATE_FILE.exists():
        return {}
    out = {}
    for line in STATE_FILE.read_text("utf-8", errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v.strip().strip("'\"")
    return out


def _copy_stream(src, dst, total: Optional[int], log: Log, what: str, raw_file=None, raw_total: Optional[int] = None) -> int:
    """Chunked copy with a progress line every 5 %; returns bytes written."""
    done, last, t0 = 0, -1, time.time()
    while True:
        buf = src.read(8 * 2**20)
        if not buf:
            break
        dst.write(buf)
        done += len(buf)
        if total:
            pct = int(done * 100 / total)
        elif raw_file is not None and raw_total:
            try:
                pct = int(raw_file.tell() * 100 / raw_total)
            except Exception:  # noqa: BLE001
                pct = -1
        else:
            pct = -1
        if pct >= 0 and pct // 5 != last // 5:
            last = pct
            rate = done / max(time.time() - t0, 0.001) / 2**20
            log(f"[intake] extracting {what}: {pct}% ({human(done)}, {rate:.0f} MB/s)")
    return done


# --------------------------------------------------------------------------- extraction
def extract_image(item: dict[str, Any], log: Log, work: Path = DEFAULT_WORK) -> Path:
    """Pull the disk image out of an archive into <work>/images; returns the image path."""
    IMAGES_DIR = Path(work) / "images"
    src = Path(item["path"])
    fmt = item["format"]
    member = item.get("member") or ""
    inner_name = Path(member).name if member else re.sub(r"\.(gz|bz2|xz)$", "", src.name, flags=re.I)
    if inner_name == src.name:
        inner_name = src.stem + ".raw"
    dest_dir = IMAGES_DIR / safe_case_id(src.name)
    dest = dest_dir / inner_name
    if dest.exists() and dest.stat().st_size > 0:
        log(f"[intake] extracted already: {dest} ({human(dest.stat().st_size)}); reusing it")
        return dest
    need = item.get("uncompressed") or (item["size"] * 4)
    free = _free_gb(IMAGES_DIR) * 2**30
    log(f"[intake] extracting {inner_name} from {src.name} ({fmt}, {human(item['size'])}) into {dest_dir} (free {human(free)}, need about {human(need)})")
    if free < need:
        raise RuntimeError(f"not enough space in the work folder {IMAGES_DIR.parent}: {human(free)} free, about {human(need)} needed. "
                           f"Point the work folder at a drive with room (Hopper -> Folders), free space there, or drop the image itself instead of the archive.")
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    t0 = time.time()
    try:
        if fmt == "zip":
            with zipfile.ZipFile(src) as z, z.open(member) as m, open(tmp, "wb") as out:
                _copy_stream(m, out, z.getinfo(member).file_size, log, inner_name)
        elif fmt in ("gz", "bz2", "xz"):
            opener = {"gz": gzip.GzipFile, "bz2": bz2.BZ2File, "xz": lzma.LZMAFile}[fmt]
            with open(src, "rb") as raw, opener(fileobj=raw) as m, open(tmp, "wb") as out:  # type: ignore[call-arg]
                _copy_stream(m, out, None, log, inner_name, raw_file=raw, raw_total=item["size"])
        elif fmt == "7z":
            exe = _seven_zip()
            if not exe:
                raise RuntimeError("7-Zip (7zz) is not installed in the distro")
            rc, _ = _run([exe, "e", "-y", "-bsp0", "-bso0", f"-o{dest_dir}", str(src), member], log)
            if rc != 0:
                raise RuntimeError(f"7-Zip failed (exit {rc})")
            got = dest_dir / Path(member).name
            if got != dest:
                got.rename(dest)
            tmp = dest
        else:
            raise RuntimeError(f"cannot extract {fmt}")
        if tmp != dest:
            tmp.rename(dest)
    except Exception:
        if tmp.exists() and tmp != dest:
            tmp.unlink(missing_ok=True)
        raise
    log(f"[intake] extracted {dest} ({human(dest.stat().st_size)}) in {time.time() - t0:.0f} s")
    return dest


def extract_tree(item: dict[str, Any], log: Log, work: Path = DEFAULT_WORK) -> Path:
    """Unpack an archive of files into <work>/trees (as root, keeping owners/modes/times where the format has them)."""
    TREES_DIR = Path(work) / "trees"
    src = Path(item["path"])
    fmt = item["format"]
    dest = TREES_DIR / safe_case_id(src.name)
    if dest.exists() and any(dest.iterdir()):
        log(f"[intake] extracted already: {dest}; reusing it")
        return dest
    need = item.get("uncompressed") or item["size"] * 4
    free = _free_gb(TREES_DIR) * 2**30
    log(f"[intake] extracting {src.name} ({fmt}, {human(item['size'])}) into {dest} (free {human(free)}, need about {human(need)})")
    if free < need:
        raise RuntimeError(f"not enough space in the work folder {TREES_DIR.parent}: {human(free)} free, about {human(need)} needed "
                           f"(Hopper -> Folders points it at a drive with room)")
    dest.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    if fmt in ("tar", "gz", "bz2", "xz"):
        rc, _ = _run(["tar", "-xpf", str(src), "-C", str(dest), "--numeric-owner", "--warning=no-unknown-keyword"], log)
    elif fmt == "zip":
        rc, _ = _run(["unzip", "-qq", "-o", str(src), "-d", str(dest)], log)
    elif fmt == "7z":
        exe = _seven_zip()
        if not exe:
            raise RuntimeError("7-Zip (7zz) is not installed in the distro")
        rc, _ = _run([exe, "x", "-y", "-bsp0", "-bso0", f"-o{dest}", str(src)], log)
    else:
        raise RuntimeError(f"cannot extract {fmt}")
    if rc != 0:
        raise RuntimeError(f"extraction failed (exit {rc})")
    # a single top-level folder that holds everything (tar of "/" made as "rootfs/...")
    tops = list(dest.iterdir())
    if len(tops) == 1 and tops[0].is_dir() and any((tops[0] / h).exists() for h in _ROOTFS_HINTS):
        dest = tops[0]
    log(f"[intake] extracted to {dest} in {time.time() - t0:.0f} s")
    return dest


def join_split(item: dict[str, Any], log: Log, work: Path = DEFAULT_WORK) -> Path:
    """Split raw (.001 .002 ...) -> one image: affuse presents it without copying; otherwise segments are joined."""
    IMAGES_DIR = Path(work) / "images"
    segs = [Path(s) for s in item["segments"]]
    first = segs[0]
    if shutil.which("affuse"):
        mp = Path("/mnt/aff") / safe_case_id(first.name)
        mp.mkdir(parents=True, exist_ok=True)
        if not any(mp.iterdir()):
            rc, _ = _run(["affuse", str(first), str(mp)], log)
            if rc != 0:
                log("[intake] affuse failed; joining the segments instead")
            else:
                raws = list(mp.glob("*.raw"))
                if raws:
                    log(f"[intake] split image presented as {raws[0]} (affuse, no copy)")
                    return raws[0]
    dest_dir = IMAGES_DIR / safe_case_id(first.name)
    dest = dest_dir / (re.sub(r"\.\d{3}$", "", first.name) + ".raw")
    if dest.exists():
        return dest
    need = item["size"]
    if _free_gb(IMAGES_DIR) * 2**30 < need:
        raise RuntimeError(f"not enough space to join {len(segs)} segments ({human(need)})")
    dest_dir.mkdir(parents=True, exist_ok=True)
    log(f"[intake] joining {len(segs)} segments into {dest} ({human(need)})")
    with open(dest, "wb") as out:
        for s in segs:
            with open(s, "rb") as f:
                shutil.copyfileobj(f, out, 8 * 2**20)
    return dest


def convert_vmdisk(path: Path, fmt: str, log: Log, work: Path = DEFAULT_WORK) -> Path:
    """qemu-nbd needs the nbd module; without it a VHDX/VMDK/qcow2 is converted to raw (qemu-img) in the work folder."""
    IMAGES_DIR = Path(work) / "images"
    if Path("/dev/nbd0").exists() or subprocess.run(["modprobe", "nbd", "max_part=16"], capture_output=True).returncode == 0:
        return path
    dest_dir = IMAGES_DIR / safe_case_id(path.name)
    dest = dest_dir / (path.stem + ".raw")
    if dest.exists():
        return dest
    info = subprocess.run(["qemu-img", "info", "--output=json", str(path)], capture_output=True, text=True)
    virt = 0
    try:
        virt = int(json.loads(info.stdout).get("virtual-size", 0))
    except Exception:  # noqa: BLE001
        pass
    if virt and _free_gb(IMAGES_DIR) * 2**30 < virt:
        raise RuntimeError(f"no nbd module and not enough space to convert the {fmt} to raw ({human(virt)})")
    dest_dir.mkdir(parents=True, exist_ok=True)
    log(f"[intake] no nbd support in this kernel: converting {path.name} ({fmt}) to raw ({human(virt)}) with qemu-img")
    rc, _ = _run(["qemu-img", "convert", "-p", "-O", "raw", str(path), str(dest)], log)
    if rc != 0:
        dest.unlink(missing_ok=True)
        raise RuntimeError("qemu-img convert failed")
    return dest


# --------------------------------------------------------------------------- mounting
def list_volumes(image: Path, log: Log) -> list[dict[str, str]]:
    """Partitions and logical volumes in an image (fs type, UUID, label, size) without mounting it."""
    rc, out = _run(["bash", str(mount_script()), str(image), "--list"], lambda s: None)
    vols = []
    for line in out.splitlines():
        if line.startswith("VOL "):
            d: dict[str, str] = {}
            for tok in line[4:].split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    d[k] = v
            vols.append(d)
    log(f"[intake] volumes in {image.name}: " + (", ".join(f"{v.get('part') and 'part ' + v['part'] or 'lv ' + v.get('lv', '?')} "
                                                         f"{v.get('fstype') or '-'} {human(int(v.get('size') or 0))}" for v in vols) or "none seen"))
    return vols


def mount_image(image: Path, log: Log, target: str = DEFAULT_TARGET, part: str = "", lv: str = "", at: str = "") -> tuple[int, str]:
    cmd = ["bash", str(mount_script()), str(image)]
    if part:
        cmd += ["--part", str(part)]
    if lv:
        cmd += ["--lv", lv]
    if at:
        cmd += ["--at", at]
    else:
        cmd += ["--target", target]
    log(f"[intake] mounting {image.name}" + (f" part {part}" if part else "") + (f" lv {lv}" if lv else "") + (f" at {at}" if at else f" at {target}"))
    rc, out = _run(cmd, log)
    if rc == 0:
        log("[intake] mounted")
    return rc, out


def umount_all(log: Log) -> None:
    _run(["bash", str(mount_script()), "--umount"], log)


_DEV_LETTER = re.compile(r"^/dev/(?:xvd|vd|sd|hd)([a-z])(\d*)$")
_DEV_NVME = re.compile(r"^/dev/nvme(\d+)n\d+p?(\d*)$")


def resolve_fstab_device(spec: str, images: list[tuple[Path, list[dict[str, str]]]], root_image: Path) -> Optional[tuple[Path, dict[str, str], str]]:
    """fstab device field -> (image, volume, how)."""
    s = spec.strip()
    if s.startswith("UUID="):
        want = s[5:].strip('"').lower()
        for img, vols in images:
            for v in vols:
                if v.get("uuid", "").lower() == want:
                    return img, v, f"UUID {want}"
    if s.startswith("LABEL="):
        want = s[6:].strip('"')
        for img, vols in images:
            for v in vols:
                if v.get("label", "") == want.replace(" ", "_"):
                    return img, v, f"label {want}"
    m = re.match(r"^/dev/mapper/(.+)$", s) or re.match(r"^/dev/([^/]+)/([^/]+)$", s)
    if m and not _DEV_LETTER.match(s) and not _DEV_NVME.match(s):
        if s.startswith("/dev/mapper/"):
            name = m.group(1)
            # vg--name-lv--name -> vg-name/lv-name
            parts = re.split(r"(?<!-)-(?!-)", name)
            lvname = "/".join(p.replace("--", "-") for p in parts) if len(parts) == 2 else name
        else:
            lvname = f"{m.group(1)}/{m.group(2)}"
        for img, vols in images:
            for v in vols:
                if v.get("lv") == lvname:
                    return img, v, f"LV {lvname}"
    m = _DEV_LETTER.match(s) or _DEV_NVME.match(s)
    if m:
        idx = (ord(m.group(1)) - ord("a")) if m.group(1).isalpha() else int(m.group(1))
        partno = m.group(2)
        ordered = sorted([img for img, _ in images], key=lambda p: (p != root_image and idx == 0, p.name.lower()))
        # device order: root image first when the entry says disk 0; otherwise by name (drive-scsi0, drive-scsi1 ...)
        by_name = sorted([img for img, _ in images], key=lambda p: p.name.lower())
        cand = by_name[idx] if idx < len(by_name) else None
        if cand is None:
            return None
        vols = dict(images).get(cand, [])
        for v in vols:
            if v.get("part") == (partno or "1"):
                return cand, v, f"device order ({s} -> {cand.name})"
        if vols and not partno:
            return cand, vols[0], f"device order ({s} -> {cand.name})"
    return None


def fstab_entries(root: Path) -> list[dict[str, str]]:
    from .probe import fstab_mounts
    return fstab_mounts(root)


def assemble(root: Path, root_image: Path, images: list[Path], log: Log) -> list[dict[str, Any]]:
    """Mount, on top of the root, the volumes its /etc/fstab says lived elsewhere - when one of the images holds them."""
    entries = [e for e in fstab_entries(root) if e["fstype"] not in ("nfs", "nfs4", "cifs", "smbfs", "fuse", "bind")]
    done: list[dict[str, Any]] = []
    if not entries:
        return done
    inv = [(img, list_volumes(img, log)) for img in images]
    for e in entries:
        mp = e["mountpoint"].rstrip("/") or "/"
        where = root / mp.lstrip("/")
        hit = resolve_fstab_device(e["device"], inv, root_image)
        if not hit:
            log(f"[intake] fstab: {mp} <- {e['device']} ({e['fstype']}): no matching volume in the dropped images")
            done.append({"mountpoint": mp, "device": e["device"], "fstype": e["fstype"], "mounted": False, "reason": "no matching volume"})
            continue
        img, vol, how = hit
        if not where.is_dir():
            log(f"[intake] fstab: {mp} <- {img.name} {vol}: mount point missing on the root; skipped")
            done.append({"mountpoint": mp, "device": e["device"], "mounted": False, "reason": "mount point missing"})
            continue
        if os.path.ismount(where):
            continue
        rc, _ = mount_image(img, log, part=vol.get("part", ""), lv=vol.get("lv", ""), at=mp)
        done.append({"mountpoint": mp, "device": e["device"], "fstype": e["fstype"], "image": str(img), "part": vol.get("part"),
                     "lv": vol.get("lv"), "matched_by": how, "mounted": rc == 0})
        log(f"[intake] assembled {mp} from {img.name} ({how})" if rc == 0 else f"[intake] could not mount {mp} from {img.name} (exit {rc})")
    return done


# --------------------------------------------------------------------------- hashes next to the images
_HEX64 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_HEX32 = re.compile(r"\b[0-9a-fA-F]{32}\b")


def expected_hashes_for(image: Path) -> dict[str, str]:
    """Digests written next to an image by the acquisition tool (hashes.txt, <name>_hash.txt, <name>.sha256 ...)."""
    out: dict[str, str] = {}
    cands = [p for p in image.parent.iterdir() if p.is_file() and p != image and p.stat().st_size < 256 * 1024
             and (re.search(r"hash|sha|md5|sum", p.name, re.I) or p.name.lower().startswith(image.name.lower()))]
    for p in sorted(cands):
        try:
            text = p.read_text("utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        mine = [l for l in lines if image.name.lower() in l.lower() or image.stem.lower() in l.lower()]
        pool = mine or (lines if p.name.lower().startswith(image.name.lower()) or len(cands) == 1 else [])
        for l in pool:
            for m in _HEX64.findall(l):
                out.setdefault("sha256", m.lower())
            for m in _HEX32.findall(l):
                if not _HEX64.search(l) or m.lower() not in out.get("sha256", ""):
                    out.setdefault("md5", m.lower())
        if out:
            out["source"] = p.name
            break
    return out


# --------------------------------------------------------------------------- the orchestrator
class Intake:
    def __init__(self, cases_root: Path, cfg: dict[str, Any], examiner: str, log: Log = print, work: Optional[Path] = None):
        from .settings import work_dir
        self.cases_root = Path(cases_root)
        self.cfg = cfg
        self.examiner = examiner
        self.log = log
        if work is None:
            work, note = work_dir(self.cases_root)
            if note:
                log(f"[intake] work folder: {note}; using the distro's own disk instead")
                work = DEFAULT_WORK
        self.work = Path(work)
        self.record: dict[str, Any] = {"images": [], "volumes": [], "steps": [], "work": str(self.work)}

    def run(self, path: Path, case_id: Optional[str] = None, deep: bool = False, replace_mount: bool = False,
            hash_images: bool = True, notes: str = "") -> Case:
        t0 = time.time()
        path = Path(path)
        item = sniff(path)
        self.log(f"[intake] detect: {item['name']} -> {item['kind']} {item.get('format', '')} ({human(item['size'])})")
        for n in item.get("notes", []):
            self.log(f"[intake]   {n}")
        if item["kind"] in ("unsupported", "unknown", "missing"):
            raise SystemExit(f"[intake] cannot take this item: {item.get('format') or item['kind']}")
        self.record["item"] = item
        base = safe_case_id(item["name"])
        case_id = case_id or unique_case_id(self.cases_root, base)

        mode, mount_root, image_path = "mount", DEFAULT_TARGET, None
        if item["kind"] == "tree" or (item["kind"] == "archive" and item.get("contains") == "tree"):
            root = Path(item["path"]) if item["kind"] == "tree" else extract_tree(item, self.log, self.work)
            mode, mount_root = "export", str(root)
        else:
            self._ensure_unmounted(replace_mount, check_only=True)   # a refusal must cost nothing: before any extraction
            images = self._images_of(item)
            if not images:
                raise SystemExit("[intake] no disk image to mount")
            self._ensure_unmounted(replace_mount)                    # the previous evidence stays mounted until we are ready
            root_image = self._mount_root(images)
            image_path = str(root_image)
            self.record["images"] = [str(p) for p in images]
            # /home, /www, /var/lib/mysql ... on another LV of the same disk or on a second disk: put them in place
            self.record["volumes"] = assemble(Path(DEFAULT_TARGET), root_image, images, self.log)
        from .probe import probe, explain
        pr = probe(Path(mount_root), self.cfg["paths"]["panel"].strip("/"))
        self.log("[intake] probe: " + explain(pr, self.cfg["paths"]["panel"]))
        self.record["probe"] = {k: pr.get(k) for k in ("is_rootfs", "os", "hostname", "panel", "www_empty", "separate_volumes", "other_panels", "mysql_datadirs", "web_roots")}

        note = (notes + "\n" if notes else "") + f"intake of {item['path']} ({item['kind']} {item.get('format', '')}); " + explain(pr, self.cfg["paths"]["panel"])
        case = Case.create(self.cases_root, case_id, self.examiner, image_path, mount_root, mode, self.cfg, notes=note)
        self.log(f"[intake] case {case_id} created (mode {mode}, root {mount_root})")
        self.record["case_id"] = case_id
        self.record["mode"] = mode
        self.record["mount_root"] = mount_root
        self.record["mounted_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save(case)

        # verify
        from .mount import check_readonly
        from .integrity import utc_now, hash_file_multi
        ro = check_readonly(case.mount_root, case.mode)
        case.meta["readonly_check"] = {**ro, "at": utc_now()}
        case.save_meta()
        case.custody.append("readonly_check", ro)
        self.log(("[intake] verify: OK " if ro["ok"] else "[intake] verify: FAIL ") + ro["reason"])
        if not ro["ok"]:
            raise SystemExit("[intake] the evidence is not mounted read-only; stopping before any tool runs")
        if hash_images and image_path:
            for i, img in enumerate([Path(p) for p in self.record["images"]]):
                size = img.stat().st_size
                exp = expected_hashes_for(img)
                self.log(f"[intake] hashing {img.name} ({human(size)})" + (f"; comparing with {exp['source']}" if exp else ""))
                last = [-1]

                def prog(d, size=size, name=img.name, last=last):
                    pct = int(d * 100 / max(size, 1))
                    if pct // 10 != last[0] // 10:
                        last[0] = pct
                        self.log(f"[intake] hashing {name}: {pct}%")
                if i == 0:
                    r = case.verify_image({k: exp.get(k, "") for k in ("sha256", "md5")} if exp else None)
                    comp = r.get("computed", {})
                else:
                    comp = hash_file_multi(img, ("sha256", "md5"), progress=prog)
                    match = None
                    if exp:
                        match = all(comp.get(k, "").lower() == v for k, v in exp.items() if k in ("sha256", "md5"))
                    case.custody.append("image_hashed", {"image_path": str(img), "image_bytes": size, "computed": comp, "expected": exp, "match": match})
                    r = {"match": match}
                self.log(f"[intake] hashed {img.name}: sha256 {comp.get('sha256', '')[:16]}... md5 {comp.get('md5', '')}" +
                         ({True: " - MATCHES the acquisition hash", False: " - DOES NOT MATCH the acquisition hash!", None: ""}[r.get("match")]))
                self.record.setdefault("hashes", {})[str(img)] = {"computed": comp, "expected": exp, "match": r.get("match")}
            self._save(case)

        # collect
        self.log("[intake] collect: starting the tools")
        from .collect import collect_case
        collect_case(case, db=True, log=self.log)
        self._save(case)
        if deep:
            self.log("[intake] deep: starting")
            from .deep import run as deep_run
            deep_run(case.dir, self.cfg)
        s = case.read_json("summary.json", {}) or {}
        inv = case.read_json("inventory.json", {}) or {}
        aa = inv.get("aapanel") or {}
        self.log(f"[intake] done: case {case_id} in {(time.time() - t0) / 60:.0f} min - {s.get('total', 0)} findings; "
                 f"aaPanel {'found at ' + aa.get('path', '/www/server/panel') if aa.get('present') else 'not found'}")
        return case

    # -- pieces
    def _images_of(self, item: dict[str, Any]) -> list[Path]:
        items = item["items"] if item["kind"] == "set" else [item]
        images: list[Path] = []
        for it in items:
            k = it["kind"]
            if k == "archive":
                if it.get("contains") != "image":
                    self.log(f"[intake] skipping {Path(it['path']).name}: an archive of files, not a disk (drop it on its own to analyse it)")
                    continue
                img = extract_image(it, self.log, self.work)
                inner = it.get("inner") or {}
                if inner.get("kind") == "vmdisk":
                    img = convert_vmdisk(img, inner.get("format", ""), self.log, self.work)
                images.append(img)
            elif k == "split":
                images.append(join_split(it, self.log, self.work))
            elif k == "vmdisk":
                images.append(convert_vmdisk(Path(it["path"]), it.get("format", ""), self.log, self.work))
            elif k in ("disk", "ewf"):
                images.append(Path(it["path"]))
            else:
                self.log(f"[intake] skipping {Path(it['path']).name}: {k} {it.get('format', '')}")
        return images

    def _ensure_unmounted(self, replace: bool, check_only: bool = False) -> None:
        st = mounted_now()
        if not st:
            return
        if not replace:
            raise SystemExit(f"[intake] something is still mounted at {st.get('TARGET')} ({st.get('IMAGE', '?')}); "
                             "unmount it first (Run tab -> Unmount) or tick 'replace what is mounted now'")
        if check_only:
            return
        self.log(f"[intake] unmounting the previous evidence ({st.get('IMAGE', st.get('TARGET'))})")
        umount_all(self.log)

    def _mount_root(self, images: list[Path]) -> Path:
        """Mount the image that holds the Linux root; with several images, try the likeliest first."""
        from .probe import probe
        order = sorted(images, key=lambda p: (not re.search(r"(0|a)(\.[^.]+)?$", p.stem), -p.stat().st_size))
        last_err = ""
        for img in order:
            rc, out = mount_image(img, self.log)
            if rc != 0:
                last_err = out[-600:]
                umount_all(lambda s: None)
                continue
            pr = probe(Path(DEFAULT_TARGET), self.cfg["paths"]["panel"].strip("/"), search=False)
            if pr.get("is_rootfs") or len(images) == 1:
                if not pr.get("is_rootfs"):
                    self.log("[intake] note: the mounted volume does not look like a Linux root file system")
                return img
            self.log(f"[intake] {img.name} is not the system disk (no /etc/passwd); trying the next image")
            umount_all(lambda s: None)
        raise SystemExit("[intake] no image could be mounted as the root file system" + (f": {last_err}" if last_err else ""))

    def _save(self, case: Case) -> None:
        (case.dir / "intake.json").write_text(json.dumps(self.record, indent=2, ensure_ascii=False, default=str), "utf-8")


def remount(case: Case, log: Log = print, replace_mount: bool = False) -> dict[str, Any]:
    """After a reboot: put the case's evidence back exactly as intake mounted it."""
    rec_path = case.dir / "intake.json"
    if not rec_path.exists():
        img = case.meta.get("image_path")
        if not img:
            raise SystemExit("this case has no intake record and no image path; mount it from the Run tab")
        rec = {"images": [img], "volumes": [], "mode": case.mode, "mount_root": str(case.mount_root)}
    else:
        rec = json.loads(rec_path.read_text("utf-8"))
    if rec.get("mode") == "export":
        log("[remount] export-mode case: nothing to mount")
        return rec
    if os.path.ismount(rec.get("mount_root") or DEFAULT_TARGET):
        st = mounted_now()
        if st.get("IMAGE") and rec.get("images") and os.path.realpath(st["IMAGE"]) == os.path.realpath(rec["images"][0]):
            log("[remount] already mounted")
            return rec
        if not replace_mount:
            raise SystemExit(f"something else is mounted at {rec.get('mount_root')} ({st.get('IMAGE', '?')}); unmount it first")
        umount_all(log)
    root_img = Path(rec["images"][0])
    if not root_img.exists():
        raise SystemExit(f"the image is not where it was: {root_img}")
    rc, _ = mount_image(root_img, log, target=rec.get("mount_root") or DEFAULT_TARGET)
    if rc != 0:
        raise SystemExit("mount failed")
    for v in rec.get("volumes", []):
        if v.get("mounted") and v.get("image"):
            mount_image(Path(v["image"]), log, part=v.get("part") or "", lv=v.get("lv") or "", at=v["mountpoint"])
    case.custody.append("remounted", {"images": rec.get("images"), "volumes": [v.get("mountpoint") for v in rec.get("volumes", []) if v.get("mounted")]})
    return rec
