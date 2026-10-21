"""What is on a mounted filesystem, before anything is run against it.

Answers the questions an examiner has right after `mount_image`: is this a Linux root filesystem
at all (or the wrong partition), which OS and hostname, where the control panel is (aaPanel / BT
Panel live at /www/server/panel by default, but the data directory is often elsewhere), whether
/www sits on another volume that is *not* part of this mount (the image's own /etc/fstab says so),
which other control panels are installed, and where the MariaDB data directory is.

Used by the mount step of the UI (shown right after a mount) and by the aaPanel normalizer (which
follows a relocated panel and explains an absent one). Read-only; bounded in time and in the number
of directories it looks at.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional

# where an aaPanel / BT Panel tree has been seen when it is not at the default place
PANEL_ROOTS = ["www/server/panel", "opt/www/server/panel", "data/www/server/panel", "home/www/server/panel",
               "srv/www/server/panel", "usr/local/www/server/panel", "root/www/server/panel", "mnt/www/server/panel",
               "mnt/data/www/server/panel", "data/server/panel"]
# other hosting control panels, by a directory that only they create
OTHER_PANELS = {
    "usr/local/cpanel": "cPanel/WHM", "usr/local/psa": "Plesk", "usr/local/CyberCP": "CyberPanel",
    "usr/local/hestia": "HestiaCP", "usr/local/vesta": "VestaCP", "usr/local/ispconfig": "ISPConfig",
    "usr/local/directadmin": "DirectAdmin", "etc/webmin": "Webmin/Virtualmin", "home/clp": "CloudPanel",
    "opt/1panel": "1Panel", "www/server/mdserver-web": "mdserver-web", "var/www/froxlor": "Froxlor",
    "usr/local/cwpsrv": "CentOS Web Panel", "usr/local/ajenti": "Ajenti", "opt/cyberpanel": "CyberPanel",
    "usr/local/lsws": "LiteSpeed/OpenLiteSpeed", "opt/plesk": "Plesk", "usr/local/sitepad": "SitePad",
}
MYSQL_DATADIRS = ["www/server/data", "var/lib/mysql", "var/lib/mariadb", "data/mysql", "opt/mysql/data", "usr/local/mysql/data"]
WEB_ROOTS = ["www/wwwroot", "var/www", "srv/www", "usr/share/nginx/html", "home/wwwroot", "data/wwwroot"]

# never descended during the bounded search (nothing of ours lives there, and they are huge)
_SKIP_TOP = {"proc", "sys", "dev", "run", "boot", "bin", "sbin", "lib", "lib32", "lib64", "libx32", "snap",
             "lost+found", "tmp", "efi"}
_SKIP_SUB = {"usr/lib", "usr/lib32", "usr/lib64", "usr/libexec", "usr/share", "usr/include", "usr/src", "usr/bin",
             "usr/sbin", "var/cache", "var/lib/apt", "var/lib/dpkg", "var/lib/yum", "var/lib/rpm", "var/lib/dnf",
             "var/log", "var/tmp", "var/spool", "etc", "var/lib/docker", "var/lib/containerd", "var/lib/snapd"}


def is_panel_dir(p: Path) -> bool:
    try:
        return (p / "data" / "default.db").is_file() or (p / "class" / "public.py").is_file() or (p / "BT-Panel").exists()
    except OSError:
        return False


def find_panel(root: Path, configured: str = "www/server/panel", max_dirs: int = 150_000,
               budget_s: float = 20.0) -> tuple[Optional[str], int]:
    """(relative path of the panel directory, or None; directories looked at).
    Known places first, then a bounded walk for a `server/panel` directory up to five levels deep."""
    root = Path(root)
    configured = configured.strip("/")
    for rel in [configured] + [r for r in PANEL_ROOTS if r != configured]:
        if is_panel_dir(root / rel):
            return rel, 0
    n = 0
    t0 = time.time()
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if not e.is_dir(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    rel = os.path.relpath(e.path, root)
                    if depth == 0 and e.name in _SKIP_TOP:
                        continue
                    if rel in _SKIP_SUB:
                        continue
                    n += 1
                    if e.name == "panel" and d.name == "server" and is_panel_dir(Path(e.path)):
                        return rel, n
                    if depth < 4:
                        stack.append((Path(e.path), depth + 1))
                    if n >= max_dirs or time.time() - t0 > budget_s:
                        return None, n
        except OSError:
            continue
    return None, n


def fstab_mounts(root: Path) -> list[dict[str, str]]:
    """Mount points the image's own /etc/fstab defines, other than / and the pseudo filesystems: tells
    whether /www, /home, /var/lib/mysql ... lived on another volume that is not part of this mount."""
    out: list[dict[str, str]] = []
    try:
        text = (Path(root) / "etc" / "fstab").read_text("utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        f = s.split()
        if len(f) < 3:
            continue
        dev, mp, fst = f[0], f[1], f[2]
        if mp in ("/", "none", "swap") or fst in ("swap", "proc", "sysfs", "tmpfs", "devpts", "devtmpfs", "efivarfs", "debugfs", "binfmt_misc") \
                or fst.startswith("cgroup") or mp.startswith(("/proc", "/sys", "/dev", "/run", "/boot")):
            continue
        out.append({"device": dev, "mountpoint": mp, "fstype": fst})
    return out


def _read_small(p: Path, limit: int = 4096) -> str:
    try:
        return p.read_text("utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def os_release(root: Path) -> str:
    txt = _read_small(Path(root) / "etc" / "os-release") or _read_small(Path(root) / "usr" / "lib" / "os-release")
    for line in txt.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    for alt in ("etc/redhat-release", "etc/centos-release", "etc/issue"):
        t = _read_small(Path(root) / alt).strip().splitlines()
        if t:
            return t[0].replace("\\n", "").replace("\\l", "").strip()
    return ""


def _nonempty_dir(p: Path) -> bool:
    try:
        return p.is_dir() and any(True for _ in p.iterdir())
    except OSError:
        return False


def probe(root: Path, configured_panel: str = "www/server/panel", search: bool = True) -> dict[str, Any]:
    """Everything the mount step and the aaPanel normalizer want to know, as one JSON-able dict."""
    root = Path(root)
    r: dict[str, Any] = {"root": str(root), "mounted": os.path.ismount(root), "entries": [], "is_rootfs": False,
                         "os": "", "hostname": "", "panel": None, "dirs_scanned": 0, "www_exists": False,
                         "www_empty": False, "fstab": [], "separate_volumes": [], "other_panels": [],
                         "mysql_datadirs": [], "web_roots": []}
    try:
        r["entries"] = sorted(p.name for p in root.iterdir())[:60]
    except OSError as e:
        r["error"] = str(e)
        return r
    r["has_passwd"] = (root / "etc" / "passwd").is_file()
    r["has_usr"] = (root / "usr").is_dir() or (root / "bin").exists()
    r["is_rootfs"] = r["has_passwd"] and r["has_usr"]
    r["os"] = os_release(root)
    r["hostname"] = _read_small(root / "etc" / "hostname").strip().splitlines()[0] if _read_small(root / "etc" / "hostname").strip() else ""
    if search:
        r["panel"], r["dirs_scanned"] = find_panel(root, configured_panel)
    else:
        rel = configured_panel.strip("/")
        r["panel"] = rel if is_panel_dir(root / rel) else None
    r["www_exists"] = (root / "www").is_dir()
    r["www_empty"] = r["www_exists"] and not _nonempty_dir(root / "www")
    r["fstab"] = fstab_mounts(root)
    interesting = ("/www", "/data", "/home", "/var", "/var/lib/mysql", "/srv", "/opt", "/mnt")
    r["separate_volumes"] = [m for m in r["fstab"] if m["mountpoint"].rstrip("/") in interesting or m["mountpoint"].startswith("/www")]
    r["other_panels"] = sorted({name for rel, name in OTHER_PANELS.items() if (root / rel).exists()})
    r["mysql_datadirs"] = [d for d in MYSQL_DATADIRS if _nonempty_dir(root / d)]
    r["web_roots"] = [d for d in WEB_ROOTS if _nonempty_dir(root / d)]
    return r


def explain(r: dict[str, Any], configured_panel: str = "www/server/panel") -> str:
    """One readable paragraph for the examiner (used in the UI and in the `aapanel.absent` finding)."""
    if r.get("error"):
        return f"could not read {r.get('root')}: {r['error']}"
    parts: list[str] = []
    if not r.get("mounted"):
        parts.append(f"{r.get('root')} is a plain directory, not a mounted image")
    if r.get("is_rootfs"):
        parts.append("Linux root filesystem" + (f": {r['os']}" if r.get("os") else "") + (f", hostname {r['hostname']}" if r.get("hostname") else ""))
    else:
        missing = " and ".join(x for x, ok in (("/etc/passwd", r.get("has_passwd")), ("/usr or /bin", r.get("has_usr"))) if not ok) or "the usual directories"
        parts.append(f"this does NOT look like a Linux root filesystem (no {missing}): the wrong partition or logical volume "
                     "may be mounted; check the partition list in the mount output and use Advanced --part N / --lv VG/LV")
    if r.get("panel"):
        parts.append(f"aaPanel/BT Panel found at /{r['panel']}" + ("" if r["panel"] == configured_panel.strip("/") else f" (not at the configured /{configured_panel.strip('/')}; followed)"))
    else:
        if r.get("www_empty"):
            parts.append("/www exists but is empty")
        elif not r.get("www_exists"):
            parts.append("there is no /www directory")
        else:
            parts.append("/www exists but holds no server/panel")
        www_vol = [m for m in r.get("separate_volumes", []) if m["mountpoint"].rstrip("/") in ("/www", "/data") or m["mountpoint"].startswith("/www")]
        if www_vol:
            m = www_vol[0]
            parts.append(f"the image's /etc/fstab mounts {m['mountpoint']} from {m['device']} ({m['fstype']}): the panel and the sites live on a "
                         f"separate volume that is not part of this mount. Mount that volume on top (Advanced --lv / --part of the same image, "
                         f"or the second disk image) at {r.get('root')}{m['mountpoint']}, then run Collect again")
        if r.get("other_panels"):
            parts.append("other control panel(s) present: " + ", ".join(r["other_panels"]))
        if r.get("dirs_scanned"):
            parts.append(f"no server/panel directory anywhere up to five levels deep ({r['dirs_scanned']} directories looked at)")
    if r.get("mysql_datadirs"):
        parts.append("MariaDB/MySQL data at " + ", ".join("/" + d for d in r["mysql_datadirs"]))
    if r.get("web_roots"):
        parts.append("web roots at " + ", ".join("/" + d for d in r["web_roots"]))
    return "; ".join(parts) + "."
