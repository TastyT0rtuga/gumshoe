"""Windows paths as the examiner writes them -> where they are inside the distro (and back).

C:\\x\\y -> /mnt/c/x/y. A mapped drive (Z:) that WSL did not mount by itself is mounted on first use;
\\\\server\\share\\x (a UNC path, e.g. the case share) is mounted at /mnt/unc/server/share with the
examiner's Windows credentials (drvfs). Quotes pasted from Explorer's "Copy as path" and stray spaces
are dropped. No Streamlit here, so the CLI and the UI share it.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Optional

UNC_ROOT = Path("/mnt/unc")


def drvfs_mount(what: str, where: Path, readonly: bool = False) -> str:
    """Mount a drive letter ('Z:') or share ('\\\\server\\share') into the distro; '' on success, else the error."""
    if os.path.ismount(where):
        return ""
    try:
        where.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return str(e)
    cmd = ["mount", "-t", "drvfs", what, str(where)] + (["-o", "ro"] if readonly else [])
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return "" if r.returncode == 0 else (r.stderr or r.stdout or f"mount exit {r.returncode}").strip()


def to_wsl(p: str, readonly: bool = False) -> tuple[str, str]:
    """(path inside the distro, note). The note is non-empty when a drive or share could not be reached."""
    p = (p or "").strip().strip('"').strip("'").strip()
    note = ""
    m = re.match(r"^([A-Za-z]):[\\/]?(.*)$", p)
    if m:
        d = m.group(1).lower()
        root = Path(f"/mnt/{d}")
        if not os.path.ismount(root):          # not auto-mounted: a mapped network drive or a disk plugged in later
            err = drvfs_mount(f"{d.upper()}:", root, readonly)
            if err:
                note = f"drive {d.upper()}: is not visible inside the distro ({err})"
        rest = m.group(2).replace("\\", "/")
        return (str(root / rest) if rest else str(root)), note
    m = re.match(r"^(?:\\\\|//)([^\\/]+)[\\/]+([^\\/]+)[\\/]?(.*)$", p)
    if m:
        server, share, rest = m.group(1), m.group(2), m.group(3).replace("\\", "/")
        where = UNC_ROOT / server.lower() / share.lower()
        err = drvfs_mount(f"\\\\{server}\\{share}", where, readonly)
        if err:
            note = (f"the share \\\\{server}\\{share} could not be opened from inside the distro ({err}). "
                    f"Map it to a drive letter in Windows (net use Z: \\\\{server}\\{share}) and use Z:\\..., or copy the item into the hopper")
        return (str(where / rest) if rest else str(where)), note
    return p, note


def to_windows(p: str) -> str:
    """/mnt/c/x/y -> C:\\x\\y and /mnt/unc/server/share/x -> \\\\server\\share\\x, for display; other paths unchanged."""
    m = re.match(r"^/mnt/([a-z])(?:/(.*))?$", p)
    if m:
        return f"{m.group(1).upper()}:\\" + (m.group(2) or "").replace("/", "\\")
    m = re.match(r"^/mnt/unc/([^/]+)/([^/]+)(?:/(.*))?$", p)
    if m:
        return f"\\\\{m.group(1)}\\{m.group(2)}\\" + (m.group(3) or "").replace("/", "\\")
    return p


def windows_username() -> Optional[str]:
    """The Windows account running WSL (best effort: the newest profile under /mnt/c/Users)."""
    users = Path("/mnt/c/Users")
    try:
        cands = [d for d in users.iterdir() if d.is_dir() and d.name.lower() not in ("public", "default", "default user", "all users")
                 and not d.name.startswith((".", "$"))]
        cands.sort(key=lambda d: (d / "NTUSER.DAT").stat().st_mtime if (d / "NTUSER.DAT").exists() else 0, reverse=True)
        return cands[0].name if cands else None
    except OSError:
        return None
