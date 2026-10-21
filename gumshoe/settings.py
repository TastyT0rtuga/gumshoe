"""Examiner settings that must survive updates: where the hopper is, where extracted images and trees
go, where exports are copied, who the examiner is.

Stored next to the cases directory (`/opt/dfir/gumshoe-settings.json` on the sandbox), which the
launcher never touches when it re-syncs the project. Folders are written the Windows way
(`D:\\DFIR\\hopper`) and resolved into the distro with winpath; the work folder may be left empty to
keep extracted images inside the distro's own disk (fastest, but that disk lives on C:).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .winpath import to_wsl

DEFAULTS: dict[str, str] = {
    "hopper": r"C:\DFIR\hopper",     # drop folder (Windows)
    "work": "",                      # extracted images/trees; '' = inside the distro (/opt/dfir)
    "exports": r"C:\DFIR\exports",   # findings exports are copied here (Windows)
    "examiner": "",
}
DISTRO_WORK = Path("/opt/dfir")


def settings_path(cases_root: Path) -> Path:
    return Path(cases_root).parent / "gumshoe-settings.json"


def load(cases_root: Path) -> dict[str, str]:
    d = dict(DEFAULTS)
    p = settings_path(cases_root)
    try:
        if p.exists():
            d.update({k: str(v) for k, v in (json.loads(p.read_text("utf-8")) or {}).items() if k in DEFAULTS})
    except Exception:  # noqa: BLE001 - a damaged settings file must not stop the UI
        pass
    return d


def save(cases_root: Path, values: dict[str, Any]) -> Path:
    d = load(cases_root)
    d.update({k: str(v).strip() for k, v in values.items() if k in DEFAULTS})
    p = settings_path(cases_root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d, indent=2), "utf-8")
    return p


def hopper_dir(cases_root: Path) -> tuple[Path, str]:
    """(hopper folder inside the distro, note if the drive is unreachable)."""
    w, note = to_wsl(load(cases_root)["hopper"])
    return Path(w), note


def work_dir(cases_root: Path) -> tuple[Path, str]:
    """Where extracted images (work/images) and trees (work/trees) go."""
    w = load(cases_root)["work"]
    if not w:
        return DISTRO_WORK, ""
    p, note = to_wsl(w)
    return Path(p), note


def exports_dir(cases_root: Path) -> str:
    return load(cases_root)["exports"]


def free_space(path: Path) -> tuple[float, float]:
    """(free GB, total GB) of the file system holding `path` (or its nearest existing parent); (0, 0) if unknown."""
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    try:
        u = shutil.disk_usage(p)
        return u.free / 2**30, u.total / 2**30
    except OSError:
        return 0.0, 0.0
