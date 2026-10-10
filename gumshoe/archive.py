"""Archive-on-cite: copy an artifact from the evidence mount into the case's
evidence/ folder with a sidecar that records where it came from, its inode
times, and its SHA-256 before and after the copy. Idempotent per SHA-256.

evidence/
  <sha256>/<basename>            the copy (copy2 keeps mtime; ctime is the copy's own)
  <sha256>/<basename>.excerpt    when the file exceeds archive.max_file_bytes: the cited line range only
  <sha256>.json                  sidecar: original path, stat times, hashes, reasons[] (each cite/finding)
  manifest.json                  every archived item
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Optional

from .integrity import hash_file, stat_times, utc_now
from .normalize.base import open_text


def _manifest(case) -> dict[str, Any]:
    p = case.evidence / "manifest.json"
    return json.loads(p.read_text("utf-8")) if p.exists() else {"items": {}}


def _save_manifest(case, m: dict[str, Any]) -> None:
    (case.evidence / "manifest.json").write_text(json.dumps(m, indent=2, ensure_ascii=False), "utf-8")


def archive(case, relpath: str, reason: str, ref_id: Optional[str] = None, line_start: Optional[int] = None,
            line_end: Optional[int] = None) -> Optional[dict[str, Any]]:
    """Returns the sidecar dict, or None if the path is not a file on the mount."""
    if not relpath or relpath.startswith(("finding://", "summary://")):
        return None
    src = case.abs(relpath)
    if not src.exists() or not src.is_file():
        return None
    st = stat_times(src)
    sha_before = hash_file(src)
    maxb = int(case.cfg["archive"]["max_file_bytes"])
    ctx = int(case.cfg["archive"].get("excerpt_context_lines", 50))
    folder = case.evidence / sha_before
    folder.mkdir(parents=True, exist_ok=True)
    sidecar_path = case.evidence / f"{sha_before}.json"
    sidecar: dict[str, Any] = json.loads(sidecar_path.read_text("utf-8")) if sidecar_path.exists() else {
        "original_path": relpath, "stat": st, "sha256_source": sha_before, "archived_at": utc_now(), "reasons": [],
        "copies": [],
    }
    reason_rec = {"reason": reason, "ref": ref_id, "at": utc_now(), "line_start": line_start, "line_end": line_end}
    sidecar["reasons"].append(reason_rec)
    dest = folder / src.name
    if st["size"] <= maxb:
        if not dest.exists():
            shutil.copy2(src, dest)
            sha_after = hash_file(dest)
            sidecar["copies"].append({"file": str(dest.relative_to(case.evidence)), "sha256_copy": sha_after,
                                      "verified": sha_after == sha_before, "kind": "full"})
    else:
        # excerpt only: the cited line range with context, plus the full-file hash already recorded
        ls = max(1, (line_start or 1) - ctx)
        le = (line_end or line_start or 1) + ctx
        ex = folder / (src.name + f".lines{ls}-{le}.excerpt")
        if not ex.exists():
            with open_text(src) as f, open(ex, "w", encoding="utf-8") as w:
                for i, line in enumerate(f, 1):
                    if i < ls:
                        continue
                    if i > le:
                        break
                    w.write(f"{i}: {line}")
            sidecar["copies"].append({"file": str(ex.relative_to(case.evidence)), "sha256_copy": hash_file(ex),
                                      "verified": None, "kind": "excerpt", "line_start": ls, "line_end": le,
                                      "note": f"source exceeds {maxb} bytes; full file remains in the image, hash recorded"})
    sidecar_path.write_text(json.dumps(sidecar, indent=2, ensure_ascii=False, default=str), "utf-8")
    m = _manifest(case)
    m["items"][sha_before] = {"original_path": relpath, "size": st["size"], "mtime": st["mtime"], "ctime": st["ctime"],
                              "copies": sidecar["copies"], "reasons": len(sidecar["reasons"]), "last_reason": reason}
    _save_manifest(case, m)
    case.custody.append("artifact_archived", {"path": relpath, "sha256": sha_before, "reason": reason, "ref": ref_id,
                                              "copies": sidecar["copies"]})
    return sidecar


def archive_findings(case, min_severity: str = "high", log=print) -> int:
    from .normalize.base import sev_rank
    n = 0
    for d in case.read_findings():
        if d.get("path") and sev_rank(d.get("severity", "info")) >= sev_rank(min_severity):
            if archive(case, d["path"], f"finding {d['id']}: {d['title'][:80]}", d["id"], d.get("line"), d.get("line")):
                n += 1
    log(f"[archive] archived {n} artifact(s) for findings >= {min_severity}")
    return n


def verify_archive(case) -> dict[str, Any]:
    m = _manifest(case)
    bad = []
    for sha, item in m["items"].items():
        for c in item["copies"]:
            p = case.evidence / c["file"]
            if not p.exists():
                bad.append({"sha256": sha, "file": c["file"], "problem": "missing"})
            elif c["kind"] == "full" and hash_file(p) != sha:
                bad.append({"sha256": sha, "file": c["file"], "problem": "hash changed"})
    res = {"items": len(m["items"]), "problems": bad, "ok": not bad}
    case.custody.append("archive_verified", res)
    return res
