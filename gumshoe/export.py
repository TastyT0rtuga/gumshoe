"""Assemble evidence on request: the original files behind chosen findings, cited
answers or explicit paths, copied into a bundle that keeps their original tree,
with a manifest (path, SHA-256, size, timestamps, why included) and a hashed zip.

Every file goes through archive() first, so each one also has its sidecar in
evidence/ and a custody record; the bundle itself is logged with its hash.
"""
from __future__ import annotations

import csv
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any, Optional

from .archive import archive
from .integrity import hash_file, stat_times, utc_now


ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".gz")


def _safe_members(names: list[str]) -> list[str]:
    return [n for n in names if n and not n.startswith(("/", "\\")) and ".." not in Path(n).parts]


def unpack(case, rel: str, dest: Path, max_bytes: int = 2 * 2**30) -> dict[str, Any]:
    """Unpack a zip/tar(.gz/.bz2/.xz)/.gz from the image into dest/, refusing absolute or
    parent-traversing members, with a per-member manifest."""
    import gzip
    import tarfile
    src = case.abs(rel)
    dest.mkdir(parents=True, exist_ok=True)
    members: list[dict[str, Any]] = []
    total = 0
    low = rel.lower()
    try:
        if low.endswith(".zip"):
            with zipfile.ZipFile(src) as z:
                for n in _safe_members(z.namelist()):
                    info = z.getinfo(n)
                    total += info.file_size
                    if total > max_bytes:
                        return {"error": "unpack size cap exceeded", "members": members}
                    z.extract(n, dest)
                    p = dest / n
                    if p.is_file():
                        members.append({"member": n, "size": info.file_size, "sha256": hash_file(p)})
        elif low.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
            with tarfile.open(src) as t:
                for m in t.getmembers():
                    if not m.isfile() or m.name not in _safe_members([m.name]):
                        continue
                    total += m.size
                    if total > max_bytes:
                        return {"error": "unpack size cap exceeded", "members": members}
                    t.extract(m, dest, filter="data") if hasattr(tarfile, "data_filter") else t.extract(m, dest)
                    p = dest / m.name
                    members.append({"member": m.name, "size": m.size, "sha256": hash_file(p)})
        elif low.endswith(".gz"):
            out = dest / Path(rel).name[:-3]
            with gzip.open(src, "rb") as r, open(out, "wb") as w:
                shutil.copyfileobj(r, w)
            members.append({"member": out.name, "size": out.stat().st_size, "sha256": hash_file(out)})
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError) as e:
        return {"error": f"{type(e).__name__}: {e}", "members": members}
    (dest / "unpacked-manifest.json").write_text(json.dumps({"source": rel, "members": members}, indent=2), "utf-8")
    return {"members": members}


def assemble(case, name: str, paths: Optional[list[str]] = None, finding_ids: Optional[list[str]] = None,
             question_index: Optional[list[int]] = None, include_extracted: bool = True, unpack_archives: bool = False,
             max_dir_files: int = 100000, log=print) -> dict[str, Any]:
    wanted: dict[str, list[str]] = {}

    def add(path: Optional[str], why: str):
        if path and not path.startswith(("finding://", "summary://", "players://")):
            wanted.setdefault(path, []).append(why)

    for p in paths or []:
        ap = case.abs(p)
        if ap.is_dir():  # a whole directory (a site root, a home directory): every file under it
            n = 0
            for f in sorted(x for x in ap.rglob("*") if x.is_file()):
                add(case.rel(f), f"under requested directory {p}")
                n += 1
                if n >= max_dir_files:
                    log(f"[export] directory {p} capped at {max_dir_files} files")
                    break
        else:
            add(p, "requested path")
    if finding_ids:
        ids = set(finding_ids)
        for d in case.read_findings():
            if d["id"] in ids:
                add(d.get("path"), f"finding {d['id']}: {d['title'][:70]}")
                for rid in d.get("related") or []:
                    pass
    if question_index:
        qlog = case.reports / "questions.jsonl"
        if qlog.exists():
            lines = qlog.read_text("utf-8").splitlines()
            for qi in question_index:
                if 1 <= qi <= len(lines):
                    q = json.loads(lines[qi - 1])
                    valid = q.get("valid_citations") or []
                    for s in q.get("sources", []):
                        if s["n"] in valid:
                            add(s["relpath"], f"cited [{s['n']}] for question {qi}: {q['question'][:60]}")
                        elif not valid:  # sources-only answer (no model): export what was retrieved
                            add(s["relpath"], f"retrieved [{s['n']}] for question {qi} (no model citations): {q['question'][:60]}")
    if not wanted:
        return {"error": "nothing to export"}
    out = case.reports / "exports" / name
    if out.exists():
        shutil.rmtree(out)
    (out / "files").mkdir(parents=True)
    manifest = []
    missing = []
    for rel, reasons in sorted(wanted.items()):
        src = case.abs(rel)
        if not src.is_file():
            missing.append(rel)
            continue
        sc = archive(case, rel, "exported: " + name, None)
        dest = out / "files" / rel.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        st = stat_times(src)
        sha = sc["sha256_source"] if sc else hash_file(src)
        manifest.append({"path": rel, "sha256": sha, "sha256_copy": hash_file(dest), "size": st["size"], "mtime": st["mtime"],
                         "ctime": st["ctime"], "crtime": st.get("crtime"), "reasons": reasons})
        if include_extracted:
            ext_dir = case.collected / "extracted"
            txt = ext_dir / f"{sha}.txt"
            if txt.exists():
                (out / "extracted").mkdir(exist_ok=True)
                shutil.copy2(txt, out / "extracted" / (Path(rel).name + ".txt"))
        if unpack_archives and rel.lower().endswith(ARCHIVE_EXTS):
            r = unpack(case, rel, out / "unpacked" / rel.strip("/").replace("/", "__"))
            manifest[-1]["unpacked"] = {"members": len(r.get("members", [])), "error": r.get("error")}
    (out / "manifest.json").write_text(json.dumps({"case": case.meta.get("case_id"), "examiner": case.meta.get("examiner"),
                                                   "created": utc_now(), "name": name, "files": manifest, "missing": missing},
                                                  indent=2, ensure_ascii=False), "utf-8")
    with open(out / "manifest.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["path", "sha256", "size", "mtime", "ctime", "crtime", "reasons"])
        for m in manifest:
            w.writerow([m["path"], m["sha256"], m["size"], m["mtime"], m["ctime"], m["crtime"], "; ".join(m["reasons"])])
    (out / "README.txt").write_text(
        f"Evidence export '{name}' from case {case.meta.get('case_id')} by {case.meta.get('examiner')} at {utc_now()}\n"
        f"files/      originals copied from the read-only image, in their original directory layout\n"
        f"extracted/  text extracted from documents (what the search index and the model saw), when available\n"
        f"unpacked/   contents of archives in the set, when --unpack was used (each with unpacked-manifest.json)\n"
        f"manifest.json / manifest.csv   path, SHA-256 of the original and of this copy, timestamps, why each file is here\n"
        f"The image remains the primary evidence; verify any copy against the SHA-256 in the manifest.\n", "utf-8")
    zpath = out.with_suffix(".zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for p in out.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(out.parent))
    zsha = hash_file(zpath)
    zpath.with_suffix(".zip.sha256").write_text(f"{zsha}  {zpath.name}\n", "utf-8")
    case.custody.append("evidence_exported", {"name": name, "files": len(manifest), "missing": missing, "zip": str(zpath.relative_to(case.dir)),
                                              "zip_sha256": zsha})
    log(f"[export] {len(manifest)} file(s) -> {zpath} (sha256 {zsha[:16]}...)")
    return {"dir": str(out), "zip": str(zpath), "zip_sha256": zsha, "files": len(manifest), "missing": missing}
