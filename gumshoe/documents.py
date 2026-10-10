"""Document discovery, text extraction and viewing support.

The model can only cite what is indexed, and an examiner must be able to open
anything it cites. This module:

  * inventories document-type files on the image (spreadsheets, Word/ODF files,
    PDFs, CSV, Markdown, JSON/XML, SQL dumps, presentations) from timeline.db when
    present, else by walking the configured roots -> collected/documents.json
  * extracts their text with location markers (sheet/row, paragraph, page) into
    collected/extracted/<sha256>.txt, so the index can cite a cell, a paragraph
    or a page of the ORIGINAL file by path, and what the model saw is preserved
  * provides `preview()` used by the UI and `open_bytes()` for download, both of
    which archive the file (hash + sidecar + custody record) first

Extraction is stdlib-first (zip/XML for xlsx/docx/odt/ods/pptx, csv module) with
optional helpers when present: openpyxl (xlsx), pdftotext/pypdf (pdf),
catdoc/antiword/xls2csv (legacy .doc/.xls).
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
import sqlite3
import subprocess
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Optional
from xml.etree import ElementTree as ET

from .integrity import hash_file, stat_times, utc_now
from .normalize.base import Finding, iter_files
from .textenc import read_text_auto

DOC_EXTS = {
    ".xlsx": "spreadsheet", ".xlsm": "spreadsheet", ".xls": "spreadsheet", ".ods": "spreadsheet", ".csv": "table", ".tsv": "table",
    ".docx": "document", ".doc": "document", ".odt": "document", ".rtf": "document", ".pdf": "pdf",
    ".pptx": "presentation", ".odp": "presentation",
    ".md": "text", ".txt": "text", ".json": "data", ".xml": "data", ".yaml": "data", ".yml": "data", ".sql": "sql",
    ".eml": "email", ".mbox": "email",
}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
XML_NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
          "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
          "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
          "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
          "d": "http://schemas.openxmlformats.org/drawingml/2006/main",
          "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
          "table": "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
          "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0"}


# ---- inventory ------------------------------------------------------------------------------
def _doc_roots(case) -> list[str]:
    d = case.cfg.get("documents", {}) or {}
    return d.get("roots") or (case.cfg["paths"]["web_roots"] + ["root", "home", "www/backup", "tmp", "var/tmp", "dev/shm", "opt", "srv", "mnt", "media", "var/backups"])


def inventory(case, log=print) -> list[dict[str, Any]]:
    d = case.cfg.get("documents", {}) or {}
    max_files = int(d.get("max_files", 200000))
    hash_cap = int(d.get("max_hash_bytes", 512 * 2**20))
    exts = tuple(DOC_EXTS) + tuple(IMAGE_EXTS)
    items: list[dict[str, Any]] = []
    tl = case.collected / "timeline.db"
    paths: list[str] = []
    if tl.exists():
        con = sqlite3.connect(tl)
        clauses, params = [], []
        for r in _doc_roots(case):
            clauses.append("path LIKE ?")
            params.append("/" + r.strip("/") + "/%")
        for (p,) in con.execute(f"SELECT path FROM files WHERE ({' OR '.join(clauses)})", params):
            if p.lower().endswith(exts):
                paths.append(p)
                if len(paths) >= max_files:
                    break
        con.close()
    else:
        for r in _doc_roots(case):
            root = case.abs(r)
            if not root.exists():
                continue
            for p in iter_files(root):
                if p.suffix.lower() in DOC_EXTS or p.suffix.lower() in IMAGE_EXTS:
                    paths.append(case.rel(p))
                    if len(paths) >= max_files:
                        break
            if len(paths) >= max_files:
                break
    for rel in paths:
        p = case.abs(rel)
        try:
            if not p.is_file():
                continue
            st = stat_times(p)
            ext = p.suffix.lower()
            items.append({"path": rel, "ext": ext, "kind": DOC_EXTS.get(ext, "image" if ext in IMAGE_EXTS else "other"),
                          "size": st["size"], "mtime": st["mtime"], "ctime": st["ctime"], "crtime": st.get("crtime"),
                          "sha256": hash_file(p) if st["size"] <= hash_cap else None, "extracted": None})
        except OSError:
            continue
    items.sort(key=lambda x: (x["kind"], x["path"]))
    return items


# ---- extractors (return text with location markers) ------------------------------------------
def _xlsx_stdlib(p: Path) -> str:
    out = []
    with zipfile.ZipFile(p) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall("a:si", XML_NS):
                shared.append("".join(t.text or "" for t in si.iter(f"{{{XML_NS['a']}}}t")))
        names = {}
        if "xl/workbook.xml" in z.namelist():
            wb = ET.fromstring(z.read("xl/workbook.xml"))
            for i, s in enumerate(wb.findall(".//a:sheet", XML_NS), 1):
                names[i] = s.get("name", f"sheet{i}")
        sheets = sorted(n for n in z.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", n))
        for n in sheets:
            idx = int(re.search(r"sheet(\d+)", n).group(1))
            out.append(f"### sheet: {names.get(idx, n)}")
            root = ET.fromstring(z.read(n))
            for row in root.iter(f"{{{XML_NS['a']}}}row"):
                cells = []
                for c in row.findall("a:c", XML_NS):
                    v = c.find("a:v", XML_NS)
                    t = c.get("t")
                    if t == "s" and v is not None and v.text and v.text.isdigit() and int(v.text) < len(shared):
                        cells.append(shared[int(v.text)])
                    elif t == "inlineStr":
                        cells.append("".join(x.text or "" for x in c.iter(f"{{{XML_NS['a']}}}t")))
                    else:
                        cells.append(v.text if v is not None and v.text else "")
                if any(cells):
                    out.append(f"row {row.get('r')}: " + " | ".join(cells))
    return "\n".join(out)


def _xlsx(p: Path) -> str:
    try:
        import openpyxl  # type: ignore
        wb = openpyxl.load_workbook(p, read_only=True, data_only=True)
        out = []
        for ws in wb.worksheets:
            out.append(f"### sheet: {ws.title}")
            for i, row in enumerate(ws.iter_rows(values_only=True), 1):
                if any(v is not None and str(v) != "" for v in row):
                    out.append(f"row {i}: " + " | ".join("" if v is None else str(v) for v in row))
        wb.close()
        return "\n".join(out)
    except ImportError:
        return _xlsx_stdlib(p)


def _docx(p: Path) -> str:
    with zipfile.ZipFile(p) as z:
        root = ET.fromstring(z.read("word/document.xml"))
    out, n = [], 0
    for para in root.iter(f"{{{XML_NS['w']}}}p"):
        text = "".join(t.text or "" for t in para.iter(f"{{{XML_NS['w']}}}t"))
        if text.strip():
            n += 1
            out.append(f"¶{n}: {text}")
    return "\n".join(out)


def _pptx(p: Path) -> str:
    out = []
    with zipfile.ZipFile(p) as z:
        slides = sorted((n for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                        key=lambda s: int(re.search(r"slide(\d+)", s).group(1)))
        for n in slides:
            slide_no = re.search(r"slide(\d+)", n).group(1)
            out.append(f"### slide {slide_no}")
            root = ET.fromstring(z.read(n))
            for t in root.iter(f"{{{XML_NS['d']}}}t"):
                if t.text and t.text.strip():
                    out.append(t.text)
    return "\n".join(out)


def _odf(p: Path) -> str:
    with zipfile.ZipFile(p) as z:
        root = ET.fromstring(z.read("content.xml"))
    out = []
    in_tables = set()
    for tbl in root.iter(f"{{{XML_NS['table']}}}table"):
        name_attr = "{" + XML_NS["table"] + "}name"
        out.append(f"### sheet: {tbl.get(name_attr, 'table')}")
        for i, row in enumerate(tbl.iter(f"{{{XML_NS['table']}}}table-row"), 1):
            cells = []
            for c in row.iter(f"{{{XML_NS['table']}}}table-cell"):
                paras = list(c.iter(f"{{{XML_NS['text']}}}p"))
                in_tables.update(id(x) for x in paras)
                cells.append(" ".join("".join(x.itertext()) for x in paras))
            if any(cells):
                out.append(f"row {i}: " + " | ".join(cells))
    n = 0
    for para in root.iter(f"{{{XML_NS['text']}}}p"):
        if id(para) in in_tables:
            continue
        text = "".join(para.itertext())
        if text.strip():
            n += 1
            out.append(f"¶{n}: {text}")
    return "\n".join(out)


def _pdf(p: Path) -> str:
    if shutil.which("pdftotext"):
        r = subprocess.run(["pdftotext", "-layout", "-enc", "UTF-8", str(p), "-"], capture_output=True, timeout=600)
        if r.returncode == 0:
            pages = r.stdout.decode("utf-8", "replace").split("\f")
            return "\n".join(f"### page {i}\n{pg.rstrip()}" for i, pg in enumerate(pages, 1) if pg.strip())
    try:
        from pypdf import PdfReader  # type: ignore
        reader = PdfReader(str(p))
        return "\n".join(f"### page {i}\n{(pg.extract_text() or '').rstrip()}" for i, pg in enumerate(reader.pages, 1))
    except ImportError:
        return ""


def _legacy(p: Path) -> str:
    """Legacy .doc / .xls via catdoc tools when present; else printable strings."""
    tool = {".doc": ["catdoc", "-w"], ".xls": ["xls2csv"]}.get(p.suffix.lower())
    if tool and shutil.which(tool[0]):
        r = subprocess.run(tool + [str(p)], capture_output=True, timeout=300)
        if r.returncode == 0:
            return r.stdout.decode("utf-8", "replace")
    if shutil.which("antiword") and p.suffix.lower() == ".doc":
        r = subprocess.run(["antiword", str(p)], capture_output=True, timeout=300)
        if r.returncode == 0:
            return r.stdout.decode("utf-8", "replace")
    data = p.read_bytes()[:20 * 2**20]
    return "\n".join(m.decode("latin-1") for m in re.findall(rb"[\x20-\x7e]{6,}", data))


def _csv(p: Path) -> str:
    text, enc = read_text_auto(p)
    dialect = "excel-tab" if p.suffix.lower() == ".tsv" else "excel"
    out = [f"### table ({enc})"]
    for i, row in enumerate(csv.reader(io.StringIO(text), dialect=dialect), 1):
        if any(c.strip() for c in row):
            out.append(f"row {i}: " + " | ".join(row))
    return "\n".join(out)


def _rtf(p: Path) -> str:
    text, _ = read_text_auto(p)
    text = re.sub(r"\\par[d]?", "\n", text)
    text = re.sub(r"\\'[0-9a-f]{2}", "", text)
    text = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", text)
    return re.sub(r"[{}]", "", text)


def _plain(p: Path) -> str:
    text, _ = read_text_auto(p)
    return text


EXTRACTORS: dict[str, Callable[[Path], str]] = {
    ".xlsx": _xlsx, ".xlsm": _xlsx, ".docx": _docx, ".pptx": _pptx, ".odt": _odf, ".ods": _odf, ".odp": _odf,
    ".pdf": _pdf, ".doc": _legacy, ".xls": _legacy, ".csv": _csv, ".tsv": _csv, ".rtf": _rtf,
    ".md": _plain, ".txt": _plain, ".json": _plain, ".xml": _plain, ".yaml": _plain, ".yml": _plain, ".sql": _plain,
    ".eml": _plain, ".mbox": _plain,
}


def extract_text(case, relpath: str, max_bytes: Optional[int] = None) -> dict[str, Any]:
    """Extract to collected/extracted/<sha256>.txt (cached). Returns {text_file, method, chars, sha256}."""
    p = case.abs(relpath)
    ext = p.suffix.lower()
    fn = EXTRACTORS.get(ext)
    if not fn or not p.is_file():
        return {"error": "no extractor for this type" if not fn else "not a file"}
    size = p.stat().st_size
    if max_bytes and size > max_bytes:
        return {"error": f"over size cap ({size} bytes)"}
    sha = hash_file(p)
    out_dir = case.collected / "extracted"
    out_dir.mkdir(parents=True, exist_ok=True)
    txt = out_dir / f"{sha}.txt"
    if not txt.exists():
        try:
            text = fn(p)
        except Exception as e:  # a corrupt file must not stop the run
            return {"error": f"{type(e).__name__}: {str(e)[:200]}"}
        header = f"# extracted from {relpath}\n# sha256 {sha} size {size} method {fn.__name__.lstrip('_')} at {utc_now()}\n"
        txt.write_text(header + text, "utf-8")
    return {"text_file": str(txt.relative_to(case.dir)), "method": fn.__name__.lstrip("_"), "sha256": sha,
            "chars": txt.stat().st_size}


def run(case, log=print) -> list[Finding]:
    d = case.cfg.get("documents", {}) or {}
    max_extract_files = int(d.get("max_extract_files", 5000))
    max_extract_bytes = int(d.get("max_extract_bytes", 25 * 2**20))
    items = inventory(case, log=log)
    n_ext, errors = 0, Counter()
    for it in items:
        if it["kind"] in ("image", "other"):
            continue
        if n_ext >= max_extract_files:
            it["extracted"] = {"error": "max_extract_files reached"}
            continue
        r = extract_text(case, it["path"], max_bytes=max_extract_bytes)
        it["extracted"] = r
        if "error" in r:
            errors[r["error"][:40]] += 1
        else:
            n_ext += 1
    case.write_json("documents.json", {"generated": utc_now(), "count": len(items), "extracted": n_ext,
                                       "by_kind": dict(Counter(i["kind"] for i in items)), "errors": dict(errors), "items": items})
    case.custody.append("documents_inventoried", {"count": len(items), "extracted": n_ext, "errors": dict(errors)})
    by_kind = Counter(i["kind"] for i in items)
    f = Finding(source="documents", severity="info", rule="documents.inventory",
                title=f"{len(items)} document/image files inventoried ({', '.join(f'{k} {v}' for k, v in by_kind.most_common())}); "
                      f"{n_ext} extracted to text and indexed",
                description="Spreadsheets, Word/ODF files, PDFs, CSV, Markdown, JSON/XML, SQL dumps and presentations found under the "
                            "document roots. Their text is indexed with sheet/row, paragraph or page markers so answers can cite them; "
                            "open any of them in the UI's Documents tab or with `gumshoe view --path ...`.",
                tags=["documents", "inventory"])
    return [f]


# ---- viewing -------------------------------------------------------------------------------
def open_bytes(case, relpath: str, reason: str = "viewed") -> Optional[bytes]:
    """Return the original file's bytes for download/preview; archives it first (hash, sidecar, custody)."""
    from .archive import archive
    p = case.abs(relpath)
    if not p.is_file():
        return None
    archive(case, relpath, reason, None)
    return p.read_bytes()


def preview(case, relpath: str, max_chars: int = 200000) -> dict[str, Any]:
    """A viewer-neutral preview: {'kind': 'table'|'text'|'markdown'|'image'|'binary', ...}. Archives the file."""
    p = case.abs(relpath)
    if not p.is_file():
        return {"kind": "missing"}
    from .archive import archive
    archive(case, relpath, "previewed", None)
    ext = p.suffix.lower()
    if ext in IMAGE_EXTS:
        return {"kind": "image", "bytes": p.read_bytes(), "ext": ext}
    if ext in (".csv", ".tsv"):
        text, enc = read_text_auto(p, limit_bytes=5 * 2**20)
        rows = list(csv.reader(io.StringIO(text), dialect="excel-tab" if ext == ".tsv" else "excel"))[:5000]
        return {"kind": "table", "sheets": {"csv": rows}, "encoding": enc}
    if ext in (".xlsx", ".xlsm"):
        try:
            import openpyxl  # type: ignore
            wb = openpyxl.load_workbook(p, read_only=True, data_only=True)
            sheets = {}
            for ws in wb.worksheets:
                sheets[ws.title] = [["" if v is None else v for v in row] for _, row in zip(range(5000), ws.iter_rows(values_only=True))]
            wb.close()
            return {"kind": "table", "sheets": sheets}
        except ImportError:
            pass
    r = extract_text(case, relpath)
    if "text_file" in r:
        text = (case.dir / r["text_file"]).read_text("utf-8")[:max_chars]
        return {"kind": "markdown" if ext == ".md" else "text", "text": text, "method": r["method"]}
    return {"kind": "binary", "size": p.stat().st_size, "note": r.get("error", "no preview")}
