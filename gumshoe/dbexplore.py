"""Explore the extracted databases without SQL, Docker or a database server: a catalog of every table across every
export, cross-table search (grep over the CSVs, then exact per-row matching), a paged table viewer with per-column
filters, exports of search results and table selections into named folders (with custody records), and an optional
SQLite *workbench* - selected tables loaded into one file so sorting, filtering and read-only SQL run instantly for
whoever wants SQL.

Everything here reads the CSV exports that `gumshoe db extract` wrote; nothing touches the evidence.

    catalog(case)                         every table: export, database, table, rows, columns, files, bytes
    search_counts(case, query, mode, keys) per-table hit counts (grep, fast, C speed)
    search_rows(entry, query, mode, ...)   the matching records of one table, exact (csv-parsed), with locators
    export_search(case, query, mode, keys) every matching record of every table -> <exports>/<case>/db-search/<stamp>/
    export_tables(case, keys)              copies of whole tables -> <exports>/<case>/db-selection/<stamp>/
    page(entry, offset, limit, filters)    a page of a table with per-column "contains" filters
    load_tables(case, keys, log)           the SQLite workbench (background: `gumshoe db load`)
    sql(case, statement, limit)            read-only SQL over the workbench

Query modes: "phrase" (the text as typed), "all" (every word, in any cell of the row), "any" (one of the words),
"regex". Matching is case-insensitive and script-agnostic (Cyrillic, CJK ...).
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from .dbexport import export_root, list_exports, slug
from .integrity import utc_now

Log = Callable[[str], None]
MODES = ("phrase", "all", "any", "regex")
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


# --------------------------------------------------------------------------- catalog
def _header(path: Path) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            return next(csv.reader(f), [])
    except OSError:
        return []


def catalog(case) -> list[dict[str, Any]]:
    """Every exported table across every export of the case, with its columns (from the CSV header) and files."""
    out: list[dict[str, Any]] = []
    for e in list_exports(case):
        root = Path(e.get("out") or "")
        tcsv = Path(e["dir"]) / "tables.csv"
        if not tcsv.exists() or not root.is_dir():
            continue
        with open(tcsv, "r", encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                files = [root / slug(r["database"]) / fn.strip() for fn in (r.get("files") or "").split(";") if fn.strip()]
                files = [p for p in files if p.exists()]
                if not files:
                    continue
                out.append({"key": f"{e['name']}/{r['database']}/{r['table']}", "export": e["name"], "database": r["database"], "table": r["table"],
                            "rows": int(r.get("rows") or 0), "columns": _header(files[0]), "files": [str(p) for p in files],
                            "bytes": sum(p.stat().st_size for p in files), "blobs": int(r.get("blobs") or 0), "rejected": int(r.get("rejected") or 0),
                            "error": r.get("error") or "", "kind": e.get("kind", "")})
    return out


def entry(case, key: str) -> Optional[dict[str, Any]]:
    for t in catalog(case):
        if t["key"] == key:
            return t
    return None


# --------------------------------------------------------------------------- matching
def _words(query: str) -> list[str]:
    return [w for w in re.split(r"\s+", query.strip()) if w]


class BadQuery(ValueError):
    """A query that cannot be run (an invalid regex): the message is for the examiner."""


def matcher(query: str, mode: str) -> Callable[[list[str]], bool]:
    """A predicate over a CSV record (list of cells) for one query and mode."""
    q = query.strip()
    if mode == "regex":
        try:
            rx = re.compile(q, re.I | re.S)
        except re.error as e:
            raise BadQuery(f"not a valid regex: {e} (in {q!r})") from e
        return lambda cells: any(rx.search(c) for c in cells)
    if mode == "all":
        ws = [w.lower() for w in _words(q)]
        return lambda cells: all(any(w in c.lower() for c in cells) for w in ws)
    if mode == "any":
        ws = [w.lower() for w in _words(q)]
        return lambda cells: any(any(w in c.lower() for c in cells) for w in ws)
    ql = q.lower()
    return lambda cells: any(ql in c.lower() for c in cells)


def _grep_cmd(query: str, mode: str, files: list[str]) -> list[str]:
    """grep that counts lines; a line is a candidate record (phrase / any: exact; all: lines holding the first word; regex:
    the pattern). Exact per-record matching happens afterwards in Python on the candidate tables only."""
    base = ["grep", "-c", "-i", "-I"]
    if mode == "regex":
        return base + ["-E", "-e", query, "--"] + files
    if mode == "all":
        ws = _words(query)
        return base + ["-F", "-e", ws[0] if ws else query, "--"] + files
    if mode == "any":
        cmd = base + ["-F"]
        for w in _words(query) or [query]:
            cmd += ["-e", w]
        return cmd + ["--"] + files
    return base + ["-F", "-e", query, "--"] + files


def search_counts(case, query: str, mode: str = "phrase", keys: Optional[set[str]] = None, cat: Optional[list[dict[str, Any]]] = None) -> list[dict[str, Any]]:
    """[{key, export, database, table, candidate_lines}] for every table with at least one candidate line, most first.
    Counts are candidate *lines* from grep (a record with a cell holding newlines spans several); the exact row counts come
    with search_rows / export_search."""
    if not query.strip() or mode not in MODES:
        return []
    matcher(query, mode)               # a bad regex is refused here, with its message, before any grep runs
    tables = [t for t in (cat or catalog(case)) if not keys or t["key"] in keys]
    out = []
    for t in tables:
        files = t["files"]
        if not files:
            continue
        try:
            r = subprocess.run(_grep_cmd(query, mode, files), capture_output=True, text=True, errors="replace", timeout=3600)
        except (subprocess.TimeoutExpired, OSError):
            continue
        if r.returncode not in (0, 1):
            continue
        n = 0
        for line in r.stdout.splitlines():
            try:
                n += int(line.rsplit(":", 1)[-1]) if len(files) > 1 else int(line.strip())
            except ValueError:
                pass
        if n:
            out.append({"key": t["key"], "export": t["export"], "database": t["database"], "table": t["table"], "candidate_lines": n, "rows": t["rows"], "columns": t["columns"]})
    out.sort(key=lambda d: -d["candidate_lines"])
    return out


def iter_records(entry: dict[str, Any]) -> Iterator[tuple[str, int, list[str]]]:
    """(file name, line number of the record's first line, cells) for every record of a table, part files in order."""
    for fp in entry["files"]:
        with open(fp, "r", encoding="utf-8-sig", newline="") as f:
            rd = csv.reader(f)
            next(rd, None)
            last = rd.line_num
            for row in rd:
                yield Path(fp).name, last + 1, row
                last = rd.line_num


def search_rows(entry: dict[str, Any], query: str, mode: str = "phrase", limit: int = 500, offset: int = 0,
                columns: Optional[list[str]] = None) -> dict[str, Any]:
    """The records of one table that match, exactly: {header, rows: [[file, line, *cells]], matched, truncated}. `columns`
    restricts the match to those columns (by name)."""
    pred = matcher(query, mode)
    header = entry["columns"]
    idx = [i for i, c in enumerate(header) if columns and c in columns] if columns else None
    rows: list[list[Any]] = []
    matched = 0
    truncated = False
    for fn, line, cells in iter_records(entry):
        probe = [cells[i] for i in idx if i < len(cells)] if idx is not None else cells
        if not pred(probe):
            continue
        matched += 1
        if matched <= offset:
            continue
        if len(rows) >= limit:
            truncated = True
            break
        rows.append([fn, line] + cells)
    return {"header": header, "rows": rows, "matched": matched if not truncated else None, "shown": len(rows), "truncated": truncated}


# --------------------------------------------------------------------------- exports
def _out_dir(case, kind: str, label: str) -> Path:
    try:
        base = export_root(case).parent
    except Exception:  # noqa: BLE001
        base = case.dir
    d = base / kind / f"{time.strftime('%Y%m%d-%H%M%S')}-{slug(label, 40)}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(2**20), b""):
            h.update(b)
    return h.hexdigest()


def export_search(case, query: str, mode: str = "phrase", keys: Optional[set[str]] = None, columns: Optional[list[str]] = None,
                  log: Log = print, out_dir: Optional[Path] = None) -> dict[str, Any]:
    """Every matching record of every (selected) table, one CSV per table with the table's header, plus summary.csv and
    query.json, in a new folder under <exports>/<case>/db-search/. A custody record names the folder and the counts."""
    cat = catalog(case)
    hits = search_counts(case, query, mode, keys, cat)
    out = out_dir or _out_dir(case, "db-search", query)
    by_key = {t["key"]: t for t in cat}
    pred = matcher(query, mode)
    summary = []
    total = 0
    t0 = time.time()
    for i, h in enumerate(hits, 1):
        t = by_key[h["key"]]
        header = t["columns"]
        idx = [k for k, c in enumerate(header) if columns and c in columns] if columns else None
        dest = out / f"{slug(t['export'], 30)}.{slug(t['database'], 30)}.{slug(t['table'], 60)}.csv"
        n = 0
        with open(dest, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, lineterminator="\r\n")
            w.writerow(["_file", "_line"] + header)
            for fn, line, cells in iter_records(t):
                probe = [cells[k] for k in idx if k < len(cells)] if idx is not None else cells
                if pred(probe):
                    w.writerow([fn, line] + cells)
                    n += 1
        if n == 0:
            dest.unlink(missing_ok=True)       # candidate lines that were not whole-record matches
            continue
        total += n
        summary.append({"export": t["export"], "database": t["database"], "table": t["table"], "rows": n, "file": dest.name, "sha256": _sha256(dest)})
        log(f"[db-search] [{i}/{len(hits)}] {t['database']}.{t['table']}: {n} matching rows -> {dest.name}")
    with open(out / "summary.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["export", "database", "table", "matching_rows", "file", "sha256"])
        for s in summary:
            w.writerow([s["export"], s["database"], s["table"], s["rows"], s["file"], s["sha256"]])
    meta = {"query": query, "mode": mode, "columns": columns, "tables_searched": len([t for t in cat if not keys or t["key"] in keys]), "tables_with_matches": len(summary),
            "matching_rows": total, "out": str(out), "written": utc_now(), "seconds": round(time.time() - t0, 1), "case": case.meta.get("case_id"),
            "custody_head_before": dict(zip(("records", "hash"), case.custody.head()))}
    (out / "query.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), "utf-8")
    (out / "README.txt").write_text(
        f"Search of the extracted databases of case {case.meta.get('case_id')} ({case.meta.get('examiner')}), {meta['written']}\n"
        f"query: {query!r}  mode: {mode}" + (f"  columns: {', '.join(columns)}" if columns else "") + "\n"
        f"{total} matching rows in {len(summary)} tables (of {meta['tables_searched']} searched).\n"
        "One CSV per table: the table's header plus _file / _line (the exported CSV file and the line of the row in it),\n"
        "so every row can be found again in the full export. summary.csv lists the files with their SHA-256.\n"
        "The CSV exports were produced read-only from the evidence; the evidence is the primary source.\n", "utf-8")
    case.custody.append("db_search_export", {"query": query, "mode": mode, "columns": columns, "tables": len(summary), "rows": total, "out": str(out),
                                             "files": [{"file": s["file"], "rows": s["rows"], "sha256": s["sha256"]} for s in summary][:200]})
    log(f"[db-search] done: {total} rows in {len(summary)} tables -> {out} ({meta['seconds']} s)")
    return meta


def export_tables(case, keys: list[str], log: Log = print, label: str = "selection") -> dict[str, Any]:
    """Whole tables (every part file) copied into a new folder under <exports>/<case>/db-selection/ - a working set for the
    case file - with manifest.csv (SHA-256 of every file) and a custody record."""
    cat = {t["key"]: t for t in catalog(case)}
    out = _out_dir(case, "db-selection", label)
    rows = []
    for k in keys:
        t = cat.get(k)
        if not t:
            continue
        for fp in t["files"]:
            src = Path(fp)
            dest = out / f"{slug(t['export'], 30)}.{slug(t['database'], 30)}.{src.name}"
            shutil.copyfile(src, dest)
            rows.append({"export": t["export"], "database": t["database"], "table": t["table"], "file": dest.name, "bytes": dest.stat().st_size, "sha256": _sha256(dest)})
        blobs = Path(t["files"][0]).parent / f"{slug(t['table'])}.blobs"
        if blobs.is_dir():
            shutil.copytree(blobs, out / f"{slug(t['export'], 30)}.{slug(t['database'], 30)}.{blobs.name}", dirs_exist_ok=True)
        log(f"[db-selection] {t['database']}.{t['table']}: {len(t['files'])} file(s)")
    with open(out / "manifest.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["export", "database", "table", "file", "bytes", "sha256"])
        for r in rows:
            w.writerow([r["export"], r["database"], r["table"], r["file"], r["bytes"], r["sha256"]])
    case.custody.append("db_tables_exported", {"tables": keys[:200], "files": len(rows), "out": str(out)})
    return {"out": str(out), "files": len(rows), "tables": len(keys)}


# --------------------------------------------------------------------------- paging (no workbench)
def page(entry: dict[str, Any], offset: int = 0, limit: int = 200, filters: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """A page of a table read from its CSV files: {header, rows, more, scanned}. Filters: column -> text the cell must
    contain (case-insensitive). Streams, so a page deep in a big table costs a scan up to it."""
    header = entry["columns"]
    idx = {c: i for i, c in enumerate(header)}
    flt = [(idx[c], v.lower()) for c, v in (filters or {}).items() if c in idx and v]
    rows: list[list[Any]] = []
    seen = 0
    scanned = 0
    more = False
    for fn, line, cells in iter_records(entry):
        scanned += 1
        if flt and not all(i < len(cells) and v in cells[i].lower() for i, v in flt):
            continue
        seen += 1
        if seen <= offset:
            continue
        if len(rows) >= limit:
            more = True
            break
        rows.append([fn, line] + cells)
    return {"header": header, "rows": rows, "more": more, "scanned": scanned, "matched_so_far": seen}


# --------------------------------------------------------------------------- the SQLite workbench
def workbench_path(case) -> Path:
    return case.dir / "db" / "workbench.sqlite"


def _sql_name(s: str) -> str:
    n = re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_") or "t"
    return ("t_" + n) if n[0].isdigit() else n


def loaded(case) -> dict[str, dict[str, Any]]:
    """key -> {name, rows, loaded_at, export, database, table, columns (SQL names), original (CSV names)} of the tables in
    the workbench."""
    p = workbench_path(case)
    if not p.exists():
        return {}
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        out = {}
        for r in con.execute("SELECT key, name, rows, loaded_at, export, database, table_, columns, original FROM _catalog"):
            out[r[0]] = {"name": r[1], "rows": r[2], "loaded_at": r[3], "export": r[4], "database": r[5], "table": r[6],
                         "columns": json.loads(r[7] or "[]"), "original": json.loads(r[8] or "[]")}
        con.close()
        return out
    except sqlite3.Error:
        return {}


def _colmap(info: dict[str, Any]) -> dict[str, str]:
    """CSV column name -> workbench column name (the UI shows the CSV names; SQL knows the sanitised ones)."""
    m = {c: c for c in info.get("columns") or []}
    for orig, c in zip(info.get("original") or [], info.get("columns") or []):
        m[orig] = c
    m.setdefault("_file", "_file")
    m.setdefault("_line", "_line")
    return m


def load_tables(case, keys: list[str], log: Log = print, replace: bool = False) -> dict[str, Any]:
    """Load tables into the workbench (one SQLite file per case; all columns TEXT; an index on every column named like an
    id / e-mail / phone / wallet so joins and lookups are instant). Re-loading a table replaces it."""
    cat = {t["key"]: t for t in catalog(case)}
    p = workbench_path(case)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p)
    con.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=OFF; PRAGMA temp_store=FILE; PRAGMA cache_size=-200000;\n"
                      "CREATE TABLE IF NOT EXISTS _catalog(key TEXT PRIMARY KEY, name TEXT, rows INTEGER, loaded_at TEXT, export TEXT, database TEXT, table_ TEXT, columns TEXT, original TEXT);")
    if "original" not in [r[1] for r in con.execute("PRAGMA table_info(_catalog)")]:
        con.execute("ALTER TABLE _catalog ADD COLUMN original TEXT")
    done = []
    t0 = time.time()
    for i, k in enumerate(keys, 1):
        t = cat.get(k)
        if not t:
            log(f"[db-load] {k}: not in the catalog, skipped")
            continue
        name = _sql_name(f"{t['database']}__{t['table']}")
        existing = {r[0] for r in con.execute("SELECT name FROM _catalog WHERE key<>?", (k,))}
        base = name
        n_ = 2
        while name in existing:
            name = f"{base}_{n_}"
            n_ += 1
        originals = list(t["columns"]) or [f"col{j + 1}" for j in range(len(_header(Path(t["files"][0]))) or 1)]
        cols = []
        seen: set[str] = set()
        for c in originals:
            cn = _sql_name(c)
            while cn in seen or cn in ("_file", "_line"):
                cn += "_"
            seen.add(cn)
            cols.append(cn)
        con.execute(f'DROP TABLE IF EXISTS "{name}"')
        con.execute(f'CREATE TABLE "{name}"(_file TEXT, _line INTEGER, ' + ", ".join(f'"{c}" TEXT' for c in cols) + ")")
        ins = f'INSERT INTO "{name}" VALUES ({",".join("?" * (len(cols) + 2))})'
        n = 0
        batch = []
        width = len(cols)
        for fn, line, cells in iter_records(t):
            cells = (cells + [None] * width)[:width] if len(cells) != width else cells
            batch.append([fn, line] + cells)
            if len(batch) >= 5000:
                con.executemany(ins, batch)
                n += len(batch)
                batch = []
                if n % 200_000 == 0:
                    log(f"[db-load] {t['database']}.{t['table']}: {n:,} rows ({time.time() - t0:.0f} s)")
        if batch:
            con.executemany(ins, batch)
            n += len(batch)
        for c, orig in zip(cols, originals):
            if re.search(r"(^|_)(id|uid|user|email|mail|phone|mobile|wallet|address|hash|ip|tx|order|account)", orig.lower()):
                try:
                    con.execute(f'CREATE INDEX IF NOT EXISTS "ix_{name}_{c}" ON "{name}"("{c}")')
                except sqlite3.Error:
                    pass
        con.execute("INSERT OR REPLACE INTO _catalog(key, name, rows, loaded_at, export, database, table_, columns, original) VALUES (?,?,?,?,?,?,?,?,?)",
                    (k, name, n, utc_now(), t["export"], t["database"], t["table"], json.dumps(cols), json.dumps(originals, ensure_ascii=False)))
        con.commit()
        done.append({"key": k, "name": name, "rows": n})
        log(f"[db-load] [{i}/{len(keys)}] {t['database']}.{t['table']} -> {name}: {n:,} rows")
    con.close()
    case.custody.append("db_workbench_loaded", {"tables": [d["key"] for d in done][:200], "rows": sum(d["rows"] for d in done), "file": str(p)})
    log(f"[db-load] done: {len(done)} tables, {sum(d['rows'] for d in done):,} rows in {time.time() - t0:.0f} s -> {p}")
    return {"loaded": done, "file": str(p), "seconds": round(time.time() - t0, 1)}


def unload(case, keys: Optional[list[str]] = None) -> int:
    """Drop tables from the workbench (all of them when keys is None); returns how many."""
    p = workbench_path(case)
    if not p.exists():
        return 0
    con = sqlite3.connect(p)
    rows = con.execute("SELECT key, name FROM _catalog" + ("" if keys is None else f" WHERE key IN ({','.join('?' * len(keys))})"), keys or ()).fetchall()
    for k, name in rows:
        con.execute(f'DROP TABLE IF EXISTS "{name}"')
        con.execute("DELETE FROM _catalog WHERE key=?", (k,))
    con.commit()
    con.execute("VACUUM")
    con.close()
    return len(rows)


_SQL_OK = re.compile(r"^\s*(?:WITH\b|SELECT\b|EXPLAIN\b|PRAGMA\s+table_info)", re.I)
_SQL_LEAD_CMT = re.compile(r"^\s*(?:--[^\n]*\n|/\*.*?\*/\s*)+", re.S)


def sql(case, statement: str, limit: int = 2000, timeout_s: int = 120) -> dict[str, Any]:
    """Read-only SQL over the workbench: {header, rows, truncated, seconds, error}. SELECT/WITH only, a row limit, a time
    limit; the connection is opened read-only, so nothing in the workbench can change."""
    p = workbench_path(case)
    if not p.exists():
        return {"error": "nothing is loaded into the workbench yet"}
    st = _SQL_LEAD_CMT.sub("", statement.strip()).strip().rstrip(";").strip()      # leading -- and /* */ comments are fine
    if not _SQL_OK.match(st):
        return {"error": "SELECT and WITH statements only (the workbench is read-only)"}
    if not sqlite3.complete_statement(st + ";") or ";" in re.sub(r"'[^']*'|\"[^\"]*\"|--[^\n]*|/\*.*?\*/", "", st, flags=re.S):
        return {"error": "one statement at a time (a ';' in the middle: run the queries one by one)"}
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    con.execute("PRAGMA query_only=1")
    deadline = time.time() + timeout_s
    con.set_progress_handler(lambda: 1 if time.time() > deadline else 0, 100_000)
    t0 = time.time()
    try:
        cur = con.execute(st)
        header = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchmany(limit + 1)
    except (sqlite3.Error, sqlite3.Warning) as e:
        con.close()
        msg = str(e)
        if "interrupted" in msg:
            msg = f"stopped after {timeout_s} s - narrow the query (a WHERE on an indexed column, a LIMIT)"
        return {"error": msg, "seconds": round(time.time() - t0, 1)}
    finally:
        try:
            con.close()
        except Exception:  # noqa: BLE001
            pass
    truncated = len(rows) > limit
    return {"header": header, "rows": [list(r) for r in rows[:limit]], "truncated": truncated, "seconds": round(time.time() - t0, 2)}


def sql_page(case, key: str, offset: int = 0, limit: int = 200, filters: Optional[dict[str, str]] = None, order_by: Optional[str] = None,
             descending: bool = False, numeric: bool = False) -> dict[str, Any]:
    """A page of a loaded table through SQL (instant on any size): {header, rows, total, more}."""
    info = loaded(case).get(key)
    if not info:
        return {"error": "not loaded"}
    p = workbench_path(case)
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{info["name"]}")')]
    cmap = _colmap(info)                      # the UI names columns as the CSV does; SQL has the sanitised names
    where = []
    args: list[Any] = []
    for c, v in (filters or {}).items():
        sc = cmap.get(c, c)
        if sc in cols and v:
            where.append(f'"{sc}" LIKE ? ESCAPE \'\\\'')
            args.append("%" + v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    w = (" WHERE " + " AND ".join(where)) if where else ""
    total = con.execute(f'SELECT COUNT(*) FROM "{info["name"]}"{w}', args).fetchone()[0]
    oc = cmap.get(order_by, order_by) if order_by else None
    col = f'CAST("{oc}" AS REAL)' if numeric else f'"{oc}"'        # every column is text; numeric sorts cast
    ob = f' ORDER BY {col} {"DESC" if descending else "ASC"}' if oc in cols else ""
    rows = [list(r) for r in con.execute(f'SELECT * FROM "{info["name"]}"{w}{ob} LIMIT ? OFFSET ?', args + [limit, offset])]
    con.close()
    # the header goes back out under the CSV names, as the rest of the tab shows them
    back = {v: k for k, v in cmap.items()}
    return {"header": [back.get(c, c) for c in cols], "rows": rows, "total": total, "more": offset + len(rows) < total}


def export_rows(case, header: list[str], rows: list[list[Any]], label: str, kind: str = "db-search", note: str = "") -> Path:
    """Rows shown in the UI (a SQL result, a filtered page) written to a CSV in a new folder under <exports>/<case>/<kind>/."""
    out = _out_dir(case, kind, label)
    dest = out / "rows.csv"
    with open(dest, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(header)
        for r in rows:
            w.writerow(["" if v is None else v for v in r])
    (out / "README.txt").write_text(f"{note or label}\ncase {case.meta.get('case_id')}, written {utc_now()}, {len(rows)} rows\nsha256 {_sha256(dest)}\n", "utf-8")
    case.custody.append("db_rows_exported", {"label": label, "rows": len(rows), "out": str(out), "sha256": _sha256(dest)})
    return out
