"""Eat any database, give back CSV folders.

Sources found on the evidence (or dropped in the hopper):
  * MariaDB / MySQL data directories      -> private server over an overlay (dbengine), every table streamed to CSV
  * mysqldump / phpMyAdmin SQL dumps      -> parsed directly, streaming, any size (.sql, .sql.gz, .sql.xz, .sql.bz2, .sql.zip)
  * PostgreSQL plain dumps (pg_dump -Fp)  -> COPY blocks parsed the same way
  * SQLite files (any extension)          -> sqlite3
  * Microsoft Access .mdb/.accdb          -> mdb-export when mdbtools is installed

Output, per source, under <case>/db/<source-slug>/:
  source.json      what it was, where it came from, hashes, server version, counts
  schema.sql       CREATE TABLE statements (as the dump or the server gave them)
  tables.csv       database, table, rows, columns, file(s), bytes - the index of everything below
  <database>/<table>.csv          UTF-8 with BOM (Excel-safe), CRLF, header row; NULL -> empty cell;
                                  more than 1,000,000 rows -> <table>.part001.csv, part002 ...
  <database>/<table>.blobs/       binary values too big for a cell, one file each (cell holds the file name)
Every run is a custody record; nothing on the evidence is written.
"""
from __future__ import annotations

import bz2
import csv
import sys
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import sqlite3
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from .integrity import utc_now

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))   # exported rows can carry cells far beyond csv's 128 KB default


Log = Callable[[str], None]
ROWS_PER_FILE = 1_000_000
CELL_MAX = 32_000                  # Excel holds 32,767 characters per cell; longer text goes to a file beside the table
BLOB_INLINE_MAX = 2048            # bytes of undecodable binary kept in the cell as hex; bigger -> a file
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SKIP_TOP = {"proc", "sys", "dev", "run", "boot", "lost+found", "snap"}
SKIP_SUB = {"usr/lib", "usr/share", "usr/src", "usr/include", "var/cache", "var/lib/apt", "var/lib/dpkg", "var/lib/docker", "var/lib/snapd"}
DUMP_EXT = (".sql", ".sql.gz", ".sql.xz", ".sql.bz2", ".sql.zip", ".dump", ".dump.gz", ".mysql", ".psql")


def slug(s: str, limit: int = 80) -> str:
    """A safe file/folder name. A name longer than the limit keeps its start plus a hash of the whole, so two long
    names that share a prefix never collide."""
    t = re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-._")
    if len(t) > limit:
        import hashlib
        t = t[:limit - 7].rstrip("-._") + "-" + hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:6]
    return t or "db"


def export_name(source: dict[str, Any]) -> str:
    """The folder name of a source's export: its file name under its parent folder (db-dump_sw.sql) plus a short hash of
    the full path, so nine dumps under one long case path get nine folders (build f truncated the path and they
    overwrote each other)."""
    import hashlib
    rel = (source.get("rel") or Path(source["path"]).name).strip("/")
    parts = [x for x in rel.split("/") if x]
    base = "-".join(parts[-2:]) if len(parts) > 1 else (parts[-1] if parts else "db")
    return slug(base, 48) + "-" + hashlib.sha1(rel.encode("utf-8", "replace")).hexdigest()[:6]


def legacy_export_name(source: dict[str, Any]) -> str:
    rel = (source.get("rel") or Path(source["path"]).name).strip("/").replace("/", "-")
    t = re.sub(r"[^A-Za-z0-9._-]+", "-", rel).strip("-._")
    return t[:60] or "db"


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


# --------------------------------------------------------------------------- finding sources
def _sqlite_header(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def _access_header(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            h = f.read(32)
        return b"Standard Jet DB" in h or b"Standard ACE DB" in h
    except OSError:
        return False


def _dump_kind(p: Path) -> Optional[str]:
    """'mysql-dump' | 'pg-dump' | None by looking at the first MB (through compression). A .sql file that shows none of
    the usual markers in its first MB is still taken as a MySQL dump (the reader reports what it found)."""
    try:
        with _open_text(p) as f:
            head = f.read(2**20)
    except Exception:  # noqa: BLE001
        return None
    if "PostgreSQL database dump" in head or re.search(r"^COPY .* FROM stdin;", head, re.M) or re.search(r"^SET statement_timeout", head, re.M):
        return "pg-dump"
    if re.search(r"(MySQL dump|MariaDB dump|phpMyAdmin SQL Dump|CREATE TABLE|INSERT INTO|REPLACE INTO|DROP TABLE|CREATE DATABASE|LOCK TABLES|SET NAMES|"
                 r"SET SQL_MODE|/\*!\d{5}|Navicat|HeidiSQL|SQLyog|Sequel|Adminer|MySQL Workbench|DBeaver|mysqldump)", head, re.I):
        return "mysql-dump"
    if p.name.lower().endswith(".sql") or ".sql." in p.name.lower():
        return "mysql-dump"
    return None


def classify_file(p: Path) -> Optional[dict[str, Any]]:
    """A single file: a dump, an sqlite db, an Access db, or nothing of interest."""
    name = p.name.lower()
    try:
        size = p.stat().st_size
    except OSError:
        return None
    if size < 100:
        return None
    if _sqlite_header(p):
        return {"kind": "sqlite", "path": str(p), "size": size}
    if name.endswith((".mdb", ".accdb")) or _access_header(p):
        if _access_header(p):
            return {"kind": "access", "path": str(p), "size": size}
    if name.endswith(DUMP_EXT) or name.endswith((".gz", ".xz", ".bz2")) and ".sql" in name:
        k = _dump_kind(p)
        if k:
            return {"kind": k, "path": str(p), "size": size}
    return None


def is_datadir(d: Path) -> bool:
    try:
        names = {p.name for p in d.iterdir()}
    except OSError:
        return False
    return ("ibdata1" in names or "aria_log_control" in names or "mysql.ibd" in names) and \
        ("mysql" in names or any(n.endswith(".frm") for n in names) or "ibdata1" in names)


def find_sources(root: Path, log: Log = print, max_dirs: int = 400_000, budget_s: float = 600) -> list[dict[str, Any]]:
    """Walk an evidence root (bounded) for datadirs, dumps, sqlite and Access files."""
    root = Path(root)
    out: list[dict[str, Any]] = []
    seen_dirs = 0
    t0 = time.time()
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        rel = os.path.relpath(d, root) if d != root else ""
        if depth == 1 and d.name in SKIP_TOP:
            continue
        if rel in SKIP_SUB:
            continue
        if is_datadir(d):
            from .dbengine import datadir_flavour
            fl = datadir_flavour(d)
            out.append({"kind": "mysql8-datadir" if fl.get("mysql8") else "mariadb-datadir", "path": str(d), "size": _du_fast(d),
                        "databases": fl.get("databases", []), "hints": fl.get("hints", [])})
            continue                      # never descend into a datadir
        try:
            with os.scandir(d) as it:
                for e in it:
                    seen_dirs += 1
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if depth < 12:
                                stack.append((Path(e.path), depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            n = e.name.lower()
                            if n.endswith(DUMP_EXT) or n.endswith((".db", ".sqlite", ".sqlite3", ".db3", ".mdb", ".accdb")) or \
                                    (".sql" in n and n.endswith((".gz", ".xz", ".bz2", ".zip"))):
                                c = classify_file(Path(e.path))
                                if c:
                                    out.append(c)
                            elif e.stat(follow_symlinks=False).st_size >= 4096 and n.endswith((".dat", ".bin", ".data", ".sqlitedb", ".sq3")):
                                c = classify_file(Path(e.path))
                                if c and c["kind"] == "sqlite":
                                    out.append(c)
                    except OSError:
                        continue
                    if seen_dirs >= max_dirs or time.time() - t0 > budget_s:
                        log(f"[db] scan stopped early ({seen_dirs} entries, {time.time() - t0:.0f} s)")
                        stack.clear()
                        break
        except OSError:
            continue
    for s in out:
        s["rel"] = "/" + os.path.relpath(s["path"], root).replace(os.sep, "/") if str(s["path"]).startswith(str(root)) else s["path"]
        s["name"] = Path(s["path"]).name
    out.sort(key=lambda s: (-s.get("size", 0), s["path"]))
    return out


def _du_fast(d: Path, limit: int = 20000) -> int:
    total, n = 0, 0
    for r, _ds, fs in os.walk(d):
        for f in fs:
            try:
                total += (Path(r) / f).stat().st_size
            except OSError:
                pass
            n += 1
            if n > limit:
                return total
    return total


# --------------------------------------------------------------------------- CSV writing
class TableWriter:
    """CSV parts of at most ROWS_PER_FILE rows, Excel-friendly (UTF-8 BOM, CRLF), blobs to files."""

    def __init__(self, out_dir: Path, table: str, columns: list[str], rows_per_file: int = ROWS_PER_FILE):
        self.out_dir = out_dir
        self.table = table
        self.columns = columns
        self.rows_per_file = rows_per_file
        self.files: list[Path] = []
        self.rows = 0
        self._f = None
        self._w = None
        self._in_file = 0
        self._part = 0
        self.blobs = 0
        self.rejected = 0
        self._rej = None
        self.blob_dir = out_dir / f"{table}.blobs"       # where spilled cells go (a worker of the parallel path shares the table's)
        self.blob_prefix = ""                           # makes a worker's blob names unique inside the shared folder
        out_dir.mkdir(parents=True, exist_ok=True)

    def reject(self, row) -> None:
        """A row the table cannot take as it is (another number of values than columns): kept, visibly, apart."""
        if self._rej is None:
            name = f"{self.table}.rejected.csv"
            self._rejf = open(self.out_dir / name, "w", newline="", encoding="utf-8-sig")
            self._rej = csv.writer(self._rejf, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
            self._rej.writerow(["row_values_as_read"] + [f"v{i + 1}" for i in range(max(len(row) - 1, 0))])
        self._rej.writerow(["" if v is None else v for v in row])
        self.rejected += 1

    def _open(self) -> None:
        self._part += 1
        name = f"{self.table}.csv" if self._part == 1 else f"{self.table}.part{self._part:03d}.csv"
        p = self.out_dir / name
        self._f = open(p, "w", newline="", encoding="utf-8-sig")
        self._w = csv.writer(self._f, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
        self._w.writerow(self.columns)
        self.files.append(p)
        self._in_file = 0

    def _rename_first(self) -> None:
        # once a second part exists, the first file gets a part number too
        if self._part == 2 and self.files and self.files[0].name == f"{self.table}.csv":
            new = self.files[0].with_name(f"{self.table}.part001.csv")
            self.files[0].rename(new)
            self.files[0] = new

    def write(self, row) -> None:
        if self._w is None or self._in_file >= self.rows_per_file:
            if self._f is not None:
                self._f.close()
            self._open()
            self._rename_first()
        self._w.writerow([self._cell(v, i) for i, v in enumerate(row)])
        self._in_file += 1
        self.rows += 1

    def write_text_row(self, row) -> None:
        """Fast path for rows that hold only str or None (the dump parser's output). A cell longer than Excel can hold
        (CELL_MAX characters) goes to <table>.blobs/rowN.column.txt and the cell says so."""
        if self._w is None or self._in_file >= self.rows_per_file:
            if self._f is not None:
                self._f.close()
            self._open()
            self._rename_first()
        cells = ["" if v is None else v for v in row]
        for i, v in enumerate(cells):
            if len(v) > CELL_MAX:
                cells[i] = self._spill_text(v, i)
        self._w.writerow(cells)
        self._in_file += 1
        self.rows += 1

    def _spill_text(self, v: str, col: int) -> str:
        self.blobs += 1
        bd = self.blob_dir
        bd.mkdir(exist_ok=True)
        colname = self.columns[col] if col < len(self.columns) else f"c{col}"
        fn = bd / f"{self.blob_prefix}row{self.rows + 1}.{slug(colname)}.txt"
        with open(fn, "w", encoding="utf-8", errors="replace") as f:
            f.write(v)
        return f"<text {len(v)} chars: {fn.parent.name}/{fn.name}>"

    def _cell(self, v, col: int):
        if v is None:
            return ""
        if isinstance(v, (bytes, bytearray, memoryview)):
            b = bytes(v)
            try:
                txt = b.decode("utf-8")
                if _CTRL_RE.search(txt) is None:
                    return txt
            except UnicodeDecodeError:
                pass
            if len(b) <= BLOB_INLINE_MAX:            # BIT columns, short binary keys, hashes: hex in the cell
                return "0x" + b.hex()
            if True:
                self.blobs += 1
                bd = self.blob_dir
                bd.mkdir(exist_ok=True)
                colname = self.columns[col] if col < len(self.columns) else f"c{col}"
                fn = bd / f"{self.blob_prefix}row{self.rows + 1}.{slug(colname)}.bin"
                fn.write_bytes(b)
                return f"<binary {len(b)} bytes: {fn.name}>"
        if isinstance(v, str):
            return v.replace("\x00", "\\0")
        return v

    def close(self) -> dict[str, Any]:
        if self._f is not None:
            self._f.close()
            self._f = None
        if self.rows == 0 and not self.files:      # an empty table still gets a header-only file
            self._open()
            self._f.close()
            self._f = None
        if self._rej is not None:
            self._rejf.close()
            self._rej = None
        return {"rows": self.rows, "files": [f.name for f in self.files], "bytes": sum(f.stat().st_size for f in self.files if f.exists()),
                "blobs": self.blobs, "rejected": self.rejected}


# --------------------------------------------------------------------------- SQL dump parsing
def _open_text(p: Path):
    n = p.name.lower()
    if n.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(p, "rb"), encoding="utf-8", errors="replace", newline="")
    if n.endswith(".xz"):
        return io.TextIOWrapper(lzma.open(p, "rb"), encoding="utf-8", errors="replace", newline="")
    if n.endswith(".bz2"):
        return io.TextIOWrapper(bz2.open(p, "rb"), encoding="utf-8", errors="replace", newline="")
    if n.endswith(".zip"):
        z = zipfile.ZipFile(p)
        members = [i for i in z.infolist() if not i.is_dir()]
        members.sort(key=lambda i: -i.file_size)
        return io.TextIOWrapper(z.open(members[0]), encoding="utf-8", errors="replace", newline="")
    return open(p, "r", encoding="utf-8", errors="replace", newline="")


# Two string grammars. MySQL's default: a backslash escapes the next character and quotes may also be doubled. With
# NO_BACKSLASH_ESCAPES (also PostgreSQL, T-SQL, SQLite, standard SQL) a backslash is an ordinary character and only
# doubling escapes a quote; read with the default grammar such a dump loses every row holding a backslash before a quote
# (`'C:\Users\'`), so the mode is detected per file (detect_backslash_escapes) and the right grammar is built here.
# Every quantifier is possessive: a string or row cut by the buffer boundary fails in linear time.
_SQ = r"'[^'\\]*+(?:(?:\\.|'')[^'\\]*+)*+'"   # single-quoted string, backslash mode
_DQ = r'"[^"\\]*+(?:(?:\\.|"")[^"\\]*+)*+"'
_SQ_NB = r"'[^']*+(?:''[^']*+)*+'"                 # single-quoted string, NO_BACKSLASH_ESCAPES mode
_DQ_NB = r'"[^"]*+(?:""[^"]*+)*+"'
_BQ = r"`[^`]*+(?:``[^`]*+)*+`"                   # backtick-quoted identifier
_CMT = r"/\*(?!!)[^*]*+\*+(?:[^/*][^*]*+\*+)*+/|--[ \t][^\n]*+|#[^\n]*+"   # comments (not /*! conditional */ ones)
_WS = r"(?:\s++|" + _CMT + r")*+"                   # whitespace and comments between the parts of a row
# an unquoted field: number, NULL, hex, DEFAULT, an expression without parentheses; stops before whitespace, a comment start
_PLAIN = r"(?:[^,()'\"\s/#-]++|-(?!-)|/(?!\*))++"
_HEXBIT = r"[xXbB]'[0-9a-fA-F]*+'"


def _grammar(backslash: bool) -> tuple:
    """(ROW_RE, FIELD_RE, TOK_RE, CSTRIP_RE) for one escape mode."""
    sq, dq = (_SQ, _DQ) if backslash else (_SQ_NB, _DQ_NB)
    func = r"\w*+\((?:" + sq + "|" + dq + r"|[^()'\"]++)*+\)"            # NOW(), ST_GeomFromText('POINT(1 2)'), (-1): one level of parentheses
    intro = r"_[A-Za-z0-9]++\s*+(?:" + sq + "|" + dq + r"|0[xX][0-9a-fA-F]++)"   # _binary 'x', _utf8mb4'x', _binary 0x41
    nstr = r"[nN](?:" + sq + "|" + dq + ")"                                  # N'unicode' (T-SQL)
    value = r"(?:" + sq + "|" + dq + "|" + intro + "|" + nstr + "|" + _HEXBIT + "|" + func + "|" + _PLAIN + ")"
    # a complete row: '(' values separated by ',' ')', comments allowed anywhere whitespace is; a match can only end at a ')'
    # with balanced quotes
    row = re.compile(r"\(" + _WS + r"(?:" + value + _WS + r"(?:," + _WS + r"|(?=\))))*+\)", re.S)
    field = re.compile(r"\s*+(?:" + value + ")", re.S)
    tok = re.compile(sq + "|" + dq + "|" + _BQ + r"|;|\n|[^'\"`;\n]++|.", re.S)
    cstrip = re.compile(sq + "|" + dq + "|" + _BQ + "|(?P<c>" + _CMT + r")|[^'\"`/#-]++|.", re.S)
    return row, field, tok, cstrip


_ROW_RE, _FIELD_RE, _TOK_RE, _CSTRIP_RE = _grammar(True)
_ROW_RE_NB, _FIELD_RE_NB, _TOK_RE_NB, _CSTRIP_RE_NB = _grammar(False)
_FUNC = r"\w*+\((?:" + _SQ + "|" + _DQ + r"|[^()'\"]++)*+\)"


def _strip_comments(text: str, cstrip) -> str:
    """Comments outside strings replaced by a space (only called for the rare row that holds a comment start)."""
    return cstrip.sub(lambda m: " " if m.group("c") else m.group(0), text)


_NB_MODE_RE = re.compile(r"NO_BACKSLASH_ESCAPES|standard_conforming_strings|PostgreSQL database dump|^\s*PRAGMA foreign_keys|^\s*GO\s*$|\[dbo\]\.", re.I | re.M)
_BS_ESCAPES_RE = re.compile(r"\\['\"\\nrtZ0]")                     # \' \" \\ \n \r \t \Z \0 : backslash escapes as mysqldump writes them
_BS_LITERAL_RE = re.compile(r"\\[^'\"\\nrtZ0%_b\s]")                 # a backslash before a character no escape uses: a literal backslash


def detect_backslash_escapes(head: str) -> tuple[bool, str]:
    """(backslash escapes?, reason) from the first part of a dump. Explicit markers decide (sql_mode, PostgreSQL, T-SQL,
    SQLite); otherwise the escapes seen decide: mysqldump and phpMyAdmin write \\' and \\\\, a NO_BACKSLASH_ESCAPES dump writes
    '' and leaves backslashes alone (C:\\Users). With neither, the MySQL default is assumed."""
    m = _NB_MODE_RE.search(head)
    if m:
        return False, f"marker {m.group(0).strip()!r}"
    n_esc = len(_BS_ESCAPES_RE.findall(head))
    n_lit = len(_BS_LITERAL_RE.findall(head))
    n_dq = head.count("''")
    if n_esc >= 1 and n_esc >= n_lit:
        return True, f"{n_esc} backslash escapes seen"
    if n_lit >= 2 and n_esc == 0:
        return False, f"{n_lit} literal backslashes and no backslash escapes seen"
    if n_dq >= 2 and n_esc == 0 and n_lit == 0:
        return False, "quotes doubled, no backslash escapes seen"
    return True, "MySQL default assumed"

_UNESC = {"0": "\x00", "n": "\n", "r": "\r", "t": "\t", "b": "\b", "Z": "\x1a", "\\": "\\", "'": "'", '"': '"', "%": "\\%", "_": "\\_"}
_BS_RE = re.compile(r"\\(.)", re.S)
_HEX_RE = re.compile(r"^(?:0[xX]([0-9a-fA-F]+)|[xX]'([0-9a-fA-F]*)')$")


def _unescape(s: str) -> str:
    if "\\" not in s:
        return s
    return _BS_RE.sub(lambda m: _UNESC.get(m.group(1), m.group(1)), s)


def _printable(b: bytes) -> bool:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(ch.isprintable() or ch in "\n\r\t" for ch in s[:256])


_ESC_RE = re.compile(r"\\(.)|''", re.S)
_DESC_RE = re.compile(r'\\(.)|""', re.S)


def _unesc_sub(m) -> str:
    c = m.group(1)
    return _UNESC.get(c, c)


def _unesc_sq_sub(m) -> str:
    c = m.group(1)
    return "'" if c is None else _UNESC.get(c, c)


def _unesc_dq_sub(m) -> str:
    c = m.group(1)
    return '"' if c is None else _UNESC.get(c, c)


def _unq(body: str, q: str, backslash: bool) -> str:
    """The value of a quoted string body: one left-to-right pass over escapes and doubled quotes (in that order of
    appearance, never one after the other, so `\\''` means backslash + quote)."""
    if backslash:
        if "\\" not in body:
            return body.replace(q + q, q) if q + q in body else body
        if q + q not in body:
            return _BS_RE.sub(_unesc_sub, body)
        return (_ESC_RE.sub(_unesc_sq_sub, body) if q == "'" else _DESC_RE.sub(_unesc_dq_sub, body))
    return body.replace(q + q, q) if q + q in body else body


def _field(t: str, backslash: bool = True):
    if t[0] == " " or t[0] == "\n" or t[0] == "\t":
        t = t.lstrip()
        if not t:
            return ""
    c = t[0]
    if c == "'":
        return _unq(t[1:-1], "'", backslash)
    if c == '"':
        return _unq(t[1:-1], '"', backslash)
    if c == "_":                       # _binary 'x', _utf8mb4'x', _binary 0x41: the introducer names a character set
        i = t.find("'")
        j = t.find('"')
        if i >= 0 and (j < 0 or i < j):
            return _unq(t[i + 1:-1], "'", backslash)
        if j >= 0:
            return _unq(t[j + 1:-1], '"', backslash)
        t = t.split(None, 1)[1] if " " in t else t[t.find("0"):]
    elif (c == "N" or c == "n") and len(t) > 1 and t[1] in "'\"":      # N'unicode' (T-SQL)
        return _unq(t[2:-1], t[1], backslash)
    if t[-1] == ")" and "(" in t:                                   # NOW(), ST_GeomFromText('POINT(1 2)'): kept as written
        return t.strip()
    t = t.strip()
    if t == "NULL" or t == "null":
        return None
    if (c == "b" or c == "B") and len(t) > 2 and t[1] == "'" and t[-1] == "'":      # bit literal b'101'
        bits = t[2:-1]
        return str(int(bits, 2)) if bits and set(bits) <= {"0", "1"} else t
    if t and t[0] in "0xX" and len(t) > 2 and (t[1] in "xX'" or t[0] in "xX"):
        m = _HEX_RE.match(t)
        if m:
            h = m.group(1) or m.group(2) or ""
            try:
                b = bytes.fromhex(h)
                return b.decode("utf-8") if _printable(b) else "0x" + h
            except ValueError:
                return t
    return t


def parse_values(text: str) -> Iterator[list]:
    """The rows in `(...),(...)` after VALUES; each row a list of python values (None for NULL).
    Regex-driven (the row and field splitting run in C); only the per-field conversion is Python."""
    findall = _FIELD_RE.findall
    fld = _field
    for m in _ROW_RE.finditer(text):
        yield [fld(t) for t in findall(m.group(0)[1:-1]) if not t.isspace()]


_CREATE_RE = re.compile(r"^\s*CREATE\s+(?:TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?(?:[`\"]?(?P<db>[^`\".\s(]+)[`\"]?\.)?[`\"]?(?P<t>[^`\"\s(]+)[`\"]?", re.I)
_INSERT_RE = re.compile(r"^\s*(?:INSERT|REPLACE)\s+(?:LOW_PRIORITY\s+|DELAYED\s+|IGNORE\s+)*INTO\s+(?:[`\"]?(?P<db>[^`\".\s(]+)[`\"]?\.)?[`\"]?(?P<t>[^`\"\s(]+)[`\"]?\s*(?:\((?P<cols>[^)]*)\))?\s*VALUES?\s*", re.I | re.S)
_USE_RE = re.compile(r"^\s*USE\s+[`\"]?([^`\";\s]+)", re.I)
_COLDEF_RE = re.compile(r"^\s*[`\"]([^`\"]+)[`\"]\s", re.M)
_NOT_COLS = ("PRIMARY", "KEY", "UNIQUE", "CONSTRAINT", "INDEX", "FULLTEXT", "SPATIAL", "FOREIGN", "CHECK", "PERIOD")


def columns_from_create(stmt: str) -> list[str]:
    """Column names of a CREATE TABLE statement (one per line or all on one line)."""
    i = stmt.find("(")
    if i < 0:
        return []
    depth, j = 0, i
    in_q = None
    for j in range(i, len(stmt)):
        c = stmt[j]
        if in_q:
            if c == in_q:
                in_q = None
            continue
        if c in ("'", '"', "`"):
            in_q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
    body = stmt[i + 1:j]
    cols: list[str] = []
    depth, start, in_q = 0, 0, None
    pieces: list[str] = []
    for k, c in enumerate(body):
        if in_q:
            if c == in_q:
                in_q = None
            continue
        if c in ("'", '"', "`"):
            in_q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            pieces.append(body[start:k])
            start = k + 1
    pieces.append(body[start:])
    for piece in pieces:
        t = piece.strip()
        if not t or t.split(None, 1)[0].upper().strip("`\"") in _NOT_COLS and not t.startswith(("`", '"')):
            continue
        if t[0] in "`\"":
            cols.append(t[1:t.index(t[0], 1)])
        else:
            cols.append(t.split(None, 1)[0])
    return cols
_COPY_RE = re.compile(r"^\s*COPY\s+(?:\"?([^\".\s]+)\"?\.)?\"?([^\"\s(]+)\"?\s*(?:\(([^)]*)\))?\s*FROM\s+stdin;?\s*$", re.I)


_QSCAN = re.compile(_SQ + "|" + _DQ + r"|\\.|['\"]", re.S)
_QCLOSE = {"'": re.compile(r"[^'\\]*(?:\\.[^'\\]*)*'", re.S), '"': re.compile(r'[^"\\]*(?:\\.[^"\\]*)*"', re.S)}


def _quote_state(line: str, in_q: Optional[str]) -> Optional[str]:
    """Which quote (if any) is still open at the end of this line; C-speed regex scan."""
    pos = 0
    if in_q:
        m = _QCLOSE[in_q].match(line)
        if not m:
            return in_q
        pos = m.end()
        in_q = None
    for m in _QSCAN.finditer(line, pos):
        t = m.group(0)
        if len(t) == 1 and (t == "'" or t == '"'):
            return t
    return None


def _statements(f) -> Iterator[str]:
    """SQL statements from a dump, streaming; quote-aware so a ';' inside a string does not split."""
    buf: list[str] = []
    in_q: Optional[str] = None
    for line in f:
        if not buf and not in_q:
            s = line.lstrip()
            if not s or s[0] == "-" and s.startswith("--") or s[0] == "#":
                continue
            if s.startswith("/*!") and "INSERT" not in s[:40].upper() and s.rstrip().endswith("*/;"):
                continue
        buf.append(line)
        if "'" in line or '"' in line:
            in_q = _quote_state(line, in_q)
        elif in_q and "\\" in line:
            in_q = _quote_state(line, in_q)
        if not in_q and line.rstrip().endswith(";"):
            yield "".join(buf)
            buf = []
    if buf:
        yield "".join(buf)


def _pg_copy_rows(f, ncols: int) -> Iterator[list]:
    for line in f:
        if line.startswith("\\."):
            return
        parts = line.rstrip("\r\n").split("\t")
        yield [None if p == "\\N" else _pg_unescape(p) for p in parts]


def _pg_unescape(s: str) -> str:
    if "\\" not in s:
        return s
    return _BS_RE.sub(lambda m: {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "b": "\b", "f": "\f", "v": "\v"}.get(m.group(1), m.group(1)), s)


# --------------------------------------------------------------------------- streaming MySQL dump reader
# Bytes in, rows out. Nothing has to fit in memory: not a line, not a statement, not a table - a dump that puts a
# whole table on one 3 GB line (some tools do) or in one INSERT with millions of rows streams through a rolling
# buffer of a few MB. Rows are recognised by a regex that only ever matches a complete row with balanced quotes,
# so a row cut by a buffer boundary is simply retried once more bytes are in.
STREAM_CHUNK = 4 * 2**20
_INSERT_HEAD_RE = re.compile(r"(?:INSERT|REPLACE)\s+(?:LOW_PRIORITY\s+|DELAYED\s+|IGNORE\s+)*(?:INTO\s+)?"
                             r"(?:[`\"\[]?(?P<db>[^`\"\[\].\s(]+)[`\"\]]?\.)?[`\"\[]?(?P<t>[^`\"\[\]\s(]+)[`\"\]]?\s*"
                             r"(?:\((?P<cols>[^)]*)\))?\s*VALUES?\s*", re.I | re.S)       # MySQL/MariaDB, PostgreSQL --inserts, T-SQL ([dbo].[t], no INTO)
_CREATE_HEAD_RE = re.compile(r"CREATE\s+(?:TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?(?:[`\"]?(?P<db>[^`\".\s(]+)[`\"]?\.)?[`\"]?(?P<t>[^`\"\s(]+)[`\"]?", re.I)
_USE_HEAD_RE = re.compile(r"USE\s+[`\"]?([^`\";\s]+)", re.I)
_CREATEDB_HEAD_RE = re.compile(r"CREATE\s+DATABASE\s+(?:/\*!\d*\s*)?(?:IF\s+NOT\s+EXISTS\s*)?(?:\*/\s*)?[`\"]?([^`\";\s/]+)", re.I)
_TOK_RE = re.compile(_SQ + "|" + _DQ + "|" + _BQ + r"|;|\n|[^'\"`;\n]++|.", re.S)   # statement text up to its ';' (quote-aware), newline by newline
# after a row the reader could not understand, quote state is unknowable (a lone quote is the usual cause), so the resync takes
# the EARLIEST row or statement boundary regardless of quotes; the row regex re-validates everything after it, so a wrong pick
# costs another row, never the rest of the file
_RESYNC_RE = re.compile(r"\)\s*+,\s*+\(|\)\s*+;|;\s*+\n|[^);]++|.", re.S)
MAX_ROW_CHARS = 128 * 2**20          # a row (or unmatched stretch) longer than this is given up on and skipped with a note
STMT_MAX = 8 * 2**20                 # a non-INSERT statement longer than this is skipped (a lone quote cannot swallow the file)
_KEYWORD_AT_LINE_RE = re.compile(r"[ \t\r]*(?:INSERT|REPLACE|CREATE|DROP|ALTER|GO\b|USE\b|LOCK\b|UNLOCK|SET\b|COMMIT|BEGIN|START\b|DELIMITER|TRUNCATE|GRANT|FLUSH|--|#|/\*)", re.I)
_SEP_RE = re.compile(_WS + r"(,|;)?", re.S)            # whitespace and complete comments, then the separator when it is there
_ROWCMT_RE = re.compile(_CMT, re.S)
_CMTSTART_RE = re.compile(r"/\*|#|--")
_ROUTINE_HEAD_RE = re.compile(r"(?:/\*!\d*\s*)?CREATE\s+(?:/\*!\d*\s*)?(?:\*/\s*)?(?:OR\s+REPLACE\s+)?(?:DEFINER\s*=\s*\S+\s+)?(?:/\*!\d*\s*)?(?:\*/\s*)?"
                              r"(?:TRIGGER|PROCEDURE|FUNCTION|EVENT)\b", re.I | re.S)
_INSERT_SET_RE = re.compile(r"(?:INSERT|REPLACE)\s+(?:LOW_PRIORITY\s+|DELAYED\s+|IGNORE\s+)*(?:INTO\s+)?[^;]{0,300}?\b(?:SET|SELECT)\b", re.I | re.S)
_WS_RE = re.compile(r"\s+", re.S)
_HEAD_WINDOW = 256 * 1024          # a statement head (INSERT INTO ... VALUES) is read within this much text


class _TextStream:
    """A rolling text buffer over an iterator of byte chunks (UTF-8, multi-byte characters split across chunks are
    handled by the incremental decoder)."""

    __slots__ = ("_it", "_dec", "buf", "pos", "eof", "consumed")

    def __init__(self, byte_chunks):
        import codecs
        self._it = iter(byte_chunks)
        self._dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.buf = ""
        self.pos = 0
        self.eof = False
        self.consumed = 0                  # bytes taken from the source (for progress)

    def fill(self, rebase: bool = True) -> bool:
        """Append the next chunk (dropping what is behind pos first unless rebase=False); False at end of input."""
        if self.eof:
            return False
        if rebase and self.pos:
            self.buf = self.buf[self.pos:]
            self.pos = 0
        try:
            b = next(self._it)
        except StopIteration:
            self.eof = True
            tail = self._dec.decode(b"", final=True)
            if tail:
                self.buf += tail
                return True
            return False
        self.consumed += len(b)
        self.buf += self._dec.decode(b)
        return True

    def ensure(self, n: int) -> None:
        """At least n characters after pos, or everything there is."""
        while len(self.buf) - self.pos < n and self.fill():
            pass


def _byte_chunks(src: Path, start: int = 0, end: Optional[int] = None, chunk: int = STREAM_CHUNK):
    """Chunks of a plain file between byte offsets (the whole file by default)."""
    with open(src, "rb") as f:
        f.seek(start)
        left = (end - start) if end is not None else None
        while left is None or left > 0:
            b = f.read(chunk if left is None else min(chunk, left))
            if not b:
                break
            if left is not None:
                left -= len(b)
            yield b


def _compressed_chunks(src: Path, chunk: int = STREAM_CHUNK):
    """Chunks of a gz / xz / bz2 / zip dump, decompressed on the fly."""
    n = src.name.lower()
    if n.endswith(".gz"):
        f = gzip.open(src, "rb")
    elif n.endswith(".xz"):
        f = lzma.open(src, "rb")
    elif n.endswith(".bz2"):
        f = bz2.open(src, "rb")
    elif n.endswith(".zip"):
        z = zipfile.ZipFile(src)
        members = [i for i in z.infolist() if not i.is_dir()]
        members.sort(key=lambda i: -i.file_size)
        f = z.open(members[0])
    else:
        f = open(src, "rb")
    with f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            yield b


def parse_mysql_dump(chunks, writer_for, on_create=None, on_db=None, progress=None, initial_db: str = "dump", backslash: bool = True) -> dict[str, int]:
    """Stream a MySQL/MariaDB dump: INSERT/REPLACE rows go to writer_for(db, table, columns-or-None).write_text_row;
    CREATE TABLE statements go to on_create(db, table, statement_text); USE / CREATE DATABASE switch the database.
    Returns counters (inserts, rows, creates, skipped, malformed, notes). Malformed input costs what it touches, never
    the rest of the file: a row the reader cannot match is given up after MAX_ROW_CHARS of unmatched text and parsing
    resumes at the next row or statement boundary; a non-INSERT statement over STMT_MAX is dropped; both are noted with
    their byte position."""
    st = _TextStream(chunks)
    cur_db = initial_db or "dump"
    stats = {"inserts": 0, "rows": 0, "creates": 0, "skipped": 0, "malformed": 0, "rejected": 0, "routines": 0}
    notes: list[str] = []
    stats["notes"] = notes
    rows_since_progress = 0
    _ROW_RE, _FIELD_RE, _TOK_RE, _CSTRIP_RE = _grammar(backslash) if not backslash else (globals()["_ROW_RE"], globals()["_FIELD_RE"], globals()["_TOK_RE"], globals()["_CSTRIP_RE"])
    delim = ";"          # DELIMITER in effect: inside a `DELIMITER ;;` region every statement is a routine body, skipped whole

    def skip_to_delim() -> None:
        """Consume one statement of a DELIMITER region (a trigger, procedure, function or event body) up to and including the
        delimiter, quote-aware, with no line heuristics: an INSERT inside the body is part of the body, never data."""
        n = len(delim)
        while True:
            m = _TOK_RE.match(st.buf, st.pos)
            if m is None:
                if st.fill():
                    continue
                st.pos = len(st.buf)
                return
            tok = m.group(0)
            if len(tok) == 1 and tok in "'\"`":
                if len(st.buf) - st.pos < STMT_MAX and st.fill():
                    continue
            if tok == ";" or (tok[0] not in "'\"`" and delim[0] in tok):
                i = tok.find(delim[0]) if tok != ";" else 0
                at = m.start() + i
                if len(st.buf) - at < n:
                    st.fill()
                if st.buf.startswith(delim, at):
                    st.pos = at + n
                    return
                st.pos = at + 1
                continue
            st.pos = m.end()
            if st.pos >= len(st.buf) and not st.fill():
                return

    def skip_statement() -> None:
        # consume up to and including the next ';' outside quotes, or up to (not including) a line that starts with a
        # statement keyword (scripts without ';', T-SQL GO batches); tolerant of buffer boundaries
        while True:
            m = _TOK_RE.match(st.buf, st.pos)
            if m is None:
                if st.fill():
                    continue
                st.pos = len(st.buf)
                return
            tok = m.group(0)
            if len(tok) == 1 and tok in "'\"`":
                # a quote without its closing quote in the buffer: usually a string cut by the chunk boundary, so read on
                # before deciding; a quote still open after STMT_MAX characters, or at the end of the file, is a lone
                # quote (a broken dump) and is stepped over so the ';' search continues
                if len(st.buf) - st.pos < STMT_MAX and st.fill():
                    continue
            if tok == "\n":
                st.ensure(24)
                if _KEYWORD_AT_LINE_RE.match(st.buf, m.end()):
                    st.pos = m.end()
                    return
            st.pos = m.end()
            if tok == ";":
                return
            if st.pos >= len(st.buf) and not st.fill():
                return

    def _resync() -> bool:
        """Skip to the next row start (after '),(') or the end of the statement (');' or ';\\n'), whichever comes first.
        True when the statement ended, False when positioned at the next row's '('."""
        while True:
            m = _RESYNC_RE.match(st.buf, st.pos)
            if m is None:
                if st.fill():
                    continue
                st.pos = len(st.buf)
                return True
            tok = m.group(0)
            if tok[0] == ")" and tok[-1] == "(":
                st.pos = m.end() - 1
                return False
            st.pos = m.end()
            if tok[0] == ")" and tok[-1] == ";" or (tok[0] == ";" and tok.endswith("\n")):
                return True
            if st.pos >= len(st.buf) and not st.fill():
                return True

    def statement_text() -> str:
        # the text of the statement at pos up to its ';' (schema statements: small; anything over 8 MB is dropped)
        start = st.pos
        head = st.buf[start:start + 60]

        def too_long() -> str:
            # over the bound: the statement is dropped (noted with its position), the ';' search goes on from here
            stats["skipped"] += 1
            if len(notes) < 20:
                notes.append(f"statement over {STMT_MAX >> 20} MB skipped near byte {max(st.consumed - (len(st.buf) - start), 0)}: {head!r}")
            skip_statement()
            return ""

        while True:
            m = _TOK_RE.match(st.buf, st.pos)
            if m is None:
                if len(st.buf) - start > STMT_MAX:
                    return too_long()
                if st.fill(rebase=False):
                    continue
                st.pos = len(st.buf)
                return st.buf[start:]
            tok = m.group(0)
            if len(tok) == 1 and tok in "'\"`":
                # a string cut by the chunk boundary (its closing quote has not arrived): read on before treating the
                # quote as lone, within the statement bound
                if len(st.buf) - start > STMT_MAX:
                    return too_long()
                if st.fill(rebase=False):
                    continue
            if tok == "\n":
                if len(st.buf) - m.end() < 24:
                    st.fill(rebase=False)
                if _KEYWORD_AT_LINE_RE.match(st.buf, m.end()) and st.pos > start:
                    st.pos = m.end()
                    return st.buf[start:st.pos]
            st.pos = m.end()
            if tok == ";":
                return st.buf[start:st.pos]
            if st.pos - start > STMT_MAX:
                return too_long()
            if st.pos >= len(st.buf) and not st.fill(rebase=False):
                return st.buf[start:]

    while True:
        # ---- skip whitespace and comments between statements
        st.ensure(16)
        if st.pos >= len(st.buf):
            break
        c = st.buf[st.pos]
        if c in " \t\r\n":
            m = _WS_RE.match(st.buf, st.pos)
            st.pos = m.end()
            continue
        two = st.buf[st.pos:st.pos + 2]
        if two == "--" or c == "#":
            nl = st.buf.find("\n", st.pos)
            while nl < 0:
                if not st.fill():
                    st.pos = len(st.buf)
                    break
                nl = st.buf.find("\n", st.pos)
            if nl >= 0:
                st.pos = nl + 1
            continue
        if two == "/*" and not st.buf.startswith("/*!", st.pos):
            end = st.buf.find("*/", st.pos)
            while end < 0:
                if not st.fill():
                    st.pos = len(st.buf)
                    break
                end = st.buf.find("*/", st.pos)
            if end >= 0:
                st.pos = end + 2
            continue
        # ---- a statement: look at its head
        st.ensure(_HEAD_WINDOW)
        head12 = st.buf[st.pos:st.pos + 12].upper()
        if head12.startswith("GO") and (len(head12) == 2 or head12[2] in "\r\n \t"):      # T-SQL batch separator
            nl = st.buf.find("\n", st.pos)
            st.pos = nl + 1 if nl >= 0 else len(st.buf)
            continue
        if head12.startswith("DELIMITER"):
            nl = st.buf.find("\n", st.pos)
            line = st.buf[st.pos + 9:nl if nl >= 0 else len(st.buf)].strip()
            delim = line.split()[0] if line else ";"
            st.pos = nl + 1 if nl >= 0 else len(st.buf)
            continue
        if delim != ";":
            # inside a DELIMITER region: routine bodies (mysqldump writes triggers, procedures, functions and events this way)
            stats["routines"] += 1
            skip_to_delim()
            continue
        if _ROUTINE_HEAD_RE.match(st.buf, st.pos):
            # a single-statement trigger/procedure/function/event outside a DELIMITER region: skipped up to its ';' with no
            # line heuristics (its body's INSERT is not data)
            stats["routines"] += 1
            skip_to_delim()
            continue
        if head12.startswith("INSERT") or head12.startswith("REPLACE"):
            m = _INSERT_HEAD_RE.match(st.buf, st.pos)
            if m is None:
                if _INSERT_SET_RE.match(st.buf, st.pos):
                    stats["skipped"] += 1
                    if len(notes) < 20:
                        notes.append(f"INSERT ... SET / INSERT ... SELECT statement skipped near byte {max(st.consumed - (len(st.buf) - st.pos), 0)} (not a VALUES list)")
                else:
                    stats["malformed"] += 1
                skip_statement()
                continue
            db = m.group("db") or cur_db
            table = m.group("t")
            cols = [x.strip().strip('`"[]') for x in (m.group("cols") or "").split(",") if x.strip()] or None
            st.pos = m.end()
            w = writer_for(db, table, cols)
            wr = w.write_text_row
            findall = _FIELD_RE.findall
            fld = _field
            cmt_search = _CMTSTART_RE.search
            stats["inserts"] += 1
            # columns: the writer's (CREATE TABLE or the first INSERT's list). An INSERT whose column list differs is mapped by
            # name; a row with another number of values than the table has goes to <table>.rejected.csv, counted, never shifted
            ncols = len(w.columns) if w.columns else 0
            remap = None
            if cols and w.columns and cols != w.columns:
                idx = {c.lower(): i for i, c in enumerate(w.columns)}
                if all(c.lower() in idx for c in cols):
                    remap = [idx[c.lower()] for c in cols]
            while True:
                if st.pos >= len(st.buf) or st.buf[st.pos] != "(":
                    # not at a row's '(': whitespace or a comment before the row (the separator took what was in the buffer;
                    # the rest came with the next chunk), or the end of the statement
                    wm = _WS_RE.match(st.buf, st.pos)
                    if wm is not None:
                        st.pos = wm.end()
                    if st.buf.startswith(("/*", "--", "#"), st.pos) and not st.buf.startswith("/*!", st.pos):
                        cm = _ROWCMT_RE.match(st.buf, st.pos)
                        if cm is not None:
                            st.pos = cm.end()
                            continue
                        # a comment cut by the buffer (no end in sight yet): more data, bounded
                        unfinished = ("*/" not in st.buf[st.pos:st.pos + STMT_MAX]) if st.buf.startswith("/*", st.pos) else ("\n" not in st.buf[st.pos:st.pos + STMT_MAX])
                        if unfinished and len(st.buf) - st.pos < STMT_MAX and not st.eof and st.fill():
                            continue
                rm = _ROW_RE.match(st.buf, st.pos)
                if rm is None:
                    if st.pos < len(st.buf) and st.buf[st.pos] == ";":     # INSERT ... VALUES; with no rows, or trailing ;
                        st.pos += 1
                        break
                    # not a complete row at pos: either the buffer ends inside it (read more), or it is not a row the reader
                    # understands (an unquoted '(' two levels deep, a lone quote, a NO_BACKSLASH_ESCAPES dump ending a cell
                    # in a backslash ...). Read on while the unmatched stretch is still short; then give the row up and
                    # resync at the next row or statement boundary outside quotes, so one bad row costs one row.
                    if len(st.buf) - st.pos < MAX_ROW_CHARS and not st.eof and st.fill():
                        continue
                    stats["malformed"] += 1
                    where = st.consumed - (len(st.buf) - st.pos)
                    if stats["malformed"] <= 20:
                        notes.append(f"row not understood near byte {max(where, 0)} in {table}: {st.buf[st.pos:st.pos + 80]!r}")
                    end_stmt = _resync()
                    if end_stmt:
                        break
                    continue
                a, b = rm.start() + 1, rm.end() - 1
                if cmt_search(st.buf, a, b) is not None:
                    # a comment start somewhere in the row (or those characters inside a string): comments outside strings go
                    row = [fld(t, backslash) for t in findall(_strip_comments(st.buf[a:b], _CSTRIP_RE))]
                elif backslash:
                    row = [fld(t) for t in findall(st.buf, a, b)]   # no copies of the row text
                else:
                    row = [fld(t, False) for t in findall(st.buf, a, b)]
                if not w.columns:
                    w.columns = [f"col{i + 1}" for i in range(len(row))]
                    ncols = len(row)
                if remap is not None:
                    if len(row) == len(remap):
                        full = [None] * ncols
                        for i, v in zip(remap, row):
                            full[i] = v
                        row = full
                    else:
                        w.reject(row)
                        stats["rejected"] += 1
                        if stats["rejected"] <= 20:
                            notes.append(f"row with {len(row)} values for {len(remap)} named columns near byte {max(st.consumed - (len(st.buf) - st.pos), 0)} in {table}: rejected")
                        row = None
                elif ncols and len(row) != ncols:
                    w.reject(row)
                    stats["rejected"] += 1
                    if stats["rejected"] <= 20:
                        notes.append(f"row with {len(row)} values for {ncols} columns near byte {max(st.consumed - (len(st.buf) - st.pos), 0)} in {table}: rejected")
                    row = None
                if row is not None:
                    wr(row)
                    stats["rows"] += 1
                rows_since_progress += 1
                st.pos = rm.end()
                # the separator: ',' -> next row; ';' -> end; buffer end -> more data; comments are whitespace
                while True:
                    sm = _SEP_RE.match(st.buf, st.pos)
                    if sm is not None and sm.group(1):
                        st.pos = sm.end()
                        sep = sm.group(1)
                        break
                    if sm is not None:
                        st.pos = sm.end()
                    if st.pos >= len(st.buf) or st.buf.startswith(("/*", "--", "#"), st.pos) and not st.buf.startswith("/*!", st.pos):
                        if st.fill():          # the separator or a comment continues in the next chunk
                            continue
                        sep = ";"
                        st.pos = len(st.buf)
                        break
                    sep = "?"                        # something else: ON DUPLICATE KEY UPDATE ..., or junk
                    break
                if sep == ";":
                    break
                if sep == "?":                       # ON DUPLICATE KEY UPDATE ..., a GO line, the next statement: the main loop takes it
                    break
                if rows_since_progress >= 50_000 and progress is not None:
                    rows_since_progress = 0
                    progress(st.consumed)
            if progress is not None and rows_since_progress:
                rows_since_progress = 0
                progress(st.consumed)
        elif head12.startswith("CREATE TABLE") or head12.startswith("CREATE TEMP"):
            text = statement_text()
            m = _CREATE_HEAD_RE.match(text)
            if m and on_create is not None:
                on_create(m.group("db") or cur_db, m.group("t"), text)
            stats["creates"] += 1
        elif head12.startswith("USE"):
            text = statement_text()
            m = _USE_HEAD_RE.match(text)
            if m:
                cur_db = m.group(1)
                if on_db is not None:
                    on_db(cur_db)
        elif head12.startswith("CREATE DATAB"):
            text = statement_text()
            m = _CREATEDB_HEAD_RE.match(text)
            if m:
                cur_db = m.group(1)
                if on_db is not None:
                    on_db(cur_db)
        else:
            stats["skipped"] += 1
            skip_statement()
    return stats


def _chunk_source(src: Path, chunk: int = STREAM_CHUNK):
    """(byte-chunk generator, function giving the position in the file on disk) for a plain or compressed dump."""
    n = src.name.lower()
    raw = open(src, "rb")
    if n.endswith(".gz"):
        f = gzip.GzipFile(fileobj=raw)
    elif n.endswith(".xz"):
        f = lzma.LZMAFile(raw)
    elif n.endswith(".bz2"):
        f = bz2.BZ2File(raw)
    elif n.endswith(".zip"):
        z = zipfile.ZipFile(raw)
        members = [i for i in z.infolist() if not i.is_dir()]
        members.sort(key=lambda i: -i.file_size)
        f = z.open(members[0])
    else:
        f = raw

    def gen():
        with raw:
            try:
                while True:
                    b = f.read(chunk)
                    if not b:
                        break
                    yield b
            finally:
                if f is not raw:
                    f.close()

    def pos():
        try:
            return raw.tell()
        except Exception:  # noqa: BLE001
            return 0
    return gen(), pos


def dump_head(src: Path, n: int = 2**20) -> str:
    try:
        with _open_text(src) as f:
            return f.read(n)
    except Exception:  # noqa: BLE001
        return ""


def extract_dump(src: Path, out: Path, log: Log, kind: str = "mysql-dump", rows_per_file: int = ROWS_PER_FILE, backslash: Optional[bool] = None) -> dict[str, Any]:
    """Parse a SQL dump straight into CSV files (one per table, under <out>/<database>/). Streams: no line, statement or
    table has to fit in memory."""
    size = src.stat().st_size
    if backslash is None and kind != "pg-dump":
        backslash, why = detect_backslash_escapes(dump_head(src))
        log(f"[db] {src.name}: string escapes: {'backslash (MySQL default)' if backslash else 'doubled quotes only (NO_BACKSLASH_ESCAPES / PostgreSQL / T-SQL / SQLite)'} - {why}")
    schema_lines: list[str] = []
    writers: dict[tuple[str, str], TableWriter] = {}
    columns: dict[tuple[str, str], list[str]] = {}
    tables: list[dict[str, Any]] = []
    t0 = time.time()
    last_pct = -1

    def writer_for(db: str, table: str, ncols_hint: Optional[list[str]]) -> TableWriter:
        key = (db, table)
        w = writers.get(key)
        if w is None:
            cols = columns.get(key) or ncols_hint or []       # CREATE TABLE's columns first; an INSERT's own list is mapped onto them
            w = writers[key] = TableWriter(out / slug(db), slug(table), cols, rows_per_file)
        return w

    def on_create(db: str, table: str, text: str) -> None:
        key = (db, table)
        columns[key] = columns_from_create(text)
        if key in writers and not writers[key].columns:
            writers[key].columns = columns[key]
        schema_lines.append(text.strip() + "\n\n")

    def progress_at(pos: int) -> None:
        nonlocal last_pct
        pct = int(pos * 100 / max(size, 1)) if pos else -1
        if pct >= 0 and pct // 5 != last_pct // 5:
            last_pct = pct
            log(f"[db] {src.name}: {pct}% ({len(writers)} tables, {sum(w.rows for w in writers.values())} rows, {(time.time() - t0):.0f} s)")

    stats: dict[str, Any] = {}
    error = None
    try:
        _extract_dump_body(src, kind, writer_for, on_create, schema_lines, progress_at, lambda st_: stats.update(st_), bool(backslash))
    except Exception as e:  # noqa: BLE001 - whatever was written so far is kept and indexed; the error is recorded
        error = f"{type(e).__name__}: {str(e)[:400]}"
        log(f"[db] {src.name}: stopped early - {error}; keeping the {sum(w.rows for w in writers.values())} rows written so far")
    for (db, table), w in sorted(writers.items()):
        r = w.close()
        tables.append({"database": db, "table": table, "rows": r["rows"], "columns": len(w.columns), "files": r["files"], "bytes": r["bytes"], "blobs": r["blobs"],
                       "rejected": r["rejected"], **({"error": "partial: " + error} if error else {})})
    (out / "schema.sql").write_text("".join(schema_lines), "utf-8")
    if stats.get("rejected"):
        log(f"[db] {src.name}: {stats['rejected']} row(s) with another number of values than their table has columns: kept in <table>.rejected.csv, not in the table")
    log(f"[db] {src.name}: done - {len(tables)} tables, {sum(t['rows'] for t in tables)} rows in {(time.time() - t0) / 60:.1f} min"
        + (f" ({stats['inserts']} INSERTs, {stats['creates']} CREATE TABLEs, {stats['skipped']} other statements skipped, {stats['malformed']} malformed)" if stats else ""))
    if stats and stats.get("malformed"):
        log(f"[db] {src.name}: {stats['malformed']} row(s) not understood (skipped): " + "; ".join(stats.get("notes", [])[:3]))
    if stats and not tables:
        log("[db]   no INSERT or CREATE TABLE statement was recognised: not a MySQL/MariaDB dump, or a dialect the reader does not know - "
            "send the first lines of the file (head -c 2000) so it can be added")
    r = {"tables": tables, "seconds": round(time.time() - t0, 1), "stats": stats}
    if error:
        r["error"] = error
    return r


def _extract_dump_body(src: Path, kind: str, writer_for, on_create, schema_lines: list[str], progress_at, set_stats, backslash: bool = True) -> None:
    if kind == "pg-dump":
        with _open_text(src) as f:
            raw = getattr(f, "buffer", None)
            if raw is not None and hasattr(raw, "fileobj"):      # gzip: position in the compressed file
                raw = raw.fileobj
            for line in f:
                m = _COPY_RE.match(line)
                if m:
                    db, table, cols = m.group(1) or "public", m.group(2), [c.strip().strip('"') for c in (m.group(3) or "").split(",") if c.strip()]
                    w = writer_for(db, table, cols)
                    for row in _pg_copy_rows(f, len(cols)):
                        w.write_text_row(row)
                    try:
                        progress_at(raw.tell() if raw is not None else 0)
                    except Exception:  # noqa: BLE001
                        pass
                elif re.match(r"^\s*CREATE TABLE", line, re.I):
                    schema_lines.append(line)
                    for nxt in f:
                        schema_lines.append(nxt)
                        if nxt.rstrip().endswith(";"):
                            break
                    schema_lines.append("\n")
    else:
        chunks, pos_fn = _chunk_source(src)
        set_stats(parse_mysql_dump(chunks, writer_for, on_create, None, lambda consumed: progress_at(pos_fn()), backslash=backslash))


# --------------------------------------------------------------------------- parallel dump parsing
PARALLEL_MIN_BYTES = 512 * 2**20
_STMT_STARTS = (b"INSERT INTO", b"REPLACE INT", b"CREATE TABL", b"DROP TABLE ", b"LOCK TABLES", b"UNLOCK TABL", b"-- ", b"/*!40000 AL", b"USE `", b"CREATE DATA")


# A quote-aware byte scan finds statement ends (';' outside strings, identifiers and comments) and the database in effect
# at each of them. Split points for the parallel workers are taken only from there, so a range never starts inside a
# text cell that happens to contain "\n-- \n" (an e-mail signature) or "INSERT INTO" (a table holding SQL) - the previous
# line-pattern scan did exactly that and lost whole worker ranges.
_BTOK_RE = re.compile(rb"'[^'\\]*+(?:(?:\\.|'')[^'\\]*+)*+'|\"[^\"\\]*+(?:(?:\\.|\"\")[^\"\\]*+)*+\"|`[^`]*+`|--[ \t][^\n]*+|\n#[^\n]*+|"
                      rb"/\*(?!!)[^*]*+\*+(?:[^/*][^*]*+\*+)*+/|;|\nDELIMITER[ \t]++[^\n]*+|[^'\"`;/\n#$|-]++|.", re.S)
_BTOK_RE_NB = re.compile(rb"'[^']*+(?:''[^']*+)*+'|\"[^\"]*+(?:\"\"[^\"]*+)*+\"|`[^`]*+`|--[ \t][^\n]*+|\n#[^\n]*+|"
                         rb"/\*(?!!)[^*]*+\*+(?:[^/*][^*]*+\*+)*+/|;|\nDELIMITER[ \t]++[^\n]*+|[^'\"`;/\n#$|-]++|.", re.S)
_BDB_RE = re.compile(rb"(?:\s|--[^\n]*\n)*+(?:USE\s+[`\"]?([^`\";\s]+)|CREATE\s+DATABASE\s+(?:/\*!\d*\s*)?(?:IF\s+NOT\s+EXISTS\s*)?(?:\*/\s*)?[`\"]?([^`\";\s/]+))", re.I)
SCAN_CHUNK = 8 * 2**20


def scan_statement_ends(src: Path, targets: list[int], log: Optional[Log] = None, backslash: bool = True) -> tuple[list[tuple[int, str]], int]:
    """For each target byte offset, the first statement end at or after it (offset just past the ';') with the database in
    effect there. One sequential pass at C speed; strings and comments are skipped as tokens, so nothing inside them counts.
    Returns ([(offset, db)], statements_seen)."""
    out: list[tuple[int, str]] = []
    ti = 0
    cur_db = "dump"
    n_stmt = 0
    size = src.stat().st_size
    tok_re = _BTOK_RE if backslash else _BTOK_RE_NB
    delim = b";"          # inside a DELIMITER region only the region's delimiter ends a statement (routine bodies are one statement)
    with open(src, "rb") as f:
        buf = b""
        base = 0           # file offset of buf[0]
        pos = 0
        eof = False
        last_log = 0

        def refill() -> bool:
            nonlocal buf, base, pos, eof
            b = f.read(SCAN_CHUNK)
            if not b:
                eof = True
                return False
            buf = buf[pos:] + b
            base += pos
            pos = 0
            return True

        while ti < len(targets):
            if pos >= len(buf):
                if not refill():
                    break
            if log and base - last_log >= 1024 * 2**20:
                last_log = base
                log(f"[db] scanning statement boundaries: {int(base * 100 / max(size, 1))}%")
            m = tok_re.match(buf, pos)
            if m is None:
                if not eof and refill():
                    continue
                pos += 1
                continue
            tok = m.group(0)
            if not eof and (m.end() >= len(buf) or (len(tok) == 1 and tok in b"'\"`")):
                # the token may continue in the next chunk, or a string's closing quote has not been read yet: more data
                # (bounded; past the bound, or at the end of the file, a quote with no closing quote is a lone quote)
                if len(buf) - pos < MAX_ROW_CHARS and refill():
                    continue
            tok0 = tok[:1]
            if tok0 == b"\n" and tok.startswith(b"\nDELIMITER"):
                parts = tok.split()
                delim = parts[1] if len(parts) > 1 else b";"
                pos = m.end()
                continue
            if delim != b";":
                # a routine body: its end is the region's delimiter (;; $$ // ...), found inside a plain run or at a ';' token
                i = tok.find(delim[:1]) if tok0 != b"'" and tok0 != b'"' and tok0 != b"`" else -1
                if i < 0:
                    pos = m.end()
                    continue
                at = m.start() + i
                if len(buf) - at < len(delim) and not eof:
                    refill()
                    continue
                if not buf.startswith(delim, at):
                    pos = at + 1
                    continue
                pos = at + len(delim)
                n_stmt += 1
                off = base + pos
                while ti < len(targets) and off >= targets[ti]:
                    if not out or out[-1][0] != off:
                        out.append((off, cur_db))
                    ti += 1
                continue
            pos = m.end()
            if tok0 == b";":
                n_stmt += 1
                off = base + pos
                if len(buf) - pos < 4096 and not eof:
                    refill()
                dm = _BDB_RE.match(buf, pos)
                if dm:
                    cur_db = (dm.group(1) or dm.group(2) or b"dump").decode("utf-8", "replace")
                while ti < len(targets) and off >= targets[ti]:
                    if not out or out[-1][0] != off:
                        out.append((off, cur_db))
                    ti += 1
    return out, n_stmt


def _split_points(src: Path, n: int, log: Optional[Log] = None, backslash: bool = True) -> list[tuple[int, str]]:
    """[(start offset, database in effect)] for n ranges: statement boundaries found by the quote-aware scan, spread evenly."""
    size = src.stat().st_size
    step = size // n
    targets = [i * step for i in range(1, n)]
    ends, _ = scan_statement_ends(src, targets, log, backslash)
    points = [(0, "dump")] + [(o, db) for o, db in ends if 0 < o < size]
    seen = set()
    uniq = []
    for o, db in points:
        if o not in seen:
            seen.add(o)
            uniq.append((o, db))
    uniq.sort()
    return uniq


def _dump_worker(args) -> dict[str, Any]:
    src, start, end, out, idx, rows_per_file, initial_db, backslash = args
    src, out = Path(src), Path(out)
    writers: dict[tuple[str, str], TableWriter] = {}
    columns: dict[tuple[str, str], list[str]] = {}
    schema: list[str] = []
    t0 = time.time()
    last = -1

    def writer_for(db: str, table: str, cols: Optional[list[str]]) -> TableWriter:
        key = (db, table)
        w = writers.get(key)
        if w is None:
            w = writers[key] = TableWriter(out / slug(db), f"{slug(table)}.w{idx:02d}", columns.get(key) or cols or [], rows_per_file)
            w.blob_dir = out / slug(db) / f"{slug(table)}.blobs"        # every worker spills into the table's folder, under its own prefix
            w.blob_prefix = f"w{idx:02d}."
        return w

    def on_create(db: str, table: str, text: str) -> None:
        key = (db, table)
        columns[key] = columns_from_create(text)
        if key in writers and not writers[key].columns:
            writers[key].columns = columns[key]
        schema.append(text.strip() + "\n\n")

    def prog(consumed: int) -> None:
        nonlocal last
        pct = int(consumed * 100 / max(end - start, 1))
        if pct // 10 != last // 10:
            last = pct
            print(f"[db] worker {idx}: {pct}% ({sum(x.rows for x in writers.values())} rows, {time.time() - t0:.0f} s)", flush=True)

    try:
        stats = parse_mysql_dump(_byte_chunks(src, start, end), writer_for, on_create, None, prog, initial_db=initial_db, backslash=backslash)
    except Exception as e:  # noqa: BLE001
        stats = {"inserts": 0, "rows": sum(w.rows for w in writers.values()), "creates": 0, "skipped": 0, "malformed": 0, "rejected": 0, "routines": 0,
                 "notes": [f"worker {idx} stopped early: {type(e).__name__}: {str(e)[:300]}"], "error": f"{type(e).__name__}: {str(e)[:300]}"}
    tables = {}
    for key, w in writers.items():
        r = w.close()
        tables[key] = {"rows": r["rows"], "files": r["files"], "blobs": r["blobs"], "rejected": r["rejected"], "columns": list(w.columns),
                       "placeholder": bool(w.columns) and w.columns[0] == "col1" and key not in columns}
    return {"idx": idx, "tables": {f"{k[0]}\x00{k[1]}": v for k, v in tables.items()}, "columns": {f"{k[0]}\x00{k[1]}": v for k, v in columns.items()},
            "schema": "".join(schema), "seconds": round(time.time() - t0, 1), "stats": stats}


def _rewrite_header(path: Path, columns: list[str]) -> None:
    tmp = path.with_suffix(".tmp")
    with open(path, "r", encoding="utf-8-sig", newline="") as fin, open(tmp, "w", encoding="utf-8-sig", newline="") as fout:
        fin.readline()
        csv.writer(fout, lineterminator="\r\n").writerow(columns)
        shutil.copyfileobj(fin, fout, 8 * 2**20)
    tmp.replace(path)


def _remap_part(path: Path, part_cols: list[str], columns: list[str]) -> bool:
    """A worker's part written in an INSERT's own column order is rewritten in the table's (CREATE TABLE) order, by name;
    False (file untouched) when a part column is not a table column."""
    idx = {c.lower(): i for i, c in enumerate(columns)}
    if not all(c.lower() in idx for c in part_cols):
        return False
    order = [idx[c.lower()] for c in part_cols]
    tmp = path.with_suffix(".tmp")
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    with open(path, "r", encoding="utf-8-sig", newline="") as fin, open(tmp, "w", encoding="utf-8-sig", newline="") as fout:
        rd = csv.reader(fin)
        wr = csv.writer(fout, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
        next(rd, None)
        wr.writerow(columns)
        n = len(columns)
        for row in rd:
            full = [""] * n
            for i, v in zip(order, row):
                full[i] = v
            wr.writerow(full)
    tmp.replace(path)
    return True


def extract_dump_parallel(src: Path, out: Path, log: Log, workers: int, rows_per_file: int = ROWS_PER_FILE) -> dict[str, Any]:
    """Plain .sql dumps over PARALLEL_MIN_BYTES: byte ranges parsed by several processes, parts stitched in order."""
    from concurrent.futures import ProcessPoolExecutor
    t0 = time.time()
    size = src.stat().st_size
    backslash, why = detect_backslash_escapes(dump_head(src))
    log(f"[db] {src.name}: string escapes: {'backslash (MySQL default)' if backslash else 'doubled quotes only (NO_BACKSLASH_ESCAPES / PostgreSQL / T-SQL / SQLite)'} - {why}")
    points = _split_points(src, workers, log, backslash)
    bounds = [p[0] for p in points] + [size]
    ranges = [(bounds[i], bounds[i + 1], points[i][1]) for i in range(len(points)) if bounds[i + 1] > bounds[i]]
    if len(ranges) <= 1:
        log(f"[db] {src.name}: no safe split point found (statements without ';'?); parsing sequentially")
        return extract_dump(src, out, log, "mysql-dump", rows_per_file, backslash)
    log(f"[db] {src.name}: {human(size)} parsed by {len(ranges)} workers at statement boundaries")
    try:
        with ProcessPoolExecutor(max_workers=len(ranges)) as ex:
            results = list(ex.map(_dump_worker, [(str(src), a, b, str(out), i, rows_per_file, db, backslash) for i, (a, b, db) in enumerate(ranges)]))
    except Exception as e:  # noqa: BLE001 - no worker processes here (no /dev/shm, a locked-down host, a worker killed by the OOM killer):
        # the file is still read, by this process alone, from a clean export folder
        log(f"[db] {src.name}: worker processes unavailable ({type(e).__name__}: {str(e)[:200]}); parsing sequentially instead")
        for child in out.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
        return extract_dump(src, out, log, "mysql-dump", rows_per_file, backslash)
    stats = {"inserts": 0, "rows": 0, "creates": 0, "skipped": 0, "malformed": 0, "rejected": 0, "routines": 0, "notes": []}
    for r in results:
        for k in ("inserts", "rows", "creates", "skipped", "malformed", "rejected", "routines"):
            stats[k] += r["stats"].get(k, 0)
        stats["notes"] += [f"worker {r['idx']}: {n}" for n in r["stats"].get("notes", [])][:5]
    if stats["malformed"]:
        log(f"[db] {src.name}: {stats['malformed']} row(s) not understood (skipped, logged): " + "; ".join(stats["notes"][:3]))
    if stats["rejected"]:
        log(f"[db] {src.name}: {stats['rejected']} row(s) with another number of values than their table has columns: kept in <table>.rejected.csv, not in the table")
    errors = [r["stats"]["error"] for r in results if r["stats"].get("error")]
    if errors:
        log(f"[db] {src.name}: {len(errors)} worker(s) stopped early: " + "; ".join(errors[:2]))
    results.sort(key=lambda r: r["idx"])
    # columns known anywhere (CREATE TABLE) win over placeholders
    columns: dict[str, list[str]] = {}
    for r in results:
        columns.update(r["columns"])
    tables: list[dict[str, Any]] = []
    all_keys: list[str] = []
    for r in results:
        for k in r["tables"]:
            if k not in all_keys:
                all_keys.append(k)
    for k in all_keys:
        db, table = k.split("\x00", 1)
        ddir = out / slug(db)
        parts: list[Path] = []
        rows = 0
        cols_used: list[str] = []
        for r in results:
            t = r["tables"].get(k)
            if not t:
                continue
            rows += t["rows"]
            cols_used = cols_used or t["columns"]
            for fn in t["files"]:
                pth = ddir / fn
                if t.get("placeholder") and columns.get(k):
                    _rewrite_header(pth, columns[k])
                elif columns.get(k) and t["columns"] and [c.lower() for c in t["columns"]] != [c.lower() for c in columns[k]]:
                    _remap_part(pth, t["columns"], columns[k])      # this worker never saw the CREATE TABLE: its INSERT's order -> the table's
                parts.append(pth)
        final: list[str] = []
        if len(parts) == 1:
            dest = ddir / f"{slug(table)}.csv"
            parts[0].rename(dest)
            final = [dest.name]
        else:
            for i, pth in enumerate(parts, 1):
                dest = ddir / f"{slug(table)}.part{i:03d}.csv"
                pth.rename(dest)
                final.append(dest.name)
        # spilled cells were written by every worker into <table>.blobs/ under its own prefix (w00.row1.col.txt): nothing to move;
        # rejected rows of the parts are joined into one <table>.rejected.csv
        blobs = sum(t.get("blobs", 0) for t in (r["tables"].get(k) for r in results) if t)
        rejected = 0
        rej_parts = [ddir / f"{slug(table)}.w{r['idx']:02d}.rejected.csv" for r in results if r["tables"].get(k)]
        rej_parts = [p_ for p_ in rej_parts if p_.exists()]
        if rej_parts:
            dest = ddir / f"{slug(table)}.rejected.csv"
            with open(dest, "w", newline="", encoding="utf-8-sig") as fout:
                for i, p_ in enumerate(rej_parts):
                    with open(p_, "r", encoding="utf-8-sig", newline="") as fin:
                        hdr = fin.readline()
                        if i == 0:
                            fout.write(hdr)
                        shutil.copyfileobj(fin, fout, 2**20)
                    p_.unlink()
            rejected = sum(t.get("rejected", 0) for t in (r["tables"].get(k) for r in results) if t)
        tables.append({"database": db, "table": table, "rows": rows, "columns": len(columns.get(k) or cols_used), "files": final,
                       "bytes": sum((ddir / f).stat().st_size for f in final), "blobs": blobs, "rejected": rejected})
    (out / "schema.sql").write_text("".join(r["schema"] for r in results), "utf-8")
    log(f"[db] {src.name}: done - {len(tables)} tables, {sum(t['rows'] for t in tables)} rows in {(time.time() - t0) / 60:.1f} min "
        f"({stats['inserts']} INSERTs, {stats['creates']} CREATE TABLEs, {stats['skipped']} other statements skipped, {stats['malformed']} malformed)")
    r = {"tables": tables, "seconds": round(time.time() - t0, 1), "workers": len(ranges), "stats": stats}
    if errors:
        r["error"] = "partial: " + errors[0]
    return r


# --------------------------------------------------------------------------- live server (datadir)
def extract_datadir(datadir: Path, out: Path, work: Path, log: Log, custody=None, rows_per_file: int = ROWS_PER_FILE,
                    include_system: bool = False) -> dict[str, Any]:
    from .dbengine import PrivateMariaDB, SYSTEM_SCHEMAS
    tables: list[dict[str, Any]] = []
    schema: list[str] = []
    t0 = time.time()
    with PrivateMariaDB(datadir, work, log, custody) as db:
        dbs = db.schemas() + (["mysql"] if include_system else [])
        plan = []
        for d in dbs:
            for t in db.tables(d):
                plan.append((d, t))
        total_est = sum(t["rows_est"] for _, t in plan) or 1
        done_rows = 0
        log(f"[db] {len(dbs)} databases, {len(plan)} tables, about {total_est} rows (server estimate)")
        for i, (d, t) in enumerate(plan, 1):
            name = t["name"]
            if t.get("type") == "VIEW":
                schema.append(f"-- view {d}.{name}\n")
                continue
            cols = db.columns(d, name)
            schema.append(f"-- {d}.{name}\n" + db.create_table(d, name) + ";\n\n")
            w = TableWriter(out / slug(d), slug(name), cols, rows_per_file)
            err = ""
            try:
                for row in db.stream("SELECT * FROM `" + name.replace("`", "``") + "`", d):
                    w.write(row)
                    if w.rows % 250000 == 0:
                        log(f"[db] [{i}/{len(plan)}] {d}.{name}: {w.rows} rows so far ({human(sum(f.stat().st_size for f in w.files if f.exists()))})")
            except Exception as e:  # noqa: BLE001 - one broken table must not stop the rest
                err = f"{type(e).__name__}: {str(e)[:200]}"
                log(f"[db] {d}.{name}: stopped after {w.rows} rows: {err}")
                try:
                    db.connection().ping(reconnect=True)
                except Exception:  # noqa: BLE001
                    db._conn = None
            r = w.close()
            done_rows += r["rows"]
            tables.append({"database": d, "table": name, "engine": t.get("engine"), "rows": r["rows"], "rows_est": t["rows_est"],
                           "columns": len(cols), "files": r["files"], "bytes": r["bytes"], "blobs": r["blobs"], "error": err})
            log(f"[db] [{i}/{len(plan)}] {d}.{name}: {r['rows']} rows -> {', '.join(r['files'])}")
        meta = {"server_version": db.version, "force_recovery": db.level, "mode": db.mode}
    (out / "schema.sql").write_text("".join(schema), "utf-8")
    log(f"[db] datadir done - {len(tables)} tables, {sum(t['rows'] for t in tables)} rows in {(time.time() - t0) / 60:.1f} min")
    return {"tables": tables, "seconds": round(time.time() - t0, 1), **meta}


# --------------------------------------------------------------------------- sqlite / access
def extract_sqlite(src: Path, out: Path, log: Log, rows_per_file: int = ROWS_PER_FILE) -> dict[str, Any]:
    tables: list[dict[str, Any]] = []
    schema: list[str] = []
    uri = f"file:{src.as_posix()}?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    dbname = slug(src.stem)
    try:
        for name, sql in con.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
            schema.append((sql or f"-- {name}") + ";\n\n")
            cur = con.execute(f'SELECT * FROM "{name}"')
            cols = [d[0] for d in cur.description]
            w = TableWriter(out / dbname, slug(name), cols, rows_per_file)
            for row in cur:
                w.write(row)
            r = w.close()
            tables.append({"database": dbname, "table": name, "rows": r["rows"], "columns": len(cols), "files": r["files"], "bytes": r["bytes"], "blobs": r["blobs"]})
    finally:
        con.close()
    (out / "schema.sql").write_text("".join(schema), "utf-8")
    log(f"[db] {src.name}: {len(tables)} tables")
    return {"tables": tables}


def extract_access(src: Path, out: Path, log: Log) -> dict[str, Any]:
    if not shutil.which("mdb-tables"):
        raise RuntimeError("mdbtools is not installed in the distro (Access .mdb/.accdb need it)")
    names = subprocess.run(["mdb-tables", "-1", str(src)], capture_output=True, text=True, errors="replace").stdout.split()
    tables = []
    dbname = slug(src.stem)
    (out / dbname).mkdir(parents=True, exist_ok=True)
    schema = subprocess.run(["mdb-schema", str(src)], capture_output=True, text=True, errors="replace").stdout
    (out / "schema.sql").write_text(schema, "utf-8")
    for n in names:
        dest = out / dbname / f"{slug(n)}.csv"
        with open(dest, "w", encoding="utf-8-sig", newline="") as f:
            r = subprocess.run(["mdb-export", "-D", "%Y-%m-%d %H:%M:%S", str(src), n], stdout=f, stderr=subprocess.DEVNULL, text=True)
        rows = max(sum(1 for _ in open(dest, encoding="utf-8-sig")) - 1, 0)
        tables.append({"database": dbname, "table": n, "rows": rows, "columns": 0, "files": [dest.name], "bytes": dest.stat().st_size, "blobs": 0})
    return {"tables": tables}


# --------------------------------------------------------------------------- the entry point
def export_root(case, out_root: Optional[Path] = None) -> Path:
    """Where the CSV folders go: the examiner's exports folder (<exports>/<case>/db, reachable from Windows) when it is
    set and writable, else the case directory."""
    if out_root is not None:
        return Path(out_root)
    try:
        from . import settings as cfgstore
        from .winpath import to_wsl
        base, note = to_wsl(cfgstore.load(case.dir.parent)["exports"])
        if base and not note:
            root = Path(base) / case.meta.get("case_id", case.dir.name) / "db"
            root.mkdir(parents=True, exist_ok=True)
            probe = root / ".write-test"
            probe.write_text("ok")
            probe.unlink()
            return root
    except Exception:  # noqa: BLE001
        pass
    return case.dir / "db"


def extract(case, source: dict[str, Any], work: Path, log: Log = print, rows_per_file: int = ROWS_PER_FILE,
            out_root: Optional[Path] = None) -> dict[str, Any]:
    """One source -> <out_root>/<slug>/ with the CSV folders (schema, tables.csv, README) and an index copy of
    source.json / tables.csv / schema.sql in <case>/db/<slug>/. Returns the summary."""
    kind = source["kind"]
    src = Path(source["path"])
    name = export_name(source)
    root = export_root(case, out_root)
    out = root / name
    idx = case.dir / "db" / name
    # never wipe another source's export: the folder is reused only when its source.json names this same source
    for d in {out, idx}:
        sj = d / "source.json"
        if sj.exists():
            try:
                prev = json.loads(sj.read_text("utf-8"))
            except Exception:  # noqa: BLE001
                prev = {}
            if prev.get("source") not in (None, str(src)) and prev.get("rel") not in (None, source.get("rel")):
                raise RuntimeError(f"export folder {d} belongs to another source ({prev.get('source')}); not overwriting it")
    for d in {out, idx}:
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    # the folder an older build (f) used for this source - shared by every source under one long path - goes when it was
    # this source's, so the stale "0 tables" entry disappears on re-extraction
    for d in {root / legacy_export_name(source), case.dir / "db" / legacy_export_name(source)}:
        sj = d / "source.json"
        if d != out and d != idx and sj.exists():
            try:
                prev = json.loads(sj.read_text("utf-8"))
                if prev.get("source") == str(src):
                    shutil.rmtree(d)
                    log(f"[db] removed the old export folder {d} (replaced by {name})")
            except Exception:  # noqa: BLE001
                pass
    t0 = time.time()
    log(f"[db] extracting {kind} {src} -> {out}")
    case.custody.append("db_extract_started", {"kind": kind, "source": str(src), "out": str(out)})
    summary: dict[str, Any] = {"kind": kind, "source": str(src), "rel": source.get("rel"), "size": source.get("size"), "started": utc_now(),
                               "out": str(out), "name": name}
    if src.is_file():
        summary["sha256"] = _sha256(src, log)
    try:
        if kind == "mariadb-datadir":
            r = extract_datadir(src, out, work / "dbwork" / name, log, case.custody, rows_per_file)
        elif kind == "mysql8-datadir":
            r = extract_datadir(src, out, work / "dbwork" / name, log, case.custody, rows_per_file)
        elif kind in ("mysql-dump", "pg-dump"):
            workers = min(6, max(1, (os.cpu_count() or 2) - 1))
            if kind == "mysql-dump" and src.suffix.lower() == ".sql" and src.stat().st_size >= PARALLEL_MIN_BYTES and workers > 1:
                r = extract_dump_parallel(src, out, log, workers, rows_per_file)
            else:
                r = extract_dump(src, out, log, kind, rows_per_file)
        elif kind == "sqlite":
            r = extract_sqlite(src, out, log, rows_per_file)
        elif kind == "access":
            r = extract_access(src, out, log)
        else:
            raise RuntimeError(f"unknown source kind {kind}")
    except Exception as e:
        summary["error"] = f"{type(e).__name__}: {e}"
        summary["finished"] = utc_now()
        for d in (out, idx):
            (d / "source.json").write_text(json.dumps(summary, indent=2, default=str), "utf-8")
        case.custody.append("db_extract_failed", {"source": str(src), "error": summary["error"][:500]})
        log(f"[db] FAILED: {summary['error']}")
        raise
    summary.update(r)
    summary["finished"] = utc_now()
    summary["seconds"] = round(time.time() - t0, 1)
    summary["custody_head_before"] = dict(zip(("records", "hash"), case.custody.head()))
    summary["tables_total"] = len(r["tables"])
    summary["rows_total"] = sum(t["rows"] for t in r["tables"])
    with open(out / "tables.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["database", "table", "rows", "columns", "files", "bytes", "blobs", "rejected", "error"])
        for t in r["tables"]:
            w.writerow([t["database"], t["table"], t["rows"], t.get("columns", ""), "; ".join(t.get("files", [])), t.get("bytes", ""), t.get("blobs", 0), t.get("rejected", 0), t.get("error", "")])
    (out / "README.txt").write_text(
        f"Database export from case {case.meta.get('case_id')} ({case.meta.get('examiner')}), {summary['finished']}\n"
        f"Source: {src} ({kind}" + (f", {human(source.get('size', 0))}" if source.get("size") else "") + ")\n"
        + (f"SHA-256 of the source file: {summary['sha256']}\n" if summary.get("sha256") else "")
        + (f"Server used: {summary.get('server_version')} on a private copy/overlay, innodb_force_recovery={summary.get('force_recovery')}\n" if summary.get("server_version") else "")
        + "tables.csv lists every table with its row count and CSV file(s); <database>/<table>.csv holds the rows\n"
        "(UTF-8 with BOM, one header row, NULL = empty cell, tables over 1,000,000 rows split into .partNNN.csv files,\n"
        "values too big for a cell saved under <table>.blobs/, rows whose number of values does not match the table's\n"
        "columns kept in <table>.rejected.csv and counted in tables.csv). schema.sql has the table definitions.\n"
        "Excel: open a CSV through Data > From Text/CSV and set card numbers, phone numbers, IBANs and other long digit\n"
        "strings to Text, or Excel shows them as 1.23457E+15 and drops digits; the file itself is exact.\n"
        "The evidence is the primary source; these files were produced read-only from it.\n", "utf-8")
    for d in (out, idx):
        (d / "source.json").write_text(json.dumps(summary, indent=2, default=str), "utf-8")
    if out != idx:
        for fn in ("tables.csv", "schema.sql", "README.txt"):
            if (out / fn).exists():
                shutil.copy2(out / fn, idx / fn)
    case.custody.append("db_extracted", {"source": str(src), "kind": kind, "tables": summary["tables_total"], "rows": summary["rows_total"],
                                         "out": str(out), "seconds": summary["seconds"]})
    log(f"[db] done: {summary['tables_total']} tables, {summary['rows_total']} rows -> {out}")
    return summary


def _sha256(p: Path, log: Log) -> str:
    h = hashlib.sha256()
    size = p.stat().st_size
    done, last = 0, -1
    with open(p, "rb") as f:
        while True:
            b = f.read(8 * 2**20)
            if not b:
                break
            h.update(b)
            done += len(b)
            pct = int(done * 100 / max(size, 1))
            if pct // 20 != last // 20:
                last = pct
                log(f"[db] hashing {p.name}: {pct}%")
    return h.hexdigest()


def auto_pick(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What an unattended intake extracts: every datadir, sqlite and Access file, and the newest dump per name
    (backup folders hold many dated copies of the same database; older copies stay available on request)."""
    out = [s for s in sources if s["kind"] in ("mariadb-datadir", "sqlite", "access")]
    dumps = [s for s in sources if s["kind"] in ("mysql-dump", "pg-dump")]
    groups: dict[str, dict[str, Any]] = {}
    for s in dumps:
        key = re.sub(r"[\d_\-\.]+", "", Path(s["path"]).name.lower())
        try:
            mt = Path(s["path"]).stat().st_mtime
        except OSError:
            mt = 0
        s["_mtime"] = mt
        if key not in groups or mt > groups[key]["_mtime"]:
            groups[key] = s
    out += sorted(groups.values(), key=lambda s: -s.get("size", 0))
    for s in sources:
        s.pop("_mtime", None)
    return out


def list_exports(case) -> list[dict[str, Any]]:
    """Every db export in the case with its summary."""
    out = []
    base = case.dir / "db"
    if not base.exists():
        return out
    for d in sorted(base.iterdir()):
        sj = d / "source.json"
        if sj.exists():
            try:
                s = json.loads(sj.read_text("utf-8"))
            except Exception:  # noqa: BLE001
                s = {"error": "unreadable source.json"}
            s["name"] = d.name
            s["dir"] = str(d)
            out.append(s)
    return out


def search(case, needle: str, max_hits: int = 500, export: Optional[str] = None) -> list[dict[str, Any]]:
    """Case-insensitive search across every exported CSV (grep); hits carry export, database, table, line and the line text."""
    if not needle.strip():
        return []
    roots = [(e["name"], Path(e["out"])) for e in list_exports(case) if e.get("out") and Path(e["out"]).is_dir() and (not export or e["name"] == export)]
    hits: list[dict[str, Any]] = []
    for name, root in roots:
        cmd = ["grep", "-r", "-i", "-n", "-I", "-F", "--include=*.csv", "--exclude=tables.csv", "-m", str(max_hits), needle, str(root)]
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        for line in r.stdout.splitlines():
            try:
                path, lineno, text = line.split(":", 2)
            except ValueError:
                continue
            p = Path(path)
            try:
                rel = p.relative_to(root)
            except ValueError:
                rel = p
            parts = rel.parts
            hits.append({"export": name, "database": parts[0] if len(parts) > 1 else "", "table": p.stem.split(".part")[0],
                         "file": str(p), "line": int(lineno), "text": text[:600]})
            if len(hits) >= max_hits:
                return hits
    return hits


def preview(csv_path: Path, n: int = 200) -> tuple[list[str], list[list[str]]]:
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        rd = csv.reader(f)
        header = next(rd, [])
        rows = []
        for i, row in enumerate(rd):
            if i >= n:
                break
            rows.append(row)
    return header, rows
