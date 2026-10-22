"""Players: who is in this evidence, how they connect, when they were active, where the money went.

Deterministic, explainable, exact - no model involved. Sources, all already produced by Gumshoe:
  * the CSV folders of every extracted database (db/<source>/tables.csv -> <database>/<table>.csv)
  * the normalized logs (collected/jsonl/auth, collected/jsonl/web), the inventory (panel users, operation
    log, sites, system accounts, authorized keys, shell histories), the findings, the extracted document
    texts (collected/extracted/*.txt)
From them:
  entities   every validated identifier (identifiers.py), normalised, with counts, first/last seen, sources
  links      pairs of identifiers that occur in the same row / line / document (how many times, where)
  activity   per identifier per day, so timelines and bursts are a query away
  players    account-like rows (a table row holding an e-mail or username plus a name/phone/password hash)
             merged over STRONG identifiers only (e-mail, phone, wallet, password hash, IBAN, card, SSH key),
             never over IPs, usernames or names (shared infrastructure must not fuse people); IPs, domains
             and names attach as attributes with counts and a "shared with N players" mark
  money      rows of transaction-like tables (amount + wallet/txid/account reference) summed per player and
             per wallet, by currency, with counterparties
Stored in <case>/players/players.db (SQLite) and written out as CSV folders for Excel. Every table row,
log line or document a fact came from is kept as a locator so the examiner can go and look.
"""
from __future__ import annotations

import csv
import json
import os
import pickle
import re
import sqlite3
import sys
import tempfile
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from . import identifiers as idf
from .integrity import utc_now

Log = Callable[[str], None]
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))   # exported rows can carry cells far beyond csv's 128 KB default
STRONG = ("email", "phone", "wallet", "pwhash", "iban", "card", "sshkey", "txid")
ACCOUNT_TABLE_RE = re.compile(r"(user|customer|client|member|account|profile|contact|person|people|employee|staff|admin|vendor|seller|buyer|"
                              r"merchant|subscriber|registr|login|auth|ftp|panel|wallet|kyc|partner|agent|affiliate|lead|order)", re.I)
TX_TABLE_RE = re.compile(r"(trans|payment|pay|invoice|order|deposit|withdraw|transfer|txn|tx|ledger|balance|billing|charge|refund|"
                         r"payout|settle|exchange|trade|swap|sale|purchase|wallet|crypto|coin)", re.I)
SKIP_TABLE_RE = re.compile(r"(cache|session|transient|cron|option|meta$|_meta|log_?archive|queue|job|migration|schema_version|statistics|stats$)", re.I)
MAX_ROWS_TEXTSCAN = 3_000_000        # free-text regex scanning stops after this many rows per table (identifier columns continue)
MAX_IDENT_PER_ROW = 24
SAMPLE_LOCATORS = 25
MAX_ENT_PER_TABLE = 3_000_000        # distinct identifiers kept per table (memory bound; the rest still count if already known)
MAX_PAIRS_PER_TABLE = 2_000_000      # distinct identifier pairs kept per table
MAX_ACTIVITY_PER_TABLE = 3_000_000   # distinct (identifier, day) cells kept per table
WORKER_GB = 3                        # rough memory a worker may need on the biggest tables; bounds the worker count


def _day(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    s = ts.strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", s)
    if m:
        return m.group(1)
    m = re.match(r"^(\d{2})/(\d{2})/(\d{4})", s)
    if m:
        return f"{m.group(3)}-{m.group(1)}-{m.group(2)}"
    if re.fullmatch(r"1[5-9]\d{8}|20\d{8}", s):
        return time.strftime("%Y-%m-%d", time.gmtime(int(s)))
    if re.fullmatch(r"1[5-9]\d{11}", s):
        return time.strftime("%Y-%m-%d", time.gmtime(int(s) // 1000))
    return None


def _ts_norm(ts: Optional[str]) -> Optional[str]:
    """A sortable ISO-ish timestamp (YYYY-MM-DD HH:MM:SS) or None."""
    if not ts:
        return None
    s = ts.strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)", s)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    d = _day(s)
    if d and re.fullmatch(r"1[5-9]\d{8}|20\d{8}", s):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(s)))
    if d and re.fullmatch(r"1[5-9]\d{11}", s):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(s) // 1000))
    return d


# --------------------------------------------------------------------------- the accumulator (one per worker)
class Acc:
    """Counts for one source: entities, pairs, daily activity, locators, money. Memory-bounded: a table with more
    distinct identifiers, pairs or (identifier, day) cells than the caps keeps counting what it already knows and
    drops the rest (reported in the table record and the log)."""

    __slots__ = ("source", "where", "ent", "pairs", "activity", "money", "account_rows", "tables", "rows",
                 "dropped_ent", "dropped_pairs", "dropped_activity", "_days")

    def __init__(self, source: str, where: str = ""):
        self.source = source
        self.where = where                                 # locator prefix when locators are row numbers (table scans)
        self.ent: dict[tuple[str, str], list] = {}        # (type, norm) -> [value, count, first, last, role | {role: n}, [locators]]
        self.pairs: dict[tuple[tuple[str, str], tuple[str, str]], list] = {}   # -> [count, first, last, where]
        self.activity: dict[tuple[tuple[str, str], str], int] = {}             # ((type, norm), day) -> n
        self.money: list[dict[str, Any]] = []              # transaction rows (bounded)
        self.account_rows: list[dict[str, Any]] = []       # rows that describe an account/person (bounded)
        self.tables: list[dict[str, Any]] = []
        self.rows = 0
        self.dropped_ent = 0                               # identifiers not kept because the per-table cap was reached
        self.dropped_pairs = 0
        self.dropped_activity = 0
        self._days: dict[str, str] = {}                    # day strings interned (a few thousand distinct)

    def seen(self, t: str, v: str, n: str, role: str, ts: Optional[str], loc) -> Optional[tuple[str, str]]:
        k = (t, n)
        e = self.ent.get(k)
        if e is None:
            if len(self.ent) >= MAX_ENT_PER_TABLE:
                self.dropped_ent += 1
                return None
            self.ent[k] = [v, 1, ts, ts, role, [loc]]
        else:
            e[1] += 1
            if ts:
                if e[2] is None or ts < e[2]:
                    e[2] = ts
                if e[3] is None or ts > e[3]:
                    e[3] = ts
            r = e[4]
            if r.__class__ is str:
                if r != role:
                    e[4] = {r: e[1] - 1, role: 1}
            else:
                r[role] = r.get(role, 0) + 1
            locs = e[5]
            if len(locs) < SAMPLE_LOCATORS:
                locs.append(loc)
        if ts:
            d = ts[:10] if (len(ts) >= 10 and ts[4] == "-") else (_day(ts) or "")
            if d:
                d = self._days.setdefault(d, d)
                ak = (k, d)
                c = self.activity.get(ak)
                if c is None:
                    if len(self.activity) >= MAX_ACTIVITY_PER_TABLE:
                        self.dropped_activity += 1
                    else:
                        self.activity[ak] = 1
                else:
                    self.activity[ak] = c + 1
        return k

    def link(self, keys: list, ts: Optional[str], where: str) -> None:
        keys = sorted(set(k for k in keys if k))
        if len(keys) < 2 or len(keys) > MAX_IDENT_PER_ROW:
            return
        pairs = self.pairs
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                pk = (keys[i], keys[j])
                p = pairs.get(pk)
                if p is None:
                    if len(pairs) >= MAX_PAIRS_PER_TABLE:
                        self.dropped_pairs += 1
                        continue
                    p = pairs[pk] = [0, None, None, where]
                p[0] += 1
                if ts:
                    if p[1] is None or ts < p[1]:
                        p[1] = ts
                    if p[2] is None or ts > p[2]:
                        p[2] = ts

    def locator(self, loc) -> str:
        return loc if loc.__class__ is str else f"{self.where}:{loc}"


# --------------------------------------------------------------------------- CSV tables
def _read_header_and_samples(path: Path, n: int = 2000) -> tuple[list[str], list[list[str]]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        rd = csv.reader(f)
        header = next(rd, [])
        samples = []
        for i, row in enumerate(rd):
            if i >= n:
                break
            samples.append(row)
    return header, samples


def type_columns(header: list[str], samples: list[list[str]]) -> list[str]:
    cols = []
    for i, name in enumerate(header):
        vals = [r[i] for r in samples if i < len(r)]
        cols.append(idf.guess_column_type(name, vals))
    return cols


def _fk_targets(header: list[str], tables: dict[str, dict[str, Any]], this_table: str) -> dict[int, str]:
    """column index -> referenced table name, for columns like customer_id / user_id / uid when such a table exists."""
    out = {}
    names = {t.lower(): t for t in tables}
    for i, col in enumerate(header):
        m = re.match(r"^(?:id_)?([a-z0-9]+?)_?id$", col.lower())
        if not m:
            continue
        base = m.group(1)
        if base in ("", "id") or base == this_table.lower():
            continue
        for cand in (base, base + "s", base + "es", base[:-1] if base.endswith("s") else base + "s", "wp_" + base + "s", "tbl_" + base, base + "_tbl"):
            if cand in names and names[cand] != this_table:
                out[i] = names[cand]
                break
    return out


def _scan_table(args) -> str:
    """Worker: one CSV table (all its part files) -> an Acc, streamed into a pack file (its path is returned).
    A table that cannot be read is reported inside the pack (header "error") instead of sinking the build."""
    source, db, table, files, fk_maps, rows_cap, packdir = args
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))          # dump rows can carry very large text cells
    where = f"{db}.{table}"
    acc = Acc(source, where)
    try:
        return _scan_table_inner(acc, source, db, table, files, fk_maps, rows_cap, packdir)
    except Exception as e:  # noqa: BLE001 - one unreadable table must not lose the others
        acc.tables = acc.tables or [{"source": source, "database": db, "table": table, "columns": [], "types": [], "account_table": False, "tx_table": False, "files": [Path(f).name for f in files]}]
        acc.tables[0]["error"] = f"{type(e).__name__}: {str(e)[:300]}"
        acc.ent = {}; acc.pairs = {}; acc.activity = {}; acc.money = []; acc.account_rows = []
        return _pack(acc, packdir)


def _scan_table_inner(acc: Acc, source: str, db: str, table: str, files: list, fk_maps, rows_cap: int, packdir) -> str:
    where = acc.where
    header, samples = _read_header_and_samples(Path(files[0]))
    ctypes = type_columns(header, samples)
    is_account = bool(ACCOUNT_TABLE_RE.search(table)) and any(t in ("email", "username", "phone") for t in ctypes)
    is_tx = bool(TX_TABLE_RE.search(table)) and ("amount" in ctypes) or ("amount" in ctypes and any(t in ("wallet", "txid") for t in ctypes))
    date_cols = [i for i, t in enumerate(ctypes) if t == "date"]
    amount_cols = [i for i, t in enumerate(ctypes) if t == "amount"]
    cur_cols = [i for i, t in enumerate(ctypes) if t == "currency"]
    ident_cols = [(i, t) for i, t in enumerate(ctypes) if t in ("email", "phone", "ip", "wallet", "txid", "pwhash", "username", "name", "domain", "iban", "card", "handle")]
    text_cols = [i for i, t in enumerate(ctypes) if t == "text"]
    fk_cols = {int(k): v for k, v in (fk_maps or {}).items()}
    acc.tables.append({"source": source, "database": db, "table": table, "columns": header, "types": ctypes, "account_table": is_account, "tx_table": is_tx, "files": [Path(f).name for f in files]})
    rowno = 0
    for fn in files:
        with open(fn, "r", encoding="utf-8-sig", newline="") as f:
            rd = csv.reader(f)
            next(rd, None)
            for row in rd:
                rowno += 1
                if rows_cap and rowno > rows_cap:
                    break
                ts = None
                for i in date_cols:
                    if i < len(row) and row[i]:
                        ts = _ts_norm(row[i])
                        if ts:
                            break
                keys: list = []
                loc = rowno
                row_idents: dict[str, str] = {}
                for i, t in ident_cols:
                    if i >= len(row) or not row[i]:
                        continue
                    r = idf.cell_value(t, row[i])
                    if r:
                        k = acc.seen(r[0], r[1], r[2], header[i], ts, loc)
                        if k:
                            keys.append(k)
                            row_idents.setdefault(r[0], r[1])
                if rowno <= MAX_ROWS_TEXTSCAN:
                    for i in text_cols:
                        if i < len(row) and row[i] and len(row[i]) >= 5:
                            for t, v, n in idf.scan_text(row[i][:4000], header[i]):
                                k = acc.seen(t, v, n, header[i], ts, loc)
                                if k:
                                    keys.append(k)
                                    row_idents.setdefault(t, v)
                # foreign keys: the referenced account's strong identifiers join this row
                for i, target in fk_cols.items():
                    if i < len(row) and row[i]:
                        ref = fk_lookup(target, row[i])
                        for t, v, n in ref:
                            k = acc.seen(t, v, n, f"{header[i]}->{target}", ts, loc)
                            if k:
                                keys.append(k)
                                row_idents.setdefault(t, v)
                if keys:
                    acc.link(keys, ts, where)
                if is_account and len(keys) >= 1 and len(acc.account_rows) < 500_000:
                    acc.account_rows.append({"source": source, "db": db, "table": table, "row": rowno, "ts": ts, "idents": [list(k) for k in sorted(set(keys))],
                                             "label": row_idents.get("name") or row_idents.get("email") or row_idents.get("username") or row_idents.get("phone") or ""})
                if is_tx and amount_cols and len(acc.money) < 2_000_000:
                    amt = None
                    for i in amount_cols:
                        if i < len(row) and row[i]:
                            try:
                                amt = float(row[i].replace(",", "")) if not re.fullmatch(r"-?\d+", row[i]) else float(row[i])
                                break
                            except ValueError:
                                continue
                    if amt is not None and amt != 0:
                        cur = ""
                        for i in cur_cols:
                            if i < len(row) and row[i]:
                                cur = row[i].strip().upper()[:12]
                                break
                        acc.money.append({"source": source, "db": db, "table": table, "row": rowno, "ts": ts, "amount": amt, "currency": cur,
                                          "idents": [list(k) for k in sorted(set(keys))][:12]})
    acc.rows = rowno
    if acc.dropped_ent or acc.dropped_pairs or acc.dropped_activity:
        acc.tables[0]["capped"] = {"identifiers_dropped": acc.dropped_ent, "pairs_dropped": acc.dropped_pairs, "activity_dropped": acc.dropped_activity}
    return _pack(acc, packdir)


_fk_path: Optional[str] = None       # the join-table store (sqlite) - opened lazily in each worker, never shared across a fork
_fk_con: Optional[sqlite3.Connection] = None
_fk_cache: dict[tuple[str, str], list] = {}


def _init_worker(fk_path: Optional[str]):
    global _fk_path, _fk_con, _fk_cache
    _fk_path = fk_path
    _fk_con = None
    _fk_cache = {}


def fk_lookup(target: str, key: str) -> list[tuple[str, str, str]]:
    """The strong identifiers of row `key` of account table `target` (from the join store), cached per worker."""
    global _fk_con
    if not _fk_path:
        return []
    k = (target, key.strip())
    r = _fk_cache.get(k)
    if r is not None:
        return r
    if _fk_con is None:
        _fk_con = sqlite3.connect(_fk_path)
    row = _fk_con.execute("SELECT idents FROM fk WHERE tbl=? AND key=?", k).fetchone()
    r = [tuple(x) for x in json.loads(row[0])] if row else []
    if len(_fk_cache) < 300_000:
        _fk_cache[k] = r
    return r


def build_fk_cache(tables: dict[str, dict[str, Any]], log: Log, fk_db: Path, max_rows: int = 20_000_000) -> set[str]:
    """For every account-like table with an id column: id -> its identifiers (so logins.customer_id joins the customer).
    Written to the sqlite file `fk_db` (bounded memory, shared by every worker); returns the names of the keyed tables."""
    if fk_db.exists():
        fk_db.unlink()
    con = sqlite3.connect(fk_db)
    con.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-100000;"
                      "CREATE TABLE fk(tbl TEXT, key TEXT, idents TEXT, PRIMARY KEY(tbl, key)) WITHOUT ROWID;")
    keyed: set[str] = set()
    for name, t in tables.items():
        header, samples = _read_header_and_samples(Path(t["files"][0]), 500)
        ctypes = type_columns(header, samples)
        if not (ACCOUNT_TABLE_RE.search(name) and any(c in ("email", "username", "phone", "wallet", "name") for c in ctypes)):
            continue
        idc = next((i for i, h in enumerate(header) if h.lower() in ("id", "uid", "user_id", "userid", "customer_id", "account_id", "pk")), None)
        if idc is None:
            continue
        ident_cols = [(i, c) for i, c in enumerate(ctypes) if c in ("email", "phone", "wallet", "username", "name", "pwhash", "handle")]

        def rows_of():
            n = 0
            for fn in t["files"]:
                with open(fn, "r", encoding="utf-8-sig", newline="") as f:
                    rd = csv.reader(f)
                    next(rd, None)
                    for row in rd:
                        n += 1
                        if n > max_rows:
                            return
                        if idc >= len(row) or not row[idc]:
                            continue
                        vals = []
                        for i, c in ident_cols:
                            if i < len(row) and row[i]:
                                r = idf.cell_value(c, row[i])
                                if r:
                                    vals.append(r)
                        if vals:
                            yield (name, row[idc].strip(), json.dumps(vals, ensure_ascii=False))
        con.executemany("INSERT OR REPLACE INTO fk VALUES (?,?,?)", rows_of())
        n = con.execute("SELECT COUNT(*) FROM fk WHERE tbl=?", (name,)).fetchone()[0]
        if n:
            keyed.add(name)
            log(f"[players] join table {name}: {n} keyed rows")
    con.commit()
    con.close()
    return keyed


def _roles_json(r, count: int) -> str:
    if r.__class__ is str:
        return json.dumps({r: count}, ensure_ascii=False)
    return json.dumps(dict(sorted(r.items(), key=lambda x: -x[1])[:6]), ensure_ascii=False)


PACK_CHUNK = 20_000


def _pack(acc: Acc, packdir) -> str:
    """Stream the accumulator into a pack file (pickle chunks), freeing it as it goes, so neither the worker nor the
    main process ever holds a second copy. Sections, each a list of chunks: header, entities, pairs, activity,
    money, account rows."""
    fd, name = tempfile.mkstemp(prefix="pack-", suffix=".pkl", dir=str(packdir))
    with os.fdopen(fd, "wb") as f:
        def dump(obj):
            pickle.dump(obj, f, protocol=pickle.HIGHEST_PROTOCOL)

        dump({"source": acc.source, "rows": acc.rows, "tables": acc.tables,
              "n": [len(acc.ent), len(acc.pairs), len(acc.activity), len(acc.money), len(acc.account_rows)]})
        loc = acc.locator
        chunk = []
        for k, e in acc.ent.items():
            chunk.append((k[0], k[1], e[0], e[1], e[2], e[3], _roles_json(e[4], e[1]), json.dumps([loc(x) for x in e[5][:SAMPLE_LOCATORS]], ensure_ascii=False)))
            if len(chunk) >= PACK_CHUNK:
                dump(chunk); chunk = []
        dump(chunk); chunk = []
        acc.ent = {}
        for (a, b), pr in acc.pairs.items():
            chunk.append((a[0], a[1], b[0], b[1], pr[0], pr[1], pr[2], pr[3]))
            if len(chunk) >= PACK_CHUNK:
                dump(chunk); chunk = []
        dump(chunk); chunk = []
        acc.pairs = {}
        for (k, d), n in acc.activity.items():
            chunk.append((k[0], k[1], d, n))
            if len(chunk) >= PACK_CHUNK:
                dump(chunk); chunk = []
        dump(chunk); chunk = []
        acc.activity = {}
        for m in acc.money:
            chunk.append((m["source"], m["db"], m["table"], m["row"], m["ts"], m["amount"], m["currency"], json.dumps(m["idents"], ensure_ascii=False)))
            if len(chunk) >= PACK_CHUNK:
                dump(chunk); chunk = []
        dump(chunk); chunk = []
        acc.money = []
        for r in acc.account_rows:
            chunk.append((r["source"], r["db"], r["table"], r["row"], r["ts"], r["label"], json.dumps(r["idents"], ensure_ascii=False)))
            if len(chunk) >= PACK_CHUNK:
                dump(chunk); chunk = []
        dump(chunk)
        acc.account_rows = []
    return name


class Pack:
    """Reader of a pack file: the header, then each section as a generator (consume the sections in order)."""

    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "rb")
        self.head = pickle.load(self.f)   # written by this build's own workers

    def section(self) -> Iterator[tuple]:
        while True:
            chunk = pickle.load(self.f)
            if not chunk:
                return
            yield from chunk
            if len(chunk) < PACK_CHUNK:
                return

    def close(self, delete: bool = True):
        self.f.close()
        if delete:
            try:
                os.unlink(self.path)
            except OSError:
                pass


# --------------------------------------------------------------------------- other sources (logs, inventory, documents)
def scan_logs_and_inventory(case, log: Log, packdir) -> str:
    acc = Acc("system")
    # auth log: user <-> ip per event
    auth = case.collected / "jsonl" / "auth" / "auth.jsonl"
    if auth.exists():
        n = 0
        with open(auth, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                try:
                    e = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                msg = e.get("message") or ""
                ts = _ts_norm(e.get("timestamp"))
                loc = f"auth.log:{e.get('line', i)}"
                keys = []
                m = re.search(r"(?:Accepted|Failed|Invalid user|session opened for user|for invalid user|for)\s+(?:\w+\s+for\s+)?(?:invalid user\s+)?([A-Za-z0-9._-]+)\s+from\s+(\S+)", msg)
                if m:
                    keys.append(acc.seen("username", m.group(1), m.group(1).lower(), "sshd", ts, loc))
                    r = idf.cell_value("ip", m.group(2))
                    if r:
                        keys.append(acc.seen(r[0], r[1], r[2], "sshd", ts, loc))
                else:
                    for t, v, nn in idf.scan_text(msg, "auth"):
                        keys.append(acc.seen(t, v, nn, "auth", ts, loc))
                if keys:
                    acc.link(keys, ts, "auth.log")
                n += 1
        log(f"[players] auth log: {n} lines")
    # web logs: ip (+ username) per request, aggregated per day
    webdir = case.collected / "jsonl" / "web"
    if webdir.exists():
        n = 0
        for fn in sorted(webdir.glob("*.jsonl")):
            with open(fn, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    try:
                        e = json.loads(line)
                    except Exception:  # noqa: BLE001
                        continue
                    ts = _ts_norm(e.get("timestamp"))
                    ip = e.get("c-ip") or e.get("ip")
                    keys = []
                    if ip:
                        r = idf.cell_value("ip", str(ip))
                        if r:
                            keys.append(acc.seen(r[0], r[1], r[2], f"web:{fn.stem}", ts, f"{fn.name}:{i}"))
                    u = e.get("username")
                    if u and u not in ("-", "null"):
                        keys.append(acc.seen("username", str(u), str(u).lower(), f"web:{fn.stem}", ts, f"{fn.name}:{i}"))
                    q = (e.get("c-uri-query") or e.get("cs-uri-query") or "")
                    if q and ("@" in q or "0x" in q):
                        for t, v, nn in idf.scan_text(q[:2000], "query"):
                            keys.append(acc.seen(t, v, nn, f"web:{fn.stem}", ts, f"{fn.name}:{i}"))
                    if keys:
                        acc.link(keys, ts, f"web:{fn.stem}")
                    n += 1
        log(f"[players] web logs: {n} requests")
    inv = case.read_json("inventory.json", {}) or {}
    aa = inv.get("aapanel") or {}
    for u in aa.get("users") or []:
        keys = []
        ts = _ts_norm(str(u.get("login_time") or ""))
        loc = "panel:users"
        for t, col in (("username", "username"), ("email", "email"), ("ip", "login_ip")):
            v = u.get(col)
            if v:
                r = idf.cell_value(t, str(v))
                if r:
                    keys.append(acc.seen(r[0], r[1], r[2], f"panel user.{col}", ts, loc))
        acc.link(keys, ts, "panel users")
        if keys:
            acc.account_rows.append({"source": "system", "db": "panel", "table": "users", "row": u.get("id"), "ts": ts, "idents": [list(k) for k in keys], "label": u.get("username") or ""})
    for e in aa.get("operation_log_sample") or []:
        ts = _ts_norm(str(e.get("addtime") or ""))
        for t, v, nn in idf.scan_text(str(e.get("log") or ""), "panel log"):
            acc.seen(t, v, nn, "panel operation log", ts, f"panel:logs:{e.get('id')}")
    for s in aa.get("sites") or []:
        ts = _ts_norm(str(s.get("addtime") or ""))
        r = idf.cell_value("domain", str(s.get("name") or ""))
        if r:
            acc.seen(r[0], r[1], r[2], "panel site", ts, f"panel:sites:{s.get('id')}")
    for f_ in (aa.get("ftps") or []):
        r = idf.cell_value("username", str(f_.get("name") or f_.get("username") or ""))
        if r:
            acc.seen(r[0], r[1], r[2], "panel ftp account", _ts_norm(str(f_.get("addtime") or "")), f"panel:ftps:{f_.get('id')}")
    sysd = inv.get("system") or {}
    for a in sysd.get("accounts") or []:
        if a.get("shell") and "nologin" not in a["shell"] and "false" not in a["shell"]:
            acc.seen("username", a["user"], a["user"].lower(), "os account (shell)", None, f"/etc/passwd:{a.get('line')}")
    for ak in sysd.get("authorized_keys") or []:
        for k in ak.get("keys") or []:
            keys = [acc.seen("sshkey", k["fingerprint"], k["fingerprint"], "authorized_keys", _ts_norm(ak.get("mtime")), f"{ak['file']}:{k.get('line')}")]
            for t, v, nn in idf.scan_text(k.get("comment") or "", "comment"):
                keys.append(acc.seen(t, v, nn, "authorized_keys comment", None, f"{ak['file']}:{k.get('line')}"))
            m = re.match(r"^/(?:home/([^/]+)|(root))/", ak["file"])
            if m:
                u = m.group(1) or m.group(2)
                keys.append(acc.seen("username", u, u.lower(), "authorized_keys owner", None, ak["file"]))
            acc.link(keys, None, "authorized_keys")
    au = inv.get("auth") or {}
    for ip, info in (au.get("sources") or {}).items():
        for ev in (info.get("accepted") or [])[:200]:
            keys = []
            r = idf.cell_value("ip", ip)
            if r:
                keys.append(acc.seen(r[0], r[1], r[2], "ssh accepted", _ts_norm(ev.get("ts")), f"{ev.get('file')}:{ev.get('line')}"))
            if ev.get("user"):
                keys.append(acc.seen("username", ev["user"], ev["user"].lower(), "ssh accepted", _ts_norm(ev.get("ts")), f"{ev.get('file')}:{ev.get('line')}"))
            acc.link(keys, _ts_norm(ev.get("ts")), "auth accepted")
    # shell histories and other text artifacts on the mount
    for h in sysd.get("shell_history") or []:
        p = case.abs(h["file"]) if h.get("file") else None
        if p and p.is_file() and p.stat().st_size < 5 * 2**20:
            try:
                text = p.read_text("utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                keys = [acc.seen("username", h["user"], h["user"].lower(), "shell history owner", None, f"{h['file']}:{i}")] if h.get("user") else []
                for t, v, nn in idf.scan_text(line, "history"):
                    keys.append(acc.seen(t, v, nn, "shell history", None, f"{h['file']}:{i}"))
                if len(keys) > 1:
                    acc.link(keys, None, "shell history")
    # findings excerpts
    for fd in case.read_findings():
        ex = (fd.get("excerpt") or "")[:3000]
        if ex:
            ts = _ts_norm(fd.get("ctime") or fd.get("mtime"))
            keys = [acc.seen(t, v, nn, f"finding {fd.get('rule')}", ts, f"finding:{fd['id']}") for t, v, nn in idf.scan_text(ex, fd.get("path") or "")]
            acc.link(keys, ts, f"finding {fd.get('rule')}")
    return _pack(acc, packdir)


def scan_documents(case, log: Log, packdir, max_docs: int = 50_000) -> str:
    acc = Acc("documents")
    doc = case.read_json("documents.json", {}) or {}
    ext_dir = case.collected / "extracted"
    n = 0
    for it in (doc.get("items") or [])[:max_docs]:
        sha = it.get("sha256")
        if not sha:
            continue
        p = ext_dir / f"{sha}.txt"
        if not p.exists():
            continue
        try:
            text = p.read_text("utf-8", errors="replace")[:2_000_000]
        except OSError:
            continue
        ts = _ts_norm(it.get("mtime"))
        keys = [acc.seen(t, v, nn, "document", ts, it.get("path") or sha) for t, v, nn in idf.scan_text(text, it.get("path") or "")]
        if len(keys) > 1:
            acc.link(keys, ts, "document")
        n += 1
    log(f"[players] documents scanned: {n}")
    return _pack(acc, packdir)


# --------------------------------------------------------------------------- the store
SCHEMA = """
CREATE TABLE IF NOT EXISTS entities(id INTEGER PRIMARY KEY, type TEXT, norm TEXT, value TEXT, count INTEGER, first_seen TEXT, last_seen TEXT,
    sources INTEGER, roles TEXT, player_id INTEGER, UNIQUE(type, norm));
CREATE TABLE IF NOT EXISTS mentions(entity_id INTEGER, source TEXT, count INTEGER, first_seen TEXT, last_seen TEXT, roles TEXT, locators TEXT,
    PRIMARY KEY(entity_id, source));
CREATE TABLE IF NOT EXISTS links(a INTEGER, b INTEGER, source TEXT, count INTEGER, first_seen TEXT, last_seen TEXT, where_ TEXT, PRIMARY KEY(a, b, source, where_));
CREATE TABLE IF NOT EXISTS activity(entity_id INTEGER, day TEXT, source TEXT, count INTEGER, PRIMARY KEY(entity_id, day, source));
CREATE TABLE IF NOT EXISTS players(id INTEGER PRIMARY KEY, label TEXT, kind TEXT, score REAL, first_seen TEXT, last_seen TEXT, n_entities INTEGER,
    n_links INTEGER, sources TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS player_entities(player_id INTEGER, entity_id INTEGER, role TEXT, PRIMARY KEY(player_id, entity_id));
CREATE TABLE IF NOT EXISTS account_rows(player_id INTEGER, source TEXT, db TEXT, table_ TEXT, row INTEGER, ts TEXT, label TEXT, idents TEXT);
CREATE TABLE IF NOT EXISTS money(id INTEGER PRIMARY KEY, source TEXT, db TEXT, table_ TEXT, row INTEGER, ts TEXT, amount REAL, currency TEXT, idents TEXT, player_id INTEGER);
CREATE TABLE IF NOT EXISTS tables_(source TEXT, db TEXT, table_ TEXT, columns TEXT, types TEXT, account_table INTEGER, tx_table INTEGER, rows INTEGER, files TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS ix_ent_norm ON entities(norm);
CREATE INDEX IF NOT EXISTS ix_ent_player ON entities(player_id);
CREATE INDEX IF NOT EXISTS ix_links_a ON links(a); CREATE INDEX IF NOT EXISTS ix_links_b ON links(b);
CREATE INDEX IF NOT EXISTS ix_act_ent ON activity(entity_id); CREATE INDEX IF NOT EXISTS ix_act_day ON activity(day);
CREATE INDEX IF NOT EXISTS ix_money_player ON money(player_id);
CREATE INDEX IF NOT EXISTS ix_pe_entity ON player_entities(entity_id);
CREATE INDEX IF NOT EXISTS ix_ar_player ON account_rows(player_id);
CREATE INDEX IF NOT EXISTS ix_ent_type ON entities(type);
"""


def db_path(case) -> Path:
    d = case.dir / "players"
    d.mkdir(exist_ok=True)
    return d / "players.db"


def _connect(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=OFF; PRAGMA temp_store=FILE; PRAGMA cache_size=-200000;")
    con.executescript(SCHEMA)
    return con


class Store:
    """players.db writer. Each packed accumulator is merged through temp tables and set operations inside SQLite,
    so the main process never holds an id map of every identifier."""

    def __init__(self, path: Path):
        self.con = _connect(path)
        self.con.executescript("""
            CREATE TEMP TABLE inc_e(type TEXT, norm TEXT, value TEXT, count INTEGER, first_seen TEXT, last_seen TEXT, roles TEXT, locators TEXT);
            CREATE TEMP TABLE inc_p(ta TEXT, na TEXT, tb TEXT, nb TEXT, count INTEGER, first_seen TEXT, last_seen TEXT, where_ TEXT);
            CREATE TEMP TABLE inc_a(type TEXT, norm TEXT, day TEXT, count INTEGER);
        """)

    def merge(self, pack_path: str) -> dict[str, Any]:
        """Merge one pack file (streamed; deleted afterwards). Returns its header."""
        pk = Pack(pack_path)
        head = pk.head
        src = head["source"]
        con = self.con
        try:
            con.execute("DELETE FROM inc_e"); con.execute("DELETE FROM inc_p"); con.execute("DELETE FROM inc_a")
            con.executemany("INSERT INTO inc_e VALUES (?,?,?,?,?,?,?,?)", pk.section())
            con.execute("INSERT INTO entities(type, norm, value, count, first_seen, last_seen, sources, roles) "
                        "SELECT type, norm, value, count, first_seen, last_seen, 1, '' FROM inc_e WHERE true "
                        "ON CONFLICT(type, norm) DO UPDATE SET count=count+excluded.count, sources=sources+1, "
                        "first_seen=CASE WHEN first_seen IS NULL OR (excluded.first_seen IS NOT NULL AND excluded.first_seen<first_seen) THEN excluded.first_seen ELSE first_seen END, "
                        "last_seen=CASE WHEN last_seen IS NULL OR (excluded.last_seen IS NOT NULL AND excluded.last_seen>last_seen) THEN excluded.last_seen ELSE last_seen END")
            con.execute("INSERT OR REPLACE INTO mentions(entity_id, source, count, first_seen, last_seen, roles, locators) "
                        "SELECT e.id, ?, i.count, i.first_seen, i.last_seen, i.roles, i.locators FROM inc_e i JOIN entities e ON e.type=i.type AND e.norm=i.norm", (src,))
            con.executemany("INSERT INTO inc_p VALUES (?,?,?,?,?,?,?,?)", pk.section())
            con.execute("INSERT INTO links(a, b, source, count, first_seen, last_seen, where_) "
                        "SELECT MIN(ea.id, eb.id), MAX(ea.id, eb.id), ?, p.count, p.first_seen, p.last_seen, p.where_ FROM inc_p p "
                        "JOIN entities ea ON ea.type=p.ta AND ea.norm=p.na JOIN entities eb ON eb.type=p.tb AND eb.norm=p.nb WHERE true "
                        "ON CONFLICT(a, b, source, where_) DO UPDATE SET count=count+excluded.count, "
                        "first_seen=CASE WHEN first_seen IS NULL OR (excluded.first_seen IS NOT NULL AND excluded.first_seen<first_seen) THEN excluded.first_seen ELSE first_seen END, "
                        "last_seen=CASE WHEN last_seen IS NULL OR (excluded.last_seen IS NOT NULL AND excluded.last_seen>last_seen) THEN excluded.last_seen ELSE last_seen END", (src,))
            con.executemany("INSERT INTO inc_a VALUES (?,?,?,?)", pk.section())
            con.execute("INSERT INTO activity(entity_id, day, source, count) SELECT e.id, a.day, ?, a.count FROM inc_a a JOIN entities e ON e.type=a.type AND e.norm=a.norm WHERE true "
                        "ON CONFLICT(entity_id, day, source) DO UPDATE SET count=count+excluded.count", (src,))
            con.executemany("INSERT INTO money(source, db, table_, row, ts, amount, currency, idents) VALUES (?,?,?,?,?,?,?,?)", pk.section())
            con.executemany("INSERT INTO account_rows(player_id, source, db, table_, row, ts, label, idents) VALUES (NULL,?,?,?,?,?,?,?)", pk.section())
            con.executemany("INSERT INTO tables_(source, db, table_, columns, types, account_table, tx_table, rows, files) VALUES (?,?,?,?,?,?,?,?,?)",
                            ((t["source"], t["database"], t["table"], json.dumps(t["columns"], ensure_ascii=False), json.dumps(t["types"]), int(t["account_table"]), int(t["tx_table"]),
                              head["rows"], json.dumps(t["files"])) for t in head["tables"]))
            con.execute("DELETE FROM inc_e"); con.execute("DELETE FROM inc_p"); con.execute("DELETE FROM inc_a")
            con.commit()
        finally:
            pk.close()
        return head

    def close(self):
        self.con.commit()
        self.con.close()


# --------------------------------------------------------------------------- players (union over strong identifiers)
class _UF:
    def __init__(self):
        self.p: dict[int, int] = {}

    def find(self, x: int) -> int:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


LINKABLE = frozenset(("ipv4", "ipv6", "domain", "url", "username", "name", "handle", "wallet", "txid", "sshkey", "phone", "email", "iban", "card", "pwhash"))
MAX_LINKED = 6_000_000               # (player, linked identifier) cells kept while deriving (memory bound)
MAX_ACCOUNT_ROWS = 4_000_000         # account rows considered for players (memory bound)


def _batched(it: Iterator, n: int = 50_000) -> Iterator[list]:
    buf = []
    for x in it:
        buf.append(x)
        if len(buf) >= n:
            yield buf
            buf = []
    if buf:
        yield buf


def derive_players(con: sqlite3.Connection, log: Log, shared_ip_threshold: int = 8) -> int:
    """Account rows -> players. Rows merge when they share a strong identifier (e-mail, phone, wallet, password hash, IBAN,
    card, SSH key); nothing merges over IPs, usernames or names. A strong identifier seen in too many rows (a placeholder
    e-mail like noreply@..., a default password hash) is demoted: it links nothing."""
    con.execute("DELETE FROM players"); con.execute("DELETE FROM player_entities"); con.execute("UPDATE entities SET player_id=NULL")
    con.execute("UPDATE account_rows SET player_id=NULL"); con.execute("UPDATE money SET player_id=NULL")
    rows = con.execute("SELECT rowid, idents, label, ts, db, table_ FROM account_rows LIMIT ?", (MAX_ACCOUNT_ROWS,)).fetchall()
    n_rows = len(rows)
    if n_rows >= MAX_ACCOUNT_ROWS:
        log(f"[players] account rows capped at {MAX_ACCOUNT_ROWS} (memory bound)")
    # how many account rows each strong identifier appears in: promiscuous ones are not glue
    occ: Counter = Counter()
    row_keys: list[list[tuple[str, str]]] = []
    for rid, idents, *_ in rows:
        ks = [tuple(k) for k in json.loads(idents)]
        row_keys.append(ks)
        for k in set(ks):
            if k[0] in STRONG:
                occ[k] += 1
    promiscuous = {k for k, c in occ.items() if c > 50}
    del occ
    uf = _UF()
    key_root: dict[tuple[str, str], int] = {}
    for i, ks in enumerate(row_keys):
        for k in ks:
            if k[0] in STRONG and k not in promiscuous:
                if k in key_root:
                    uf.union(key_root[k], i)
                else:
                    key_root[k] = i
    del key_root
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(rows)):
        groups[uf.find(i)].append(i)
    del uf
    # entity ids for the keys of the account rows only (not the whole entity table)
    con.execute("CREATE TEMP TABLE IF NOT EXISTS need(type TEXT, norm TEXT, PRIMARY KEY(type, norm)) WITHOUT ROWID")
    con.execute("DELETE FROM need")
    con.executemany("INSERT OR IGNORE INTO need VALUES (?,?)", (k for ks in row_keys for k in ks))
    ent_ids = {(t, n): i for i, t, n in con.execute("SELECT e.id, e.type, e.norm FROM need nd JOIN entities e ON e.type=nd.type AND e.norm=nd.norm")}
    con.execute("DELETE FROM need")
    pid = 0
    players_rows, pe_rows, row_updates, strong_updates = [], [], [], []
    for root, members in groups.items():
        pid += 1
        keys: Counter = Counter()
        labels: Counter = Counter()
        sources: Counter = Counter()
        first = last = None
        for i in members:
            rid, idents, label, ts, db, table = rows[i]
            for k in row_keys[i]:
                keys[k] += 1
            if label:
                labels[label] += 1
            sources[f"{db}.{table}"] += 1
            if ts:
                first = ts if first is None or ts < first else first
                last = ts if last is None or ts > last else last
            row_updates.append((pid, rid))
        label = labels.most_common(1)[0][0] if labels else next((k[1] for k in keys if k[0] == "email"), None) or f"player {pid}"
        kind = "account" if any(k[0] in ("email", "username") for k in keys) else "contact"
        players_rows.append((pid, label, kind, 0.0, first, last, len(keys), 0, json.dumps(dict(sources.most_common(10)), ensure_ascii=False), ""))
        for k in keys:
            eid = ent_ids.get(k)
            if eid is None:
                continue
            role = "strong" if k[0] in STRONG and k not in promiscuous else ("attribute" if k[0] in ("name", "username", "handle", "domain", "url") else "weak")
            pe_rows.append((pid, eid, role))
            if role == "strong":
                strong_updates.append((pid, eid))
        if len(players_rows) >= 20_000:
            con.executemany("INSERT INTO players(id, label, kind, score, first_seen, last_seen, n_entities, n_links, sources, summary) VALUES (?,?,?,?,?,?,?,?,?,?)", players_rows)
            con.executemany("INSERT OR IGNORE INTO player_entities(player_id, entity_id, role) VALUES (?,?,?)", pe_rows)
            players_rows, pe_rows = [], []
    con.executemany("INSERT INTO players(id, label, kind, score, first_seen, last_seen, n_entities, n_links, sources, summary) VALUES (?,?,?,?,?,?,?,?,?,?)", players_rows)
    con.executemany("INSERT OR IGNORE INTO player_entities(player_id, entity_id, role) VALUES (?,?,?)", pe_rows)
    con.executemany("UPDATE account_rows SET player_id=? WHERE rowid=?", row_updates)
    con.executemany("UPDATE entities SET player_id=? WHERE id=? AND player_id IS NULL", strong_updates)
    del rows, row_keys, groups, ent_ids, players_rows, pe_rows, row_updates, strong_updates
    con.commit()
    # linked identifiers (IPs, wallets, domains...) reached through row/line co-occurrence with the player's strong identifiers
    ent_player = {i: p for i, p in con.execute("SELECT entity_id, player_id FROM player_entities WHERE role='strong'")}
    linked: dict[tuple[int, int], list] = {}
    dropped = 0
    for a, b, c, f, l, ta, tb in con.execute("SELECT l.a, l.b, SUM(l.count), MIN(l.first_seen), MAX(l.last_seen), ea.type, eb.type FROM links l "
                                             "JOIN entities ea ON ea.id=l.a JOIN entities eb ON eb.id=l.b GROUP BY l.a, l.b"):
        for src_e, other, ot in ((a, b, tb), (b, a, ta)):
            p = ent_player.get(src_e)
            if p is None or other in ent_player or ot not in LINKABLE:
                continue
            k = (p, other)
            cur = linked.get(k)
            if cur is None:
                if len(linked) >= MAX_LINKED:
                    dropped += 1
                    continue
                linked[k] = [c, f, l]
            else:
                cur[0] += c
                cur[1] = min(x for x in (cur[1], f) if x) if (cur[1] or f) else None
                cur[2] = max(x for x in (cur[2], l) if x) if (cur[2] or l) else None
    if dropped:
        log(f"[players] linked identifiers capped: {dropped} (player, identifier) pairs not kept")
    per_entity_players: Counter = Counter(other for (_, other) in linked)
    ent_type = {}
    for batch in _batched(iter(per_entity_players), 5000):
        qs = ",".join("?" * len(batch))
        ent_type.update({i: t for i, t in con.execute(f"SELECT id, type FROM entities WHERE id IN ({qs})", batch)})
    con.executemany("INSERT OR IGNORE INTO player_entities(player_id, entity_id, role) VALUES (?,?,?)",
                    ((p, other, "shared" if (ent_type.get(other) in ("ipv4", "ipv6") and per_entity_players[other] >= shared_ip_threshold) else "linked")
                     for (p, other) in linked))
    del linked, per_entity_players, ent_type
    con.commit()
    # money -> player (by any of the row's identifiers that belong to one player; wallets/txids/accounts also through 'linked')
    key_player: dict[tuple[str, str], int] = {}
    for p, t, n in con.execute("SELECT pe.player_id, e.type, e.norm FROM player_entities pe JOIN entities e ON e.id=pe.entity_id WHERE pe.role='strong'"):
        key_player.setdefault((t, n), p)
    any_player: dict[tuple[str, str], int] = {}
    for p, t, n in con.execute("SELECT pe.player_id, e.type, e.norm FROM player_entities pe JOIN entities e ON e.id=pe.entity_id "
                               "WHERE pe.role IN ('strong','linked') AND e.type IN ('wallet','txid','iban','card')"):
        any_player.setdefault((t, n), p)
    money_updates = []
    for mid, idents in con.execute("SELECT id, idents FROM money"):
        cands: Counter = Counter()
        for k in json.loads(idents):
            k = tuple(k)
            p = key_player.get(k)
            if p is None and k[0] in ("wallet", "txid", "iban", "card"):
                p = any_player.get(k)
            if p is not None:
                cands[p] += 1
        if cands:
            money_updates.append((cands.most_common(1)[0][0], mid))
    con.executemany("UPDATE money SET player_id=? WHERE id=?", money_updates)
    del key_player, any_player, money_updates
    # scores: activity + reach, set-based
    n_links = dict(con.execute("SELECT player_id, COUNT(*) FROM player_entities WHERE role IN ('linked','shared') GROUP BY player_id"))
    act = dict(con.execute("SELECT pe.player_id, SUM(a.count) FROM activity a JOIN player_entities pe ON pe.entity_id=a.entity_id WHERE pe.role='strong' GROUP BY pe.player_id"))
    money_n = dict(con.execute("SELECT player_id, COUNT(*) FROM money WHERE player_id IS NOT NULL GROUP BY player_id"))
    span = {p: (f, l) for p, f, l in con.execute("SELECT pe.player_id, MIN(e.first_seen), MAX(e.last_seen) FROM entities e JOIN player_entities pe ON pe.entity_id=e.id "
                                                 "WHERE pe.role='strong' GROUP BY pe.player_id")}
    con.executemany("UPDATE players SET n_links=?, score=?, first_seen=COALESCE(first_seen, ?), last_seen=COALESCE(?, last_seen) WHERE id=?",
                    ((n_links.get(p, 0), (act.get(p) or 0) + 5 * n_links.get(p, 0) + 3 * money_n.get(p, 0), span.get(p, (None, None))[0], span.get(p, (None, None))[1], p)
                     for p in range(1, pid + 1)))
    con.commit()
    log(f"[players] {pid} players from {n_rows} account rows ({len(promiscuous)} promiscuous identifiers ignored as glue)")
    return pid


# --------------------------------------------------------------------------- build
def _cap_note(head: dict[str, Any]) -> str:
    c = head["tables"][0].get("capped") if head.get("tables") else None
    if not c:
        return ""
    return (f" (capped: {c['identifiers_dropped']} more identifiers, {c['pairs_dropped']} more pairs and {c.get('activity_dropped', 0)} more day cells "
            f"not kept - the table is bigger than the per-table memory bound)")


def _mem_available_gb() -> float:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 2**20
    except OSError:
        pass
    return 8.0


def _worker_count() -> int:
    """Workers: one per CPU minus one, at most 6, and never more than the memory allows (WORKER_GB each, the main process kept aside)."""
    by_cpu = max(1, (os.cpu_count() or 2) - 1)
    by_mem = max(1, int((_mem_available_gb() - 2) // WORKER_GB))
    return max(1, min(6, by_cpu, by_mem))


def build(case, log: Log = print, workers: Optional[int] = None) -> dict[str, Any]:
    from . import dbexport
    t0 = time.time()
    path = db_path(case)
    if path.exists():
        path.unlink()
        for ext in ("-wal", "-shm"):
            Path(str(path) + ext).unlink(missing_ok=True)
    store = Store(path)
    log("[players] start")
    # tables from every db export
    jobs = []
    exports = dbexport.list_exports(case)
    tables_by_name: dict[str, dict[str, Any]] = {}
    listed = 0
    missing_example = ""
    for e in exports:
        out = Path(e.get("out") or "")
        tcsv = Path(e["dir"]) / "tables.csv"
        if not tcsv.exists() or not out.is_dir():
            continue
        with open(tcsv, "r", encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                if not r.get("files") or SKIP_TABLE_RE.search(r["table"] or ""):
                    continue
                listed += 1
                files = [str(out / dbexport.slug(r["database"]) / fn.strip()) for fn in r["files"].split(";") if fn.strip()]
                present = [fn for fn in files if Path(fn).exists()]
                if not present:
                    missing_example = missing_example or (files[0] if files else "")
                    continue
                files = present
                tables_by_name[r["table"]] = {"source": e["name"], "db": r["database"], "files": files}
                jobs.append((e["name"], r["database"], r["table"], files))
    log(f"[players] {len(jobs)} tables from {len(exports)} database export(s)" + (f"; {listed - len(jobs)} listed table(s) skipped" if listed > len(jobs) else ""))
    if exports and not jobs:
        for e in exports:
            out = Path(e.get("out") or "")
            tcsv = Path(e["dir"]) / "tables.csv"
            log(f"[players]   export {e['name']}: tables.csv {'found' if tcsv.exists() else 'MISSING'} at {tcsv}; CSV folder {out} {'exists' if out.is_dir() else 'MISSING'}"
                + (f" (first missing file: {missing_example})" if missing_example else ""))
        log("[players]   nothing to scan: the CSV folders of the exports are not where source.json says (exports folder moved or unmounted?). "
            "Databases tab -> Extract again, or Hopper -> Folders to point the exports folder at the drive.")
    fk_db = path.parent / "fk.sqlite"
    keyed = build_fk_cache({n: t for n, t in tables_by_name.items()}, log, fk_db) if jobs else set()
    fk_maps = {}
    for src, db, table, files in jobs:
        header, _ = _read_header_and_samples(Path(files[0]), 1)
        m = _fk_targets(header, {n: t for n, t in tables_by_name.items() if n in keyed}, table)
        if m:
            fk_maps[(src, db, table)] = {str(k): v for k, v in m.items()}
    n_workers = workers or _worker_count()
    # biggest tables first: one per worker while the small ones fill the gaps
    jobs.sort(key=lambda j: -sum(Path(f).stat().st_size for f in j[3]))
    packdir = path.parent / "packs"
    packdir.mkdir(exist_ok=True)
    for old in packdir.glob("pack-*.pkl"):
        old.unlink(missing_ok=True)
    args = [(src, db, table, files, fk_maps.get((src, db, table), {}), 0, str(packdir)) for src, db, table, files in jobs]
    done = 0

    def _report(pack_path: str):
        nonlocal done
        head = store.merge(pack_path)
        done += 1
        t = head["tables"][0]
        if t.get("error"):
            log(f"[players] [{done}/{len(args)}] {t['database']}.{t['table']}: NOT READ - {t['error']}")
            return
        log(f"[players] [{done}/{len(args)}] {t['database']}.{t['table']}: {head['rows']} rows, {head['n'][0]} identifiers" + _cap_note(head))

    if args:
        if n_workers > 1 and len(args) > 1:
            from concurrent.futures import FIRST_COMPLETED, wait
            log(f"[players] scanning with {n_workers} workers")
            with ProcessPoolExecutor(max_workers=n_workers, initializer=_init_worker, initargs=(str(fk_db) if keyed else None,)) as ex:
                pending = set()
                queue = list(args)
                while queue or pending:
                    while queue and len(pending) < n_workers:       # at most n_workers results in flight (memory bound)
                        pending.add(ex.submit(_scan_table, queue.pop(0)))
                    finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for fut in finished:
                        _report(fut.result())
        else:
            _init_worker(str(fk_db) if keyed else None)
            for a in args:
                _report(_scan_table(a))
    _init_worker(None)
    store.merge(scan_logs_and_inventory(case, log, packdir))
    store.merge(scan_documents(case, log, packdir))
    n_players = derive_players(store.con, log)
    stats = {"entities": store.con.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
             "links": store.con.execute("SELECT COUNT(*) FROM links").fetchone()[0],
             "players": n_players, "money_rows": store.con.execute("SELECT COUNT(*) FROM money").fetchone()[0],
             "tables": len(jobs), "seconds": round(time.time() - t0, 1), "built": utc_now()}
    for k, v in stats.items():
        store.con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?,?)", (k, str(v)))
    store.close()
    fk_db.unlink(missing_ok=True)
    try:
        packdir.rmdir()
    except OSError:
        pass
    write_outputs(case, log)
    case.custody.append("players_built", stats)
    log(f"[players] done: {stats['players']} players, {stats['entities']} identifiers, {stats['links']} links, {stats['money_rows']} money rows in {stats['seconds']} s")
    return stats


# --------------------------------------------------------------------------- queries for the UI / CLI
def open_db(case) -> Optional[sqlite3.Connection]:
    p = db_path(case)
    if not p.exists():
        return None
    con = sqlite3.connect(p)
    con.row_factory = sqlite3.Row
    return con


def _player_row(con: sqlite3.Connection, p) -> dict[str, Any]:
    ents = con.execute("SELECT e.type, e.value, pe.role FROM player_entities pe JOIN entities e ON e.id=pe.entity_id WHERE pe.player_id=? ORDER BY pe.role, e.type", (p["id"],)).fetchall()
    by = defaultdict(list)
    for e in ents:
        by[(e["role"], e["type"])].append(e["value"])
    money = con.execute("SELECT currency, COUNT(*), SUM(amount) FROM money WHERE player_id=? GROUP BY currency", (p["id"],)).fetchall()
    return {"id": p["id"], "label": p["label"], "kind": p["kind"], "score": p["score"], "first_seen": p["first_seen"], "last_seen": p["last_seen"],
            "emails": by[("strong", "email")], "phones": by[("strong", "phone")], "usernames": by[("attribute", "username")], "names": by[("attribute", "name")],
            "wallets": by[("strong", "wallet")] + by[("linked", "wallet")], "ips": by[("linked", "ipv4")] + by[("linked", "ipv6")],
            "shared_ips": by[("shared", "ipv4")] + by[("shared", "ipv6")], "domains": by[("attribute", "domain")] + by[("linked", "domain")],
            "money": {c or "?": {"n": n, "sum": s} for c, n, s in money}, "sources": json.loads(p["sources"] or "{}"), "n_links": p["n_links"]}


def iter_players(con: sqlite3.Connection) -> Iterator[dict[str, Any]]:
    """Every player, best score first, one at a time (streaming; for the CSV output)."""
    for p in con.execute("SELECT * FROM players ORDER BY score DESC, id"):
        yield _player_row(con, p)


def list_players(con: sqlite3.Connection, limit: int = 500, q: str = "") -> list[dict[str, Any]]:
    out = []
    rows = con.execute("SELECT * FROM players ORDER BY score DESC, id LIMIT ?", (limit * 4 if q else limit,)).fetchall()
    for p in rows:
        d = _player_row(con, p)
        if q:
            hay = json.dumps(d, ensure_ascii=False).lower()
            if q.lower() not in hay:
                continue
        out.append(d)
        if len(out) >= limit:
            break
    return out


def player_detail(con: sqlite3.Connection, pid: int) -> dict[str, Any]:
    p = con.execute("SELECT * FROM players WHERE id=?", (pid,)).fetchone()
    if not p:
        return {}
    ents = [dict(r) for r in con.execute("SELECT e.id, e.type, e.value, e.norm, e.count, e.first_seen, e.last_seen, e.sources, pe.role FROM player_entities pe "
                                           "JOIN entities e ON e.id=pe.entity_id WHERE pe.player_id=? ORDER BY pe.role, e.type, e.count DESC", (pid,))]
    for e in ents:
        e["mentions"] = [dict(m) for m in con.execute("SELECT source, count, first_seen, last_seen, roles, locators FROM mentions WHERE entity_id=? ORDER BY count DESC", (e["id"],))]
        e["shared_with"] = con.execute("SELECT COUNT(DISTINCT player_id) FROM player_entities WHERE entity_id=? AND player_id<>?", (e["id"], pid)).fetchone()[0]
    strong_ids = [e["id"] for e in ents if e["role"] == "strong"]
    act = []
    if strong_ids:
        qs = ",".join("?" * len(strong_ids))
        act = [dict(r) for r in con.execute(f"SELECT day, SUM(count) AS n FROM activity WHERE entity_id IN ({qs}) GROUP BY day ORDER BY day", strong_ids)]
    rows = [dict(r) for r in con.execute("SELECT source, db, table_, row, ts, label FROM account_rows WHERE player_id=? ORDER BY ts", (pid,))]
    money = [dict(r) for r in con.execute("SELECT source, db, table_, row, ts, amount, currency, idents FROM money WHERE player_id=? ORDER BY ts", (pid,))]
    msum = [dict(r) for r in con.execute("SELECT currency, COUNT(*) AS n, SUM(amount) AS total, SUM(CASE WHEN amount>0 THEN amount ELSE 0 END) AS inflow, "
                                           "SUM(CASE WHEN amount<0 THEN amount ELSE 0 END) AS outflow, MIN(ts) AS first, MAX(ts) AS last FROM money WHERE player_id=? GROUP BY currency", (pid,))]
    return {"player": dict(p), "entities": ents, "activity": act, "account_rows": rows, "money": money, "money_summary": msum}


def entity_lookup(con: sqlite3.Connection, text: str, limit: int = 50) -> list[dict[str, Any]]:
    t = text.strip()
    if not t:
        return []
    cands = {t, t.lower()}
    for typ, v, n in idf.scan_text(t, "search"):
        cands.add(n)
    r = idf.cell_value("phone", t)
    if r:
        cands.add(r[2])
    out = []
    seen = set()
    for c in cands:
        for e in con.execute("SELECT * FROM entities WHERE norm=? OR value=? OR norm LIKE ? LIMIT ?", (c, c, f"%{c.lower()}%", limit)):
            if e["id"] in seen:
                continue
            seen.add(e["id"])
            d = dict(e)
            d["players"] = [dict(x) for x in con.execute("SELECT p.id, p.label, pe.role FROM player_entities pe JOIN players p ON p.id=pe.player_id WHERE pe.entity_id=?", (e["id"],))]
            d["mentions"] = [dict(m) for m in con.execute("SELECT source, count, first_seen, last_seen, roles, locators FROM mentions WHERE entity_id=? ORDER BY count DESC", (e["id"],))]
            d["linked"] = [dict(x) for x in con.execute(
                "SELECT e2.type, e2.value, SUM(l.count) AS n, MIN(l.first_seen) AS first, MAX(l.last_seen) AS last, GROUP_CONCAT(DISTINCT l.where_) AS where_ FROM links l "
                "JOIN entities e2 ON e2.id = CASE WHEN l.a=? THEN l.b ELSE l.a END WHERE l.a=? OR l.b=? GROUP BY e2.id ORDER BY n DESC LIMIT 100", (e["id"], e["id"], e["id"]))]
            out.append(d)
            if len(out) >= limit:
                return out
    return out


def trends(con: sqlite3.Connection) -> dict[str, Any]:
    days = [dict(r) for r in con.execute("SELECT day, SUM(count) AS n FROM activity GROUP BY day ORDER BY day")]
    counts = [d["n"] for d in days]
    med = sorted(counts)[len(counts) // 2] if counts else 0
    bursts = [d for d in days if med and d["n"] > 4 * med][:50]
    top_ips = [dict(r) for r in con.execute("SELECT e.value, COUNT(DISTINCT pe.player_id) AS players, e.count AS mentions, e.first_seen, e.last_seen FROM entities e "
                                            "JOIN player_entities pe ON pe.entity_id=e.id WHERE e.type IN ('ipv4','ipv6') GROUP BY e.id ORDER BY players DESC, mentions DESC LIMIT 30")]
    wallets = [dict(r) for r in con.execute("SELECT e.id, e.value, e.count, e.first_seen, e.last_seen, (SELECT COUNT(DISTINCT player_id) FROM player_entities WHERE entity_id=e.id) AS players "
                                            "FROM entities e WHERE e.type='wallet' ORDER BY e.count DESC LIMIT 100")]
    money = [dict(r) for r in con.execute("SELECT currency, COUNT(*) AS n, SUM(amount) AS total, SUM(CASE WHEN amount>0 THEN amount ELSE 0 END) AS inflow, "
                                          "SUM(CASE WHEN amount<0 THEN amount ELSE 0 END) AS outflow, MIN(ts) AS first, MAX(ts) AS last FROM money GROUP BY currency ORDER BY n DESC")]
    by_type = {r[0]: r[1] for r in con.execute("SELECT type, COUNT(*) FROM entities GROUP BY type")}
    new_accounts = [dict(r) for r in con.execute("SELECT substr(ts,1,7) AS month, COUNT(*) AS n FROM account_rows WHERE ts IS NOT NULL GROUP BY month ORDER BY month")]
    last_day = days[-1]["day"] if days else None
    recent = []
    if last_day:
        recent = [dict(r) for r in con.execute("SELECT e.type, e.value, SUM(a.count) AS n FROM activity a JOIN entities e ON e.id=a.entity_id WHERE a.day >= date(?, '-7 days') "
                                               "GROUP BY e.id ORDER BY n DESC LIMIT 30", (last_day,))]
    meta = {k: v for k, v in con.execute("SELECT key, value FROM meta")}
    return {"days": days, "median_per_day": med, "bursts": bursts, "top_ips": top_ips, "wallets": wallets, "money": money, "by_type": by_type,
            "new_accounts": new_accounts, "last_day": last_day, "recent": recent, "meta": meta}


# --------------------------------------------------------------------------- outputs
def dossier_text(con: sqlite3.Connection, pid: int) -> str:
    d = player_detail(con, pid)
    if not d:
        return ""
    p = d["player"]
    lines = [f"# Player {pid}: {p['label']}", "",
             f"kind {p['kind']} · active {p['first_seen'] or '?'} to {p['last_seen'] or '?'} · {p['n_entities']} identifiers · sources {p['sources']}", ""]
    by = defaultdict(list)
    for e in d["entities"]:
        by[e["role"]].append(e)
    for role, title in (("strong", "Identifiers (merge keys)"), ("attribute", "Names, usernames, handles, domains"), ("linked", "Linked through rows and log lines"), ("shared", "Shared infrastructure (IPs used by many players)")):
        if by.get(role):
            lines.append(f"## {title}")
            for e in by[role][:80]:
                where = "; ".join(f"{m['source']} x{m['count']}" for m in e["mentions"][:4])
                lines.append(f"- {e['type']}: {e['value']} (x{e['count']}, {e['first_seen'] or '?'} .. {e['last_seen'] or '?'}; {where})" +
                             (f" - shared with {e['shared_with']} other player(s)" if e["shared_with"] else ""))
            lines.append("")
    if d["money_summary"]:
        lines.append("## Money")
        for m in d["money_summary"]:
            lines.append(f"- {m['currency'] or '?'}: {m['n']} rows, net {m['total']:.2f}, in {m['inflow']:.2f}, out {m['outflow']:.2f}, {m['first'] or '?'} .. {m['last'] or '?'}")
        lines.append("")
    if d["account_rows"]:
        lines.append("## Account rows")
        for r in d["account_rows"][:40]:
            lines.append(f"- {r['db']}.{r['table_']} row {r['row']} ({r['ts'] or 'undated'}): {r['label']}")
        lines.append("")
    if d["activity"]:
        lines.append(f"## Activity: {len(d['activity'])} active days; busiest " + ", ".join(f"{a['day']} ({a['n']})" for a in sorted(d["activity"], key=lambda a: -a["n"])[:5]))
    return "\n".join(lines)


def write_outputs(case, log: Log = print) -> dict[str, Any]:
    """players.csv, entities.csv, links.csv, wallets.csv, transactions.csv, activity.csv, dossiers/*.md - into the exports folder
    (Windows-reachable) and an index copy under <case>/players/."""
    from .dbexport import export_root
    con = open_db(case)
    if con is None:
        return {}
    try:
        out = export_root(case).parent / "players"
    except Exception:  # noqa: BLE001
        out = case.dir / "players" / "export"
    out.mkdir(parents=True, exist_ok=True)
    n_players = 0
    top: list[int] = []
    with open(out / "players.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["player", "label", "kind", "score", "first_seen", "last_seen", "emails", "phones", "usernames", "names", "wallets", "ips", "shared_ips", "domains", "money", "sources"])
        for p in iter_players(con):
            n_players += 1
            if len(top) < 2000:
                top.append(p["id"])
            w.writerow([p["id"], p["label"], p["kind"], round(p["score"], 1), p["first_seen"], p["last_seen"], "; ".join(p["emails"]), "; ".join(p["phones"]),
                        "; ".join(p["usernames"]), "; ".join(p["names"]), "; ".join(p["wallets"]), "; ".join(p["ips"][:50]), "; ".join(p["shared_ips"][:50]),
                        "; ".join(p["domains"][:30]), "; ".join(f"{c}: {v['sum']:.2f} ({v['n']})" for c, v in p["money"].items()),
                        "; ".join(f"{k} x{v}" for k, v in p["sources"].items())])
    with open(out / "entities.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["type", "value", "normalized", "count", "first_seen", "last_seen", "sources", "player", "roles"])
        for e in con.execute("SELECT type, value, norm, count, first_seen, last_seen, sources, player_id, roles FROM entities ORDER BY type, count DESC"):
            w.writerow(list(e))
    with open(out / "links.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["type_a", "a", "type_b", "b", "count", "first_seen", "last_seen", "where", "source"])
        for r in con.execute("SELECT ea.type, ea.value, eb.type, eb.value, l.count, l.first_seen, l.last_seen, l.where_, l.source FROM links l JOIN entities ea ON ea.id=l.a JOIN entities eb ON eb.id=l.b ORDER BY l.count DESC LIMIT 2000000"):
            w.writerow(list(r))
    with open(out / "wallets.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["network", "address", "count", "first_seen", "last_seen", "players", "player_labels", "sources"])
        for e in con.execute("SELECT id, norm, value, count, first_seen, last_seen FROM entities WHERE type='wallet' ORDER BY count DESC"):
            pls = con.execute("SELECT p.id, p.label FROM player_entities pe JOIN players p ON p.id=pe.player_id WHERE pe.entity_id=?", (e["id"],)).fetchall()
            srcs = con.execute("SELECT source, count FROM mentions WHERE entity_id=? ORDER BY count DESC", (e["id"],)).fetchall()
            w.writerow([e["norm"].split(":", 1)[0], e["value"], e["count"], e["first_seen"], e["last_seen"], "; ".join(str(x[0]) for x in pls), "; ".join(x[1] for x in pls),
                        "; ".join(f"{s[0]} x{s[1]}" for s in srcs[:10])])
    with open(out / "transactions.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["ts", "amount", "currency", "player", "player_label", "identifiers", "source", "database", "table", "row"])
        for m in con.execute("SELECT m.ts, m.amount, m.currency, m.player_id, p.label, m.idents, m.source, m.db, m.table_, m.row FROM money m LEFT JOIN players p ON p.id=m.player_id ORDER BY m.ts"):
            idents = "; ".join(f"{t}={v}" for t, v in json.loads(m["idents"] or "[]"))
            w.writerow([m["ts"], m["amount"], m["currency"], m["player_id"], m["label"], idents, m["source"], m["db"], m["table_"], m["row"]])
    with open(out / "activity.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["day", "events", "distinct_identifiers"])
        for r in con.execute("SELECT day, SUM(count), COUNT(DISTINCT entity_id) FROM activity GROUP BY day ORDER BY day"):
            w.writerow(list(r))
    dd = out / "dossiers"
    dd.mkdir(exist_ok=True)
    for old in dd.glob("player-*.md"):
        old.unlink(missing_ok=True)
    for pid in top:
        (dd / f"player-{pid:05d}.md").write_text(dossier_text(con, pid), "utf-8")
    con.close()
    idx = case.dir / "players"
    for fn in ("players.csv", "wallets.csv", "activity.csv"):
        try:
            import shutil
            shutil.copy2(out / fn, idx / fn)
        except OSError:
            pass
    (idx / "export.json").write_text(json.dumps({"out": str(out), "written": utc_now(), "players": n_players}, indent=2), "utf-8")
    log(f"[players] CSV folders -> {out}")
    return {"out": str(out), "players": n_players}


def exports_dir(case) -> Optional[str]:
    p = case.dir / "players" / "export.json"
    if p.exists():
        try:
            return json.loads(p.read_text("utf-8")).get("out")
        except Exception:  # noqa: BLE001
            return None
    return None
