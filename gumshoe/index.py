"""SQLite FTS5 index with provenance per chunk (+ optional vectors via Ollama).

Sources indexed:
  * every finding (one chunk each, kind=finding)
  * text artifacts from the image matched by config index.include_globs (kind=artifact),
    capped per file: files above max_file_bytes are sampled as head + tail + every
    line referenced by a finding
  * tool summaries (trends, inventory) as JSON text (kind=summary)
Each chunk records source path, SHA-256 of the whole file, byte and line ranges.
"""
from __future__ import annotations

import fnmatch
import json
import sqlite3
import struct
from pathlib import Path
from typing import Any, Iterator, Optional

from .integrity import hash_file
from .normalize.base import is_binary_file, open_text

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY, relpath TEXT UNIQUE, kind TEXT, sha256 TEXT, size INTEGER, sampled INTEGER DEFAULT 0,
  encoding TEXT
);
CREATE TABLE IF NOT EXISTS chunks (
  id INTEGER PRIMARY KEY, source_id INTEGER, byte_start INTEGER, byte_end INTEGER, line_start INTEGER, line_end INTEGER,
  text TEXT, finding_id TEXT
);
CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(text, content='chunks', content_rowid='id', tokenize='unicode61');
CREATE TABLE IF NOT EXISTS vectors (chunk_id INTEGER PRIMARY KEY, dim INTEGER, vec BLOB);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)
    return con


def _chunk_text(text: str, size: int, overlap: int, line_offset: int = 1) -> Iterator[tuple[int, int, int, int, str]]:
    """Yield (byte_start, byte_end, line_start, line_end, chunk) over text, cutting at line breaks when possible."""
    n = len(text)
    pos = 0
    while pos < n:
        end = min(n, pos + size)
        if end < n:
            nl = text.rfind("\n", pos + size // 2, end)
            if nl != -1:
                end = nl + 1
        chunk = text[pos:end]
        ls = line_offset + text.count("\n", 0, pos)
        le = ls + chunk.count("\n")
        bs = len(text[:pos].encode("utf-8", "replace"))
        be = bs + len(chunk.encode("utf-8", "replace"))
        yield bs, be, ls, le, chunk
        if end >= n:
            break
        pos = max(end - overlap, pos + 1)


class Index:
    def __init__(self, case):
        self.case = case
        self.cfg = case.cfg["index"]
        self.con = connect(case.index_db)

    def close(self):
        self.con.close()

    # ---- building -----------------------------------------------------------
    def _upsert_source(self, relpath: str, kind: str, sha256: Optional[str], size: int, sampled: bool,
                       encoding: Optional[str] = None) -> int:
        cur = self.con.execute("SELECT id FROM sources WHERE relpath=?", (relpath,))
        row = cur.fetchone()
        if row:
            sid = row[0]
            self.con.execute("DELETE FROM chunks_fts WHERE rowid IN (SELECT id FROM chunks WHERE source_id=?)", (sid,))
            self.con.execute("DELETE FROM vectors WHERE chunk_id IN (SELECT id FROM chunks WHERE source_id=?)", (sid,))
            self.con.execute("DELETE FROM chunks WHERE source_id=?", (sid,))
            self.con.execute("UPDATE sources SET kind=?, sha256=?, size=?, sampled=?, encoding=? WHERE id=?",
                             (kind, sha256, size, int(sampled), encoding, sid))
            return sid
        cur = self.con.execute("INSERT INTO sources(relpath, kind, sha256, size, sampled, encoding) VALUES (?,?,?,?,?,?)",
                               (relpath, kind, sha256, size, int(sampled), encoding))
        return cur.lastrowid

    def _add_chunk(self, sid: int, bs: int, be: int, ls: int, le: int, text: str, finding_id: Optional[str] = None) -> int:
        cur = self.con.execute("INSERT INTO chunks(source_id, byte_start, byte_end, line_start, line_end, text, finding_id) "
                               "VALUES (?,?,?,?,?,?,?)", (sid, bs, be, ls, le, text, finding_id))
        cid = cur.lastrowid
        self.con.execute("INSERT INTO chunks_fts(rowid, text) VALUES (?,?)", (cid, text))
        return cid

    def add_findings(self, findings: list[dict[str, Any]]) -> int:
        from .normalize.base import Finding
        n = 0
        for d in findings:
            f = Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__})
            text = f.as_text()
            sid = self._upsert_source(f"finding://{f.id}", "finding", f.sha256, len(text), False)
            self._add_chunk(sid, 0, len(text.encode("utf-8")), 0, 0, text, f.id)
            n += 1
        self.con.commit()
        return n

    def add_summaries(self) -> int:
        n = 0
        for name in ("summary.json", "trends.json", "inventory.json", "bursts.json", "dbreview.json", "documents.json"):
            p = self.case.collected / name
            if not p.exists():
                continue
            text = p.read_text("utf-8", errors="replace")
            sid = self._upsert_source(f"summary://{name}", "summary", hash_file(p), p.stat().st_size, False)
            for bs, be, ls, le, chunk in _chunk_text(text, self.cfg["chunk_chars"], self.cfg["chunk_overlap"]):
                self._add_chunk(sid, bs, be, ls, le, chunk)
                n += 1
        self.con.commit()
        return n

    def add_players(self, log=print) -> int:
        """One searchable dossier per player (players://<id>), so Ask can answer 'what do we know about X' with a citation."""
        from .players import open_db, dossier_text, list_players
        con = open_db(self.case)
        if con is None:
            return 0
        n = 0
        try:
            for p in list_players(con, limit=5000):
                text = dossier_text(con, p["id"])
                if not text:
                    continue
                sid = self._upsert_source(f"players://{p['id']}", "player", None, len(text), False)
                for bs, be, ls, le, chunk in _chunk_text(text, self.cfg["chunk_chars"], self.cfg["chunk_overlap"]):
                    self._add_chunk(sid, bs, be, ls, le, chunk)
                    n += 1
        finally:
            con.close()
        self.con.commit()
        log(f"[index] player dossier chunks: {n}")
        return n

    def add_documents(self, log=print) -> int:
        """Index the extracted text of every inventoried document under the ORIGINAL path
        (kind=document), so a citation names the spreadsheet/PDF/Word file itself and the
        sheet/row, paragraph or page marker inside the chunk says where."""
        doc = self.case.read_json("documents.json", {}) or {}
        n = 0
        for it in doc.get("items", []):
            ex = it.get("extracted") or {}
            tf = ex.get("text_file")
            if not tf:
                continue
            p = self.case.dir / tf
            if not p.exists():
                continue
            # plain-text files already indexed as raw artifacts (with their detected encoding) stay that way
            row = self.con.execute("SELECT kind FROM sources WHERE relpath=?", (it["path"],)).fetchone()
            if row and row[0] == "artifact":
                continue
            text = p.read_text("utf-8", errors="replace")
            sid = self._upsert_source(it["path"], "document", ex.get("sha256") or it.get("sha256"), it.get("size") or 0, False,
                                      f"extracted:{ex.get('method')}")
            for bs, be, ls, le, chunk in _chunk_text(text, self.cfg["chunk_chars"], self.cfg["chunk_overlap"]):
                # carry the last location marker (sheet/page/paragraph) into each chunk so it is self-describing
                marker = ""
                for line in reversed(text[:bs].splitlines()[-200:]):
                    if line.startswith("### "):
                        marker = line[4:].strip()
                        break
                head = f"[{Path(it['path']).name} — {marker}]\n" if marker and not chunk.startswith("### ") else f"[{Path(it['path']).name}]\n"
                self._add_chunk(sid, bs, be, ls, le, head + chunk)
                n += 1
            if n and n % 2000 == 0:
                self.con.commit()
        self.con.commit()
        return n

    def _hit_lines(self, findings: list[dict[str, Any]]) -> dict[str, set[int]]:
        hits: dict[str, set[int]] = {}
        for d in findings:
            if d.get("path") and d.get("line"):
                hits.setdefault(d["path"], set()).add(int(d["line"]))
        return hits

    def iter_artifacts(self) -> Iterator[Path]:
        root = self.case.mount_root
        seen = set()
        for pattern in self.cfg["include_globs"]:
            for p in root.glob(pattern):
                if p.is_file() and p not in seen:
                    seen.add(p)
                    yield p

    def add_artifacts(self, findings: list[dict[str, Any]], log=print) -> int:
        hits = self._hit_lines(findings)
        maxb = int(self.cfg["max_file_bytes"])
        head_b, tail_b = int(self.cfg["sample_head_bytes"]), int(self.cfg["sample_tail_bytes"])
        n = 0
        for p in self.iter_artifacts():
            rel = self.case.rel(p)
            try:
                size = p.stat().st_size
                if size == 0 or (p.suffix != ".gz" and is_binary_file(p)):
                    continue
                sha = hash_file(p)
                sampled = size > maxb
                if not sampled:
                    with open_text(p) as f:
                        text = f.read()
                        enc = getattr(f, "detected_encoding", "utf-8")
                    sid = self._upsert_source(rel, "artifact", sha, size, sampled, enc)
                    for bs, be, ls, le, chunk in _chunk_text(text, self.cfg["chunk_chars"], self.cfg["chunk_overlap"]):
                        self._add_chunk(sid, bs, be, ls, le, chunk)
                        n += 1
                else:
                    sid = self._upsert_source(rel, "artifact", sha, size, sampled, None)
                    n += self._add_sampled(sid, p, head_b, tail_b, hits.get(rel, set()))
            except OSError as e:
                log(f"[index] skip {rel}: {e}")
            if n and n % 2000 == 0:
                self.con.commit()
        self.con.commit()
        return n

    def _add_sampled(self, sid: int, p: Path, head_b: int, tail_b: int, hit_lines: set[int]) -> int:
        """Head + tail + lines referenced by findings (with 3 lines of context)."""
        n = 0
        want = set()
        for l in hit_lines:
            want.update(range(max(1, l - 3), l + 4))
        head_text, tail_lines, hit_text = [], [], []
        read = 0
        with open_text(p) as f:
            for i, line in enumerate(f, 1):
                b = len(line.encode("utf-8", "replace"))
                if read < head_b:
                    head_text.append(line)
                elif i in want:
                    hit_text.append(f"{i}: {line}")
                tail_lines.append(line)
                if len(tail_lines) > 4000:
                    tail_lines.pop(0)
                read += b
        for label, text in (("head", "".join(head_text)), ("hits", "".join(hit_text)), ("tail", "".join(tail_lines))):
            if not text.strip():
                continue
            for bs, be, ls, le, chunk in _chunk_text(text, self.cfg["chunk_chars"], self.cfg["chunk_overlap"]):
                self._add_chunk(sid, bs if label == "head" else -1, be if label == "head" else -1, ls if label == "head" else 0,
                                le if label == "head" else 0, f"[{label} sample of {p.name}]\n" + chunk)
                n += 1
        return n

    def add_vectors(self, client, log=print) -> int:
        """Optional: embed chunks lacking a vector. Slow on CPU; run once, overnight."""
        n = 0
        rows = self.con.execute("SELECT c.id, c.text FROM chunks c LEFT JOIN vectors v ON v.chunk_id=c.id WHERE v.chunk_id IS NULL").fetchall()
        for cid, text in rows:
            vec = client.embed(text[:4000])
            if not vec:
                continue
            blob = struct.pack(f"{len(vec)}f", *vec)
            self.con.execute("INSERT OR REPLACE INTO vectors(chunk_id, dim, vec) VALUES (?,?,?)", (cid, len(vec), blob))
            n += 1
            if n % 200 == 0:
                self.con.commit()
                log(f"[index] embedded {n}/{len(rows)}")
        self.con.commit()
        return n

    # ---- searching ------------------------------------------------------------
    @staticmethod
    def _fts_query(q: str) -> str:
        """Escape for FTS5: quote each token, OR them (lenient recall), keep phrases in quotes.
        Tokens are Unicode words, so Cyrillic (or any script) queries work with the
        unicode61 tokenizer."""
        import re
        phrases = re.findall(r'"([^"]+)"', q)
        rest = re.sub(r'"[^"]+"', " ", q)
        toks = [t for t in re.findall(r"[\w./:@-]+", rest, re.UNICODE) if len(t) > 1]
        parts = [f'"{p}"' for p in phrases] + [f'"{t}"' for t in toks]
        return " OR ".join(parts) if parts else '""'

    def search(self, query: str, k: int = 8, client=None) -> list[dict[str, Any]]:
        q = self._fts_query(query)
        rows = self.con.execute(
            "SELECT c.id, c.text, s.relpath, s.sha256, c.byte_start, c.byte_end, c.line_start, c.line_end, c.finding_id, s.kind, "
            "bm25(chunks_fts) AS score, s.encoding FROM chunks_fts JOIN chunks c ON c.id=chunks_fts.rowid JOIN sources s ON s.id=c.source_id "
            "WHERE chunks_fts MATCH ? ORDER BY score LIMIT ?", (q, k * 3)).fetchall()
        results = {r[0]: {"chunk_id": r[0], "text": r[1], "relpath": r[2], "sha256": r[3], "byte_start": r[4], "byte_end": r[5],
                          "line_start": r[6], "line_end": r[7], "finding_id": r[8], "kind": r[9], "bm25": r[10], "encoding": r[11]}
                   for r in rows}
        # reciprocal-rank fusion with vectors when available
        ranks: dict[int, float] = {cid: 1.0 / (60 + i) for i, cid in enumerate(results)}
        if client is not None and self.case.cfg["llm"].get("use_embeddings"):
            try:
                qv = client.embed(query)
                if qv:
                    import math
                    best = []
                    qn = math.sqrt(sum(x * x for x in qv)) or 1.0
                    for cid, dim, blob in self.con.execute("SELECT chunk_id, dim, vec FROM vectors"):
                        v = struct.unpack(f"{dim}f", blob)
                        dot = sum(a * b for a, b in zip(qv, v))
                        vn = math.sqrt(sum(x * x for x in v)) or 1.0
                        best.append((dot / (qn * vn), cid))
                    best.sort(reverse=True)
                    for i, (_, cid) in enumerate(best[:k * 3]):
                        ranks[cid] = ranks.get(cid, 0.0) + 1.0 / (60 + i)
                        if cid not in results:
                            r = self.con.execute("SELECT c.id, c.text, s.relpath, s.sha256, c.byte_start, c.byte_end, c.line_start, "
                                                 "c.line_end, c.finding_id, s.kind FROM chunks c JOIN sources s ON s.id=c.source_id WHERE c.id=?",
                                                 (cid,)).fetchone()
                            if r:
                                results[cid] = {"chunk_id": r[0], "text": r[1], "relpath": r[2], "sha256": r[3], "byte_start": r[4],
                                                "byte_end": r[5], "line_start": r[6], "line_end": r[7], "finding_id": r[8], "kind": r[9]}
            except Exception:
                pass
        ordered = sorted(results.values(), key=lambda r: -ranks.get(r["chunk_id"], 0))
        return ordered[:k]

    def stats(self) -> dict[str, Any]:
        s = self.con.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        c = self.con.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        v = self.con.execute("SELECT COUNT(*) FROM vectors").fetchone()[0]
        return {"sources": s, "chunks": c, "vectors": v, "db": str(self.case.index_db)}


def build(case, log=print, with_vectors: bool = False, client=None) -> dict[str, Any]:
    idx = Index(case)
    findings = case.read_findings()
    nf = idx.add_findings(findings)
    log(f"[index] findings: {nf}")
    ns = idx.add_summaries()
    log(f"[index] summary chunks: {ns}")
    na = idx.add_artifacts(findings, log=log)
    log(f"[index] artifact chunks: {na}")
    nd = idx.add_documents(log=log)
    log(f"[index] document chunks: {nd}")
    try:
        idx.add_players(log=log)
    except Exception as e:  # noqa: BLE001 - dossiers are a bonus, never a reason to fail the index
        log(f"[index] players skipped: {e}")
    nv = 0
    if with_vectors and client is not None:
        nv = idx.add_vectors(client, log=log)
        log(f"[index] vectors: {nv}")
    st = idx.stats()
    idx.close()
    case.custody.append("index_built", {**st, "findings": nf, "summary_chunks": ns, "artifact_chunks": na, "document_chunks": nd,
                                        "vectors": nv})
    return st
