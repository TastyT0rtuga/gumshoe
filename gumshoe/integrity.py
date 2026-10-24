"""Hashing, inode times and the hash-chained custody log.

Every record in custody.log is JSON on one line and carries the SHA-256 of the
previous record plus its own SHA-256 over (seq, ts, actor, action, details,
prev). Editing or removing any line breaks the chain, which `verify_chain`
detects.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

CHUNK = 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def hash_file(path: os.PathLike | str, algo: str = "sha256") -> str:
    """Stream-hash a file. Opens read-only; never modifies atime on Linux
    when O_NOATIME is available (ignored silently elsewhere)."""
    h = hashlib.new(algo)
    flags = os.O_RDONLY
    noatime = getattr(os, "O_NOATIME", 0)
    fd = None
    try:
        try:
            fd = os.open(path, flags | noatime)
        except PermissionError:
            fd = os.open(path, flags)  # O_NOATIME needs owner/CAP_FOWNER
        with os.fdopen(fd, "rb", buffering=0) as f:
            fd = None
            while True:
                b = f.read(CHUNK)
                if not b:
                    break
                h.update(b)
    finally:
        if fd is not None:
            os.close(fd)
    return h.hexdigest()


def hash_file_multi(path: os.PathLike | str, algos: tuple[str, ...] = ("sha256", "md5"), progress=None) -> dict[str, str]:
    """All requested digests in ONE pass over the file (a 500 GB image is read once, not once per algorithm)."""
    hs = {a: hashlib.new(a) for a in algos}
    done = 0
    with open(path, "rb", buffering=0) as f:
        while True:
            b = f.read(8 * CHUNK)
            if not b:
                break
            for h in hs.values():
                h.update(b)
            done += len(b)
            if progress and done % (1024 * CHUNK) < 8 * CHUNK:
                progress(done)
    return {a: h.hexdigest() for a, h in hs.items()}


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    return hashlib.new(algo, data).hexdigest()


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def stat_times(path: os.PathLike | str) -> dict[str, Any]:
    """atime/mtime/ctime as ISO UTC plus epoch; crtime when the platform
    exposes st_birthtime (Windows, macOS, some Linux builds). On Linux the
    bodyfile from UAC supplies crtime where Python cannot."""
    st = os.stat(path, follow_symlinks=False)

    def iso(t: float) -> str:
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    out = {
        "size": st.st_size,
        "mode": oct(st.st_mode & 0o7777),
        "uid": getattr(st, "st_uid", None),
        "gid": getattr(st, "st_gid", None),
        "inode": getattr(st, "st_ino", None),
        "atime": iso(st.st_atime),
        "mtime": iso(st.st_mtime),
        "ctime": iso(st.st_ctime),
        "atime_epoch": st.st_atime,
        "mtime_epoch": st.st_mtime,
        "ctime_epoch": st.st_ctime,
    }
    bt = getattr(st, "st_birthtime", None)
    out["crtime"] = iso(bt) if bt else None
    out["crtime_epoch"] = bt
    return out


@dataclass
class CustodyRecord:
    seq: int
    ts: str
    actor: str
    host: str
    action: str
    details: dict[str, Any]
    prev: str
    hash: str = ""

    def payload(self) -> str:
        d = {k: v for k, v in asdict(self).items() if k != "hash"}
        return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def compute_hash(self) -> str:
        return hash_text(self.payload())


class CustodyLog:
    """Append-only JSONL with a hash chain."""

    GENESIS = "0" * 64

    def __init__(self, path: Path, actor: str = "gumshoe", anchor: Optional[Path] = None):
        self.path = Path(path)
        self.actor = actor
        self.host = socket.gethostname()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
        # the anchor: the head of the chain (seq + hash) appended to a second file outside the case folder after every
        # record, so a chain that was truncated or rewritten in place no longer verifies; it is written best-effort
        self.anchor = Path(anchor) if anchor else None

    def head(self) -> tuple[int, str]:
        """(records, hash of the last record) - the chain head to write into manifests and reports."""
        last = self._last()
        return (last.seq, last.hash) if last else (0, self.GENESIS)

    def _anchor_write(self, rec: "CustodyRecord") -> None:
        if not self.anchor:
            return
        try:
            self.anchor.parent.mkdir(parents=True, exist_ok=True)
            with open(self.anchor, "a", encoding="utf-8") as f:
                f.write(json.dumps({"seq": rec.seq, "hash": rec.hash, "ts": rec.ts}, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass

    def _anchor_entries(self) -> list[dict[str, Any]]:
        if not self.anchor or not self.anchor.exists():
            return []
        out = []
        try:
            with open(self.anchor, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
        except (OSError, ValueError):
            return []
        return out

    def _last(self) -> Optional[CustodyRecord]:
        last = None
        for rec in self.iter_records():
            last = rec
        return last

    def iter_records(self) -> Iterator[CustodyRecord]:
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                yield CustodyRecord(**d)

    def append(self, action: str, details: Optional[dict[str, Any]] = None, actor: Optional[str] = None) -> CustodyRecord:
        last = self._last()
        rec = CustodyRecord(
            seq=(last.seq + 1) if last else 1,
            ts=utc_now(),
            actor=actor or self.actor,
            host=self.host,
            action=action,
            details=details or {},
            prev=last.hash if last else self.GENESIS,
        )
        rec.hash = rec.compute_hash()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(rec), sort_keys=True, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._anchor_write(rec)
        return rec

    def verify(self) -> tuple[bool, int, Optional[int], str]:
        """Returns (ok, records_checked, first_bad_seq, message)."""
        prev = self.GENESIS
        n = 0
        expected_seq = 1
        hashes: dict[int, str] = {}
        for rec in self.iter_records():
            n += 1
            if rec.seq != expected_seq:
                return False, n, rec.seq, f"sequence gap: expected {expected_seq}, found {rec.seq}"
            if rec.prev != prev:
                return False, n, rec.seq, "previous-hash mismatch (a record was altered or removed)"
            if rec.compute_hash() != rec.hash:
                return False, n, rec.seq, "record hash mismatch (record content was altered)"
            prev = rec.hash
            hashes[rec.seq] = rec.hash
            expected_seq += 1
        # the anchor: every head ever written, in order. The log must hold every anchored (seq, hash); the anchor's
        # sequence numbers must never step back (a cut chain that was appended to again leaves 1,2,3,2,3 behind); and the
        # log must not run past the anchor (records written without an anchor)
        entries = self._anchor_entries()
        if entries:
            last_seq = 0
            top = 0
            for a in entries:
                seq, h = int(a.get("seq", 0)), a.get("hash")
                if seq <= last_seq:
                    return False, n, seq, f"chain cut and re-extended: the anchor outside the case folder steps back from record {last_seq} to {seq}"
                last_seq = seq
                top = max(top, seq)
                if seq > n:
                    return False, n, n + 1, f"chain truncated: the anchor outside the case folder records {seq} records, the log holds {n}"
                if hashes.get(seq) != h:
                    return False, n, seq, f"chain rewritten: record {seq} differs from the hash anchored outside the case folder"
            if n > top:
                return False, n, top + 1, f"{n - top} record(s) after record {top} are not in the anchor outside the case folder (the anchor folder was not writable, or the records were added by hand)"
            return True, n, None, f"chain intact over {n} records, head {prev[:12]}… matches the anchor ({len(entries)} anchored)"
        return True, n, None, f"chain intact over {n} records, head {prev[:12]}… (no anchor file)"

    def tail(self, n: int = 20) -> list[CustodyRecord]:
        recs = list(self.iter_records())
        return recs[-n:]


def elapsed_ms(start: float) -> int:
    return int((time.time() - start) * 1000)
