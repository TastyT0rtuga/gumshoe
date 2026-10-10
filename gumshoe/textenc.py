"""Text encoding detection and script tagging (stdlib only).

Servers administered in Russian (and files uploaded from Windows) mix UTF-8 with
Windows-1251, KOI8-R, CP866 and UTF-16. Every text read in Gumshoe goes through
`open_text`/`read_text_auto`, which pick the encoding from a sample and record it,
so Cyrillic content indexes, searches, archives and reports correctly.

Detection order: BOM -> strict UTF-8 -> best of cp1251 / koi8_r / cp866 by Cyrillic
letter density -> UTF-8 with replacement. `charset_normalizer` is used instead when
it happens to be installed (it is not required).
"""
from __future__ import annotations

import gzip
import io
import re
from pathlib import Path
from typing import Optional

CYRILLIC = re.compile(r"[Ѐ-ӿ]")
CYRILLIC_LETTERS = re.compile(r"[А-яЁё]")  # А-я, Ё/ё
LATIN = re.compile(r"[A-Za-z]")
CJK = re.compile(r"[一-鿿぀-ヿ가-힯]")
ARABIC = re.compile(r"[؀-ۿ]")

SAMPLE = 64 * 1024
LEGACY = ("cp1251", "koi8_r", "cp866")


def _density(text: str) -> float:
    if not text:
        return 0.0
    letters = len(CYRILLIC_LETTERS.findall(text)) + len(LATIN.findall(text))
    bad = text.count("�") + sum(1 for ch in text if ord(ch) < 32 and ch not in "\r\n\t")
    return (letters - 3 * bad) / max(1, len(text))


def detect_encoding(sample: bytes) -> str:
    if sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        return "utf-16"
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    try:
        sample.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        pass
    try:  # optional, better heuristics if present
        from charset_normalizer import from_bytes  # type: ignore
        best = from_bytes(sample).best()
        if best and best.encoding:
            return best.encoding
    except Exception:
        pass
    # UTF-16 without BOM: many NULs in even/odd positions
    if len(sample) > 64 and sample[1::2].count(0) > len(sample) // 4:
        return "utf-16-le"
    scored = []
    for enc in LEGACY:
        try:
            scored.append((_density(sample.decode(enc, "replace")), enc))
        except LookupError:
            continue
    scored.sort(reverse=True)
    if scored and scored[0][0] > 0.3:
        return scored[0][1]
    return "utf-8"  # with replacement by the callers


def open_text(path: Path, encoding: Optional[str] = None):
    """Open plain or gzip text for streaming read with a detected (or given) encoding."""
    p = Path(path)
    raw = gzip.open(p, "rb") if p.suffix == ".gz" else open(p, "rb")
    try:
        if encoding is None:
            head = raw.read(SAMPLE)
            encoding = detect_encoding(head)
            raw.seek(0)
    except Exception:
        encoding = encoding or "utf-8"
        try:
            raw.seek(0)
        except Exception:
            raw.close()
            raw = gzip.open(p, "rb") if p.suffix == ".gz" else open(p, "rb")
    wrapper = io.TextIOWrapper(raw, encoding=encoding, errors="replace", newline="")
    wrapper.detected_encoding = encoding  # type: ignore[attr-defined]
    return wrapper


def read_text_auto(path: Path, limit_bytes: Optional[int] = None) -> tuple[str, str]:
    p = Path(path)
    opener = gzip.open if p.suffix == ".gz" else open
    with opener(p, "rb") as f:
        data = f.read(limit_bytes) if limit_bytes else f.read()
    enc = detect_encoding(data[:SAMPLE])
    return data.decode(enc, "replace"), enc


def is_binary_sample(sample: bytes) -> bool:
    """NUL bytes mean binary, except for UTF-16 text (which is NUL-rich)."""
    if b"\x00" not in sample:
        return False
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False
    if len(sample) > 64 and sample[1::2].count(0) > len(sample) // 4 and sample[0::2].count(0) < len(sample) // 20:
        return False
    return True


def has_cyrillic(text: Optional[str]) -> bool:
    return bool(text) and bool(CYRILLIC.search(text))


def script_tags(text: Optional[str]) -> list[str]:
    if not text:
        return []
    tags = []
    if CYRILLIC.search(text):
        tags.append("cyrillic")
    if CJK.search(text):
        tags.append("cjk")
    if ARABIC.search(text):
        tags.append("arabic")
    return tags


def safe_str(s: str) -> str:
    """Make a path/string JSON-safe when the filesystem handed us undecodable bytes
    (Python keeps them as surrogate escapes, which json cannot serialize)."""
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
