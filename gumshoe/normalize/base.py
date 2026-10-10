from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterator, Optional

from ..integrity import hash_file, stat_times, utc_now

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 0


def bump(s: str, steps: int = 1) -> str:
    return SEVERITIES[min(len(SEVERITIES) - 1, sev_rank(s) + steps)]


@dataclass
class Finding:
    source: str                      # which normalizer/tool produced it: uac, loki, goaccess, chainsaw, aapanel, dbreview, correlate
    severity: str                    # info|low|medium|high|critical
    title: str
    description: str = ""
    path: Optional[str] = None       # mount-relative posix path of the artifact
    line: Optional[int] = None
    offset: Optional[int] = None
    excerpt: Optional[str] = None
    sha256: Optional[str] = None     # of the artifact at observation time
    size: Optional[int] = None
    mtime: Optional[str] = None
    ctime: Optional[str] = None
    crtime: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    rule: Optional[str] = None       # YARA/Sigma rule name or internal check id
    raw_ref: Optional[str] = None    # path (case-relative) to the raw tool output this came from
    related: list[str] = field(default_factory=list)  # ids of linked findings
    observed_at: str = field(default_factory=utc_now)
    id: str = field(default_factory=lambda: "F-" + uuid.uuid4().hex[:10])
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("path", "title", "description", "excerpt"):
            if isinstance(d.get(k), str):
                d[k] = safe_str(d[k])
        return d

    def tag_scripts(self) -> None:
        """Add cyrillic/cjk/arabic tags when the artifact path or text carries that script."""
        found = set()
        for s in (self.path, self.title, self.description, self.excerpt):
            found.update(script_tags(s))
        if found:
            self.tags = sorted(set(self.tags) | found)

    def as_text(self) -> str:
        """Compact text form used for indexing and for the model's context."""
        parts = [f"[{self.severity.upper()}] {self.title} (id {self.id}, source {self.source})"]
        if self.path:
            loc = self.path + (f":{self.line}" if self.line else "")
            parts.append(f"artifact: {loc}")
        if self.sha256:
            parts.append(f"sha256: {self.sha256}")
        if self.rule:
            parts.append(f"rule: {self.rule}")
        if self.mtime or self.ctime:
            parts.append(f"mtime: {self.mtime} ctime: {self.ctime} crtime: {self.crtime}")
        if self.description:
            parts.append(self.description)
        if self.excerpt:
            parts.append("excerpt: " + self.excerpt.strip())
        if self.tags:
            parts.append("tags: " + ", ".join(self.tags))
        return "\n".join(parts)


def provenance(case, relpath: Optional[str], do_hash: bool = True, max_hash_bytes: int = 2 * 1024 * 1024 * 1024) -> dict[str, Any]:
    """sha256 + inode times for a mount-relative path. Missing files return {}."""
    if not relpath:
        return {}
    p = case.abs(relpath)
    try:
        if not p.exists() or p.is_dir():
            return {}
        st = stat_times(p)
        out = {"size": st["size"], "mtime": st["mtime"], "ctime": st["ctime"], "crtime": st.get("crtime")}
        if do_hash and st["size"] <= max_hash_bytes:
            out["sha256"] = hash_file(p)
        return out
    except OSError:
        return {}


def with_provenance(case, f: Finding) -> Finding:
    pv = provenance(case, f.path)
    for k in ("sha256", "size", "mtime", "ctime", "crtime"):
        if pv.get(k) and getattr(f, k) in (None, ""):
            setattr(f, k, pv[k])
    return f


from ..textenc import open_text, is_binary_sample, script_tags, safe_str  # noqa: E402  (re-exported)


def is_binary_file(path: Path, probe: int = 8192) -> bool:
    try:
        with open(path, "rb") as f:
            b = f.read(probe)
        return is_binary_sample(b)
    except OSError:
        return True


def read_lines(path: Path, limit: Optional[int] = None) -> Iterator[tuple[int, str]]:
    with open_text(path) as f:
        for i, line in enumerate(f, 1):
            if limit and i > limit:
                break
            yield i, line.rstrip("\n")


def excerpt_at(path: Path, line_no: int, context: int = 2, max_len: int = 400) -> str:
    try:
        lo, hi = max(1, line_no - context), line_no + context
        buf = []
        for i, line in read_lines(path, limit=hi):
            if i >= lo:
                mark = ">" if i == line_no else " "
                buf.append(f"{mark}{i}: {line[:max_len]}")
        return "\n".join(buf)
    except OSError:
        return ""


def iter_files(root: Path, follow_symlinks: bool = False) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        for fn in filenames:
            yield Path(dirpath) / fn


def web_relative(case, relpath: str) -> Optional[str]:
    """For a file under a configured web root, return its path relative to
    that site's document root (what a URL would reference)."""
    rel = relpath.lstrip("/")
    for wr in case.cfg["paths"]["web_roots"]:
        wr = wr.strip("/")
        if rel.startswith(wr + "/"):
            rest = rel[len(wr) + 1:]
            # first component is the site directory in aaPanel (/www/wwwroot/<site>/...)
            parts = rest.split("/", 1)
            return "/" + (parts[1] if len(parts) > 1 else parts[0])
    return None
