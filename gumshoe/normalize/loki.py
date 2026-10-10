"""Loki normalizer: parses loki.log / loki CSV output into findings.

Loki writes one line per event, e.g.
  20250101T10:00:00Z,HOST,ALERT,FILE: /mnt/evidence/www/wwwroot/site/x.php SCORE: 70 TYPE: PHP SIZE: 1234
  FIRST_BYTES: ... MD5: ... SHA1: ... SHA256: ... CREATED: ... MODIFIED: ... ACCESSED: ...
  REASON_1: Yara Rule MATCH: <rule name> SUBSCORE: 70 DESCRIPTION: <text> REF: <url> MATCHES: ...
Levels: ALERT, WARNING, NOTICE, INFO, RESULT. The parser is tolerant: it keys on
"FILE:", "SCORE:", "SHA256:" and "REASON_n:" wherever they appear.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from .base import Finding, with_provenance, read_lines

LEVEL_SEV = {"ALERT": "high", "WARNING": "medium", "NOTICE": "low", "INFO": "info", "RESULT": "info"}
KV = re.compile(r"\b(FILE|SCORE|TYPE|SIZE|MD5|SHA1|SHA256|CREATED|MODIFIED|ACCESSED|MATCHES|FIRST_BYTES|REASON_\d+|DESCRIPTION|REF|SUBSCORE|SOURCE):\s")


def parse_message(msg: str) -> dict[str, Any]:
    """Split 'KEY: value KEY: value' into a dict; REASON_n keep their tail (which
    itself contains SUBSCORE/DESCRIPTION/REF)."""
    out: dict[str, Any] = {}
    positions = [(m.start(), m.end(), m.group(1)) for m in KV.finditer(msg)]
    for i, (s, e, key) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(msg)
        val = msg[e:end].strip()
        if key.startswith("REASON_"):
            out.setdefault("reasons", []).append(val)
        else:
            out[key] = val
    return out


def _severity(level: str, score: Optional[int]) -> str:
    base = LEVEL_SEV.get(level.upper(), "low")
    if score is not None:
        if score >= 100:
            return "critical"
        if score >= 60:
            return "high" if base in ("high", "medium") else base
    return base


def _strip_mount(case, p: str) -> str:
    """Loki reports absolute host paths; convert to mount-relative."""
    mr = str(case.mount_root).rstrip("/\\")
    if p.startswith(mr):
        p = p[len(mr):]
    return "/" + p.replace("\\", "/").lstrip("/")


def parse_log(case, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for no, line in read_lines(path):
        if not line.strip():
            continue
        # timestamp,host,level,message  (CSV mode) or "ts host LEVEL: message" (plain)
        m = re.match(r"^(\S+),([^,]*),(ALERT|WARNING|NOTICE|INFO|RESULT),(.*)$", line)
        if m:
            ts, host, level, msg = m.groups()
        else:
            m = re.match(r"^(\S+)\s+(\S+)\s+(ALERT|WARNING|NOTICE|INFO|RESULT):\s*(.*)$", line)
            if not m:
                continue
            ts, host, level, msg = m.groups()
        if "FILE:" not in msg:
            continue  # module status lines
        kv = parse_message(msg)
        score = None
        try:
            score = int(kv.get("SCORE", "").strip() or 0)
        except ValueError:
            pass
        rules = []
        for r in kv.get("reasons", []):
            mm = re.search(r"MATCH:\s*(\S+)", r)
            rules.append(mm.group(1) if mm else r[:80])
        relpath = _strip_mount(case, kv.get("FILE", "").strip())
        f = Finding(
            source="loki", severity=_severity(level, score), rule=", ".join(rules) or None,
            title=f"Loki {level}: {Path(relpath).name} matched {len(rules)} rule(s), score {score}",
            description="; ".join(kv.get("reasons", []))[:1500],
            path=relpath, sha256=(kv.get("SHA256") or "").strip().lower() or None,
            tags=["loki", "signature"] + (["web-root"] if any(relpath.lstrip("/").startswith(w.strip("/") + "/") for w in case.cfg["paths"]["web_roots"]) else []),
            raw_ref=str(path.relative_to(case.dir)) if path.is_relative_to(case.dir) else str(path),
            line=None, extra={"loki_ts": ts, "loki_type": kv.get("TYPE"), "loki_size": kv.get("SIZE"), "line_in_log": no},
        )
        with_provenance(case, f)
        findings.append(f)
    return findings


def run(case) -> list[Finding]:
    raw_dir = case.raw / "loki"
    findings: list[Finding] = []
    logs = sorted(list(raw_dir.glob("*.log")) + list(raw_dir.glob("*.csv"))) if raw_dir.exists() else []
    if not logs:
        return [Finding(source="loki", severity="info", rule="loki.missing",
                        title="No Loki output found; YARA/IOC pass not run",
                        description=f"Expected loki.log or CSV under {raw_dir}. Run `gumshoe collect --tools loki`.")]
    for lg in logs:
        findings += parse_log(case, lg)
    # de-duplicate on (path, rule)
    seen = set()
    out = []
    for f in findings:
        key = (f.path, f.rule)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
