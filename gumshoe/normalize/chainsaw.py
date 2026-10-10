"""Chainsaw normalizer: `chainsaw hunt ... --json` detections -> findings.

Chainsaw's JSON output is a list of detections. Field names have shifted a
little between releases, so this reads defensively: name/title, level,
timestamp, tags/authors, and the matched document (path + the JSON row, which
for Gumshoe's JSONL carries source_file and line back to the original log).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import Finding, with_provenance

LEVEL_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info"}


def _first(d: dict, *keys, default=None):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def detections(doc: Any):
    if isinstance(doc, list):
        for item in doc:
            yield item
    elif isinstance(doc, dict):
        for k in ("detections", "hits", "results"):
            if isinstance(doc.get(k), list):
                yield from doc[k]
                return
        yield doc


def run(case) -> list[Finding]:
    raw_dir = case.raw / "chainsaw"
    outs = sorted(raw_dir.glob("*.json")) if raw_dir.exists() else []
    if not outs:
        return [Finding(source="chainsaw", severity="info", rule="chainsaw.missing",
                        title="No Chainsaw output found; Sigma pass over web/auth logs not run",
                        description=f"Expected *.json under {raw_dir}. Run `gumshoe collect --tools chainsaw`.")]
    findings: list[Finding] = []
    seen = set()
    for out in outs:
        try:
            doc = json.loads(out.read_text("utf-8", errors="replace") or "[]")
        except json.JSONDecodeError as e:
            findings.append(Finding(source="chainsaw", severity="info", title=f"Unreadable Chainsaw output {out.name}",
                                    description=str(e)))
            continue
        for det in detections(doc):
            if not isinstance(det, dict):
                continue
            name = _first(det, "name", "title", "rule", default="(unnamed rule)")
            level = str(_first(det, "level", "severity", default="medium")).lower()
            ts = _first(det, "timestamp", "time")
            document = det.get("document") or {}
            data = document.get("data") if isinstance(document, dict) else None
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    data = {"raw": data}
            data = data or {}
            src = data.get("source_file")
            line = data.get("line")
            key = (name, src, line)
            if key in seen:
                continue
            seen.add(key)
            tags = det.get("tags") or []
            if isinstance(tags, str):
                tags = [tags]
            excerpt = data.get("message") or data.get("c-uri") or json.dumps(data)[:300]
            f = Finding(
                source="chainsaw", severity=LEVEL_SEV.get(level, "medium"), rule=name,
                title=f"Sigma: {name}",
                description=(f"Matched at {ts}. " if ts else "") + ("ip " + str(data.get("c-ip")) + " " if data.get("c-ip") else "") +
                            ("status " + str(data.get("sc-status")) if data.get("sc-status") else ""),
                path=src, line=int(line) if isinstance(line, int) or (isinstance(line, str) and line.isdigit()) else None,
                excerpt=str(excerpt)[:400], tags=["sigma"] + [t for t in tags if isinstance(t, str)][:12],
                raw_ref=str(out.relative_to(case.dir)), extra={"detection": {k: det[k] for k in det if k != "document"},
                                                               "row": data},
            )
            findings.append(with_provenance(case, f))
    return findings
