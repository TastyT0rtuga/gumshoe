"""Orchestration: run tools (optional) and normalize everything into findings.

Order matters: weblog/auth conversion before Chainsaw (it hunts the JSONL),
Loki before correlation (it needs the hits), aaPanel before correlation (panel IPs).
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Optional

from .integrity import utc_now
from .normalize import uac, loki, goaccess, weblog2jsonl, authlog2jsonl, chainsaw, aapanel, correlate, webapp
from .normalize.base import Finding, sev_rank
from .runners import RUNNERS, ToolMissing
from . import documents

TOOL_ORDER = ["uac", "loki", "goaccess", "clamav", "plaso"]  # chainsaw runs after conversion, below
# registry: every normalizer Gumshoe knows; the active PROFILE (config `normalizers:`) picks which run, in this order
REGISTRY: dict[str, Callable[[Any], list[Finding]]] = {
    "uac": uac.run,            # first: builds timeline.db, which the document inventory reads
    "documents": documents.run,
    "loki": loki.run,
    "goaccess": goaccess.run,
    "weblog": weblog2jsonl.run,
    "auth": authlog2jsonl.run,
    "chainsaw": chainsaw.run,
    "aapanel": aapanel.run,
    "webapp": webapp.run,
}


def active_normalizers(cfg) -> list[tuple[str, Callable[[Any], list[Finding]]]]:
    wanted = cfg.get("normalizers") or list(REGISTRY)
    out = []
    for name in wanted:
        if name in REGISTRY:
            out.append((name, REGISTRY[name]))
    return out


def run_tools(case, tools: Optional[list[str]] = None, skip: Optional[list[str]] = None, log=print) -> dict[str, Any]:
    cfg_tools = case.cfg["tools"]
    wanted = tools or [t for t in TOOL_ORDER + ["chainsaw"] if cfg_tools.get(t, {}).get("enabled")]
    skip = set(skip or [])
    results: dict[str, Any] = {}
    from .runners import record_tool_versions
    try:
        versions = record_tool_versions(case)
        present = [f"{k} {v.get('version', '')}".strip() for k, v in versions["tools"].items() if v.get("path")]
        log("[tools] versions recorded in collected/tool_versions.json: " + ("; ".join(present) if present else "none found on PATH"))
    except Exception as e:  # never let bookkeeping stop a collection
        log(f"[tools] could not record tool versions: {e}")
    # conversion must precede chainsaw
    needs_conversion = "chainsaw" in wanted and "chainsaw" not in skip
    for name in [t for t in TOOL_ORDER if t in wanted and t not in skip]:
        log(f"[tools] running {name} ...")
        try:
            results[name] = RUNNERS[name](case)
            log(f"[tools] {name} done")
        except ToolMissing as e:
            results[name] = {"skipped": str(e)}
            case.custody.append("tool_skipped", {"tool": name, "reason": str(e)})
            log(f"[tools] {name} skipped: {e}")
    if needs_conversion:
        log("[tools] converting web and auth logs to JSONL for Chainsaw ...")
        weblog2jsonl.run(case)
        authlog2jsonl.run(case)
        try:
            results["chainsaw"] = RUNNERS["chainsaw"](case)
            log("[tools] chainsaw done")
            if not (case.cfg.get("logs") or {}).get("keep_jsonl", True):
                import shutil
                web = case.jsonl / "web"
                size = sum(p.stat().st_size for p in web.glob("*.jsonl")) if web.exists() else 0
                shutil.rmtree(web, ignore_errors=True)
                case.custody.append("jsonl_deleted", {"dir": str(web.relative_to(case.dir)), "bytes": size,
                                                      "note": "derived data; reproducible from the logs in the image"})
                log(f"[tools] deleted converted web JSONL ({size // 2**20} MB) per logs.keep_jsonl=false")
        except ToolMissing as e:
            results["chainsaw"] = {"skipped": str(e)}
            case.custody.append("tool_skipped", {"tool": "chainsaw", "reason": str(e)})
            log(f"[tools] chainsaw skipped: {e}")
    return results


def normalize_all(case, only: Optional[list[str]] = None, log=print) -> list[dict[str, Any]]:
    findings: list[Finding] = []
    per_source: dict[str, int] = {}
    for name, fn in active_normalizers(case.cfg):
        if only and name not in only:
            continue
        log(f"[normalize] {name} ...")
        try:
            got = fn(case)
        except Exception as e:  # a broken normalizer must not sink the run; record it as a finding
            got = [Finding(source=name, severity="info", rule=f"{name}.error",
                           title=f"Normalizer {name} failed: {type(e).__name__}", description=str(e)[:800])]
        per_source[name] = len(got)
        findings += got
    log("[normalize] correlating ...")
    findings = correlate.run(case, findings)
    # script tagging: findings whose artifact path or text carries Cyrillic/CJK/Arabic get a tag so the
    # examiner can filter them and send them to `gumshoe translate`
    for f in findings:
        f.tag_scripts()
    non_latin = [f for f in findings if any(t in f.tags for t in ("cyrillic", "cjk", "arabic"))]
    if non_latin:
        findings.append(Finding(source="correlate", severity="info", rule="text.non_latin",
                                title=f"{len(non_latin)} finding(s) reference non-Latin-script text (" +
                                      ", ".join(sorted({t for f in non_latin for t in f.tags if t in ('cyrillic', 'cjk', 'arabic')})) + ")",
                                description="Filter by the script tag in the UI or run `gumshoe translate --all` for labelled machine "
                                            "translations next to the originals. Certified translation is needed for anything relied upon.",
                                related=[f.id for f in non_latin[:50]], tags=["translation"]))
    findings.sort(key=lambda f: (-sev_rank(f.severity), f.source, f.title))
    dicts = [f.to_dict() for f in findings]
    case.write_findings(dicts)
    summary = {
        "generated": utc_now(),
        "total": len(findings),
        "by_severity": dict(Counter(f.severity for f in findings)),
        "by_source": dict(Counter(f.source for f in findings)),
        "by_rule": dict(Counter(f.rule or "-" for f in findings)),
        "normalizers": per_source,
    }
    case.write_json("summary.json", summary)
    case.custody.append("normalized", {k: v for k, v in summary.items() if k != "by_rule"})
    return dicts
