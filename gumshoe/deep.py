"""`gumshoe deep`: the leave-it-alone run.

Applies the `deep:` overrides from config (every tool on, Loki intense everywhere,
every document extracted, big index cap, vectors, machine translation of all
non-Latin findings, 7B narrative in the report), then runs the whole pipeline in
order, unattended and resumable, logging each stage to the custody chain and to
reports/deep-run.log. Models are unloaded before the tool phase so the scanners
have the RAM, and loaded only in the model phase.

Interactive use (ask, UI, view, translate of one finding) keeps the fast tier;
nothing here changes config.yaml on disk — the effective deep config is written
into the case as config.deep.effective.yaml.
"""
from __future__ import annotations

import json
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from .case import Case, deep_merge
from .integrity import utc_now
from .llm import Ollama

DEEP_DEFAULTS: dict[str, Any] = {
    "tools": {"plaso": {"enabled": True}, "clamav": {"enabled": True}},
    "loki_intense_everywhere": True,
    "documents": {"max_extract_files": 1000000, "max_extract_bytes": 200 * 2**20, "max_files": 2000000},
    "index": {"max_file_bytes": 500 * 2**20, "sample_head_bytes": 16 * 2**20, "sample_tail_bytes": 16 * 2**20},
    "vectors": True,
    "translate_all": True,
    "report_llm": True,
    "min_severity_to_archive": "medium",
}


def deep_config(cfg: dict[str, Any]) -> dict[str, Any]:
    d = deep_merge(DEEP_DEFAULTS, cfg.get("deep", {}) or {})
    out = deep_merge(cfg, {})
    out["tools"] = deep_merge(out["tools"], d.get("tools", {}))
    if d.get("loki_intense_everywhere"):
        extra = [a for a in out["tools"]["loki"].get("extra_args", []) if a != "--intense"] + ["--intense"]
        out["tools"]["loki"]["extra_args"] = extra
        out["tools"]["loki"]["intense_globs"] = []
    out["documents"] = deep_merge(out.get("documents", {}), d.get("documents", {}))
    out["index"] = deep_merge(out["index"], d.get("index", {}))
    out["llm"]["use_embeddings"] = bool(d.get("vectors"))
    out["report"]["include_llm_narrative"] = bool(d.get("report_llm"))
    out["report"]["min_severity_to_archive"] = d.get("min_severity_to_archive", "medium")
    out["_deep"] = d
    return out


def run(case_dir: Path, cfg: dict[str, Any], skip_tools: bool = False, no_vectors: bool = False, log: Optional[Callable] = None) -> dict[str, Any]:
    dcfg = deep_config(cfg)
    if no_vectors:
        dcfg["llm"]["use_embeddings"] = False
    case = Case.open(case_dir, dcfg)
    (case.dir / "config.deep.effective.yaml").write_text(yaml.safe_dump({k: v for k, v in dcfg.items() if k != "_deep"}, sort_keys=False), "utf-8")
    logf = open(case.reports / "deep-run.log", "a", encoding="utf-8")

    def say(msg: str):
        line = f"{utc_now()} {msg}"
        logf.write(line + "\n"); logf.flush()
        (log or print)(line)

    stages: list[dict[str, Any]] = []

    def stage(name: str, fn: Callable[[], Any]):
        t0 = time.time()
        say(f"=== {name} ===")
        case.custody.append("deep_stage_start", {"stage": name})
        try:
            out = fn()
            rec = {"stage": name, "ok": True, "seconds": round(time.time() - t0, 1)}
            say(f"--- {name} done in {rec['seconds']} s")
        except Exception as e:
            rec = {"stage": name, "ok": False, "seconds": round(time.time() - t0, 1), "error": f"{type(e).__name__}: {e}"}
            say(f"!!! {name} FAILED: {rec['error']}\n{traceback.format_exc()}")
        case.custody.append("deep_stage_end", rec)
        stages.append(rec)

    say(f"deep run on case {case.meta.get('case_id')} ({case.mount_root}, mode {case.mode})")
    ro = case.meta.get("readonly_check") or {}
    if not ro.get("ok"):
        say("read-only check has not passed; run `gumshoe verify` first")
        logf.close()
        return {"error": "verify first"}
    client = Ollama(dcfg["llm"])
    if client.available():
        client.unload("interactive"); client.unload("report")
        say("models unloaded for the tool phase")
    elif not client.enabled:
        say("AI assistant off: the run does every tool, the index and the reports; no vectors, translations or narrative")
    from .collect import run_tools, normalize_all
    from .index import build as build_index
    from .translate import translate_findings
    from .report import build as build_report
    from .archive import verify_archive
    if not skip_tools:
        stage("tools (UAC, Loki intense, GoAccess, ClamAV, Plaso, log conversion, Chainsaw)", lambda: run_tools(case, log=say))
    if (dcfg.get("dbreview") or {}).get("enabled", True):
        stage("MariaDB review (copy + crash recovery + canned queries)", lambda: __import__("gumshoe.dbreview", fromlist=["review"]).review(case, log=say))
    stage("normalize + documents + webapp + correlate", lambda: normalize_all(case, log=say))
    stage("index" + (" + vectors" if dcfg["llm"]["use_embeddings"] else ""),
          lambda: build_index(case, log=say, with_vectors=dcfg["llm"]["use_embeddings"] and client.available(), client=client))
    if (dcfg.get("_deep") or {}).get("translate_all") and client.available():
        stage("translate all non-Latin findings (7B)", lambda: translate_findings(case, all_non_latin=True, tier="report", client=client, log=say))
    stage("report (deterministic" + (" + 7B narrative)" if client.available() else ")"),
          lambda: build_report(case, kind="triage", with_llm=dcfg["report"]["include_llm_narrative"] and client.available(), log=say))
    stage("report: trends + ioc", lambda: (build_report(case, kind="trends", with_llm=False, log=say), build_report(case, kind="ioc", with_llm=False, log=say)))
    stage("verify archive + custody", lambda: (verify_archive(case), case.custody.verify()))
    if client.available():
        client.unload("report")
    summary = {"case": case.meta.get("case_id"), "finished": utc_now(), "stages": stages,
               "findings": (case.read_json("summary.json", {}) or {}).get("by_severity"),
               "custody": case.custody.verify()[3]}
    (case.reports / "deep-summary.json").write_text(json.dumps(summary, indent=2), "utf-8")
    say("deep run finished: " + json.dumps({s["stage"]: ("ok" if s["ok"] else "FAILED") for s in stages}))
    logf.close()
    return summary
