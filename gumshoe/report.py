"""Report generation: the sections a digital forensics team writes, built from
the deterministic findings first; optional AI narrative sections are generated
under the citation guard and labelled as such.

Kinds:
  triage  - full examination report (case info, methodology, summary, findings, timeline,
            trends, indicators, archived artifacts, limitations, custody)
  trends  - the statistics sections only
  ioc     - indicators only (markdown + ioc.csv)
"""
from __future__ import annotations

import csv
import html
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from . import __version__
from .archive import archive_findings
from .integrity import utc_now, hash_text
from .llm import Ollama, LLMUnavailable
from .normalize.base import SEVERITIES, sev_rank
from .rag import SYSTEM, guard

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _md_escape(s: Any) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(_md_escape(c) for c in r) + " |")
    return "\n".join(out)


def _translation_block(f: dict[str, Any]) -> str:
    tr = (f.get("extra") or {}).get("translation_en")
    if not tr:
        return ""
    warn = f"\n\n_Not reproduced verbatim by the model: {', '.join(tr['tokens_missing'])} — check against the original._" if tr.get("tokens_missing") else ""
    return (f"> **Machine translation ({tr.get('model')}) — investigative aid, verify against the original; "
            f"certified translation required for reliance.**\n\n```\n{tr['translation'][:1200]}\n```{warn}\n\n")


def _tool_runs(case) -> list[dict[str, Any]]:
    runs = []
    for rec in case.custody.iter_records():
        if rec.action == "tool_end":
            d = rec.details
            runs.append({"tool": d.get("tool"), "cmd": " ".join(d.get("cmd", [])), "exit": d.get("exit_code", d.get("error")),
                         "duration_s": round((d.get("duration_ms") or 0) / 1000, 1), "at": rec.ts})
        elif rec.action == "tool_skipped":
            runs.append({"tool": rec.details.get("tool"), "cmd": "(skipped)", "exit": rec.details.get("reason"), "duration_s": 0,
                         "at": rec.ts})
    return runs


def narrate(case, client: Optional[Ollama], heading: str, instruction: str, sources: list[dict[str, Any]]) -> str:
    """AI narrative under the guard. `sources` are findings dicts; they become [n]."""
    if not client or not sources:
        return ""
    numbered = []
    for i, d in enumerate(sources, 1):
        loc = (d.get("path") or "") + (f":{d['line']}" if d.get("line") else "")
        numbered.append(f"[{i}] ({d['severity']}, {d['source']}, id {d['id']}) {d['title']}\n    artifact: {loc} sha256: {(d.get('sha256') or '')[:16]}\n"
                        f"    {d.get('description', '')[:500]}")
    prompt = f"SOURCES:\n" + "\n".join(numbered) + f"\n\nTASK: {instruction}\nWrite 1-3 short paragraphs with citations."
    try:
        gen = client.generate(prompt, system=SYSTEM, tier="report")
    except LLMUnavailable as e:
        return f"_AI narrative not generated: {e}_\n"
    cleaned, valid, invalid = guard(gen["response"], len(sources))
    legend = "\n".join(f"- [{i}] {d['id']} — {d.get('path') or d['title'][:60]}" for i, d in enumerate(sources, 1) if i in valid)
    note = f"\n\n_Model cited {invalid}, outside the sources; removed._" if invalid else ""
    case.custody.append("narrative", {"section": heading, "model": gen["model"], "sources": [d["id"] for d in sources],
                                      "valid": valid, "invalid": invalid, "text_sha256": hash_text(cleaned)})
    return (f"> **AI-generated narrative ({gen['model']}) — verify every statement against the cited findings below; "
            f"it is not a finding.**\n\n{cleaned}{note}\n\n**Citations:**\n{legend}\n")


def build(case, kind: str = "triage", with_llm: Optional[bool] = None, log=print, html_out: bool = True) -> Path:
    cfg = case.cfg
    findings = case.read_findings()
    summary = case.read_json("summary.json", {}) or {}
    trends = case.read_json("trends.json", {}) or {}
    inv = case.read_json("inventory.json", {}) or {}
    manifest = json.loads((case.evidence / "manifest.json").read_text("utf-8")) if (case.evidence / "manifest.json").exists() else {"items": {}}
    use_llm = cfg["report"]["include_llm_narrative"] if with_llm is None else with_llm
    client = Ollama(cfg["llm"]) if use_llm else None
    if client and not client.available():
        log("[report] model not reachable; narrative sections skipped")
        client = None
    meta = case.meta
    chain_ok, chain_n, bad_seq, chain_msg = case.custody.verify()
    if kind == "triage":
        archive_findings(case, cfg["report"].get("min_severity_to_archive", "high"), log=log)
        manifest = json.loads((case.evidence / "manifest.json").read_text("utf-8")) if (case.evidence / "manifest.json").exists() else {"items": {}}

    parts: list[str] = []
    title = {"triage": "Forensic Examination Report", "trends": "Activity Trends Report", "ioc": "Indicators of Compromise"}[kind]
    parts.append(f"# {title} — {meta.get('case_id')}\n")
    parts.append(f"Generated {utc_now()} by Gumshoe {__version__} · Examiner: {meta.get('examiner')}\n")

    # ---- 1. case information ----------------------------------------------
    if kind in ("triage",):
        ih = meta.get("image_hashes") or {}
        rows = [["Case ID", meta.get("case_id")], ["Examiner", meta.get("examiner")], ["Created", meta.get("created")],
                ["Evidence image", meta.get("image_path") or "(not set)"], ["Mount / export root", meta.get("mount_root")],
                ["Access mode", meta.get("mode")], ["Analysis host", f"{meta.get('host')} ({meta.get('platform')})"],
                ["Image SHA-256 (computed)", (ih.get("computed") or {}).get("sha256", "(not computed)")],
                ["Image MD5 (computed)", (ih.get("computed") or {}).get("md5", "(not computed)")],
                ["Acquisition hash match", {True: "MATCH", False: "MISMATCH - the evidence is not what the acquisition record says",
                                            None: "NOT VERIFIED - no acquisition hash was given; nothing in this report rests on a verified image"}.get(ih.get("match"))],
                ["Evidence verified", "yes" if ih.get("match") is True else "NO"],
                ["Read-only verification", meta.get("readonly_check", {}).get("reason", "not run") if isinstance(meta.get("readonly_check"), dict) else "not run"],
                ["Custody chain", chain_msg],
                ["Custody head at report time", "record %d, hash %s" % case.custody.head()]]
        parts.append("## 1. Case information\n\n" + _table(["Item", "Value"], rows) + "\n")
        parts.append("## 2. Scope and objectives\n\n" + (meta.get("notes") or "_Enter scope in case notes (`gumshoe init --notes`)._") + "\n")
        # ---- 3. methodology ------------------------------------------------
        runs = _tool_runs(case)
        parts.append("## 3. Evidence handling and methodology\n\n"
                     "The image was accessed read-only (see Case information). Established tools were run against the mounted "
                     "filesystem and their unmodified output retained under `collected/raw/`. Gumshoe normalized that output into "
                     "findings carrying the artifact path, line, excerpt, SHA-256 and inode times, correlated findings across sources, "
                     "and archived every artifact referenced by a finding at or above the configured severity. Every action is in the "
                     "hash-chained custody log.\n\n" +
                     _table(["Tool", "Command", "Exit / note", "Seconds", "At"],
                            [[r["tool"], f"`{r['cmd'][:160]}`", r["exit"], r["duration_s"], r["at"]] for r in runs]) + "\n")

    # ---- 4. summary ------------------------------------------------------------
    by_sev = summary.get("by_severity", {}) or Counter(f["severity"] for f in findings)
    if kind in ("triage",):
        parts.append("## 4. Summary of findings\n\n" +
                     _table(["Severity", "Count"], [[s, by_sev.get(s, 0)] for s in reversed(SEVERITIES)]) + "\n\n" +
                     _table(["Source", "Count"], sorted(((k, v) for k, v in (summary.get("by_source") or {}).items()), key=lambda x: -x[1])) + "\n")
        top = [f for f in findings if sev_rank(f["severity"]) >= sev_rank("medium")][:25]
        parts.append(narrate(case, client, "summary",
                             "Summarize what these findings show about the state of the server: initial access, persistence, "
                             "web-facing compromise, data movement. State only what the sources support.", top))
    # ---- 5. findings -------------------------------------------------------------
    if kind in ("triage",):
        parts.append("## 5. Findings\n")
        for sev in reversed(SEVERITIES):
            group = [f for f in findings if f["severity"] == sev]
            if not group:
                continue
            parts.append(f"### 5.{5 - SEVERITIES.index(sev)} {sev.capitalize()} ({len(group)})\n")
            rows = [[f["id"], f["source"], f["title"][:110], (f.get("path") or "") + (f":{f['line']}" if f.get("line") else ""),
                     (f.get("sha256") or "")[:12], f.get("ctime") or f.get("mtime") or ""] for f in group[:400]]
            parts.append(_table(["ID", "Source", "Finding", "Artifact", "SHA-256", "ctime/mtime"], rows) + "\n")
            if sev in ("critical", "high"):
                for f in group[:60]:
                    parts.append(f"**{f['id']} — {f['title']}**  \n"
                                 f"Artifact: `{f.get('path') or '-'}`" + (f" line {f['line']}" if f.get("line") else "") +
                                 f"  \nSHA-256: `{f.get('sha256') or '-'}`  \nmtime {f.get('mtime')} · ctime {f.get('ctime')} · crtime {f.get('crtime')}  \n"
                                 f"Rule: `{f.get('rule') or '-'}` · Tags: {', '.join(f.get('tags') or [])}" +
                                 (f" · Related: {', '.join(f.get('related'))}" if f.get("related") else "") + "\n\n" +
                                 (f"{f['description']}\n\n" if f.get("description") else "") +
                                 (f"```\n{f['excerpt'][:1200]}\n```\n" if f.get("excerpt") else "") +
                                 _translation_block(f))
    # ---- 6. timeline -------------------------------------------------------------
    if kind in ("triage",):
        events = []
        for f in findings:
            t = None
            for key in ("ctime", "mtime"):
                if f.get(key):
                    t = f[key]
                    break
            ex = f.get("extra") or {}
            if f["source"] == "auth" and ex.get("accepted"):
                t = ex["accepted"][0].get("ts")
            if f["source"] == "correlate" and ex.get("requests"):
                t = ex["requests"][0].get("ts")
            if f["rule"] == "uac.burst":
                t = ex.get("burst", {}).get("start")
            if t and sev_rank(f["severity"]) >= sev_rank("medium"):
                events.append((str(t), f))
        events.sort(key=lambda x: x[0])
        parts.append("## 6. Timeline of key events\n\n" +
                     _table(["Time (UTC)", "Severity", "Event", "Artifact", "ID"],
                            [[t, f["severity"], f["title"][:100], f.get("path") or "", f["id"]] for t, f in events[:300]]) + "\n")
        parts.append(narrate(case, client, "timeline", "Describe the sequence of events in time order, naming the artifact for each step.",
                             [f for _, f in events[:30]]))
    # ---- 7. trends ---------------------------------------------------------------
    if kind in ("triage", "trends"):
        parts.append("## 7. Activity trends\n")
        for site, s in (trends.get("sites") or {}).items():
            g = s.get("general", {})
            parts.append(f"### Web site {site}\n\nRequests {g.get('total_requests')} · unique visitors {g.get('unique_visitors')} · "
                         f"bandwidth {g.get('bandwidth')} · {g.get('start_date')} to {g.get('end_date')}\n")
            parts.append("**Requests per day**\n\n" + _table(["Date", "Hits", "Visitors", "Bytes"],
                         [[d["date"], d["hits"], d["visitors"], d["bytes"]] for d in s.get("per_day", [])[:120]]) + "\n")
            parts.append("**Top addresses**\n\n" + _table(["Address", "Hits", "Bytes", "Share of bytes"],
                         [[h["ip"], h["hits"], h["bytes"], f"{h.get('bytes_share', 0):.1%}"] for h in s.get("top_ips", [])[:25]]) + "\n")
            parts.append("**Top paths**\n\n" + _table(["Path", "Hits", "Bytes"],
                         [[p["path"], p["hits"], p["bytes"]] for p in s.get("top_paths", [])[:25]]) + "\n")
            parts.append("**Status codes**\n\n" + _table(["Status", "Hits"], [[x["status"], x["hits"]] for x in s.get("status", [])[:20]]) + "\n")
        auth = (inv.get("auth") or {})
        if auth.get("sources"):
            rows = sorted(((ip, v["failed"], len(v["accepted"]), (v.get("first") or {}).get("ts"), (v.get("last") or {}).get("ts"))
                           for ip, v in auth["sources"].items()), key=lambda r: -r[1])[:40]
            parts.append("### SSH authentication by source address\n\n" +
                         _table(["Address", "Failures", "Accepted", "First", "Last"], [list(r) for r in rows]) + "\n")
        pl = ((inv.get("aapanel") or {}).get("operation_log") or {})
        if pl.get("by_ip"):
            rows = sorted(((ip, v["count"], v["first"], v["last"], ", ".join(v.get("types", [])[:6])) for ip, v in pl["by_ip"].items()),
                          key=lambda r: -r[1])[:40]
            parts.append("### aaPanel operations by source address\n\n" +
                         _table(["Address", "Entries", "First", "Last", "Types"], [list(r) for r in rows]) + "\n")
    # ---- 8. indicators -------------------------------------------------------------
    if kind in ("triage", "ioc"):
        iocs: list[dict[str, str]] = []
        seen = set()

        def add(kind_, value, ctx, fid):
            key = (kind_, value)
            if value and key not in seen:
                seen.add(key)
                iocs.append({"type": kind_, "value": value, "context": ctx[:120], "finding": fid})

        for f in findings:
            if sev_rank(f["severity"]) < sev_rank("medium"):
                continue
            ex = f.get("extra") or {}
            if ex.get("ip"):
                add("ipv4", ex["ip"], f["title"], f["id"])
            for ip in IP_RE.findall(f.get("description") or ""):
                add("ipv4", ip, f["title"], f["id"])
            if f.get("sha256") and f["source"] in ("loki", "correlate", "uac", "aapanel", "chainsaw"):
                add("sha256", f["sha256"], f.get("path") or f["title"], f["id"])
            if f.get("path") and f["source"] in ("loki", "correlate"):
                add("path", f["path"], f["title"], f["id"])
            if f.get("rule") and f["source"] in ("loki", "chainsaw"):
                add("rule", f["rule"], f["source"], f["id"])
        parts.append("## 8. Indicators\n\n" + _table(["Type", "Value", "Context", "Finding"],
                                                      [[i["type"], i["value"], i["context"], i["finding"]] for i in iocs]) + "\n")
        with open(case.reports / "ioc.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["type", "value", "context", "finding"])
            w.writeheader()
            w.writerows(iocs)
    # ---- 9. archived artifacts ---------------------------------------------------------
    if kind in ("triage",):
        rows = [[sha[:16], it["original_path"], it["size"], it["mtime"], it["ctime"], len(it["copies"]), it["last_reason"][:60]]
                for sha, it in manifest.get("items", {}).items()]
        parts.append("## 9. Archived artifacts\n\n" + (_table(["SHA-256", "Original path", "Size", "mtime", "ctime", "Copies", "Reason"], rows)
                                                     if rows else "_None archived yet._") + "\n")
        # ---- 10. limitations ----------------------------------------------------------------
        lim = []
        if meta.get("mode") == "export":
            lim.append("Analysis ran on an exported file tree, not a mounted filesystem: SUID bits, ownership and ctime are those of the export, "
                       "and UAC/MariaDB review were not available.")
        skipped = [r["tool"] for r in _tool_runs(case) if r["cmd"] == "(skipped)"]
        if skipped:
            lim.append("Tools not run on this host: " + ", ".join(skipped) + ".")
        sampled = [f for f in findings if f.get("rule", "").endswith(".missing")]
        if sampled:
            lim.append("Inputs not found: " + "; ".join(f["title"] for f in sampled) + ".")
        lim.append("Detection coverage is that of the rule sets on the drive (signature-base, Sigma) at the date they were pulled; "
                   "absence of a hit is not evidence of absence.")
        lim.append("AI-generated narrative sections are drafting aids generated from the cited findings only; they are labelled, "
                   "logged, and must be verified against the artifacts before any statement is relied on.")
        if (meta.get("image_hashes") or {}).get("match") is not True:
            lim.append("The image hash was not confirmed against the acquisition record inside this case; record the comparison before reporting.")
        parts.append("## 10. Limitations\n\n" + "\n".join(f"- {l}" for l in lim) + "\n")
        # ---- 11. custody ----------------------------------------------------------------------
        recs = list(case.custody.iter_records())
        parts.append(f"## 11. Custody log ({len(recs)} records, {chain_msg})\n\n" +
                     _table(["Seq", "Time", "Action", "Detail"], [[r.seq, r.ts, r.action, json.dumps(r.details, default=str)[:140]] for r in recs[-80:]]) + "\n")

    md = "\n".join(parts)
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    out = case.reports / f"{kind}-{stamp}.md"
    out.write_text(md, "utf-8")
    if html_out:
        (case.reports / f"{kind}-{stamp}.html").write_text(to_html(md, title), "utf-8")
    case.custody.append("report_generated", {"kind": kind, "file": str(out.relative_to(case.dir)), "sha256": hash_text(md),
                                             "findings": len(findings), "llm": bool(client)})
    log(f"[report] wrote {out}")
    return out


def to_html(md: str, title: str) -> str:
    """Small markdown -> HTML converter (headings, paragraphs, tables, code fences, blockquotes, lists, bold/code)."""
    try:
        import markdown  # type: ignore
        body = markdown.markdown(md, extensions=["tables", "fenced_code"])
    except Exception:
        body = _mini_md(md)
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
            "<style>body{font-family:system-ui,Segoe UI,Arial;max-width:1100px;margin:2rem auto;padding:0 1rem;line-height:1.45}"
            "table{border-collapse:collapse;font-size:13px;margin:.5rem 0}td,th{border:1px solid #ccc;padding:3px 6px;vertical-align:top}"
            "th{background:#f0f0f0}code{background:#f4f4f4;padding:1px 3px}pre{background:#f4f4f4;padding:.6rem;overflow:auto}"
            "blockquote{border-left:4px solid #e0a000;background:#fff8e6;padding:.4rem .8rem}</style></head><body>" + body + "</body></html>")


def _inline(s: str) -> str:
    s = html.escape(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"_([^_]+)_", r"<em>\1</em>", s)
    return s


def _mini_md(md: str) -> str:
    out, i, lines = [], 0, md.split("\n")
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            buf = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                buf.append(lines[i]); i += 1
            out.append("<pre>" + html.escape("\n".join(buf)) + "</pre>"); i += 1; continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            out.append(f"<h{len(m.group(1))}>{_inline(m.group(2))}</h{len(m.group(1))}>"); i += 1; continue
        if line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i]); i += 1
            cells = [r.strip("|").split("|") for r in rows if not re.match(r"^\|\s*-+", r)]
            if cells:
                out.append("<table><tr>" + "".join(f"<th>{_inline(c.strip())}</th>" for c in cells[0]) + "</tr>" +
                           "".join("<tr>" + "".join(f"<td>{_inline(c.strip())}</td>" for c in r) + "</tr>" for r in cells[1:]) + "</table>")
            continue
        if line.startswith(">"):
            out.append("<blockquote>" + _inline(line.lstrip("> ")) + "</blockquote>"); i += 1; continue
        if line.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(f"<li>{_inline(lines[i][2:])}</li>"); i += 1
            out.append("<ul>" + "".join(items) + "</ul>"); continue
        if line.strip():
            out.append(f"<p>{_inline(line)}</p>")
        i += 1
    return "\n".join(out)
