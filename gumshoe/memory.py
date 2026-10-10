"""Three kinds of memory for the model, all of them context and none of them evidence.

1. Case brief   — a compact, auto-generated summary of the case (counts, top findings, key
                  addresses, sites, accounts) placed FIRST in every prompt. Because it is stable
                  across questions, Ollama's prompt-prefix cache evaluates it once per model
                  load and skips it afterwards: on CPU, where prompt reading is the slow part,
                  that is the difference between a 60 s and a 20 s answer.
2. Examiner notes — notes.md in the case directory: the examiner's own working notes (hypotheses,
                  confirmed facts, incident window, who is who). Shown to the model as a labelled
                  block it may use for context but may not cite; hashed into the custody log on
                  every change. Pinned findings are always offered as citable sources.
3. Session memory — the last turns of a named session, so follow-ups ("and the second address?")
                  work, plus the chunks cited in the previous answer re-injected as sources so
                  the follow-up stays grounded in the same evidence. Stored under
                  reports/sessions/<name>.jsonl and recorded in each answer packet.

Prompt order is fixed parts first (system, brief, notes, pinned), variable parts last
(retrieved sources, recent turns, question) to make the prefix cache effective.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from .integrity import hash_text, utc_now


# ---- examiner notes and pins ----------------------------------------------------------
def notes_path(case) -> Path:
    return case.dir / "notes.md"


def read_notes(case) -> str:
    p = notes_path(case)
    return p.read_text("utf-8") if p.exists() else ""


def write_notes(case, text: str, actor: str = "examiner") -> str:
    p = notes_path(case)
    p.write_text(text, "utf-8")
    h = hash_text(text)
    case.custody.append("notes_updated", {"sha256": h, "chars": len(text), "by": actor})
    return h


def append_note(case, line: str) -> str:
    text = read_notes(case)
    text = (text.rstrip("\n") + "\n" if text else "") + f"- {utc_now()[:16]}Z {line.strip()}\n"
    return write_notes(case, text)


def pins_path(case) -> Path:
    return case.dir / "pins.json"


def read_pins(case) -> list[str]:
    p = pins_path(case)
    return json.loads(p.read_text("utf-8")) if p.exists() else []


def set_pin(case, finding_id: str, pinned: bool = True) -> list[str]:
    pins = [x for x in read_pins(case) if x != finding_id]
    if pinned:
        pins.append(finding_id)
    pins_path(case).write_text(json.dumps(pins), "utf-8")
    case.custody.append("pin_changed", {"finding": finding_id, "pinned": pinned})
    return pins


# ---- case brief ----------------------------------------------------------------------
def build_brief(case, max_chars: int = 2500) -> str:
    """Deterministic summary from the normalized outputs; cached to collected/brief.txt and
    regenerated whenever summary.json is newer than the cache."""
    out = case.collected / "brief.txt"
    summ = case.collected / "summary.json"
    if out.exists() and summ.exists() and out.stat().st_mtime >= summ.stat().st_mtime:
        return out.read_text("utf-8")
    s = case.read_json("summary.json", {}) or {}
    inv = case.read_json("inventory.json", {}) or {}
    findings = case.read_findings()
    lines = [f"CASE {case.meta.get('case_id')} — evidence root {case.meta.get('mount_root')} ({case.mode}); "
             f"findings {s.get('total', 0)}: " + ", ".join(f"{k} {v}" for k, v in (s.get('by_severity') or {}).items())]
    top = [f for f in findings if f["severity"] in ("critical", "high")][:15]
    if top:
        lines.append("Top findings: " + "; ".join(f"{f['id']} {f['title'][:80]} ({f.get('path') or '-'})" for f in top))
    auth = (inv.get("auth") or {}).get("sources") or {}
    if auth:
        worst = sorted(auth.items(), key=lambda kv: -kv[1].get("failed", 0))[:6]
        lines.append("SSH sources (failed/accepted): " + ", ".join(f"{ip} {v.get('failed', 0)}/{len(v.get('accepted', []))}" for ip, v in worst))
    aa = inv.get("aapanel") or {}
    if aa.get("sites"):
        lines.append("Sites: " + ", ".join(str(x.get("name")) for x in aa["sites"][:20]))
    if (aa.get("operation_log") or {}).get("by_ip"):
        ips = sorted(aa["operation_log"]["by_ip"].items(), key=lambda kv: -kv[1].get("count", 0))[:6]
        lines.append("Panel operation addresses: " + ", ".join(f"{ip} ({v.get('count')})" for ip, v in ips))
    sysinv = inv.get("system") or {}
    if sysinv.get("accounts"):
        lines.append("Login-shell accounts: " + ", ".join(a["user"] for a in sysinv["accounts"] if a.get("shell", "").endswith(("bash", "sh", "zsh")))[:300])
    webapps = (inv.get("webapps") or {}).get("sites") or []
    if webapps:
        lines.append("Web apps: " + "; ".join(f"{w['site'].rsplit('/', 1)[-1]} {w['framework']} {w.get('version') or ''}".strip() for w in webapps[:12]))
    tr = case.read_json("trends.json", {}) or {}
    for site, t in list((tr.get("sites") or {}).items())[:3]:
        g = t.get("general", {})
        lines.append(f"Web traffic {site}: {g.get('total_requests')} requests, {g.get('unique_visitors')} visitors, {g.get('start_date')}–{g.get('end_date')}; "
                     "top addresses " + ", ".join(h["ip"] for h in t.get("top_ips", [])[:5]))
    text = "\n".join(lines)[:max_chars]
    out.write_text(text, "utf-8")
    return text


# ---- sessions --------------------------------------------------------------------------
def session_path(case, name: str) -> Path:
    d = case.reports / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in name)[:40] or "default"
    return d / f"{safe}.jsonl"


def read_session(case, name: str, last: int = 4) -> list[dict[str, Any]]:
    p = session_path(case, name)
    if not p.exists():
        return []
    turns = [json.loads(l) for l in p.read_text("utf-8").splitlines() if l.strip()]
    return turns[-last:]


def append_session(case, name: str, turn: dict[str, Any]) -> None:
    with open(session_path(case, name), "a", encoding="utf-8") as f:
        f.write(json.dumps(turn, ensure_ascii=False) + "\n")


def clear_session(case, name: str) -> None:
    p = session_path(case, name)
    if p.exists():
        p.unlink()
    case.custody.append("session_cleared", {"session": name})


def list_sessions(case) -> list[dict[str, Any]]:
    d = case.reports / "sessions"
    out = []
    if d.exists():
        for p in sorted(d.glob("*.jsonl")):
            n = sum(1 for l in p.read_text("utf-8").splitlines() if l.strip())
            out.append({"session": p.stem, "turns": n, "updated_epoch": p.stat().st_mtime})
    return out


def previous_chunk_ids(case, name: str, last: int = 2) -> list[int]:
    ids: list[int] = []
    for t in read_session(case, name, last=last):
        for cid in t.get("cited_chunk_ids", []):
            if cid not in ids:
                ids.append(cid)
    return ids


def conversation_block(turns: list[dict[str, Any]], max_chars: int = 2500) -> str:
    if not turns:
        return ""
    parts = []
    for t in turns:
        parts.append(f"Q: {t['question'][:400]}\nA: {(t.get('answer') or '(no answer)')[:900]}")
    text = "\n\n".join(parts)
    return text[-max_chars:]
