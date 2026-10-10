"""Cited question answering with a fabrication guard.

ask():
  1. retrieve top-k chunks (FTS5 BM25, optional vectors)
  2. number them [1]..[k] and build the prompt
  3. generate with the interactive tier (or report tier when asked)
  4. parse [n] citations; any n outside 1..k is removed and the answer is marked
     unsupported-in-part; an answer with no valid citation is marked unsupported
  5. archive every cited source file; log question, chunk ids, answer hash to custody
If Ollama is unreachable the retrieved sources are returned with answer=None.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from .archive import archive
from .index import Index
from .integrity import hash_text, utc_now
from .llm import Ollama, LLMUnavailable

SYSTEM = (
    "You are assisting a digital forensic examiner. Answer ONLY from the numbered SOURCES. "
    "After every factual sentence put the citation(s) it rests on, like [2] or [1][4]. "
    "Never cite a number that is not in the SOURCES. If the sources do not contain the answer, say "
    "'The indexed sources do not show this.' Do not speculate about intent. Be concise and concrete: "
    "quote paths, timestamps, addresses and hashes exactly as they appear. "
    "Answer in English. Sources may contain Russian or other non-English text: quote the original exactly and "
    "add an English translation in square brackets right after it, marked (translation)."
)

CITE = re.compile(r"\[(\d{1,3})\]")


def format_sources(chunks: list[dict[str, Any]]) -> str:
    out = []
    for i, c in enumerate(chunks, 1):
        loc = c["relpath"]
        if c.get("line_start"):
            loc += f" lines {c['line_start']}-{c['line_end']}"
        sha = (c.get("sha256") or "")[:16]
        out.append(f"[{i}] {loc} (sha256 {sha}...)\n{c['text'].strip()}\n")
    return "\n".join(out)


def guard(answer: str, k: int) -> tuple[str, list[int], list[int]]:
    valid, invalid = [], []
    for m in CITE.finditer(answer):
        n = int(m.group(1))
        (valid if 1 <= n <= k else invalid).append(n)
    cleaned = CITE.sub(lambda m: m.group(0) if 1 <= int(m.group(1)) <= k else "[unsupported citation removed]", answer)
    return cleaned, sorted(set(valid)), sorted(set(invalid))


def _chunks_by_id(case, ids: list[int]) -> list[dict[str, Any]]:
    if not ids:
        return []
    idx = Index(case)
    out = []
    for cid in ids:
        r = idx.con.execute("SELECT c.id, c.text, s.relpath, s.sha256, c.byte_start, c.byte_end, c.line_start, c.line_end, c.finding_id, s.kind, "
                            "s.encoding FROM chunks c JOIN sources s ON s.id=c.source_id WHERE c.id=?", (cid,)).fetchone()
        if r:
            out.append({"chunk_id": r[0], "text": r[1], "relpath": r[2], "sha256": r[3], "byte_start": r[4], "byte_end": r[5],
                        "line_start": r[6], "line_end": r[7], "finding_id": r[8], "kind": r[9], "encoding": r[10]})
    idx.close()
    return out


def _pinned_chunks(case) -> list[dict[str, Any]]:
    from .memory import read_pins
    pins = read_pins(case)
    if not pins:
        return []
    idx = Index(case)
    out = []
    for fid in pins:
        r = idx.con.execute("SELECT c.id, c.text, s.relpath, s.sha256, c.byte_start, c.byte_end, c.line_start, c.line_end, c.finding_id, s.kind, "
                            "s.encoding FROM chunks c JOIN sources s ON s.id=c.source_id WHERE c.finding_id=?", (fid,)).fetchone()
        if r:
            out.append({"chunk_id": r[0], "text": r[1], "relpath": r[2], "sha256": r[3], "byte_start": r[4], "byte_end": r[5],
                        "line_start": r[6], "line_end": r[7], "finding_id": r[8], "kind": r[9], "encoding": r[10], "pinned": True})
    idx.close()
    return out


def ask(case, question: str, k: Optional[int] = None, tier: str = "interactive", client: Optional[Ollama] = None,
        do_archive: bool = True, session: Optional[str] = None, use_memory: bool = True) -> dict[str, Any]:
    """Cited answer. With `session`, the last turns and the chunks they cited come along so
    follow-ups stay grounded; with `use_memory`, the case brief, examiner notes and pinned
    findings are included (fixed-prefix first, for Ollama's prompt cache)."""
    from .memory import build_brief, read_notes, read_session, append_session, previous_chunk_ids, conversation_block
    k = k or int(case.cfg["retrieval"]["top_k"])
    client = client or Ollama(case.cfg["llm"])
    idx = Index(case)
    retrieved = idx.search(question, k=k, client=client)
    idx.close()
    # sources = pinned (stable) + previously cited in this session + freshly retrieved, de-duplicated
    chunks: list[dict[str, Any]] = []
    seen: set[int] = set()
    for c in (_pinned_chunks(case) if use_memory else []) + (_chunks_by_id(case, previous_chunk_ids(case, session)) if session else []) + retrieved:
        if c["chunk_id"] not in seen:
            seen.add(c["chunk_id"])
            chunks.append(c)
    chunks = chunks[: k + 6]
    result: dict[str, Any] = {"question": question, "asked_at": utc_now(), "k": k, "tier": tier, "session": session,
                              "sources": [{"n": i + 1, "chunk_id": c["chunk_id"], "relpath": c["relpath"], "sha256": c.get("sha256"),
                                           "line_start": c.get("line_start"), "line_end": c.get("line_end"),
                                           "finding_id": c.get("finding_id"), "kind": c.get("kind"),
                                           "origin": "pinned" if c.get("pinned") else ("carried" if c not in retrieved else "retrieved")}
                                          for i, c in enumerate(chunks)],
                              "answer": None, "supported": None, "valid_citations": [], "invalid_citations": [], "model": None}
    if not chunks:
        result["note"] = "no indexed text matched the question"
        case.custody.append("question", {"question": question, "chunks": [], "note": result["note"]})
        return result
    # fixed prefix first (brief, notes), then the variable parts
    prefix = ""
    if use_memory:
        brief = build_brief(case)
        notes = read_notes(case).strip()
        prefix = f"CASE BRIEF (context, generated from the findings; cite sources, not this):\n{brief}\n\n"
        if notes:
            prefix += f"EXAMINER NOTES (the examiner's working notes; context only, never cite them as evidence):\n{notes[:4000]}\n\n"
        result["context"] = {"brief_sha256": hash_text(brief), "notes_sha256": hash_text(notes) if notes else None}
    convo = conversation_block(read_session(case, session)) if session else ""
    prompt = (prefix + f"SOURCES:\n{format_sources(chunks)}\n" +
              (f"CONVERSATION SO FAR (earlier answers are not sources; cite the SOURCES above):\n{convo}\n\n" if convo else "") +
              f"QUESTION: {question}\n\nAnswer with citations.")
    try:
        gen = client.generate(prompt, system=SYSTEM, tier=tier)
        cleaned, valid, invalid = guard(gen["response"], len(chunks))
        result.update({"answer": cleaned, "model": gen["model"], "valid_citations": valid, "invalid_citations": invalid,
                       "supported": bool(valid) and not invalid, "generation": {k2: v for k2, v in gen.items() if k2 != "response"}})
        if invalid:
            result["note"] = f"model cited {invalid}, which were not among the {len(chunks)} retrieved sources; removed"
        if not valid:
            result["note"] = (result.get("note") or "") + " answer carries no valid citation; treat as unsupported"
    except LLMUnavailable as e:
        result["note"] = f"model unavailable ({e}); returning retrieved sources only"
    archived = []
    if do_archive:
        cited = result["valid_citations"] or []
        for n in cited:
            c = chunks[n - 1]
            sc = archive(case, c["relpath"], f"cited [{n}] for question: {question[:120]}", ref_id=None,
                         line_start=c.get("line_start"), line_end=c.get("line_end"))
            if sc:
                archived.append(c["relpath"])
            if c.get("finding_id"):
                # a finding chunk cites its own artifact
                for d in case.read_findings():
                    if d["id"] == c["finding_id"] and d.get("path"):
                        if archive(case, d["path"], f"cited via finding {d['id']} for question: {question[:120]}", d["id"],
                                   d.get("line"), d.get("line")):
                            archived.append(d["path"])
                        break
    result["archived"] = sorted(set(archived))
    case.custody.append("question", {"question": question, "chunks": [c["chunk_id"] for c in chunks], "session": session,
                                     "answer_sha256": hash_text(result["answer"] or ""), "model": result["model"],
                                     "valid_citations": result["valid_citations"], "invalid_citations": result["invalid_citations"],
                                     "archived": result["archived"], "context": result.get("context")})
    if session:
        append_session(case, session, {"at": result["asked_at"], "question": question, "answer": result.get("answer"),
                                       "cited_chunk_ids": [chunks[n - 1]["chunk_id"] for n in (result["valid_citations"] or [])],
                                       "model": result.get("model")})
    qlog = case.reports / "questions.jsonl"
    with open(qlog, "a", encoding="utf-8") as f:
        import json
        f.write(json.dumps(result, ensure_ascii=False) + "\n")
    result["question_index"] = sum(1 for _ in open(qlog, "r", encoding="utf-8"))
    result["packet"] = write_packet(case, result, chunks)
    return result


def write_packet(case, result: dict[str, Any], chunks: list[dict[str, Any]]) -> str:
    """A self-contained, cited answer file: the question, the answer, and for every source its
    path, location, SHA-256 and the exact excerpt the model was given. reports/answers/NNN-*.md"""
    import re as _re
    adir = case.reports / "answers"
    adir.mkdir(parents=True, exist_ok=True)
    slug = _re.sub(r"[^a-z0-9]+", "-", result["question"].lower())[:50].strip("-") or "question"
    path = adir / f"{result.get('question_index', 0):03d}-{slug}.md"
    valid = set(result.get("valid_citations") or [])
    ctx = result.get("context") or {}
    lines = [f"# Question {result.get('question_index', 0)} — {case.meta.get('case_id')}", "",
             f"**Asked:** {result['asked_at']}  ·  **Model:** {result.get('model') or 'none (sources only)'}  ·  "
             f"**Supported:** {result.get('supported')}" + (f"  ·  **Session:** {result['session']}" if result.get("session") else "")
             + (f"  ·  brief {ctx['brief_sha256'][:12]}" if ctx.get("brief_sha256") else "")
             + (f"  ·  notes {ctx['notes_sha256'][:12]}" if ctx.get("notes_sha256") else ""),
             "", f"## Question", "", result["question"], "", "## Answer", "",
             result.get("answer") or "_No model answer; retrieved sources follow._", ""]
    if result.get("note"):
        lines += [f"_Note: {result['note']}_", ""]
    lines += ["## Sources (exact text supplied to the model)", ""]
    for i, c in enumerate(chunks, 1):
        loc = c["relpath"]
        if c.get("line_start"):
            loc += f", lines {c['line_start']}–{c['line_end']}"
        origin = next((s.get("origin") for s in result.get("sources", []) if s["n"] == i), "retrieved")
        mark = ("cited" if i in valid else "not cited") + f", {origin}"
        lines += [f"### [{i}] {loc}  ({mark})", "", f"SHA-256: `{c.get('sha256') or '-'}`  ·  kind: {c.get('kind')}"
                  + (f"  ·  encoding: {c.get('encoding')}" if c.get("encoding") else ""), "", "```", c["text"].strip()[:4000], "```", ""]
    lines += ["---", f"Archived with this answer: {', '.join(result.get('archived') or []) or 'none'}. "
              "Open any source with `gumshoe view --path <path>` or export the set with "
              f"`gumshoe export --question {result.get('question_index', 0)} --name q{result.get('question_index', 0)}`."]
    path.write_text("\n".join(lines), "utf-8")
    return str(path.relative_to(case.dir))
