"""Machine translation of non-English evidence text with the local model.

An investigative aid, not a certified translation: every translation is labelled
with the model, kept next to the original, hashed, and logged in the custody
chain. Technical tokens (paths, addresses, hashes, commands, user names) must be
copied verbatim, which the prompt insists on and the caller spot-checks by
requiring every IPv4 address and SHA-256 in the source to reappear in the output.

Qwen2.5 handles Russian well; use the `report` tier (7B) for translation when
accuracy matters, the 3B for a quick gist.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

from .integrity import hash_text, utc_now
from .llm import Ollama, LLMUnavailable
from .textenc import has_cyrillic, script_tags

SYSTEM = (
    "You are a translator assisting a digital forensic examiner. Translate the TEXT into English. "
    "Copy every file path, IP address, URL, hash, command, user name, email address, number and timestamp exactly as written. "
    "Keep line breaks. Do not summarize, do not add commentary, do not omit anything. "
    "If part of the text is already English, keep it. Output only the translation."
)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA = re.compile(r"\b[0-9a-f]{64}\b")


def translate_text(client: Ollama, text: str, tier: str = "report", source_lang_hint: str = "") -> dict[str, Any]:
    prompt = (f"TEXT ({source_lang_hint or 'language unknown'}):\n{text}\n\nENGLISH TRANSLATION:")
    gen = client.generate(prompt, system=SYSTEM, tier=tier, temperature=0.0)
    out = gen["response"].strip()
    missing = [t for t in set(IPV4.findall(text) + SHA.findall(text)) if t not in out]
    return {"translation": out, "model": gen["model"], "tokens_missing": missing, "source_sha256": hash_text(text),
            "translation_sha256": hash_text(out), "at": utc_now()}


def _lang_hint(text: str) -> str:
    tags = script_tags(text)
    return {"cyrillic": "Cyrillic script, probably Russian or Ukrainian", "cjk": "CJK script", "arabic": "Arabic script"}.get(
        tags[0] if tags else "", "")


def translate_findings(case, finding_ids: Optional[list[str]] = None, all_non_latin: bool = False, tier: str = "report",
                       client: Optional[Ollama] = None, log=print) -> dict[str, Any]:
    """Translate excerpts/descriptions of findings; stores extra.translation_en and writes
    reports/translations.md + .jsonl."""
    client = client or Ollama(case.cfg["llm"])
    findings = case.read_findings()
    todo = []
    for d in findings:
        text = "\n".join(t for t in (d.get("excerpt"), d.get("description")) if t)
        if finding_ids and d["id"] in finding_ids:
            todo.append((d, text))
        elif all_non_latin and script_tags(text + (d.get("path") or "")):
            todo.append((d, text))
    done, skipped = [], []
    if not client.available():
        return {"translated": 0, "skipped": len(todo), "note": "model unavailable; nothing translated"}
    for d, text in todo:
        if not text.strip():
            skipped.append(d["id"])
            continue
        try:
            tr = translate_text(client, text[:6000], tier=tier, source_lang_hint=_lang_hint(text))
        except LLMUnavailable as e:
            log(f"[translate] stopped: {e}")
            break
        d.setdefault("extra", {})["translation_en"] = tr
        d["tags"] = sorted(set(d.get("tags", []) + ["machine-translated"]))
        done.append((d, text, tr))
        case.custody.append("translation", {"finding": d["id"], "model": tr["model"], "source_sha256": tr["source_sha256"],
                                            "translation_sha256": tr["translation_sha256"], "tokens_missing": tr["tokens_missing"]})
        log(f"[translate] {d['id']} ({tr['model']})" + (f" — WARNING tokens missing: {tr['tokens_missing']}" if tr["tokens_missing"] else ""))
    case.write_findings(findings)
    md = [f"# Machine translations — {case.meta.get('case_id')}\n",
          "Investigative aid only. Each block shows the original text and a translation produced by a local model; "
          "anything relied upon needs a certified translation. Technical tokens were required to be copied verbatim; "
          "a WARNING marks a block where one did not reappear.\n"]
    with open(case.reports / "translations.jsonl", "a", encoding="utf-8") as jl:
        for d, text, tr in done:
            jl.write(json.dumps({"finding": d["id"], "path": d.get("path"), "source": text, **tr}, ensure_ascii=False) + "\n")
            warn = f"\n\n**WARNING: not reproduced verbatim: {', '.join(tr['tokens_missing'])}**" if tr["tokens_missing"] else ""
            md.append(f"## {d['id']} — {d['title']}\n\nArtifact: `{d.get('path') or '-'}`\n\n**Original**\n\n```\n{text[:3000]}\n```\n\n"
                      f"**English (machine translation, {tr['model']})**\n\n```\n{tr['translation'][:3000]}\n```{warn}\n")
    (case.reports / "translations.md").write_text("\n".join(md), "utf-8")
    return {"translated": len(done), "skipped": len(skipped), "file": str(case.reports / "translations.md")}


def translate_artifact(case, relpath: str, max_chars: int = 12000, tier: str = "report", client: Optional[Ollama] = None) -> dict[str, Any]:
    """Translate the (text) content of one artifact from the image, in chunks; archives the artifact first."""
    from .archive import archive
    from .textenc import read_text_auto
    client = client or Ollama(case.cfg["llm"])
    p = case.abs(relpath)
    if not p.exists() or not p.is_file():
        return {"error": "not a file on the mount"}
    text, enc = read_text_auto(p, limit_bytes=max_chars * 4)
    text = text[:max_chars]
    archive(case, relpath, "translated", None)
    parts, out = [], []
    for i in range(0, len(text), 3000):
        parts.append(text[i:i + 3000])
    for part in parts:
        tr = translate_text(client, part, tier=tier, source_lang_hint=_lang_hint(part))
        out.append(tr["translation"])
    result = {"path": relpath, "encoding": enc, "chars": len(text), "model": client.model_for(tier), "translation": "\n".join(out),
              "source_sha256": hash_text(text), "at": utc_now()}
    case.custody.append("translation", {"path": relpath, "model": result["model"], "source_sha256": result["source_sha256"],
                                        "translation_sha256": hash_text(result["translation"])})
    with open(case.reports / "translations.jsonl", "a", encoding="utf-8") as jl:
        jl.write(json.dumps(result, ensure_ascii=False) + "\n")
    return result
