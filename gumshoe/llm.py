"""Minimal Ollama client (urllib only). Two tiers: `interactive` (3B) and
`report` (7B). If Ollama is unreachable every caller degrades gracefully."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional


class LLMUnavailable(RuntimeError):
    pass


OFF_NOTE = "the AI assistant is off (sidebar switch, or llm.enabled in config.yaml); nothing in the evidence depends on it"

# what the model unlocks - shown next to the switch, so turning it on or off is an informed choice
UNLOCKS = [
    {"name": "Ask", "with": "questions in plain language over everything indexed; every answer cites its sources and claims without a citation are removed",
     "without": "Find: the same search over the same index with the same citations, no generated text"},
    {"name": "Report narrative", "with": "labelled drafting sections in the triage report, written from the cited findings (7B model)",
     "without": "the report of findings, tables, timeline and custody, with no generated text"},
    {"name": "Translation", "with": "Russian, Chinese and Arabic findings translated to English, labelled as machine translation (7B model)",
     "without": "non-Latin findings are tagged by script and shown as they are"},
    {"name": "Deep profile", "with": "the walk-away run adds translations and the narrative report at the end",
     "without": "the walk-away run does every tool, the index and the report without generated text"},
    {"name": "Semantic search", "with": "vectors (embeddings) so Ask/Find also match paraphrases",
     "without": "keyword search (full-text index)"},
]


class Ollama:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.base = (os.environ.get("GUMSHOE_OLLAMA") or cfg.get("base_url") or "http://127.0.0.1:11434").rstrip("/")
        self.timeout = int(cfg.get("timeout_s", 900))
        self.enabled = bool(cfg.get("enabled", False))       # the switch: off means no call is ever made

    def reachable(self) -> bool:
        """Is an Ollama answering at base_url - regardless of the switch (the sidebar says 'installed but off')."""
        try:
            req = urllib.request.Request(self.base + "/api/tags")
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status == 200
        except Exception:
            return False

    def state(self) -> dict[str, Any]:
        """{'enabled', 'reachable', 'models', 'missing', 'label'} for the UI and `gumshoe status`."""
        reach = self.reachable()
        have = self.models() if reach else []
        want = [m for m in (self.cfg.get("models") or {}).values() if m]
        missing = [m for m in want if m and not any(h == m or h.split(":")[0] == m.split(":")[0] and h.startswith(m) for h in have)]
        if not self.enabled:
            label = "off" + (" (a model is installed and reachable; turn the switch on to use it)" if reach else "")
        elif not reach:
            label = "on, but no model is reachable at " + self.base + " (lite bundle, or Ollama not running)"
        elif missing:
            label = "on; reachable, but these models are missing: " + ", ".join(missing)
        else:
            label = "on; " + ", ".join(have[:4])
        return {"enabled": self.enabled, "reachable": reach, "models": have, "missing": missing, "label": label}

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError, OSError) as e:
            raise LLMUnavailable(f"Ollama at {self.base}: {e}") from e

    def available(self) -> bool:
        """Usable: the switch is on and an Ollama answers."""
        return self.enabled and self.reachable()

    def models(self) -> list[str]:
        try:
            req = urllib.request.Request(self.base + "/api/tags")
            with urllib.request.urlopen(req, timeout=5) as r:
                return [m.get("name") for m in json.loads(r.read().decode("utf-8")).get("models", [])]
        except Exception:
            return []

    def model_for(self, tier: str) -> str:
        return self.cfg["models"].get(tier) or self.cfg["models"]["interactive"]

    def generate(self, prompt: str, system: str = "", tier: str = "interactive", num_ctx: Optional[int] = None,
                 temperature: Optional[float] = None, keep_alive: Optional[str] = None) -> dict[str, Any]:
        if not self.enabled:
            raise LLMUnavailable(OFF_NOTE)
        model = self.model_for(tier)
        ctx = num_ctx or (self.cfg.get("num_ctx_report") if tier == "report" else self.cfg.get("num_ctx_interactive")) or 4096
        body = {
            "model": model, "prompt": prompt, "system": system, "stream": False,
            "keep_alive": keep_alive or self.cfg.get("keep_alive", "30m"),
            "options": {"num_ctx": int(ctx), "temperature": float(self.cfg.get("temperature", 0.1) if temperature is None else temperature),
                        "num_thread": int(self.cfg.get("num_thread", 8))},
        }
        out = self._post("/api/generate", body)
        return {"model": model, "response": out.get("response", ""), "eval_count": out.get("eval_count"),
                "prompt_eval_count": out.get("prompt_eval_count"), "total_duration_ms": (out.get("total_duration") or 0) // 1_000_000}

    def unload(self, tier: str) -> None:
        try:
            self._post("/api/generate", {"model": self.model_for(tier), "prompt": "", "keep_alive": 0})
        except LLMUnavailable:
            pass

    def embed(self, text: str) -> list[float]:
        if not self.enabled:
            raise LLMUnavailable(OFF_NOTE)
        out = self._post("/api/embeddings", {"model": self.cfg["models"].get("embed", "nomic-embed-text"), "prompt": text})
        return out.get("embedding") or []
