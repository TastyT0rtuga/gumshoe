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


class Ollama:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.base = (os.environ.get("GUMSHOE_OLLAMA") or cfg.get("base_url") or "http://127.0.0.1:11434").rstrip("/")
        self.timeout = int(cfg.get("timeout_s", 900))

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError, OSError) as e:
            raise LLMUnavailable(f"Ollama at {self.base}: {e}") from e

    def available(self) -> bool:
        try:
            req = urllib.request.Request(self.base + "/api/tags")
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status == 200
        except Exception:
            return False

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
        out = self._post("/api/embeddings", {"model": self.cfg["models"].get("embed", "nomic-embed-text"), "prompt": text})
        return out.get("embedding") or []
