"""GoAccess normalizer: turns the JSON report into trends.json for the UI and
the report. Pure statistics; no detection logic lives here."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import Finding


def _panel(doc: dict, name: str) -> list[dict[str, Any]]:
    p = doc.get(name) or {}
    return p.get("data") or []


def _count(x: Any) -> int:
    if isinstance(x, dict):
        return int(x.get("count") or 0)
    try:
        return int(x or 0)
    except (TypeError, ValueError):
        return 0


def summarize(doc: dict) -> dict[str, Any]:
    gen = doc.get("general") or {}
    per_day = [{"date": d.get("data"), "hits": _count(d.get("hits")), "visitors": _count(d.get("visitors")),
                "bytes": _count(d.get("bytes"))} for d in _panel(doc, "visitors")]
    per_day.sort(key=lambda r: str(r["date"]))
    hosts = [{"ip": d.get("data"), "hits": _count(d.get("hits")), "visitors": _count(d.get("visitors")),
              "bytes": _count(d.get("bytes")), "country": d.get("country"), "hostname": d.get("hostname")}
             for d in _panel(doc, "hosts")]
    hosts.sort(key=lambda r: -r["hits"])
    paths = [{"path": d.get("data"), "hits": _count(d.get("hits")), "bytes": _count(d.get("bytes")),
              "method": d.get("method"), "protocol": d.get("protocol")} for d in _panel(doc, "requests")]
    paths.sort(key=lambda r: -r["hits"])
    not_found = [{"path": d.get("data"), "hits": _count(d.get("hits"))} for d in _panel(doc, "not_found")]
    not_found.sort(key=lambda r: -r["hits"])
    status = []
    for d in _panel(doc, "status_codes"):
        status.append({"status": d.get("data"), "hits": _count(d.get("hits"))})
        for sub in d.get("items") or []:
            status.append({"status": sub.get("data"), "hits": _count(sub.get("hits"))})
    agents = [{"agent": d.get("data"), "hits": _count(d.get("hits"))} for d in _panel(doc, "browsers")]
    agents.sort(key=lambda r: -r["hits"])
    total_bytes = sum(h["bytes"] for h in hosts) or 1
    for h in hosts:
        h["bytes_share"] = round(h["bytes"] / total_bytes, 4)
    return {
        "general": {
            "total_requests": gen.get("total_requests"), "valid_requests": gen.get("valid_requests"),
            "failed_requests": gen.get("failed_requests"), "unique_visitors": gen.get("unique_visitors"),
            "bandwidth": gen.get("bandwidth"), "start_date": gen.get("start_date"), "end_date": gen.get("end_date"),
            "log_path": gen.get("log_path"),
        },
        "per_day": per_day, "top_ips": hosts[:100], "top_paths": paths[:200], "not_found": not_found[:100],
        "status": status, "top_agents": agents[:100],
    }


def run(case) -> list[Finding]:
    raw_dir = case.raw / "goaccess"
    reports = sorted(raw_dir.glob("*.json")) if raw_dir.exists() else []
    if not reports:
        return [Finding(source="goaccess", severity="info", rule="goaccess.missing",
                        title="No GoAccess report found; web-log trends not computed",
                        description=f"Expected *.json under {raw_dir}. Run `gumshoe collect --tools goaccess`.")]
    trends: dict[str, Any] = {"sites": {}}
    findings: list[Finding] = []
    for rp in reports:
        try:
            doc = json.loads(rp.read_text("utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            findings.append(Finding(source="goaccess", severity="info", title=f"Unreadable GoAccess report {rp.name}",
                                    description=str(e)))
            continue
        s = summarize(doc)
        trends["sites"][rp.stem] = s
        # a single remote address pulling a large share of all bytes is worth a look (data-volume, not a verdict)
        for h in s["top_ips"][:5]:
            if h["bytes_share"] >= 0.25 and h["hits"] >= 50:
                findings.append(Finding(source="goaccess", severity="low", rule="goaccess.bytes_share",
                                        title=f"{h['ip']} received {h['bytes_share']:.0%} of all bytes served by {rp.stem}",
                                        description=f"{h['hits']} requests, {h['bytes']} bytes. Check what it downloaded.",
                                        tags=["trend", "data-volume"], raw_ref=str(rp.relative_to(case.dir)),
                                        extra={"ip": h["ip"], "site": rp.stem}))
    case.write_json("trends.json", trends)
    return findings
