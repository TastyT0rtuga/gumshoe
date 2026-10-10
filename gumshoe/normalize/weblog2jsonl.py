"""Web access log -> JSONL in Sigma `webserver` field names, for Chainsaw.

Handles the nginx/Apache "combined" format (aaPanel's default for /www/wwwlogs):
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
and the common variant without referer/agent. Rotated .gz files are streamed.

Output per site: collected/jsonl/web/<site>.jsonl, one JSON object per line:
  c-ip, username, timestamp (ISO 8601), cs-method, c-uri, c-uri-stem, c-uri-query, c-uri-extension,
  cs-version, sc-status, sc-bytes, cs-referer, c-useragent, source_file, line
Also writes collected/web_requests_index.json: POST/PUT targets and archive-type downloads with
status 200, used by the correlator (not a detection by itself).
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from .base import Finding, open_text

COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)
TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_time(s: str) -> Optional[str]:
    try:
        return datetime.strptime(s, TIME_FMT).isoformat()
    except ValueError:
        return None


def parse_line(line: str) -> Optional[dict[str, Any]]:
    m = COMBINED.match(line)
    if not m:
        return None
    d = m.groupdict()
    req = d["request"] or ""
    parts = req.split(" ")
    method = parts[0] if parts and parts[0] else ""
    target = parts[1] if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 else ""
    stem, _, query = target.partition("?")
    ext = ""
    base = stem.rsplit("/", 1)[-1]
    if "." in base:
        ext = "." + base.rsplit(".", 1)[-1].lower()
    try:
        nbytes = int(d["bytes"])
    except (TypeError, ValueError):
        nbytes = 0
    # Sigma's webserver/proxy taxonomy, with both spellings the rule corpus uses for the
    # uri parts (c-uri-* and cs-uri-*) so off-the-shelf rules match without rewrites.
    return {
        "c-ip": d["ip"], "username": None if d["user"] in ("-", "") else d["user"],
        "timestamp": parse_time(d["time"]) or d["time"], "cs-method": method, "c-uri": target,
        "c-uri-stem": stem, "cs-uri-stem": stem, "c-uri-query": query, "cs-uri-query": query,
        "c-uri-extension": ext, "cs-uri-extension": ext, "cs-version": version,
        "sc-status": int(d["status"]), "sc-bytes": nbytes, "cs-bytes": nbytes, "cs-referer": d.get("referer") or "",
        "c-useragent": d.get("agent") or "", "cs-user-agent": d.get("agent") or "",
    }


def iter_log_files(case) -> Iterator[tuple[str, Path]]:
    """Yield (site, path) for every access log under the configured web_logs dirs,
    plus /var/log/nginx and /var/log/apache2 if present. Error logs are skipped."""
    seen = set()
    for base in case.cfg["paths"]["web_logs"] + ["var/log/nginx", "var/log/apache2"]:
        root = case.abs(base)
        if not root.exists():
            continue
        for p in sorted(root.iterdir()):
            if not p.is_file():
                continue
            name = p.name
            if "error" in name.lower():
                continue
            if not (name.endswith(".log") or ".log." in name or name.endswith(".gz") or "access" in name):
                continue
            site = re.sub(r"(\.log)?(\.\d+)?(\.gz)?$", "", name)
            key = (site, name)
            if key in seen:
                continue
            seen.add(key)
            yield site, p


def in_window(case, ts: Optional[str]) -> bool:
    """Honour logs.since / logs.until (ISO strings) when set; unparsable timestamps pass through."""
    lg = case.cfg.get("logs", {}) or {}
    since, until = lg.get("since"), lg.get("until")
    if not (since or until) or not ts:
        return True
    try:
        t = datetime.fromisoformat(str(ts))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        if since and t < datetime.fromisoformat(str(since)).replace(tzinfo=timezone.utc):
            return False
        if until and t > datetime.fromisoformat(str(until)).replace(tzinfo=timezone.utc):
            return False
    except ValueError:
        return True
    return True


def run(case) -> list[Finding]:
    out_dir = case.jsonl / "web"
    out_dir.mkdir(parents=True, exist_ok=True)
    h = case.cfg["heuristics"]
    dump_exts = tuple(h.get("dump_extensions", []))
    max_stems = int((case.cfg.get("logs") or {}).get("max_post_stems", 500000))
    # bounded per-stem summary of POST/PUT targets (not every request): count, first/last, up to 50 ips, 10 samples
    posts: dict[str, dict[str, Any]] = {}
    stems_capped = False
    downloads: list[dict[str, Any]] = []
    counts: dict[str, int] = defaultdict(int)
    skipped_window: dict[str, int] = defaultdict(int)
    unparsed: dict[str, int] = defaultdict(int)
    findings: list[Finding] = []
    writers: dict[str, Any] = {}
    try:
        for site, path in iter_log_files(case):
            rel = case.rel(path)
            if site not in writers:
                writers[site] = open(out_dir / f"{site}.jsonl", "w", encoding="utf-8")
            w = writers[site]
            with open_text(path) as f:
                for no, line in enumerate(f, 1):
                    rec = parse_line(line.rstrip("\n"))
                    if not rec:
                        unparsed[rel] += 1
                        continue
                    if not in_window(case, rec["timestamp"]):
                        skipped_window[rel] += 1
                        continue
                    rec["source_file"] = rel
                    rec["line"] = no
                    rec["site"] = site
                    w.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    counts[site] += 1
                    if rec["cs-method"] in ("POST", "PUT"):
                        stem = rec["c-uri-stem"]
                        e = posts.get(stem)
                        if e is None:
                            if len(posts) >= max_stems:
                                stems_capped = True
                                continue
                            e = posts[stem] = {"count": 0, "first": rec["timestamp"], "last": rec["timestamp"], "ips": [],
                                               "statuses": [], "sample": [], "site": site}
                        e["count"] += 1
                        e["last"] = rec["timestamp"]
                        if rec["c-ip"] not in e["ips"] and len(e["ips"]) < 50:
                            e["ips"].append(rec["c-ip"])
                        if rec["sc-status"] not in e["statuses"]:
                            e["statuses"].append(rec["sc-status"])
                        if len(e["sample"]) < 10:
                            e["sample"].append({"ip": rec["c-ip"], "ts": rec["timestamp"], "status": rec["sc-status"], "file": rel, "line": no})
                    if rec["sc-status"] == 200 and rec["c-uri-stem"].lower().endswith(dump_exts) and rec["sc-bytes"] > 0 and len(downloads) < 10000:
                        downloads.append({"ip": rec["c-ip"], "ts": rec["timestamp"], "uri": rec["c-uri-stem"],
                                          "bytes": rec["sc-bytes"], "file": rel, "line": no, "site": site})
    finally:
        for w in writers.values():
            w.close()
    if not counts:
        findings.append(Finding(source="weblog", severity="info", rule="weblog.missing",
                                title="No web access logs found under the configured web_logs paths",
                                description="Checked: " + ", ".join(case.cfg["paths"]["web_logs"] + ["var/log/nginx", "var/log/apache2"])))
    # archive/dump downloads are reported as findings (data-theft staging is a common pattern on web hosts)
    by_uri: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for d in downloads:
        by_uri[d["uri"]].append(d)
    for uri, items in by_uri.items():
        ips = sorted({i["ip"] for i in items})
        first = items[0]
        findings.append(Finding(
            source="weblog", severity="high" if uri.lower().endswith((".sql", ".sql.gz")) else "medium",
            rule="weblog.dump_download", title=f"Archive/dump file served with 200: {uri}",
            description=f"{len(items)} successful request(s) from {len(ips)} address(es): {', '.join(ips[:10])}. "
                        f"Largest response {max(i['bytes'] for i in items)} bytes.",
            path=first["file"], line=first["line"], tags=["web", "data-transfer"],
            extra={"uri": uri, "requests": items[:50]},
        ))
    case.write_json("web_requests_index.json", {"posts": posts, "posts_capped": stems_capped, "downloads": downloads,
                                                 "counts": dict(counts), "unparsed_lines": dict(unparsed),
                                                 "skipped_outside_window": dict(skipped_window),
                                                 "window": {k: (case.cfg.get("logs") or {}).get(k) for k in ("since", "until")}})
    if stems_capped:
        findings.append(Finding(source="weblog", severity="info", rule="weblog.posts_capped",
                                title=f"POST/PUT target index capped at {max_stems} distinct paths",
                                description="Correlation of signature hits with requests still runs over the raw logs; only the summary index was bounded."))
    return findings
