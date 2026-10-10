"""Cross-source correlation. Runs after every normalizer.

  A. A signature hit (Loki) on a file under a web root that is also a request
     target in the access logs -> the hit becomes critical and a linked finding
     lists who requested it, when, with what method and status.
  B. A brute-forcing address (auth) that also appears in the panel operation
     log -> both findings are raised and linked.
  C. Findings whose artifact ctime falls inside a change burst get the burst tag.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any

from .base import Finding, bump, web_relative, open_text


def run(case, findings: list[Finding]) -> list[Finding]:
    new: list[Finding] = []
    # ---- A: signature hits x web requests ------------------------------------
    flagged: dict[str, Finding] = {}
    for f in findings:
        if f.source == "loki" and f.path:
            wr = web_relative(case, f.path)
            if wr:
                flagged[wr] = f
    if flagged:
        # stream the RAW access logs (not the JSONL, which may have been deleted after Chainsaw);
        # keep a bounded set of matching requests per flagged file
        from .weblog2jsonl import iter_log_files, parse_line, in_window
        hits: dict[str, list[dict[str, Any]]] = defaultdict(list)
        totals: dict[str, int] = defaultdict(int)
        for site, path in iter_log_files(case):
            rel = case.rel(path)
            with open_text(path) as f:
                for no, line in enumerate(f, 1):
                    rec = parse_line(line.rstrip("\n"))
                    if not rec or not in_window(case, rec["timestamp"]):
                        continue
                    stem = rec["c-uri-stem"]
                    for wr in flagged:
                        if stem == wr or stem.endswith(wr):
                            totals[wr] += 1
                            if len(hits[wr]) < 2000:
                                hits[wr].append({"ip": rec["c-ip"], "ts": rec["timestamp"], "method": rec["cs-method"],
                                                 "status": rec["sc-status"], "bytes": rec["sc-bytes"], "file": rel, "line": no,
                                                 "agent": rec["c-useragent"]})
        for wr, reqs in hits.items():
            f = flagged[wr]
            f.severity = "critical"
            f.tags = sorted(set(f.tags + ["correlated", "requested"]))
            ips = sorted({r["ip"] for r in reqs if r["ip"]})
            posts = [r for r in reqs if r["method"] in ("POST", "PUT")]
            reqs_sorted = sorted(reqs, key=lambda r: str(r["ts"]))
            first = reqs_sorted[0]
            link = Finding(
                source="correlate", severity="critical", rule="correlate.flagged_file_requested",
                title=f"Signature-flagged file {wr} was requested {totals[wr]} time(s) from {len(ips)} address(es)",
                description=(f"{len(posts)} POST/PUT request(s). Addresses: {', '.join(ips[:15])}. First {first['ts']}, "
                             f"last {reqs_sorted[-1]['ts']}. Statuses: {sorted({r['status'] for r in reqs})}."),
                path=first["file"], line=first["line"], tags=["correlated", "web", "web-shell-activity"],
                related=[f.id], extra={"uri": wr, "requests": reqs_sorted[:200], "flagged_finding": f.id, "flagged_path": f.path},
            )
            f.related = sorted(set(f.related + [link.id]))
            new.append(link)
    # ---- B: brute-force sources x panel operations ----------------------------
    panel_ips = {f.extra.get("ip"): f for f in findings if f.rule == "aapanel.panel_ip" and f.extra.get("ip")}
    for f in findings:
        if f.rule in ("auth.bruteforce", "auth.bruteforce_success"):
            ip = f.extra.get("ip")
            if ip and ip in panel_ips:
                pf = panel_ips[ip]
                pf.severity = bump(pf.severity, 2)
                f.severity = bump(f.severity, 1)
                f.related = sorted(set(f.related + [pf.id]))
                pf.related = sorted(set(pf.related + [f.id]))
                pf.tags = sorted(set(pf.tags + ["correlated"]))
                new.append(Finding(source="correlate", severity="high", rule="correlate.bruteforce_panel",
                                   title=f"{ip} brute-forced SSH and also performed panel operations",
                                   description="The same address appears in sshd failures and in the aaPanel operation log.",
                                   related=[f.id, pf.id], tags=["correlated", "panel-access", "brute-force"],
                                   extra={"ip": ip}))
    # ---- C: burst tagging ------------------------------------------------------
    bursts = case.read_json("bursts.json", []) or []
    def _p(s):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None
    windows = [(_p(b["start"]), _p(b["end"])) for b in bursts if b.get("start") and b.get("end")]
    if windows:
        for f in findings:
            c = _p(f.ctime) if f.ctime else None
            if c and any(s and e and s <= c < e for s, e in windows):
                f.tags = sorted(set(f.tags + ["in-burst-window"]))
    return findings + new
