"""auth.log -> JSONL for Chainsaw (Sigma `linux` keyword rules match on `message`),
plus per-source-address SSH statistics that no signature expresses:
failures per address, failures followed by an accepted login from the same
address, root logins, and account-management events (useradd/usermod/userdel/
passwd/groupadd), which are reported as findings.

Formats handled: classic syslog ("Oct  9 11:14:46 host sshd[123]: ...") with the
year taken from the file's mtime (recorded in the finding), and RFC 3339
("2026-10-09T11:14:46.123456+00:00 host sshd[123]: ...") used by newer rsyslog.
Rotated .gz files are streamed.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .base import Finding, open_text, with_provenance

CLASSIC = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$")
RFC = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z))\s+(?P<host>\S+)\s+(?P<prog>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$")
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

FAILED = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")
ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")
ACCOUNT = re.compile(r"\b(useradd|usermod|userdel|groupadd|groupmod|chpasswd|passwd)\b")
SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.*)$")


def parse_line(line: str, default_year: int) -> Optional[dict[str, Any]]:
    m = RFC.match(line)
    if m:
        d = m.groupdict()
        ts = d["ts"]
    else:
        m = CLASSIC.match(line)
        if not m:
            return None
        d = m.groupdict()
        try:
            ts = datetime(default_year, MONTHS[d["mon"]], int(d["day"]), *map(int, d["time"].split(":")),
                          tzinfo=timezone.utc).isoformat()
        except (KeyError, ValueError):
            ts = f"{d['mon']} {d['day']} {d['time']}"
    return {"timestamp": ts, "host": d["host"], "program": d["prog"], "pid": d.get("pid"), "message": d["msg"]}


def iter_auth_files(case):
    vl = case.abs(case.cfg["paths"]["var_log"])
    if not vl.exists():
        return
    for p in sorted(vl.iterdir()):
        if p.is_file() and (p.name.startswith("auth.log") or p.name.startswith("secure")):
            yield p


def run(case) -> list[Finding]:
    out_dir = case.jsonl / "auth"
    out_dir.mkdir(parents=True, exist_ok=True)
    h = case.cfg["heuristics"]
    threshold = int(h.get("ssh_failure_threshold", 20))
    per_ip: dict[str, dict[str, Any]] = defaultdict(lambda: {"failed": 0, "invalid_users": set(), "accepted": [],
                                                              "first": None, "last": None, "users": set()})
    account_events: list[dict[str, Any]] = []
    sudo_events: list[dict[str, Any]] = []
    root_logins: list[dict[str, Any]] = []
    findings: list[Finding] = []
    n_lines = 0
    with open(out_dir / "auth.jsonl", "w", encoding="utf-8") as w:
        for p in iter_auth_files(case):
            rel = case.rel(p)
            year = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).year
            with open_text(p) as f:
                for no, line in enumerate(f, 1):
                    rec = parse_line(line.rstrip("\n"), year)
                    if not rec:
                        continue
                    rec["source_file"] = rel
                    rec["line"] = no
                    w.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    n_lines += 1
                    msg = rec["message"]
                    ref = {"ts": rec["timestamp"], "file": rel, "line": no}
                    m = FAILED.search(msg) or INVALID.search(msg)
                    if m:
                        ip = m.group("ip")
                        s = per_ip[ip]
                        s["failed"] += 1
                        s["users"].add(m.group("user"))
                        if "Invalid user" in msg:
                            s["invalid_users"].add(m.group("user"))
                        s["first"] = s["first"] or ref
                        s["last"] = ref
                        continue
                    m = ACCEPTED.search(msg)
                    if m:
                        ip = m.group("ip")
                        s = per_ip[ip]
                        ev = {**ref, "user": m.group("user"), "method": m.group("method"), "failures_before": s["failed"]}
                        s["accepted"].append(ev)
                        s["first"] = s["first"] or ref
                        s["last"] = ref
                        if m.group("user") == "root":
                            root_logins.append({**ev, "ip": ip})
                        continue
                    if rec["program"] in ("useradd", "usermod", "userdel", "groupadd", "groupmod", "chpasswd", "passwd") or ACCOUNT.search(msg) and rec["program"] not in ("sshd", "sudo", "CRON"):
                        account_events.append({**ref, "program": rec["program"], "message": msg})
                        continue
                    m = SUDO.search(line)
                    if m:
                        sudo_events.append({**ref, "user": m.group("user"), "command": m.group("cmd")[:300]})
    if n_lines == 0:
        findings.append(Finding(source="auth", severity="info", rule="auth.missing",
                                title="No auth.log / secure files found", description="Checked " + case.cfg["paths"]["var_log"]))
    # findings from the statistics
    for ip, s in per_ip.items():
        if s["failed"] >= threshold:
            after = [a for a in s["accepted"] if a["failures_before"] >= threshold]
            if after:
                a = after[0]
                f = Finding(source="auth", severity="critical", rule="auth.bruteforce_success",
                            title=f"SSH brute force from {ip} followed by an accepted login as {a['user']}",
                            description=f"{s['failed']} failed attempts against {len(s['users'])} user name(s) "
                                        f"({', '.join(sorted(s['users'])[:8])}), then 'Accepted {a['method']}' at {a['ts']}.",
                            path=a["file"], line=a["line"], tags=["ssh", "brute-force", "initial-access"],
                            extra={"ip": ip, "failed": s["failed"], "accepted": s["accepted"]})
            else:
                f = Finding(source="auth", severity="medium", rule="auth.bruteforce",
                            title=f"SSH brute force from {ip}: {s['failed']} failures, no success seen",
                            description=f"Targets: {', '.join(sorted(s['users'])[:12])}. First {s['first']['ts']}, last {s['last']['ts']}.",
                            path=s["first"]["file"], line=s["first"]["line"], tags=["ssh", "brute-force"],
                            extra={"ip": ip, "failed": s["failed"]})
            findings.append(with_provenance(case, f))
    for ev in root_logins:
        findings.append(with_provenance(case, Finding(
            source="auth", severity="high", rule="auth.root_login",
            title=f"Direct root login via {ev['method']} from {ev['ip']} at {ev['ts']}",
            path=ev["file"], line=ev["line"], tags=["ssh", "root"], extra=ev)))
    for ev in account_events:
        findings.append(with_provenance(case, Finding(
            source="auth", severity="high", rule="auth.account_change",
            title=f"Account management event: {ev['program']}", description=ev["message"][:500],
            path=ev["file"], line=ev["line"], excerpt=ev["message"][:300], tags=["account", "persistence"], extra=ev)))
    inv = case.read_json("inventory.json", {}) or {}
    inv["auth"] = {
        "sources": {ip: {"failed": s["failed"], "accepted": s["accepted"], "first": s["first"], "last": s["last"],
                         "users": sorted(s["users"])[:50]} for ip, s in per_ip.items()},
        "sudo_commands": sudo_events[:2000], "root_logins": root_logins, "account_events": account_events,
        "lines": n_lines,
    }
    case.write_json("inventory.json", inv)
    return findings
