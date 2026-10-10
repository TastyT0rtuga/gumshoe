"""UAC (Unix-like Artifact Collector) normalizer.

Reads the UAC output directory (or extracts its tar.gz) for:
  * bodyfile/bodyfile.txt  -> timeline.csv, timestomp check (mtime vs ctime), burst windows
  * the collected copies of key files -> structural checks that need no signatures:
      - /etc/passwd: UID 0 accounts other than root, service accounts with login shells,
        accounts not present in /etc/passwd- (the pre-change backup)
      - /etc/ld.so.preload present and non-empty
      - cron entries and systemd units whose commands point at temp or hidden paths, or pipe to a shell
      - authorized_keys inventory with ctime
      - sshd_config: PermitRootLogin / PasswordAuthentication
      - sudoers NOPASSWD ALL
If a file is not in the UAC copy, the same path is read from the mount.
"""
from __future__ import annotations

import csv
import re
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .base import Finding, with_provenance, read_lines, is_binary_file, sev_rank
from ..integrity import hash_file

BODYFILE_COLS = ["md5", "name", "inode", "mode", "uid", "gid", "size", "atime", "mtime", "ctime", "crtime"]


def _iso(epoch: str | int | float) -> Optional[str]:
    try:
        e = int(float(epoch))
        if e <= 0:
            return None
        return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return None


def locate_uac_root(raw_dir: Path) -> Optional[Path]:
    """UAC writes <dest>/uac-<host>-<os>-<ts>/ (dir) or .tar.gz. Extract if needed."""
    if not raw_dir.exists():
        return None
    for p in sorted(raw_dir.iterdir()):
        if p.is_dir() and (p / "bodyfile").exists():
            return p
    for p in sorted(raw_dir.glob("*.tar.gz")):
        dest = raw_dir / (p.name[:-7])
        if not dest.exists():
            with tarfile.open(p, "r:gz") as t:
                t.extractall(dest)  # trusted: our own tool's output inside the case dir
        inner = [d for d in dest.iterdir() if d.is_dir()]
        if (dest / "bodyfile").exists():
            return dest
        if inner:
            return inner[0]
    # a bare bodyfile dropped in by hand (self-test)
    if (raw_dir / "bodyfile").exists():
        return raw_dir
    return None


def _collected_or_mount(case, uac_root: Optional[Path], relpath: str) -> Optional[Path]:
    rel = relpath.lstrip("/")
    if uac_root:
        for sub in ("files", "[root]", "root"):
            c = uac_root / sub / rel
            if c.exists() and c.is_file():
                return c
    m = case.abs(rel)
    return m if m.exists() and m.is_file() else None


def _epoch(v: str) -> Optional[int]:
    try:
        e = int(float(v))
        return e if e > 0 else None
    except (ValueError, TypeError):
        return None


def load_bodyfile(case, path: Path) -> tuple[Path, int]:
    """Stream the bodyfile into collected/timeline.db (SQLite). Millions of rows stay on disk, not in RAM."""
    import sqlite3
    db = case.collected / "timeline.db"
    if db.exists():
        db.unlink()
    con = sqlite3.connect(db)
    con.executescript("""
    PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
    CREATE TABLE files (path TEXT, inode TEXT, mode TEXT, uid TEXT, gid TEXT, size INTEGER,
                        atime INTEGER, mtime INTEGER, ctime INTEGER, crtime INTEGER);
    """)
    n = 0
    batch = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 11:
                continue
            try:
                size = int(parts[6])
            except ValueError:
                size = None
            batch.append(("/" + parts[1].lstrip("/"), parts[2], parts[3], parts[4], parts[5], size,
                          _epoch(parts[7]), _epoch(parts[8]), _epoch(parts[9]), _epoch(parts[10])))
            if len(batch) >= 20000:
                con.executemany("INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?,?)", batch)
                n += len(batch)
                batch = []
    if batch:
        con.executemany("INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?,?)", batch)
        n += len(batch)
    con.executescript("CREATE INDEX ix_ctime ON files(ctime); CREATE INDEX ix_path ON files(path);")
    con.commit()
    con.close()
    return db, n


def _scope_sql(case) -> tuple[str, list[str]]:
    """WHERE fragment restricting to web roots + system dirs (the places worth a timeline)."""
    clauses, params = [], []
    for wr in case.cfg["paths"]["web_roots"]:
        clauses.append("path LIKE ?")
        params.append("/" + wr.strip("/") + "/%")
    for d in ("/etc/", "/root/", "/home/", "/var/spool/cron/", "/www/server/cron/", "/www/server/panel/", "/tmp/", "/dev/shm/", "/var/tmp/", "/opt/"):
        clauses.append("path LIKE ?")
        params.append(d + "%")
    return "(" + " OR ".join(clauses) + ")", params


def _web_sql(case) -> tuple[str, list[str]]:
    clauses, params = [], []
    for wr in case.cfg["paths"]["web_roots"]:
        clauses.append("path LIKE ?")
        params.append("/" + wr.strip("/") + "/%")
    return "(" + " OR ".join(clauses) + ")", params


def timeline_and_checks(case, db: Path) -> tuple[list[dict[str, Any]], list[Finding]]:
    """Timestomp check, change bursts and a bounded CSV export, all as SQL over timeline.db."""
    import sqlite3
    h = case.cfg["heuristics"]
    findings: list[Finding] = []
    gap = int(h.get("timestomp_gap_seconds", 5))
    con = sqlite3.connect(db)
    web_where, web_params = _web_sql(case)
    rows = con.execute(f"SELECT path, size, mtime, ctime, crtime FROM files WHERE {web_where} AND size > 0 AND mtime IS NOT NULL "
                       f"AND ctime IS NOT NULL AND (ctime - mtime) > ? ORDER BY ctime DESC LIMIT 5000", web_params + [gap]).fetchall()
    for path, size, m, c, cr in rows:
        findings.append(Finding(
            source="uac", severity="high", rule="uac.timestomp",
            title="Possible timestomping: mtime older than ctime in web root",
            description=(f"mtime {_iso(m)} is {c - m} s older than ctime {_iso(c)}. On ext4, ctime cannot be set from userland, "
                         f"so a copied-in or touch -r'd file shows this gap. crtime: {_iso(cr) if cr else None}."),
            path=path, mtime=_iso(m), ctime=_iso(c), crtime=_iso(cr) if cr else None, size=size, tags=["timestomp", "web-root"],
        ))
    win = int(h.get("burst_window_seconds", 600))
    minf = int(h.get("burst_min_files", 25))
    scope_where, scope_params = _scope_sql(case)
    bursts = []
    for b, cnt in con.execute(f"SELECT ctime / ? AS b, COUNT(*) FROM files WHERE ctime IS NOT NULL AND {scope_where} "
                              f"GROUP BY b HAVING COUNT(*) >= ? ORDER BY b", [win] + scope_params + [minf]).fetchall()[:500]:
        sample = [r[0] for r in con.execute(f"SELECT path FROM files WHERE ctime >= ? AND ctime < ? AND {scope_where} LIMIT 15",
                                            [b * win, (b + 1) * win] + scope_params)]
        bursts.append({"start": _iso(b * win), "end": _iso((b + 1) * win), "count": cnt, "sample": sample})
    for bw in bursts:
        findings.append(Finding(
            source="uac", severity="medium", rule="uac.burst",
            title=f"Change burst: {bw['count']} files changed (ctime) between {bw['start']} and {bw['end']}",
            description="Many inode changes in one window usually mark a deployment, an update, or an intrusion. "
                        "Sample: " + ", ".join(bw["sample"]),
            tags=["burst", "timeline"], extra={"burst": bw},
        ))
    case.write_json("bursts.json", bursts)
    # bounded CSV export of the scoped rows (the full data stays in timeline.db for the UI and SQL)
    cap = int(case.cfg.get("timeline", {}).get("csv_max_rows", 500000))
    out = case.collected / "timeline.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ctime", "mtime", "atime", "crtime", "size", "mode", "uid", "gid", "inode", "path"])
        for r in con.execute(f"SELECT ctime, mtime, atime, crtime, size, mode, uid, gid, inode, path FROM files WHERE {scope_where} "
                             f"ORDER BY ctime, mtime LIMIT ?", scope_params + [cap]):
            w.writerow([_iso(r[0]) if r[0] else None, _iso(r[1]) if r[1] else None, _iso(r[2]) if r[2] else None,
                        _iso(r[3]) if r[3] else None] + list(r[4:]))
    con.close()
    return bursts, findings


# ---- structural checks over collected files ---------------------------------

def _finding_from_file(case, uac_root, relpath: str, **kw) -> Finding:
    f = Finding(source="uac", path=relpath, **kw)
    return with_provenance(case, f)


def check_passwd(case, uac_root) -> tuple[list[Finding], dict[str, Any]]:
    h = case.cfg["heuristics"]
    findings: list[Finding] = []
    inv: dict[str, Any] = {"accounts": []}
    p = _collected_or_mount(case, uac_root, "etc/passwd")
    if not p:
        return findings, inv
    backup = _collected_or_mount(case, uac_root, "etc/passwd-")
    backup_users = set()
    if backup:
        for _, line in read_lines(backup):
            if ":" in line:
                backup_users.add(line.split(":", 1)[0])
    expected_nologin = set(h.get("service_accounts_expected_nologin", []))
    login_shells = set(h.get("login_shells", []))
    for no, line in read_lines(p):
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, _, uid, gid, gecos, home, shell = parts[:7]
        try:
            uid_i = int(uid)
        except ValueError:
            continue
        inv["accounts"].append({"user": user, "uid": uid_i, "gid": gid, "home": home, "shell": shell, "line": no})
        if uid_i == 0 and user != "root":
            findings.append(_finding_from_file(case, uac_root, "/etc/passwd", severity="critical", rule="uac.uid0",
                                               title=f"UID 0 account other than root: {user}",
                                               description="Any account with UID 0 is root. A second one is a classic backdoor.",
                                               line=no, excerpt=line, tags=["persistence", "account"]))
        if user in expected_nologin and shell in login_shells:
            findings.append(_finding_from_file(case, uac_root, "/etc/passwd", severity="medium", rule="uac.service_shell",
                                               title=f"Service account with a login shell: {user} -> {shell}",
                                               description="Service accounts normally carry /usr/sbin/nologin or /bin/false.",
                                               line=no, excerpt=line, tags=["persistence", "account"]))
        if backup_users and user not in backup_users:
            findings.append(_finding_from_file(case, uac_root, "/etc/passwd", severity="high", rule="uac.account_added",
                                               title=f"Account not present in /etc/passwd- backup: {user}",
                                               description="/etc/passwd- is the copy made by the last account change; "
                                                           "an account missing from it was added by that change.",
                                               line=no, excerpt=line, tags=["persistence", "account"]))
    return findings, inv


def check_preload(case, uac_root) -> list[Finding]:
    p = _collected_or_mount(case, uac_root, "etc/ld.so.preload")
    if not p:
        return []
    content = "".join(l for _, l in read_lines(p)).strip()
    sev = "critical" if content else "low"
    return [_finding_from_file(case, uac_root, "/etc/ld.so.preload", severity=sev, rule="uac.ld_preload",
                               title="/etc/ld.so.preload is present" + (" and non-empty" if content else " (empty)"),
                               description="Libraries listed here load into every process; the file does not exist on a "
                                           "clean Ubuntu install. Content: " + (content or "(empty)"),
                               excerpt=content or None, tags=["persistence", "rootkit-indicator"])]


def _suspicious_command(case, cmd: str) -> list[str]:
    h = case.cfg["heuristics"]
    reasons = []
    for pre in h.get("suspicious_path_prefixes", []):
        if pre in cmd:
            reasons.append(f"references {pre.rstrip('/')}")
    if re.search(r"(^|[\s/])\.[A-Za-z0-9_-]+/", cmd):
        reasons.append("hidden directory in path")
    for tok in h.get("pipe_to_shell_tokens", []):
        if tok in cmd:
            reasons.append("pipes to a shell")
    if re.search(r"\b(curl|wget)\b", cmd) and re.search(r"\b(sh|bash|python[23]?|perl)\b", cmd):
        reasons.append("downloads and executes")
    return reasons


# Shell-history review: the classic "what did the operator type" step. Patterns are categories of
# administrative action worth a second look (account changes, log handling, compiling in temp dirs,
# history suppression); each hit is reported with its line so the examiner reads it in context.
HISTORY_FILES = (".bash_history", ".zsh_history", ".sh_history", ".ash_history", ".mysql_history",
                 ".python_history", ".psql_history")
HISTORY_PATTERNS: list[tuple[str, str, str]] = [  # (regex, label, severity)
    (r"\b(useradd|adduser|usermod|userdel|chsh|passwd|chpasswd|visudo|gpasswd)\b", "account or privilege change", "medium"),
    (r"\b(sudo\s+su\b|sudo\s+-i\b|sudo\s+-s\b|su\s+-\s*$|su\s+root)", "switch to root", "low"),
    (r"(var/log/|/lastlog\b|/wtmp\b|/btmp\b|/utmp\b|auth\.log|\bsecure\b)", "touches a log file", "medium"),
    (r"\b(history\s+-c|unset\s+HISTFILE|HISTFILE=|HISTSIZE=0|shred\b|wipe\b)", "history or file wiping", "high"),
    (r"\b(gcc|cc|g\+\+|make|tcc)\b", "compiles source", "medium"),
    (r"\bchmod\s+(\+x|[0-7]*7[0-7]*)\b", "marks executable", "low"),
    (r"\b(nc|ncat|netcat|socat)\b|/dev/tcp/", "network listener / relay tool", "high"),
    (r"\b(crontab\s+-|systemctl\s+(enable|start)|update-rc\.d|rc\.local)\b", "scheduling or service change", "medium"),
    (r"\b(scp|sftp|rsync|ftp|tftp)\b", "file transfer", "low"),
    (r"\b(mysqldump|mysql\s+-u|mariadb\s+-u|psql\b)", "database access", "low"),
    (r"\b(tar|zip|7z|rar)\b.*\b(www|html|wwwroot|home|etc)\b", "archives system or web content", "low"),
]


def check_shell_history(case, uac_root, accounts: list[dict[str, Any]]) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Find every shell/database history file in the home directory of each account (plus /root),
    inventory them, and flag lines matching HISTORY_PATTERNS or _suspicious_command."""
    findings: list[Finding] = []
    inv: list[dict[str, Any]] = []
    homes = {"root": "root"}
    for a in accounts:
        home = (a.get("home") or "").strip("/")
        if home and home not in ("nonexistent", "dev/null", "bin", "sbin", "usr/sbin", "var/run", "run"):
            homes.setdefault(a["user"], home)
    seen: set[str] = set()
    for user, home in homes.items():
        for name in HISTORY_FILES:
            rel = f"{home}/{name}"
            if rel in seen:
                continue
            seen.add(rel)
            p = _collected_or_mount(case, uac_root, rel)
            if not p or is_binary_file(p):
                continue
            lines = [(no, l.rstrip("\n")) for no, l in read_lines(p)]
            entry = {"user": user, "file": "/" + rel, "lines": len(lines), "size": p.stat().st_size, "flagged": 0}
            flagged: list[dict[str, Any]] = []
            for no, line in lines:
                if not line.strip() or line.startswith("#"):
                    continue
                reasons = list(_suspicious_command(case, line))
                sev = "medium" if reasons else "info"
                for rx, label, s in HISTORY_PATTERNS:
                    if re.search(rx, line):
                        reasons.append(label)
                        if sev_rank(s) > sev_rank(sev):
                            sev = s
                if reasons:
                    flagged.append({"line": no, "command": line[:300], "reasons": reasons, "severity": sev})
            entry["flagged"] = len(flagged)
            inv.append(entry)
            tail = "\n".join(l for _, l in lines[-15:])
            findings.append(_finding_from_file(case, uac_root, "/" + rel, severity="info", rule="uac.history",
                                               title=f"Shell history for {user}: {len(lines)} lines, {len(flagged)} worth reading ({name})",
                                               description="Last lines are quoted; every flagged line is listed in inventory.json under "
                                                           "system.shell_history. History files are user-writable and carry no timestamps "
                                                           "unless HISTTIMEFORMAT was set, so treat them as leads, not as a log.",
                                               excerpt=tail or None, tags=["history", "account"],
                                               extra={"user": user, "flagged": flagged[:200]}))
            # one finding per flagged line of medium or higher so each is citable and archivable on its own
            for fl in flagged:
                if sev_rank(fl["severity"]) < sev_rank("medium"):
                    continue
                findings.append(_finding_from_file(case, uac_root, "/" + rel, severity=fl["severity"], rule="uac.history_command",
                                                   title=f"{user} history: {'; '.join(fl['reasons'])}",
                                                   description=f"Command at line {fl['line']} of {name} for account {user}.",
                                                   line=fl["line"], excerpt=fl["command"], tags=["history", "account"],
                                                   extra={"user": user, "reasons": fl["reasons"]}))
    return findings, inv


def check_cron(case, uac_root) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    inventory: list[dict[str, Any]] = []
    candidates: list[str] = ["etc/crontab"]
    # enumerate from mount (UAC copies the same tree)
    for base in ("etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly",
                 "var/spool/cron/crontabs", "var/spool/cron"):
        roots = []
        if uac_root:
            roots += [uac_root / "files" / base, uac_root / "[root]" / base]
        roots.append(case.abs(base))
        seen = set()
        for r in roots:
            if r.exists() and r.is_dir():
                for f in sorted(r.iterdir()):
                    if f.is_file() and f.name not in seen:
                        seen.add(f.name)
                        candidates.append(f"{base}/{f.name}")
    for rel in candidates:
        p = _collected_or_mount(case, uac_root, rel)
        if not p or is_binary_file(p):
            continue
        for no, line in read_lines(p):
            s = line.strip()
            if not s or s.startswith("#") or "=" in s.split()[0]:
                continue
            inventory.append({"file": "/" + rel, "line": no, "entry": s})
            reasons = _suspicious_command(case, s)
            if reasons:
                findings.append(_finding_from_file(case, uac_root, "/" + rel, severity="high", rule="uac.cron_suspicious",
                                                   title=f"Cron entry {'; '.join(reasons)}",
                                                   description="Scheduled command with properties common to malicious persistence.",
                                                   line=no, excerpt=s, tags=["persistence", "cron"]))
    return findings, inventory


def check_systemd(case, uac_root) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    inventory: list[dict[str, Any]] = []
    for base in ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system", "root/.config/systemd/user"):
        roots = []
        if uac_root:
            roots += [uac_root / "files" / base, uac_root / "[root]" / base]
        roots.append(case.abs(base))
        seen = set()
        for r in roots:
            if not (r.exists() and r.is_dir()):
                continue
            for f in sorted(r.rglob("*.service")):
                rel = base + "/" + f.relative_to(r).as_posix()
                if rel in seen or not f.is_file():
                    continue
                seen.add(rel)
                exec_lines = []
                for no, line in read_lines(f):
                    if line.strip().startswith(("ExecStart", "ExecStartPre", "ExecStartPost")):
                        exec_lines.append((no, line.strip()))
                p = _collected_or_mount(case, uac_root, rel)
                inventory.append({"unit": "/" + rel, "exec": [l for _, l in exec_lines]})
                for no, line in exec_lines:
                    reasons = _suspicious_command(case, line)
                    if reasons and base == "etc/systemd/system":
                        findings.append(_finding_from_file(case, uac_root, "/" + rel, severity="high",
                                                           rule="uac.systemd_suspicious",
                                                           title=f"systemd unit {'; '.join(reasons)}: {f.name}",
                                                           description="Unit in /etc/systemd/system (admin-created) whose "
                                                                       "command has properties common to malicious persistence.",
                                                           line=no, excerpt=line, tags=["persistence", "systemd"]))
    return findings, inventory


def check_authorized_keys(case, uac_root) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    inventory: list[dict[str, Any]] = []
    homes = ["root"]
    home_root = case.abs("home")
    if home_root.exists():
        homes += [f"home/{d.name}" for d in sorted(home_root.iterdir()) if d.is_dir()]
    www = case.abs("www")
    if www.exists():
        homes.append("www")
    for hdir in homes:
        rel = f"{hdir}/.ssh/authorized_keys"
        p = _collected_or_mount(case, uac_root, rel)
        if not p:
            continue
        f = _finding_from_file(case, uac_root, "/" + rel, severity="medium" if hdir == "root" else "low",
                               rule="uac.authorized_keys",
                               title=f"SSH authorized_keys present for {hdir.split('/')[-1]}",
                               description="Each key below grants login as this user. Compare ctime with the incident window "
                                           "and confirm each key with the owner.",
                               tags=["persistence", "ssh"])
        keys = []
        for no, line in read_lines(p):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            keytype = parts[0] if parts else ""
            comment = " ".join(parts[2:]) if len(parts) > 2 else ""
            fp = None
            try:
                import base64, hashlib
                blob = base64.b64decode(parts[1]) if len(parts) > 1 else b""
                fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
            except Exception:
                fp = None
            keys.append({"line": no, "type": keytype, "fingerprint": fp, "comment": comment})
        f.extra["keys"] = keys
        f.excerpt = "\n".join(f"{k['line']}: {k['type']} {k['fingerprint']} {k['comment']}".strip() for k in keys)
        inventory.append({"file": "/" + rel, "ctime": f.ctime, "mtime": f.mtime, "keys": keys})
        findings.append(f)
    return findings, inventory


def check_sshd_and_sudoers(case, uac_root) -> list[Finding]:
    findings: list[Finding] = []
    p = _collected_or_mount(case, uac_root, "etc/ssh/sshd_config")
    if p:
        for no, line in read_lines(p):
            s = line.strip()
            if re.match(r"^PermitRootLogin\s+yes", s, re.I):
                findings.append(_finding_from_file(case, uac_root, "/etc/ssh/sshd_config", severity="low",
                                                   rule="uac.sshd_root", title="sshd permits root login",
                                                   line=no, excerpt=s, tags=["hardening", "ssh"]))
            if re.match(r"^PasswordAuthentication\s+yes", s, re.I):
                findings.append(_finding_from_file(case, uac_root, "/etc/ssh/sshd_config", severity="low",
                                                   rule="uac.sshd_password", title="sshd permits password authentication",
                                                   line=no, excerpt=s, tags=["hardening", "ssh"]))
    for rel in ["etc/sudoers"] + [f"etc/sudoers.d/{f.name}" for f in (case.abs("etc/sudoers.d").iterdir() if case.abs("etc/sudoers.d").exists() else [])]:
        p = _collected_or_mount(case, uac_root, rel)
        if not p:
            continue
        for no, line in read_lines(p):
            s = line.strip()
            if "NOPASSWD" in s and "ALL" in s and not s.startswith("#"):
                findings.append(_finding_from_file(case, uac_root, "/" + rel, severity="medium", rule="uac.sudo_nopasswd",
                                                   title="sudoers grants NOPASSWD ALL", line=no, excerpt=s,
                                                   tags=["persistence", "sudo"]))
    return findings


def run(case) -> list[Finding]:
    raw_dir = case.raw / "uac"
    uac_root = locate_uac_root(raw_dir)
    findings: list[Finding] = []
    inventory: dict[str, Any] = {}
    bodyfile = None
    if uac_root:
        for cand in (uac_root / "bodyfile" / "bodyfile.txt", uac_root / "bodyfile.txt"):
            if cand.exists():
                bodyfile = cand
                break
    if bodyfile:
        db, nrows = load_bodyfile(case, bodyfile)
        bursts, f = timeline_and_checks(case, db)
        findings += f
        inventory["bodyfile_rows"] = nrows
        inventory["bursts"] = len(bursts)
        inventory["timeline_db"] = str(db.relative_to(case.dir))
    else:
        findings.append(Finding(source="uac", severity="info", rule="uac.missing",
                                title="No UAC bodyfile found; timeline and timestomp checks skipped",
                                description=f"Expected UAC output under {raw_dir}. Run `gumshoe collect --tools uac`."))
    f, inv = check_passwd(case, uac_root); findings += f; inventory.update(inv)
    f, inv = check_shell_history(case, uac_root, inventory.get("accounts", [])); findings += f; inventory["shell_history"] = inv
    findings += check_preload(case, uac_root)
    f, inv = check_cron(case, uac_root); findings += f; inventory["cron"] = inv
    f, inv = check_systemd(case, uac_root); findings += f; inventory["systemd"] = inv
    f, inv = check_authorized_keys(case, uac_root); findings += f; inventory["authorized_keys"] = inv
    findings += check_sshd_and_sudoers(case, uac_root)
    for fd in findings:
        fd.raw_ref = str(uac_root.relative_to(case.dir)) if uac_root else None
    existing = case.read_json("inventory.json", {}) or {}
    existing["system"] = inventory
    case.write_json("inventory.json", existing)
    return findings
