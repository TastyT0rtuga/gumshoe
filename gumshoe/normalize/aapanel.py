"""aaPanel / BT Panel artifacts. Nothing off the shelf reads these, so this is
custom glue:

  * data/default.db (SQLite, opened read-only and immutable): users (login IP/time),
    logs (the panel operation log: who did what, from where), crontab (panel-managed
    scheduled tasks and their script bodies), sites, domain, databases, ftps, firewall
    — credential columns are never read.
  * /www/server/cron/<id>  the generated task scripts and their .log outputs
  * data/port.pl, admin_path.pl, ssl.pl, limitip.conf, domain.conf
  * vhost/nginx/*.conf and vhost/apache/*.conf: root/alias outside the web roots,
    proxy_pass to a non-local upstream, include of a file outside the panel tree,
    rewrite/return to an external URL.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Optional

from .base import Finding, with_provenance, read_lines, is_binary_file
from .uac import _suspicious_command

SECRET_COLS = re.compile(r"(pass|pwd|salt|secret|token|key|auth)", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _connect_ro(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True)
    # panel text is normally UTF-8; never fail on a stray legacy-encoded row (Cyrillic cp1251 etc.)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    return con


def _tables(con: sqlite3.Connection) -> list[str]:
    return [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]


def _columns(con: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in con.execute(f"PRAGMA table_info('{table}')")]


def _rows(con: sqlite3.Connection, table: str, limit: int = 5000) -> list[dict[str, Any]]:
    cols = [c for c in _columns(con, table) if not SECRET_COLS.search(c)]
    if not cols:
        return []
    q = f"SELECT {', '.join(chr(34) + c + chr(34) for c in cols)} FROM \"{table}\" LIMIT {int(limit)}"
    return [dict(zip(cols, r)) for r in con.execute(q)]


def _epoch_to_iso(v: Any) -> Any:
    try:
        from datetime import datetime, timezone
        iv = int(v)
        if 1_000_000_000 < iv < 4_000_000_000:
            return datetime.fromtimestamp(iv, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        pass
    return v


def panel_db(case, panel_rel: str) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    inv: dict[str, Any] = {}
    db_rel = f"{panel_rel}/data/default.db"
    db = case.abs(db_rel)
    if not db.exists():
        return findings, inv
    try:
        con = _connect_ro(db)
    except sqlite3.Error as e:
        findings.append(Finding(source="aapanel", severity="info", title="Panel database could not be opened",
                                description=str(e), path="/" + db_rel))
        return findings, inv
    try:
        tables = set(_tables(con))
        inv["tables"] = sorted(tables)
        if "users" in tables:
            users = _rows(con, "users")
            for u in users:
                u["login_time"] = _epoch_to_iso(u.get("login_time"))
            inv["users"] = users
            for u in users:
                f = Finding(source="aapanel", severity="info", rule="aapanel.user",
                            title=f"Panel account {u.get('username')} last login {u.get('login_time')} from {u.get('login_ip')}",
                            path="/" + db_rel, tags=["aapanel", "account"], extra=u)
                findings.append(with_provenance(case, f))
        if "logs" in tables:
            logs = _rows(con, "logs", limit=20000)
            by_ip: dict[str, dict[str, Any]] = {}
            cats: dict[str, int] = {}
            for row in logs:
                row["addtime"] = _epoch_to_iso(row.get("addtime"))
                text = f"{row.get('type', '')} {row.get('log', '')}"
                cats[row.get("type", "")] = cats.get(row.get("type", ""), 0) + 1
                for ip in IP_RE.findall(text):
                    e = by_ip.setdefault(ip, {"count": 0, "first": row["addtime"], "last": row["addtime"], "types": set()})
                    e["count"] += 1
                    e["last"] = row["addtime"]
                    e["types"].add(row.get("type", ""))
            inv["operation_log"] = {"rows": len(logs), "by_type": cats,
                                    "by_ip": {ip: {**e, "types": sorted(e["types"])} for ip, e in by_ip.items()}}
            inv["operation_log_sample"] = logs[-500:]
            for ip, e in by_ip.items():
                f = Finding(source="aapanel", severity="low", rule="aapanel.panel_ip",
                            title=f"Panel operations from {ip}: {e['count']} entries ({', '.join(sorted(e['types']))[:120]})",
                            description=f"First {e['first']}, last {e['last']}. Confirm the address belongs to an administrator.",
                            path="/" + db_rel, tags=["aapanel", "panel-access"], extra={"ip": ip, **{k: v for k, v in e.items() if k != 'types'}})
                findings.append(with_provenance(case, f))
        if "crontab" in tables:
            crons = _rows(con, "crontab")
            for c in crons:
                c["addtime"] = _epoch_to_iso(c.get("addtime"))
            inv["panel_cron"] = crons
            for c in crons:
                body = str(c.get("sBody") or "")
                reasons = _suspicious_command(case, body) if body else []
                sev = "high" if reasons else "info"
                f = Finding(source="aapanel", severity=sev, rule="aapanel.cron",
                            title=f"Panel cron task '{c.get('name')}' ({c.get('sType') or c.get('type')}) added {c.get('addtime')}"
                                  + (f" — {'; '.join(reasons)}" if reasons else ""),
                            description=f"Status {c.get('status')}, schedule type {c.get('type')} {c.get('where1')} "
                                        f"{c.get('where_hour')}:{c.get('where_minute')}. Script id {c.get('echo')}.",
                            path="/" + db_rel, excerpt=body[:600] or None, tags=["aapanel", "cron", "persistence"], extra=c)
                findings.append(with_provenance(case, f))
        for t in ("sites", "domain", "databases", "ftps", "firewall", "binding"):
            if t in tables:
                rows = _rows(con, t)
                for r in rows:
                    if "addtime" in r:
                        r["addtime"] = _epoch_to_iso(r["addtime"])
                inv[t] = rows
    finally:
        con.close()
    return findings, inv


def panel_cron_scripts(case, cron_rel: str) -> list[Finding]:
    findings: list[Finding] = []
    root = case.abs(cron_rel)
    if not root.exists():
        return findings
    for p in sorted(root.iterdir()):
        if not p.is_file() or p.suffix == ".log" or is_binary_file(p):
            continue
        rel = "/" + cron_rel.strip("/") + "/" + p.name
        body = "\n".join(l for _, l in read_lines(p, limit=400))
        reasons = _suspicious_command(case, body)
        f = Finding(source="aapanel", severity="high" if reasons else "info", rule="aapanel.cron_script",
                    title=f"Panel cron script {p.name}" + (f" — {'; '.join(reasons)}" if reasons else ""),
                    path=rel, excerpt=body[:600], tags=["aapanel", "cron", "persistence"])
        findings.append(with_provenance(case, f))
    return findings


def panel_settings(case, panel_rel: str) -> tuple[list[Finding], dict[str, Any]]:
    inv: dict[str, Any] = {}
    findings: list[Finding] = []
    for name in ("port.pl", "admin_path.pl", "ssl.pl", "limitip.conf", "domain.conf", "basic_auth.json"):
        p = case.abs(f"{panel_rel}/data/{name}")
        if p.exists() and p.is_file() and not is_binary_file(p):
            txt = "\n".join(l for _, l in read_lines(p, limit=50)).strip()
            inv[name] = txt if name != "basic_auth.json" else "(present)"
    plugins_dir = case.abs(f"{panel_rel}/plugin")
    if plugins_dir.exists():
        inv["plugins"] = sorted(d.name for d in plugins_dir.iterdir() if d.is_dir())
    if inv:
        findings.append(Finding(source="aapanel", severity="info", rule="aapanel.settings",
                                title=f"Panel settings: port {inv.get('port.pl')}, entrance {inv.get('admin_path.pl')}, "
                                      f"ssl {'on' if 'ssl.pl' in inv else 'off'}, ip limit {inv.get('limitip.conf') or 'none'}",
                                path=f"/{panel_rel}/data", tags=["aapanel"], extra=inv))
    return findings, inv


DIRECTIVE = re.compile(r"^\s*(root|alias|proxy_pass|rewrite|include|return|fastcgi_pass|location|server_name|set_real_ip_from)\s+(.*?);?\s*$")
APACHE = re.compile(r"^\s*(DocumentRoot|ProxyPass|ProxyPassReverse|Include|IncludeOptional|RewriteRule|Alias|Redirect)\s+(.*)$", re.I)


def vhost_configs(case, panel_rel: str) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    inv: list[dict[str, Any]] = []
    web_roots = [w.strip("/") for w in case.cfg["paths"]["web_roots"]]
    allowed_include = (f"/{panel_rel}/vhost", "/www/server/nginx/conf", "/www/server/apache/conf", "/etc/nginx", "/etc/apache2",
                       "/www/server/panel/vhost")
    for sub, rx in (("vhost/nginx", DIRECTIVE), ("vhost/apache", APACHE)):
        d = case.abs(f"{panel_rel}/{sub}")
        if not d.exists():
            continue
        for cf in sorted(d.glob("*.conf")):
            rel = f"/{panel_rel}/{sub}/{cf.name}"
            entry = {"file": rel, "directives": []}
            for no, line in read_lines(cf):
                m = rx.match(line)
                if not m:
                    continue
                key, val = m.group(1), m.group(2).strip().rstrip(";")
                entry["directives"].append({"line": no, key: val})
                k = key.lower()
                reason = None
                if k in ("root", "alias", "documentroot"):
                    v = val.split()[0].strip('"')
                    if not any(v.lstrip("/").startswith(w + "/") or v.strip("/") == w for w in web_roots) and not v.startswith(("/www/server/phpmyadmin", "/www/server/stop")):
                        reason = f"document root outside the web roots: {v}"
                elif k in ("proxy_pass", "proxypass", "proxypassreverse"):
                    if not re.search(r"(127\.0\.0\.1|localhost|unix:|\[::1\])", val):
                        reason = f"proxies to a non-local upstream: {val}"
                elif k in ("include", "includeoptional"):
                    v = val.split()[0].strip('"')
                    if v.startswith("/") and not v.startswith(allowed_include):
                        reason = f"includes a file outside the panel/nginx tree: {v}"
                elif k in ("rewrite", "rewriterule", "return", "redirect"):
                    if re.search(r"https?://", val) and not re.search(r"\$host|\$server_name|%\{HTTP_HOST\}", val):
                        reason = f"redirects to a fixed external URL: {val[:120]}"
                if reason:
                    f = Finding(source="aapanel", severity="medium", rule="aapanel.vhost",
                                title=f"vhost {cf.name}: {reason}", path=rel, line=no, excerpt=line.strip(),
                                description="Verify against the site owner's intent; injected vhost directives are a known "
                                            "way to redirect, proxy or expose content on control-panel hosts.",
                                tags=["aapanel", "vhost", "web"])
                    findings.append(with_provenance(case, f))
            inv.append(entry)
    return findings, inv


def run(case) -> list[Finding]:
    panel_rel = case.cfg["paths"]["panel"].strip("/")
    cron_rel = case.cfg["paths"]["panel_cron"].strip("/")
    findings: list[Finding] = []
    inv_all = case.read_json("inventory.json", {}) or {}
    if not case.abs(panel_rel).exists():
        inv_all["aapanel"] = {"present": False}
        case.write_json("inventory.json", inv_all)
        return [Finding(source="aapanel", severity="info", rule="aapanel.absent",
                        title="aaPanel directory not found; panel checks skipped", description=f"Looked for /{panel_rel}")]
    f, inv = panel_db(case, panel_rel); findings += f
    findings += panel_cron_scripts(case, cron_rel)
    f2, settings = panel_settings(case, panel_rel); findings += f2
    f3, vh = vhost_configs(case, panel_rel); findings += f3
    inv_all["aapanel"] = {"present": True, **inv, "settings": settings, "vhosts": vh}
    case.write_json("inventory.json", inv_all)
    return findings
