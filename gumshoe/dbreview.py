"""MariaDB review through a private server (inside WSL).

The InnoDB/Aria files in the datadir cannot be parsed safely without the
engine, so a private mariadbd is started over the datadir (an overlay: the
evidence stays read-only, the server's writes land in the case's work folder;
see dbengine.py), a fixed set of queries runs into static JSON, and it stops.

Server images are almost never cleanly shut down, so the redo log is dirty and
InnoDB must run crash recovery; that is impossible under --innodb-read-only, so
recovery is allowed to roll forward on the copy. If startup fails the
--innodb-force-recovery level is raised 0 -> 1 -> 3 -> 4 (4 and above make
InnoDB read-only internally) and the level used is written to the custody log
and dbreview.json. The evidence mount is never opened by the server. Needs
`mariadbd` and `mariadb` on PATH (apt install mariadb-server in the distro)
and free disk at least the size of the datadir for the copy.

Queries (all read-only):
  * mysql.user / global_priv: accounts, hosts, auth plugin          -> inventory + findings for '%' hosts
  * mysql.func: registered user-defined functions                     -> critical if any (UDF persistence)
  * mysql.plugin: installed plugins                                   -> inventory
  * per database: *_users / *_usermeta (WordPress-style) newest accounts and administrators,
    *_options siteurl/home/active_plugins/users_can_register/default_role
Also parses the server's own my.cnf files from the image (secure_file_priv,
bind-address, general_log) and /root/.mysql_history (text, indexed as an artifact).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from .normalize.base import Finding, with_provenance, read_lines


def _mysql(sock: Path, sql: str, db: Optional[str] = None) -> list[list[str]]:
    cmd = ["mariadb", f"--socket={sock}", "-u", "root", "-N", "-B", "--raw"]
    if db:
        cmd.append(db)
    cmd += ["-e", sql]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[:400])
    return [line.split("\t") for line in out.stdout.splitlines() if line.strip()]


def _select_existing(sock: Path, table: str, wanted: list[str], db: Optional[str] = None, extra: str = "") -> tuple[list[str], list[list[str]]]:
    """SELECT only the columns that exist in this server's version of the table (MySQL 5.x/8 and MariaDB differ)."""
    cols = {r[0] for r in _mysql(sock, f"SHOW COLUMNS FROM {table}", db)}
    use = [c for c in wanted if c in cols]
    if not use:
        return [], []
    return use, _mysql(sock, f"SELECT {', '.join(use)} FROM {table} {extra}".strip(), db)


def static_inventory(datadir: Path) -> dict[str, Any]:
    """What the datadir says about itself without a server: databases (directories), their table files and
    newest change, and version hints. Always recorded; the only review possible when the server cannot open the files."""
    inv: dict[str, Any] = {"databases": {}, "version_hints": []}
    for d in sorted(p for p in datadir.iterdir() if p.is_dir() and not p.name.startswith(("#", "."))):
        files = [f for f in d.iterdir() if f.is_file()]
        tables = sorted({f.stem.split(".")[0] for f in files if f.suffix in (".frm", ".ibd", ".MYD", ".MAD", ".sdi", ".par")})
        newest = max((f.stat().st_mtime for f in files), default=0)
        inv["databases"][d.name] = {"tables": tables[:500], "n_tables": len(tables), "files": len(files),
                                    "bytes": sum(f.stat().st_size for f in files),
                                    "newest_mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(newest)) if newest else None}
    upg = datadir / "mysql_upgrade_info"
    if upg.exists():
        inv["version_hints"].append(f"mysql_upgrade_info: {upg.read_text(errors='replace').strip()[:80]}")
    if (datadir / "#innodb_redo").exists() or (datadir / "undo_001").exists() or (datadir / "mysql.ibd").exists():
        inv["version_hints"].append("MySQL 8.0+ datadir layout (#innodb_redo / undo_001 / mysql.ibd): MariaDB cannot open it; review with MySQL 8")
    if (datadir / "aria_log_control").exists():
        inv["version_hints"].append("aria_log_control present: MariaDB")
    for name in ("auto.cnf", "mysqld-auto.cnf"):
        f = datadir / name
        if f.exists():
            inv["version_hints"].append(f"{name}: {f.read_text(errors='replace').strip()[:120]}")
    for f in sorted(datadir.glob("*.err"))[:3]:
        inv["version_hints"].append(f"error log in datadir: {f.name} ({f.stat().st_size} bytes)")
    return inv


def review(case, log=print) -> list[Finding]:
    findings: list[Finding] = []
    results: dict[str, Any] = {"started": time.time()}
    datadir = None
    for rel in case.cfg["paths"]["mariadb_data"]:
        p = case.abs(rel)
        if p.exists() and (p / "mysql").exists():
            datadir = p
            results["datadir"] = case.rel(p)
            break
    # ---- config and history from the image (no server needed) ----------------------
    for rel in ("etc/my.cnf", "etc/mysql/my.cnf", "www/server/mysql/etc/my.cnf", "etc/mysql/mariadb.conf.d/50-server.cnf"):
        p = case.abs(rel)
        if not p.exists():
            continue
        for no, line in read_lines(p):
            s = line.strip()
            if re.match(r"^secure[-_]file[-_]priv\s*=\s*$", s) or re.match(r"^secure[-_]file[-_]priv\s*=\s*[\"']{2}\s*$", s):
                findings.append(with_provenance(case, Finding(source="dbreview", severity="medium", rule="db.secure_file_priv",
                                                              title="secure_file_priv is empty: LOAD_FILE/INTO OUTFILE allowed anywhere",
                                                              path="/" + rel, line=no, excerpt=s, tags=["mariadb", "hardening"])))
            if re.match(r"^bind[-_]address\s*=\s*(0\.0\.0\.0|::)\s*$", s):
                findings.append(with_provenance(case, Finding(source="dbreview", severity="low", rule="db.bind_all",
                                                              title="MariaDB bound to all interfaces", path="/" + rel, line=no, excerpt=s,
                                                              tags=["mariadb", "hardening"])))
            if re.match(r"^general[-_]log\s*=\s*(1|on)\s*$", s, re.I):
                findings.append(with_provenance(case, Finding(source="dbreview", severity="info", rule="db.general_log",
                                                              title="MariaDB general query log is enabled (a query log may exist in the datadir)",
                                                              path="/" + rel, line=no, excerpt=s, tags=["mariadb"])))
    hist = case.abs("root/.mysql_history")
    if hist.exists():
        lines = [l for _, l in read_lines(hist, limit=5000)]
        hits = [l for l in lines if re.search(r"INTO\s+(OUT|DUMP)FILE|LOAD_FILE|CREATE\s+FUNCTION|GRANT\s+ALL|CREATE\s+USER", l, re.I)]
        findings.append(with_provenance(case, Finding(
            source="dbreview", severity="high" if hits else "info", rule="db.history",
            title=f"root's MariaDB command history: {len(lines)} lines" + (f", {len(hits)} with file-write, UDF or grant statements" if hits else ""),
            path="/root/.mysql_history", excerpt="\n".join(hits[:20]) or None, tags=["mariadb", "history"])))
    # ---- plugin dir inventory --------------------------------------------------------
    for rel in case.cfg["paths"]["mariadb_plugin"]:
        d = case.abs(rel)
        if d.exists():
            sos = sorted(p for p in d.iterdir() if p.suffix == ".so")
            results.setdefault("plugin_dir", {})[rel] = [p.name for p in sos]
    if datadir is None:
        findings.append(Finding(source="dbreview", severity="info", rule="db.no_datadir",
                                title="No MariaDB datadir found; table review skipped",
                                description="Looked in " + ", ".join(case.cfg["paths"]["mariadb_data"])))
        case.write_json("dbreview.json", results)
        return findings
    try:
        results["static"] = static_inventory(datadir)
        dbs_static = results["static"]["databases"]
        app_dbs = [n for n in dbs_static if n not in ("mysql", "performance_schema", "sys", "information_schema")]
        findings.append(Finding(source="dbreview", severity="info", rule="db.inventory",
                                title=f"MariaDB/MySQL datadir {results['datadir']}: {len(app_dbs)} application database(s), "
                                      f"{sum(d['n_tables'] for d in dbs_static.values())} table(s)",
                                description="Databases (newest table change): " + "; ".join(
                                    f"{n} ({dbs_static[n]['n_tables']} tables, {dbs_static[n]['newest_mtime']})" for n in app_dbs[:40]) +
                                    ((" | " + " | ".join(results["static"]["version_hints"])) if results["static"]["version_hints"] else ""),
                                path=results["datadir"], tags=["mariadb", "inventory"]))
    except Exception as e:  # noqa: BLE001
        results["static_error"] = str(e)[:300]
    if not shutil.which("mariadbd") or not shutil.which("mariadb"):
        findings.append(Finding(source="dbreview", severity="info", rule="db.no_server",
                                title="mariadbd/mariadb not on PATH; table review skipped (run inside the WSL distro)"))
        case.write_json("dbreview.json", results)
        return findings
    # ---- a private server over the datadir (overlay: no copy; see dbengine) ------------------
    from .dbengine import PrivateMariaDB, datadir_flavour
    fl = datadir_flavour(datadir)
    from .dbengine import mysql8_available
    if fl.get("mysql8") and not mysql8_available():
        findings.append(Finding(source="dbreview", severity="info", rule="db.mysql8",
                                title="MySQL 8.0 data directory and the MySQL 8.0 engine is not unpacked in this distro; table review skipped",
                                description="Run Gumshoe.bat once with a bundle that carries the mysql-server-core-8.0 debs (unpacked to /opt/dfir/mysql8). "
                                            "The static inventory above still applies.", path=results["datadir"]))
        case.write_json("dbreview.json", results)
        return findings
    work = case.collected / "dbwork"
    try:
        srv = PrivateMariaDB(datadir, work, log, case.custody).__enter__()
    except Exception as e:  # noqa: BLE001
        findings.append(Finding(source="dbreview", severity="info", rule="db.start_failed",
                                title="MariaDB review failed: the private server would not start on this datadir",
                                description=f"{type(e).__name__}: {str(e)[:600]}", path=results["datadir"]))
        results["start_error"] = str(e)[:600]
        case.write_json("dbreview.json", results)
        return findings
    sock = srv.sock
    used_level = srv.level
    results["innodb_force_recovery"] = used_level
    results["mode"] = srv.mode
    if used_level:
        findings.append(Finding(source="dbreview", severity="info", rule="db.recovery_level",
                                title=f"MariaDB needed innodb_force_recovery={used_level} to start (dirty shutdown in the image)",
                                description="Recovery ran in the overlay/copy only. Levels 3-4 skip transaction rollback/undo; row data "
                                            "from uncommitted transactions may be absent."))
    errors: list[str] = []

    def step(name, fn):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - one failed query must not end the review
            errors.append(f"{name}: {type(e).__name__}: {str(e)[:300]}")

    def _users():
        cols, rows = _select_existing(sock, "mysql.user", ["User", "Host", "plugin", "authentication_string", "account_locked",
                                                           "password_expired", "is_role"])
        results["users_columns"] = cols
        results["users"] = rows
        ih = cols.index("Host") if "Host" in cols else -1
        iu = cols.index("User") if "User" in cols else -1
        for u in rows:
            if ih >= 0 and iu >= 0 and len(u) > ih and u[ih] == "%":
                findings.append(Finding(source="dbreview", severity="medium", rule="db.user_anyhost",
                                        title=f"MariaDB account '{u[iu]}'@'%' can connect from any host", tags=["mariadb", "account"],
                                        path=results["datadir"], extra={"user": dict(zip(cols, u))}))

    def _func():
        cols, rows = _select_existing(sock, "mysql.func", ["name", "ret", "dl", "type"])
        results["func"] = rows
        idl = cols.index("dl") if "dl" in cols else 2
        for fn in rows:
            findings.append(Finding(source="dbreview", severity="critical", rule="db.udf",
                                    title=f"User-defined function registered: {fn[0]} -> {fn[idl] if len(fn) > idl else '?'}",
                                    description="mysql.func lists UDFs loaded from the plugin directory; a UDF is the classic way to "
                                                "run OS commands from SQL. Compare the library name with the plugin-dir inventory.",
                                    path=results["datadir"], tags=["mariadb", "persistence", "udf"], extra={"func": fn}))

    def _plugins():
        results["plugins"] = _select_existing(sock, "mysql.plugin", ["name", "dl"])[1]

    def _databases():
        dbs = [r[0] for r in _mysql(sock, "SHOW DATABASES") if r and r[0] not in ("information_schema", "performance_schema", "mysql", "sys")]
        results["databases"] = {}
        for db in dbs:
            info: dict[str, Any] = {}
            try:
                info["tables"] = [r[0] for r in _mysql(sock, "SHOW TABLES", db)]
            except Exception as e:  # noqa: BLE001
                info["error"] = str(e)[:200]; results["databases"][db] = info; continue
            for t in info["tables"]:
                if not (t.endswith("_users") or t == "users"):
                    continue
                try:
                    cols = {r[0] for r in _mysql(sock, f"SHOW COLUMNS FROM `{t}`", db)}
                    if not {"user_login", "user_registered"} <= cols:
                        continue
                    prefix = t[:-5]
                    info[t] = _mysql(sock, f"SELECT ID, user_login, user_email, user_registered FROM `{t}` ORDER BY user_registered DESC LIMIT 25", db)
                    admins = _mysql(sock, f"SELECT u.ID, u.user_login, u.user_registered FROM `{t}` u JOIN `{prefix}usermeta` m ON m.user_id=u.ID "
                                          f"WHERE m.meta_key LIKE '%capabilities' AND m.meta_value LIKE '%administrator%' ORDER BY u.user_registered DESC", db)
                    info[f"{t}_administrators"] = admins
                    for a in admins[:10]:
                        findings.append(Finding(source="dbreview", severity="low", rule="db.wp_admin",
                                                title=f"{db}: WordPress administrator '{a[1]}' registered {a[2]}",
                                                description="Confirm each administrator with the site owner; attacker-created admins are common.",
                                                path=results["datadir"], tags=["mariadb", "wordpress", "account"], extra={"db": db, "row": a}))
                    opts = _mysql(sock, f"SELECT option_name, LEFT(option_value, 400) FROM `{prefix}options` WHERE option_name IN "
                                        f"('siteurl','home','admin_email','users_can_register','default_role','active_plugins')", db)
                    info[f"{prefix}options"] = opts
                    for o in opts:
                        if o[0] == "users_can_register" and o[1] == "1":
                            findings.append(Finding(source="dbreview", severity="low", rule="db.wp_register",
                                                    title=f"{db}: WordPress open registration is enabled", path=results["datadir"],
                                                    tags=["mariadb", "wordpress"], extra={"db": db}))
                        if o[0] == "default_role" and o[1] == "administrator":
                            findings.append(Finding(source="dbreview", severity="high", rule="db.wp_default_admin",
                                                    title=f"{db}: WordPress default role for new users is administrator", path=results["datadir"],
                                                    tags=["mariadb", "wordpress", "persistence"], extra={"db": db}))
                except Exception as e:  # noqa: BLE001
                    info[f"{t}_error"] = str(e)[:200]
            results["databases"][db] = info

    try:
        results["server_version"] = (_mysql(sock, "SELECT VERSION()") or [[""]])[0][0]
        step("users", _users)
        step("func", _func)
        step("plugins", _plugins)
        step("databases", _databases)
        if errors:
            results["errors"] = errors
            findings.append(Finding(source="dbreview", severity="info", rule="db.partial",
                                    title=f"MariaDB review completed with {len(errors)} query error(s)", description="; ".join(errors)[:800]))
    finally:
        srv.close()
    results["finished"] = time.time()
    case.write_json("dbreview.json", results)
    return findings
