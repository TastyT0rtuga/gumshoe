"""MariaDB review on a copy of the datadir (inside WSL).

The InnoDB/Aria files in the datadir cannot be parsed safely without the
engine, so this copies the datadir into the case directory, starts a private
mariadbd on the COPY (unix socket, --skip-networking --skip-grant-tables),
runs a fixed set of queries into static JSON, and stops it.

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
    if not shutil.which("mariadbd") or not shutil.which("mariadb"):
        findings.append(Finding(source="dbreview", severity="info", rule="db.no_server",
                                title="mariadbd/mariadb not on PATH; table review skipped (run inside the WSL distro)"))
        case.write_json("dbreview.json", results)
        return findings
    # ---- copy datadir into the case directory ---------------------------------------------
    work = case.collected / "dbcopy"
    sock = work / "mariadb.sock"
    if not (work / "data").exists():
        dbcfg = case.cfg.get("dbreview", {}) or {}
        cap = int(float(dbcfg.get("max_copy_gb", 20)) * 2**30)
        wanted = set(dbcfg.get("databases") or [])
        # size per top-level entry: system files + mysql/ schema are always needed; app databases are optional
        entries = {}
        for e in datadir.iterdir():
            entries[e.name] = sum(p.stat().st_size for p in e.rglob("*") if p.is_file()) if e.is_dir() else e.stat().st_size
        total = sum(entries.values())
        system = {n for n, _ in entries.items() if not (datadir / n).is_dir() or n in ("mysql", "performance_schema", "sys")}
        per_table = any(True for _ in datadir.rglob("*.ibd"))
        if total <= cap:
            chosen = set(entries)
        else:
            chosen = system | {n for n in entries if n in wanted}
            if not per_table:
                findings.append(Finding(source="dbreview", severity="info", rule="db.shared_tablespace",
                                        title="MariaDB datadir uses a shared tablespace (no .ibd files); a partial copy cannot work",
                                        description=f"Datadir is {total // 2**30} GB, above dbreview.max_copy_gb={cap // 2**30}. Raise the cap or "
                                                    "review the database on a larger host."))
                case.write_json("dbreview.json", results)
                return findings
            skipped = sorted(set(entries) - chosen)
            findings.append(Finding(source="dbreview", severity="info", rule="db.partial_copy",
                                    title=f"MariaDB datadir is {total // 2**30} GB; only the system schema and {len(chosen - system)} named database(s) were copied",
                                    description="Add databases to dbreview.databases in config.yaml and re-run `gumshoe dbreview` to include: " +
                                                ", ".join(skipped[:40])))
        size = sum(entries[n] for n in chosen)
        free = shutil.disk_usage(case.dir).free
        if size * 1.1 > free:
            findings.append(Finding(source="dbreview", severity="info", rule="db.no_space",
                                    title=f"MariaDB review skipped: copy needs {size // 2**20} MB, only {free // 2**20} MB free in the case directory"))
            case.write_json("dbreview.json", results)
            return findings
        log(f"[dbreview] copying {len(chosen)} entries ({size // 2**20} MB) from {datadir} -> {work / 'data'} (this can take a while)")
        (work / "data").mkdir(parents=True, exist_ok=True)
        for n in sorted(chosen):
            src = datadir / n
            if src.is_dir():
                shutil.copytree(src, work / "data" / n, symlinks=False, ignore_dangling_symlinks=True)
            else:
                shutil.copy2(src, work / "data" / n)
        results["copied"] = sorted(chosen)
        case.custody.append("db_datadir_copied", {"from": case.rel(datadir), "to": str((work / "data").relative_to(case.dir)),
                                                  "bytes": size, "entries": sorted(chosen),
                                                  "note": "crash recovery will run on this copy, never on the evidence"})
    err = work / "mariadbd.err"
    (work / "tmp").mkdir(exist_ok=True)

    def _start(level: int) -> subprocess.Popen:
        cmd = ["mariadbd", "--no-defaults", f"--datadir={work / 'data'}", f"--socket={sock}", "--skip-networking",
               "--skip-grant-tables", "--skip-log-bin", f"--log-error={err}", f"--pid-file={work / 'mariadbd.pid'}",
               f"--tmpdir={work / 'tmp'}", "--innodb-buffer-pool-size=256M", f"--innodb-force-recovery={level}",
               "--skip-slave-start", "--event-scheduler=OFF", "--skip-name-resolve"]
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        case.custody.append("db_server_started", {"cmd": cmd, "force_recovery": level})
        return p

    def _wait(p: subprocess.Popen, seconds: int = 180) -> bool:
        for _ in range(seconds):
            if p.poll() is not None:
                return False
            if sock.exists():
                try:
                    _mysql(sock, "SELECT 1")
                    return True
                except Exception:
                    pass
            time.sleep(1)
        return False

    proc = None
    used_level = None
    for level in (0, 1, 3, 4):
        if sock.exists():
            try:
                sock.unlink()
            except OSError:
                pass
        proc = _start(level)
        if _wait(proc):
            used_level = level
            break
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
        log(f"[dbreview] mariadbd did not start with innodb_force_recovery={level}; see {err}")
    results["innodb_force_recovery"] = used_level
    if used_level is None:
        findings.append(Finding(source="dbreview", severity="info", rule="db.start_failed",
                                title="MariaDB review failed: server would not start on the copy at any recovery level",
                                description=f"See {err}. The datadir copy is kept for manual work."))
        case.write_json("dbreview.json", results)
        return findings
    if used_level:
        findings.append(Finding(source="dbreview", severity="info", rule="db.recovery_level",
                                title=f"MariaDB copy needed innodb_force_recovery={used_level} to start (dirty shutdown in the image)",
                                description="Recovery ran on the case copy only. Levels 3-4 skip transaction rollback/undo; row data "
                                            "from uncommitted transactions may be absent."))
    try:
        results["users"] = _mysql(sock, "SELECT User, Host, plugin, account_locked, password_expired FROM mysql.user")
        for u in results["users"]:
            if len(u) > 1 and u[1] == "%":
                findings.append(Finding(source="dbreview", severity="medium", rule="db.user_anyhost",
                                        title=f"MariaDB account '{u[0]}'@'%' can connect from any host", tags=["mariadb", "account"],
                                        path=results["datadir"], extra={"user": u}))
        results["func"] = _mysql(sock, "SELECT name, ret, dl, type FROM mysql.func")
        for fn in results["func"]:
            findings.append(Finding(source="dbreview", severity="critical", rule="db.udf",
                                    title=f"User-defined function registered: {fn[0]} -> {fn[2] if len(fn) > 2 else '?'}",
                                    description="mysql.func lists UDFs loaded from the plugin directory; a UDF is the classic way to "
                                                "run OS commands from SQL. Compare the library name with the plugin-dir inventory.",
                                    path=results["datadir"], tags=["mariadb", "persistence", "udf"], extra={"func": fn}))
        results["plugins"] = _mysql(sock, "SELECT name, dl FROM mysql.plugin")
        dbs = [r[0] for r in _mysql(sock, "SHOW DATABASES") if r and r[0] not in ("information_schema", "performance_schema", "mysql", "sys")]
        results["databases"] = {}
        for db in dbs:
            info: dict[str, Any] = {"tables": [r[0] for r in _mysql(sock, "SHOW TABLES", db)]}
            for t in info["tables"]:
                if t.endswith("_users") or t == "users":
                    cols = {r[0] for r in _mysql(sock, f"SHOW COLUMNS FROM `{t}`", db)}
                    if {"user_login", "user_registered"} <= cols:
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
            results["databases"][db] = info
    except Exception as e:
        findings.append(Finding(source="dbreview", severity="info", rule="db.error", title=f"MariaDB review failed: {type(e).__name__}",
                                description=str(e)[:600]))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
        case.custody.append("db_server_stopped", {})
    results["finished"] = time.time()
    case.write_json("dbreview.json", results)
    return findings
