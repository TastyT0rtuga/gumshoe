"""A private MariaDB server over an evidence datadir, without copying 100 GB.

The InnoDB/Aria files in a datadir cannot be read safely without the engine, and the engine must be
able to write (crash recovery: server images are almost never cleanly shut down). So the datadir is
presented to a private `mariadbd` through an **overlay**: the read-only evidence is the lower layer,
writes land in an upper directory in the work folder. Only the files the server actually modifies
(redo/undo, system tablespace, tables touched by recovery) are copied up; a 100 GB datadir needs a few
GB of work space, not 100. When overlayfs is not available (work folder on a Windows drive), the
datadir is copied as before.

The server runs with `--skip-networking --skip-grant-tables` on a unix socket, as root inside the
distro, with `--innodb-force-recovery` raised 0 -> 1 -> 3 -> 4 -> 6 until it starts (4+ make InnoDB
read-only internally). Everything it does is logged to the custody chain. MySQL 8.0 datadirs (data
dictionary in mysql.ibd, no .frm files) cannot be opened by MariaDB; they are reported, not opened.
"""
from __future__ import annotations

import os
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

Log = Callable[[str], None]
SYSTEM_SCHEMAS = {"mysql", "information_schema", "performance_schema", "sys"}
MYSQL8_ROOT = Path("/opt/dfir/mysql8")        # mysql-server-core-8.0 unpacked by the bundle's update script (not installed)


def mysql8_available() -> bool:
    return (MYSQL8_ROOT / "usr" / "sbin" / "mysqld").exists()


def datadir_flavour(datadir: Path) -> dict[str, Any]:
    """What kind of datadir this is (engine family, version hints) from file names alone."""
    d = Path(datadir)
    info: dict[str, Any] = {"mysql8": False, "mariadb": False, "hints": []}
    try:
        names = {p.name for p in d.iterdir()}
    except OSError as e:
        info["error"] = str(e)
        return info
    if "mysql.ibd" in names or "#innodb_redo" in names or "undo_001" in names:
        info["mysql8"] = True
        info["hints"].append("MySQL 8.0 layout (mysql.ibd / #innodb_redo)")
    if "aria_log_control" in names or any(n.startswith("ddl_recovery") for n in names):
        info["mariadb"] = True
        info["hints"].append("MariaDB (aria_log_control)")
    if "auto.cnf" in names:
        info["hints"].append("auto.cnf present (MySQL 5.6+ or MariaDB 10.x)")
    for n in sorted(names):
        if n.endswith(".err"):
            info["hints"].append(f"error log {n}")
    try:
        up = d / "mysql_upgrade_info"
        if up.is_file():
            info["upgrade_info"] = up.read_text("utf-8", errors="replace").strip()[:40]
            info["hints"].append(f"mysql_upgrade_info: {info['upgrade_info']}")
    except OSError:
        pass
    info["databases"] = sorted(p.name for p in d.iterdir() if p.is_dir() and p.name not in SYSTEM_SCHEMAS and not p.name.startswith(("#", ".")))
    return info


def _special(path: Path) -> bool:
    try:
        m = path.lstat().st_mode
    except OSError:
        return True
    return not (stat.S_ISREG(m) or stat.S_ISDIR(m) or stat.S_ISLNK(m))


def _du(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                pass
    return total


class PrivateMariaDB:
    """with PrivateMariaDB(datadir, work, log) as db: db.query(...) / db.stream(...)"""

    def __init__(self, datadir: Path, work: Path, log: Log = print, custody=None, buffer_pool: str = "512M", engine: str = "auto"):
        self.datadir = Path(datadir)
        self.work = Path(work)
        self.log = log
        self.custody = custody
        self.buffer_pool = buffer_pool
        self.engine = engine                     # auto | mariadb | mysql8
        self.sock = self.work / "mariadbd.sock"
        self.err = self.work / "mariadbd.err"
        self.data = self.work / "data"
        self.mode = ""            # overlay | copy
        self.level: Optional[int] = None
        self.version = ""
        self.proc: Optional[subprocess.Popen] = None
        self._overlay_mounted = False
        self._conn = None
        self.upper: Optional[Path] = None

    # ---- datadir presentation
    def _prepare(self) -> None:
        self.work.mkdir(parents=True, exist_ok=True)
        (self.work / "tmp").mkdir(exist_ok=True)
        if self.data.exists() and os.path.ismount(self.data):
            subprocess.run(["umount", "-l", str(self.data)], capture_output=True)
        upper, wdir = self.work / "upper", self.work / "work"
        for d in (upper, wdir, self.data):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
            d.mkdir(parents=True, exist_ok=True)
        # overlayfs needs an upper/work directory on a Linux file system: the work folder first, then the
        # distro's own disk (the work folder may be a Windows drive, where overlayfs cannot write)
        candidates = [(upper, wdir)]
        alt = Path("/opt/dfir/dbwork") / self.work.name
        if not str(self.work).startswith("/opt/dfir"):
            candidates.append((alt / "upper", alt / "work"))
        for up, wd in candidates:
            try:
                for d in (up, wd):
                    if d.exists():
                        shutil.rmtree(d, ignore_errors=True)
                    d.mkdir(parents=True, exist_ok=True)
            except OSError:
                continue
            def _ovl(x) -> str:                      # overlayfs option values: commas, colons and backslashes must be escaped
                return str(x).replace("\\", "\\\\").replace(",", "\\,").replace(":", "\\:")
            r = subprocess.run(["mount", "-t", "overlay", "overlay", "-o", f"lowerdir={_ovl(self.datadir)},upperdir={_ovl(up)},workdir={_ovl(wd)}", str(self.data)],
                               capture_output=True, text=True, errors="replace")
            if r.returncode == 0:
                self.mode = "overlay"
                self._overlay_mounted = True
                self.upper = up
                self.log(f"[db] datadir {self.datadir} presented through an overlay; the server's writes go to {up}")
                self._custody("db_datadir_overlay", {"lower": str(self.datadir), "upper": str(up)})
                return
            last = (r.stderr or r.stdout).strip()[:120]
        self.log(f"[db] overlay not possible here ({last}); copying the datadir instead")
        self._copy()

    def _copy(self) -> None:
        size = _du(self.datadir)
        free = shutil.disk_usage(self.work).free
        if free < size * 1.05:
            raise RuntimeError(f"not enough space to copy the datadir ({size / 2**30:.1f} GB needed, {free / 2**30:.1f} GB free in {self.work})")
        self.log(f"[db] copying {size / 2**30:.1f} GB datadir to {self.data} ...")
        skipped: list[str] = []

        def ignore(dirpath, names):
            bad = [n for n in names if _special(Path(dirpath) / n)]
            skipped.extend(bad)
            return bad
        shutil.rmtree(self.data, ignore_errors=True)
        shutil.copytree(self.datadir, self.data, symlinks=False, ignore=ignore, ignore_dangling_symlinks=True, dirs_exist_ok=True)
        self.mode = "copy"
        if skipped:
            self.log(f"[db] skipped {len(skipped)} special entries (sockets, FIFOs): {', '.join(skipped[:8])}")
        self._custody("db_datadir_copied", {"from": str(self.datadir), "to": str(self.data), "bytes": size, "skipped": skipped[:50]})

    # ---- server
    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.engine == "mysql8":
            env["LD_LIBRARY_PATH"] = str(MYSQL8_ROOT / "usr" / "lib" / "x86_64-linux-gnu") + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
        return env

    def _client_exe(self) -> str:
        if self.engine == "mysql8":
            return str(MYSQL8_ROOT / "usr" / "bin" / "mysql")
        return shutil.which("mariadb") or shutil.which("mysql") or "mariadb"

    def _cmd(self, level: int) -> list[str]:
        common = [f"--datadir={self.data}", f"--socket={self.sock}", "--skip-networking", "--skip-grant-tables", "--skip-log-bin",
                  f"--log-error={self.err}", f"--pid-file={self.work / 'mariadbd.pid'}", f"--tmpdir={self.work / 'tmp'}",
                  f"--innodb-buffer-pool-size={self.buffer_pool}", f"--innodb-force-recovery={level}", "--event-scheduler=OFF",
                  "--skip-name-resolve", "--innodb-flush-log-at-trx-commit=0", "--max-allowed-packet=1G",
                  "--net-read-timeout=3600", "--net-write-timeout=3600", "--wait-timeout=86400"]
        if self.engine == "mysql8":
            share = MYSQL8_ROOT / "usr" / "share" / "mysql-8.0"
            cmd = [str(MYSQL8_ROOT / "usr" / "sbin" / "mysqld"), "--no-defaults", f"--basedir={MYSQL8_ROOT / 'usr'}",
                   f"--lc-messages-dir={share}", f"--plugin-dir={MYSQL8_ROOT / 'usr' / 'lib' / 'mysql' / 'plugin'}", "--mysqlx=OFF",
                   "--upgrade=MINIMAL", "--secure-file-priv=", "--skip-replica-start", "--performance-schema=OFF"] + common
        else:
            exe = shutil.which("mariadbd") or shutil.which("mysqld") or "mariadbd"
            cmd = [exe, "--no-defaults", "--skip-slave-start"] + common
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd.append("--user=root")
        return cmd

    def _start(self, level: int) -> subprocess.Popen:
        cmd = self._cmd(level)
        with open(self.err, "ab") as errf:
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=errf, env=self._env())
        self._custody("db_server_started", {"cmd": cmd, "force_recovery": level, "engine": self.engine})
        return p

    def _alive(self) -> bool:
        if not self.sock.exists():
            return False
        try:
            self.query("SELECT 1")
            return True
        except Exception:  # noqa: BLE001
            return False

    def _wait(self, p: subprocess.Popen, seconds: int = 600) -> bool:
        for _ in range(seconds):
            if p.poll() is not None:
                return False
            if self._alive():
                return True
            time.sleep(1)
        return False

    def __enter__(self) -> "PrivateMariaDB":
        fl = datadir_flavour(self.datadir)
        if self.engine == "auto":
            self.engine = "mysql8" if fl.get("mysql8") else "mariadb"
        if self.engine == "mysql8" and not mysql8_available():
            raise RuntimeError("this is a MySQL 8.0 data directory (mysql.ibd data dictionary); the MariaDB engine cannot open it and the "
                               "MySQL 8.0 engine is not unpacked under /opt/dfir/mysql8 (the bundle's debs folder carries it; run Gumshoe.bat once)")
        self.log(f"[db] engine: {'MySQL 8.0 (bundled, unpacked)' if self.engine == 'mysql8' else 'MariaDB'}; " + "; ".join(fl.get("hints", [])[:3]))
        self._prepare()
        for level in (0, 1, 3, 4, 6):
            if self.sock.exists():
                try:
                    self.sock.unlink()
                except OSError:
                    pass
            self.proc = self._start(level)
            if self._wait(self.proc):
                self.level = level
                break
            self.proc.terminate()
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.log(f"[db] mariadbd did not start with innodb_force_recovery={level} (see {self.err})")
        if self.level is None:
            self.close()
            raise RuntimeError(f"the server would not start on this datadir at any recovery level; see {self.err}")
        try:
            self.version = self.query("SELECT VERSION()")[0][0]
        except Exception:  # noqa: BLE001
            self.version = "?"
        self.log(f"[db] private server up: {self.version}, innodb_force_recovery={self.level}, datadir via {self.mode}")
        if self.level:
            self.log("[db] note: recovery level > 0 means uncommitted or undo-pending rows may be missing or stale")
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        if self._overlay_mounted:
            r = subprocess.run(["umount", str(self.data)], capture_output=True, text=True, errors="replace")
            if r.returncode != 0:
                self.log(f"[db] overlay umount: {(r.stderr or r.stdout).strip()[:160]}; retrying lazily")
                time.sleep(2)
                r = subprocess.run(["umount", "-l", str(self.data)], capture_output=True, text=True, errors="replace")
                if r.returncode != 0:
                    self.log(f"[db] overlay still mounted at {self.data}: {(r.stderr or r.stdout).strip()[:160]}")
            self._overlay_mounted = False
        self._custody("db_server_stopped", {"mode": self.mode, "force_recovery": self.level})

    def _custody(self, kind: str, data: dict[str, Any]) -> None:
        if self.custody is not None:
            try:
                self.custody.append(kind, data)
            except Exception:  # noqa: BLE001
                pass

    # ---- queries
    def query(self, sql: str, db: Optional[str] = None) -> list[list[str]]:
        """Small result sets through the client binary (tab separated, raw)."""
        cmd = [self._client_exe(), f"--socket={self.sock}", "-u", "root", "-N", "-B", "--raw"]
        if db:
            cmd.append(db)
        cmd += ["-e", sql]
        out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=3600, env=self._env())
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip()[:400])
        return [line.split("\t") for line in out.stdout.splitlines() if line.strip()]

    def connection(self):
        """A PyMySQL connection over the socket (vendored); raises if PyMySQL is unavailable."""
        if self._conn is None:
            from . import vendor
            vendor.use()
            import pymysql  # type: ignore
            self._conn = pymysql.connect(unix_socket=str(self.sock), user="root", charset="utf8mb4", autocommit=True,
                                         read_timeout=3600, write_timeout=3600, binary_prefix=True)
        return self._conn

    def stream(self, sql: str, db: Optional[str] = None, batch: int = 5000) -> Iterator[tuple]:
        """Rows of an arbitrarily large SELECT without buffering them (unbuffered cursor)."""
        from . import vendor
        vendor.use()
        import pymysql.cursors  # type: ignore
        conn = self.connection()
        if db:
            conn.select_db(db)
        with conn.cursor(pymysql.cursors.SSCursor) as cur:
            cur.execute(sql)
            while True:
                rows = cur.fetchmany(batch)
                if not rows:
                    break
                for r in rows:
                    yield r

    def columns(self, db: str, table: str) -> list[str]:
        return [r[0] for r in self.query(f"SHOW COLUMNS FROM `{table}`", db)]

    def schemas(self) -> list[str]:
        return [r[0] for r in self.query("SHOW DATABASES") if r[0] not in SYSTEM_SCHEMAS]

    def tables(self, db: str) -> list[dict[str, Any]]:
        rows = self.query("SELECT TABLE_NAME, ENGINE, IFNULL(TABLE_ROWS,0), IFNULL(DATA_LENGTH,0)+IFNULL(INDEX_LENGTH,0), TABLE_TYPE "
                          f"FROM information_schema.TABLES WHERE TABLE_SCHEMA='{db}' ORDER BY TABLE_NAME")
        return [{"name": r[0], "engine": r[1], "rows_est": int(r[2] or 0), "bytes": int(r[3] or 0), "type": r[4]} for r in rows]

    def create_table(self, db: str, table: str) -> str:
        try:
            r = self.query(f"SHOW CREATE TABLE `{table}`", db)
            return r[0][1].replace("\\n", "\n") if r and len(r[0]) > 1 else ""
        except Exception as e:  # noqa: BLE001
            return f"-- SHOW CREATE TABLE failed: {e}"
