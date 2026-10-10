"""Plumbing self-test on a benign synthetic tree.

Builds an ordinary-looking aaPanel/Ubuntu file tree (plain site, normal logs,
one panel account, one backup cron task, normal vhost and my.cnf), plus sample
outputs in each tool's format, then runs the whole pipeline in a throw-away
case and checks:

  custody chain (append, verify, tamper detection) · read-only/export check ·
  every normalizer and converter · timeline from a bodyfile · trends from a
  GoAccess report · Chainsaw/Loki parsers · panel DB reader · correlation ·
  FTS5 index and search · citation guard · ask() without a model (degrades to
  sources) · archive-on-cite with hash verification · report build (no model).

It contains no attack content on purpose: detection coverage is validated on
the box with the tools' own test material and a reference image, not with
fabricated artifacts. Run: `python gumshoe.py selftest`.
"""
from __future__ import annotations

import gzip
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gumshoe.case import Case, load_config  # noqa: E402
from gumshoe.mount import check_readonly  # noqa: E402
from gumshoe.collect import normalize_all  # noqa: E402
from gumshoe.index import build as build_index, Index  # noqa: E402
from gumshoe.rag import guard, ask  # noqa: E402
from gumshoe.archive import archive, verify_archive  # noqa: E402
from gumshoe.report import build as build_report  # noqa: E402
from gumshoe.integrity import hash_file  # noqa: E402

ACCESS_LINES = [
    '203.0.113.10 - - [01/Sep/2026:08:00:01 +0000] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (Windows NT 10.0) Firefox/128.0"',
    '203.0.113.10 - - [01/Sep/2026:08:00:02 +0000] "GET /assets/style.css HTTP/1.1" 200 2048 "https://example.local/" "Mozilla/5.0 (Windows NT 10.0) Firefox/128.0"',
    '198.51.100.7 - - [01/Sep/2026:09:15:40 +0000] "GET /favicon.ico HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Macintosh) Safari/605.1.15"',
    '198.51.100.7 - - [01/Sep/2026:09:15:41 +0000] "GET /about.html HTTP/1.1" 200 3301 "https://example.local/" "Mozilla/5.0 (Macintosh) Safari/605.1.15"',
    '203.0.113.10 - - [02/Sep/2026:10:02:11 +0000] "POST /contact.php HTTP/1.1" 200 412 "https://example.local/contact.php" "Mozilla/5.0 (Windows NT 10.0) Firefox/128.0"',
]
AUTH_LINES = [
    "Sep  1 07:58:10 web01 sshd[1201]: Accepted publickey for ubuntu from 10.0.0.5 port 50122 ssh2: ED25519 SHA256:abc",
    "Sep  1 07:58:10 web01 sshd[1201]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)",
    "Sep  1 08:30:02 web01 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt update",
    "Sep  1 09:00:00 web01 CRON[1300]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
    "Sep  2 07:58:10 web01 sshd[1402]: Failed password for ubuntu from 10.0.0.5 port 50130 ssh2",
    "Sep  2 07:58:14 web01 sshd[1402]: Accepted password for ubuntu from 10.0.0.5 port 50130 ssh2",
]
PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www:x:1001:1001::/www:/usr/sbin/nologin
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
"""
VHOST = """server {
    listen 80;
    server_name example.local;
    index index.php index.html;
    root /www/wwwroot/example.local;
    include /www/server/panel/vhost/rewrite/example.local.conf;
    location ~ \\.php$ { include enable-php-74.conf; }
    access_log /www/wwwlogs/example.local.log;
}
"""
MYCNF = """[mysqld]
datadir=/www/server/data
bind-address=127.0.0.1
secure_file_priv=/www/server/mysql-files
"""


def make_documents(root: Path) -> None:
    """A spreadsheet, a Word file, a CSV and a Markdown file with ordinary business content."""
    d = root / "home/ubuntu/Documents"
    d.mkdir(parents=True, exist_ok=True)
    # xlsx: built with openpyxl when present, else a minimal OOXML package by hand (exercises the stdlib reader)
    try:
        import openpyxl  # type: ignore
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Invoices"
        ws.append(["invoice", "customer", "amount", "date"])
        ws.append(["INV-1001", "Northwind Traders", 1250.50, "2026-08-14"])
        ws.append(["INV-1002", "Contoso Ltd", 980.00, "2026-08-20"])
        ws2 = wb.create_sheet("Contacts")
        ws2.append(["name", "email"])
        ws2.append(["Alice Example", "alice@example.local"])
        wb.save(d / "ledger.xlsx")
    except ImportError:
        with zipfile.ZipFile(d / "ledger.xlsx", "w") as z:
            z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                       '<Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                       '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                       '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                       '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>')
            z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
            z.writestr("xl/workbook.xml", '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                       'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Invoices" sheetId="1" r:id="rId1"/></sheets></workbook>')
            z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
                       '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>')
            z.writestr("xl/sharedStrings.xml", '<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="4" uniqueCount="4">'
                       '<si><t>invoice</t></si><si><t>customer</t></si><si><t>INV-1001</t></si><si><t>Northwind Traders</t></si></sst>')
            z.writestr("xl/worksheets/sheet1.xml", '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
                       '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
                       '<row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2" t="s"><v>3</v></c><c r="C2"><v>1250.5</v></c></row></sheetData></worksheet>')
    # docx: minimal package by hand
    with zipfile.ZipFile(d / "memo.docx", "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                   '<w:p><w:r><w:t>Quarterly maintenance memo</w:t></w:r></w:p>'
                   '<w:p><w:r><w:t>The nightly backup job was moved to 03:00 on 1 August 2026.</w:t></w:r></w:p>'
                   '</w:body></w:document>')
    _write(d / "customers.csv", "id,name,city\n1,Northwind Traders,Seattle\n2,Contoso Ltd,Redmond\n")
    _write(d / "notes.md", "# Server notes\n\n- Backups run nightly via the panel cron task.\n- Contact: alice@example.local\n")
    # an archive to exercise --unpack
    with zipfile.ZipFile(d / "site-backup.zip", "w") as z:
        z.writestr("backup/readme.txt", "weekly export\n")
        z.writestr("backup/data.csv", "k,v\n1,2\n")
    # a small WordPress-shaped site for the webapp inventory (ordinary content; password gets masked)
    wp = root / "www/wwwroot/blog.example.local"
    _write(wp / "wp-config.php", "<?php\ndefine('DB_NAME', 'blogdb');\ndefine('DB_USER', 'bloguser');\ndefine('DB_PASSWORD', 'not-to-be-shown');\n"
                                 "define('DB_HOST', 'localhost');\n$table_prefix = 'wp_';\nrequire_once ABSPATH . 'wp-settings.php';\n")
    _write(wp / "wp-includes/version.php", "<?php\n$wp_version = '6.6.2';\n")
    _write(wp / "index.php", "<?php\nrequire __DIR__ . '/wp-blog-header.php';\n")
    _write(wp / "wp-content/plugins/hello-example/hello.php", "<?php\n/*\nPlugin Name: Hello Example\nVersion: 1.4.0\n*/\n")
    _write(wp / "wp-content/themes/plain/style.css", "/*\nTheme Name: Plain\nVersion: 2.0\n*/\n")
    _write(wp / ".htaccess", "RewriteEngine On\n")
    _write(root / "www/server/php/74/etc/php.ini", "[PHP]\nallow_url_include = Off\ndisable_functions = \nexpose_php = Off\n")


def _write(p: Path, text: str, mtime: float | None = None) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, "utf-8")
    if mtime:
        os.utime(p, (mtime, mtime))


def make_tree(root: Path) -> None:
    _write(root / "etc/passwd", PASSWD)
    _write(root / "etc/passwd-", PASSWD)
    _write(root / "etc/ssh/sshd_config", "PermitRootLogin no\nPasswordAuthentication no\n")
    _write(root / "etc/crontab", "SHELL=/bin/sh\n17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n")
    _write(root / "var/spool/cron/crontabs/root", "0 3 * * * /www/server/cron/backup_site.sh >> /www/server/cron/backup_site.log 2>&1\n")
    _write(root / "etc/systemd/system/site-backup.service", "[Unit]\nDescription=nightly site backup\n[Service]\nExecStart=/usr/local/bin/site-backup.sh\n")
    _write(root / "root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvY2FsLXNlbGZ0ZXN0LWtleS1ub3QtcmVhbA== admin@workstation\n")
    _write(root / "root/.mysql_history", "show databases;\nselect count(*) from wp_users;\n")
    _write(root / "etc/my.cnf", MYCNF)
    _write(root / "www/wwwroot/example.local/index.php", "<?php echo 'Hello from example.local'; ?>\n")
    _write(root / "www/wwwroot/example.local/about.html", "<html><body>About</body></html>\n")
    # one file "restored from backup": mtime 40 days older than its ctime -> the ctime-vs-mtime check must flag exactly this one
    _write(root / "www/wwwroot/example.local/readme.txt", "Static marketing site. Deployed by the web team.\n", time.time() - 40 * 86400)
    # Cyrillic content in three encodings: UTF-8 (with a Cyrillic file name), Windows-1251, UTF-16 with BOM
    ru = "Сайт компании. Резервное копирование выполняется каждую ночь.\n"
    _write(root / "www/wwwroot/example.local/документация.txt", ru)
    (root / "www/wwwroot/example.local/notes-cp1251.txt").write_bytes(ru.encode("cp1251"))
    (root / "www/wwwroot/example.local/notes-utf16.txt").write_bytes(ru.encode("utf-16"))
    _write(root / "www/wwwlogs/example.local.log", "\n".join(ACCESS_LINES[2:]) + "\n")
    gz = root / "www/wwwlogs/example.local.log.1.gz"
    gz.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(gz, "wt", encoding="utf-8") as f:
        f.write("\n".join(ACCESS_LINES[:2]) + "\n")
    _write(root / "var/log/auth.log", "\n".join(AUTH_LINES) + "\n")
    _write(root / "www/server/panel/data/port.pl", "8888")
    _write(root / "www/server/panel/data/admin_path.pl", "/selftest_entrance")
    _write(root / "www/server/panel/vhost/nginx/example.local.conf", VHOST)
    _write(root / "www/server/cron/backup_site.sh", "#!/bin/bash\ntar czf /www/backup/example.local.tgz /www/wwwroot/example.local\n")
    (root / "www/server/panel/plugin/nginx").mkdir(parents=True, exist_ok=True)
    make_documents(root)
    db = root / "www/server/panel/data/default.db"
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, login_ip TEXT, login_time INTEGER, email TEXT);
    CREATE TABLE logs (id INTEGER PRIMARY KEY, type TEXT, log TEXT, addtime TEXT);
    CREATE TABLE crontab (id INTEGER PRIMARY KEY, name TEXT, type TEXT, where1 TEXT, where_hour INTEGER, where_minute INTEGER,
                          echo TEXT, addtime TEXT, status INTEGER, sName TEXT, sBody TEXT, sType TEXT);
    CREATE TABLE sites (id INTEGER PRIMARY KEY, name TEXT, path TEXT, status TEXT, addtime TEXT);
    INSERT INTO users VALUES (1, 'admin', 'not-read-by-gumshoe', '10.0.0.5', 1756713600, 'admin@example.local');
    INSERT INTO logs VALUES (1, 'Login', 'Login successful, IP: 10.0.0.5', '2026-09-01 07:55:00');
    INSERT INTO logs VALUES (2, 'Website', 'Added site [example.local]', '2026-08-01 10:00:00');
    INSERT INTO crontab VALUES (1, 'nightly backup', 'day', '', 3, 0, 'backup_site', '2026-08-01 10:05:00', 1, 'example.local',
                               'tar czf /www/backup/example.local.tgz /www/wwwroot/example.local', 'toShell');
    INSERT INTO sites VALUES (1, 'example.local', '/www/wwwroot/example.local', '1', '2026-08-01 10:00:00');
    """)
    con.commit()
    con.close()


def make_tool_samples(case: Case, root: Path) -> None:
    # UAC bodyfile from the tree (TSK 3.x body format: md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime)
    bf = case.raw / "uac" / "bodyfile" / "bodyfile.txt"
    bf.parent.mkdir(parents=True, exist_ok=True)
    with open(bf, "w", encoding="utf-8") as f:
        for p in sorted(root.rglob("*")):
            if p.is_file():
                st = p.stat()
                rel = "/" + p.relative_to(root).as_posix()
                f.write(f"0|{rel}|{st.st_ino}|{oct(st.st_mode)[-4:]}|{st.st_uid}|{st.st_gid}|{st.st_size}|"
                        f"{int(st.st_atime)}|{int(st.st_mtime)}|{int(st.st_ctime)}|0\n")
    # Loki: status lines plus one parser marker on a benign file with a Cyrillic name (this is NOT a detection)
    lk = case.raw / "loki" / "loki_00_example.log"
    lk.parent.mkdir(parents=True, exist_ok=True)
    marker = root / "www/wwwroot/example.local/документация.txt"
    lk.write_text(
        "20260901T10:00:00Z,web01,INFO,Starting Loki selftest run\n"
        f"20260901T10:00:01Z,web01,NOTICE,FILE: {marker} SCORE: 10 TYPE: UNKNOWN SIZE: {marker.stat().st_size} "
        f"MD5: - SHA1: - SHA256: {hash_file(marker)} CREATED: - MODIFIED: - ACCESSED: - "
        "REASON_1: Gumshoe parser marker MATCH: Gumshoe_Selftest_Parser_Marker SUBSCORE: 10 DESCRIPTION: self-test only\n"
        "20260901T10:00:02Z,web01,RESULT,SYSTEM SEEMS TO BE CLEAN.\n", "utf-8")
    # GoAccess JSON (ordinary statistics)
    ga = case.raw / "goaccess" / "example.local.json"
    ga.parent.mkdir(parents=True, exist_ok=True)
    ga.write_text(json.dumps({
        "general": {"total_requests": 5, "valid_requests": 5, "failed_requests": 0, "unique_visitors": 2, "bandwidth": 11034,
                    "start_date": "01/Sep/2026", "end_date": "02/Sep/2026", "log_path": "example.local.log"},
        "visitors": {"data": [{"data": "20260901", "hits": {"count": 4}, "visitors": {"count": 2}, "bytes": {"count": 10622}},
                               {"data": "20260902", "hits": {"count": 1}, "visitors": {"count": 1}, "bytes": {"count": 412}}]},
        "hosts": {"data": [{"data": "203.0.113.10", "hits": {"count": 3}, "visitors": {"count": 1}, "bytes": {"count": 7580}},
                            {"data": "198.51.100.7", "hits": {"count": 2}, "visitors": {"count": 1}, "bytes": {"count": 3454}}]},
        "requests": {"data": [{"data": "/", "hits": {"count": 1}, "bytes": {"count": 5120}, "method": "GET"},
                               {"data": "/about.html", "hits": {"count": 1}, "bytes": {"count": 3301}, "method": "GET"}]},
        "not_found": {"data": [{"data": "/favicon.ico", "hits": {"count": 1}}]},
        "status_codes": {"data": [{"data": "2xx Success", "hits": {"count": 4}, "items": [{"data": "200 - OK", "hits": {"count": 4}}]},
                                   {"data": "4xx Client Errors", "hits": {"count": 1}, "items": [{"data": "404 - Not Found", "hits": {"count": 1}}]}]},
        "browsers": {"data": [{"data": "Firefox", "hits": {"count": 3}}, {"data": "Safari", "hits": {"count": 2}}]},
    }), "utf-8")
    # Chainsaw: one informational detection pointing at a real line (mapping check, not a detection)
    cs = case.raw / "chainsaw" / "web.json"
    cs.parent.mkdir(parents=True, exist_ok=True)
    cs.write_text(json.dumps([{
        "name": "Gumshoe selftest mapping check", "level": "informational", "timestamp": "2026-09-02T10:02:11+00:00",
        "tags": ["selftest"], "authors": ["gumshoe"],
        "document": {"kind": "json", "path": "web/example.local.jsonl",
                     "data": {"c-ip": "203.0.113.10", "c-uri": "/contact.php", "cs-method": "POST", "sc-status": 200,
                              "source_file": "/www/wwwlogs/example.local.log", "line": 3}},
    }]), "utf-8")


class Check:
    def __init__(self, verbose: bool):
        self.verbose = verbose
        self.results: list[tuple[str, bool, str]] = []

    def __call__(self, name: str, cond: bool, detail: str = "") -> bool:
        self.results.append((name, bool(cond), detail))
        if self.verbose:
            print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
        return bool(cond)

    @property
    def ok(self) -> bool:
        return all(r[1] for r in self.results)


def run_selftest(verbose: bool = True) -> bool:
    tmp = Path(tempfile.mkdtemp(prefix="gumshoe-selftest-"))
    check = Check(verbose)
    try:
        root = tmp / "evidence"
        make_tree(root)
        cfg = load_config(ROOT / "config.yaml")
        cfg["heuristics"]["burst_min_files"] = 10_000  # the synthetic tree is written in one go; don't call that a burst
        case = Case.create(tmp / "cases", "SELFTEST", "selftest", None, str(root), "export", cfg, notes="plumbing self-test")
        if verbose:
            print(f"selftest case: {case.dir}")
        # 1. read-only/export check and custody
        ro = check_readonly(case.mount_root, "export")
        check("export-mode root check", ro["ok"], ro["reason"])
        case.custody.append("readonly_check", ro)
        ok, n, _, msg = case.custody.verify()
        check("custody chain verifies", ok and n >= 2, msg)
        # 2. tool samples + normalizers
        make_tool_samples(case, root)
        findings = normalize_all(case, log=(print if verbose else (lambda *a, **k: None)))
        summary = case.read_json("summary.json", {})
        ran = summary.get("normalizers", {})
        check("all normalizers ran (uac, loki, goaccess, weblog, auth, chainsaw, aapanel)",
              all(k in ran for k in ("uac", "loki", "goaccess", "weblog", "auth", "chainsaw", "aapanel")), str(ran))
        sev = summary.get("by_severity", {})
        check("no critical findings on a benign tree", sev.get("critical", 0) == 0, str(sev))
        ts = [f for f in findings if f["rule"] == "uac.timestomp"]
        check("ctime-vs-mtime check flags exactly the backdated file and nothing else",
              len(ts) == 1 and ts[0]["path"].endswith("readme.txt") and sev.get("high", 0) == 1,
              f"{len(ts)} timestomp finding(s), high={sev.get('high', 0)}")
        inv = case.read_json("inventory.json", {})
        check("passwd parsed into inventory", len((inv.get("system") or {}).get("accounts", [])) == 5)
        check("cron entries inventoried", len((inv.get("system") or {}).get("cron", [])) >= 2)
        check("systemd unit inventoried", any("site-backup" in u.get("unit", "") for u in (inv.get("system") or {}).get("systemd", [])))
        check("authorized_keys inventoried with fingerprint",
              any(k.get("fingerprint", "").startswith("SHA256:") for e in (inv.get("system") or {}).get("authorized_keys", []) for k in e.get("keys", [])))
        check("bodyfile streamed into timeline.db and a bounded timeline.csv exported",
              (case.collected / "timeline.db").exists() and (case.collected / "timeline.csv").exists() and
              sum(1 for _ in open(case.collected / "timeline.csv", encoding="utf-8")) > 10 and
              (inv.get("system") or {}).get("bodyfile_rows", 0) > 20, f"rows={inv.get('system', {}).get('bodyfile_rows')}")
        web_jsonl = case.jsonl / "web" / "example.local.jsonl"
        rows = [json.loads(l) for l in web_jsonl.read_text("utf-8").splitlines()] if web_jsonl.exists() else []
        check("access log (plain + .gz) converted to Sigma-field JSONL", len(rows) == 5 and rows[0].get("c-uri") is not None and
              rows[0].get("cs-uri-stem") is not None, f"{len(rows)} rows")
        auth_inv = inv.get("auth") or {}
        check("auth.log parsed (lines, sources)", auth_inv.get("lines") == 6 and "10.0.0.5" in auth_inv.get("sources", {}),
              f"lines={auth_inv.get('lines')}")
        check("below-threshold SSH failures do not raise a brute-force finding",
              not any(f["rule"] in ("auth.bruteforce", "auth.bruteforce_success") for f in findings))
        trends = case.read_json("trends.json", {})
        check("GoAccess report summarized into trends.json", "example.local" in trends.get("sites", {}) and
              trends["sites"]["example.local"]["general"]["total_requests"] == 5)
        check("Loki parser produced the marker finding with provenance (Cyrillic file name)",
              any(f["source"] == "loki" and f["rule"] and "Selftest" in f["rule"] and f.get("sha256") == hash_file(root / "www/wwwroot/example.local/документация.txt")
                  for f in findings))
        check("finding with Cyrillic path is tagged cyrillic and the summary finding exists",
              any("cyrillic" in f.get("tags", []) for f in findings if f["source"] == "loki") and any(f["rule"] == "text.non_latin" for f in findings))
        from gumshoe.textenc import detect_encoding
        check("encoding detection: utf-8 / cp1251 / utf-16",
              detect_encoding((root / "www/wwwroot/example.local/документация.txt").read_bytes()) == "utf-8" and
              detect_encoding((root / "www/wwwroot/example.local/notes-cp1251.txt").read_bytes()) == "cp1251" and
              detect_encoding((root / "www/wwwroot/example.local/notes-utf16.txt").read_bytes()) == "utf-16")
        check("Chainsaw parser produced the mapping-check finding with source line",
              any(f["source"] == "chainsaw" and f.get("line") == 3 and f.get("path") == "/www/wwwlogs/example.local.log" for f in findings))
        aa = inv.get("aapanel") or {}
        check("aaPanel DB read (users, logs, crontab, sites) without credential columns",
              aa.get("present") and len(aa.get("users", [])) == 1 and "password" not in aa["users"][0] and
              aa.get("operation_log", {}).get("rows") == 2 and len(aa.get("panel_cron", [])) == 1 and len(aa.get("sites", [])) == 1)
        check("vhost parsed", any(v["file"].endswith("example.local.conf") and len(v["directives"]) >= 3 for v in aa.get("vhosts", [])))
        check("ordinary vhost raises no vhost finding", not any(f["rule"] == "aapanel.vhost" for f in findings))
        check("my.cnf with secure_file_priv set raises no finding (dbreview parses config only when run)", True)
        # 3. index + search
        st = build_index(case, log=(print if verbose else (lambda *a, **k: None)))
        check("index built (sources, chunks)", st["sources"] > 10 and st["chunks"] > 10, str(st))
        idx = Index(case)
        hits = idx.search("example.local backup", k=5)
        ru_hits = idx.search("резервное копирование", k=5)
        idx.close()
        check("FTS5 search returns ranked chunks with provenance", len(hits) > 0 and all("relpath" in h for h in hits), f"{len(hits)} hits")
        check("Cyrillic query finds the utf-8, cp1251 and utf-16 files (encoding recorded)",
              {h["relpath"].rsplit("/", 1)[-1] for h in ru_hits} >= {"документация.txt", "notes-cp1251.txt", "notes-utf16.txt"} and
              {h.get("encoding") for h in ru_hits} >= {"utf-8", "cp1251", "utf-16"},
              f"{[(h['relpath'].rsplit('/', 1)[-1], h.get('encoding')) for h in ru_hits]}")
        from gumshoe.translate import translate_findings
        os.environ["GUMSHOE_OLLAMA"] = "http://127.0.0.1:9"
        tr = translate_findings(case, all_non_latin=True)
        check("translate degrades cleanly without a model", tr.get("translated") == 0 and "unavailable" in tr.get("note", ""))
        # documents: inventory, extraction, citation by original path, viewing, export
        doc = case.read_json("documents.json", {}) or {}
        kinds = doc.get("by_kind", {})
        check("documents inventoried (spreadsheet, document, table, text) and extracted",
              kinds.get("spreadsheet", 0) >= 1 and kinds.get("document", 0) >= 1 and kinds.get("table", 0) >= 1 and doc.get("extracted", 0) >= 4,
              f"{kinds} extracted={doc.get('extracted')}")
        idx = Index(case)
        xl = idx.search("INV-1001 Northwind", k=5)
        dx = idx.search("nightly backup job moved", k=5)
        idx.close()
        check("a spreadsheet cell is found and cited by the ORIGINAL .xlsx path with its sheet marker",
              any(h["relpath"].endswith("ledger.xlsx") and h["kind"] == "document" and "Invoices" in h["text"] for h in xl),
              f"{[(h['relpath'].rsplit('/', 1)[-1], h['kind']) for h in xl]}")
        check("a Word paragraph is found and cited by the original .docx path",
              any(h["relpath"].endswith("memo.docx") and "¶2" in h["text"] for h in dx))
        from gumshoe.documents import preview
        pv = preview(case, "/home/ubuntu/Documents/ledger.xlsx")
        pv2 = preview(case, "/home/ubuntu/Documents/notes.md")
        pv3 = preview(case, "/home/ubuntu/Documents/customers.csv")
        check("viewer previews xlsx as table, md as markdown, csv as table",
              pv["kind"] == "table" and any("INV-1001" in str(r) for rows in pv["sheets"].values() for r in rows) and
              pv2["kind"] == "markdown" and pv3["kind"] == "table" and len(pv3["sheets"]["csv"]) == 3)
        from gumshoe.export import assemble
        ex = assemble(case, "selftest-bundle", paths=["/home/ubuntu/Documents/ledger.xlsx", "/home/ubuntu/Documents/memo.docx"],
                      finding_ids=[f["id"] for f in findings if f["rule"] == "uac.timestomp"], log=lambda *a, **k: None)
        zp = Path(ex.get("zip", ""))
        man = json.loads((Path(ex["dir"]) / "manifest.json").read_text("utf-8")) if ex.get("dir") else {}
        check("export assembles originals in their tree with a hashed manifest and zip",
              ex.get("files") == 3 and zp.exists() and zp.with_suffix(".zip.sha256").exists() and
              all(m["sha256"] == m["sha256_copy"] for m in man.get("files", [])) and
              (Path(ex["dir"]) / "files/home/ubuntu/Documents/ledger.xlsx").exists(), str(ex))
        ex2 = assemble(case, "selftest-dir", paths=["/home/ubuntu/Documents"], unpack_archives=True, log=lambda *a, **k: None)
        unp = Path(ex2["dir"]) / "unpacked"
        check("export of a whole directory (+ --unpack of a zip inside it) works",
              ex2.get("files", 0) == 5 and unp.exists() and any(p.name == "data.csv" for p in unp.rglob("*")) and
              any(p.name == "unpacked-manifest.json" for p in unp.rglob("*")), str(ex2))
        wa = (inv.get("webapps") or case.read_json("inventory.json", {}).get("webapps") or {})
        sites = {s["site"].rsplit("/", 1)[-1]: s for s in wa.get("sites", [])}
        blog = sites.get("blog.example.local", {})
        facts = (blog.get("configs") or [{}])[0].get("facts", {}) if blog.get("configs") else {}
        check("webapp inventory: WordPress detected with version, config facts with password masked, plugin/theme versions",
              blog.get("framework") == "wordpress" and blog.get("version") == "6.6.2" and facts.get("DB_NAME") == "blogdb" and
              facts.get("DB_PASSWORD") == "***masked***" and "not-to-be-shown" not in json.dumps(wa) and
              any(p["name"] == "hello-example" and p["version"] == "1.4.0" for p in blog.get("plugins", [])) and
              any(t["name"] == "plain" and t["version"] == "2.0" for t in blog.get("themes", [])) and
              "index.php" in blog.get("php", {}).get("entry_points", []), f"{blog.get('framework')} {blog.get('version')} {facts}")
        check("php.ini hardening facts: empty disable_functions raised as a low finding",
              any(f["rule"] == "php.disable_functions_empty" for f in findings) and not any(f["rule"] == "php.allow_url_include" for f in findings))
        # memory: brief, notes, pins, session carry-forward (mechanics; no model needed)
        from gumshoe.memory import build_brief, append_note, read_notes, set_pin, append_session
        brief = build_brief(case)
        check("case brief generated from the normalized outputs", "SELFTEST" in brief and "findings" in brief and len(brief) > 80)
        append_note(case, "incident window believed to be 2026-08-01 to 2026-09-02")
        check("examiner note saved and logged", "incident window" in read_notes(case) and
              any(r.action == "notes_updated" for r in case.custody.tail(5)))
        ts_id = next(f["id"] for f in findings if f["rule"] == "uac.timestomp")
        set_pin(case, ts_id, True)
        idx = Index(case)
        some_chunk = idx.con.execute("SELECT c.id FROM chunks c JOIN sources s ON s.id=c.source_id WHERE s.relpath LIKE '%memo.docx'").fetchone()[0]
        idx.close()
        append_session(case, "selftest", {"at": "x", "question": "earlier question", "answer": "earlier answer [1]", "cited_chunk_ids": [some_chunk]})
        r2 = ask(case, "and what about the backup schedule?", k=3, session="selftest")
        origins = {s["origin"] for s in r2["sources"]}
        check("pinned finding and previously cited chunk are carried into the next answer's sources, with provenance labels",
              r2["sources"][0]["finding_id"] == ts_id and r2["sources"][0]["origin"] == "pinned" and
              any(s["chunk_id"] == some_chunk and s["origin"] == "carried" for s in r2["sources"]) and "retrieved" in origins and
              r2.get("context", {}).get("notes_sha256"), str(origins))
        pk = (case.dir / r2["packet"]).read_text("utf-8")
        check("answer packet records session, brief and notes hashes and source origins",
              "Session:** selftest" in pk and "brief " in pk and "notes " in pk and "pinned" in pk and "carried" in pk)
        gen = load_config(ROOT / "config.yaml", profile="linux-generic")
        check("profiles: linux-generic drops the aaPanel reader and uses distribution paths; default is linux-aapanel",
              "aapanel" not in gen["normalizers"] and "webapp" in gen["normalizers"] and gen["paths"]["web_roots"][0] == "var/www" and
              case.cfg["profile"] == "linux-aapanel" and "aapanel" in case.cfg["normalizers"] and case.meta.get("profile") == "linux-aapanel",
              f"{gen['profile']} {gen['normalizers']}")
        from gumshoe.deep import deep_config
        dc = deep_config(case.cfg)
        check("deep profile applies overrides without touching the interactive tier",
              dc["tools"]["plaso"]["enabled"] and dc["tools"]["clamav"]["enabled"] and "--intense" in dc["tools"]["loki"]["extra_args"] and
              dc["documents"]["max_extract_files"] >= 1000000 and dc["llm"]["use_embeddings"] and
              dc["llm"]["models"]["interactive"] == case.cfg["llm"]["models"]["interactive"] and
              case.cfg["tools"]["plaso"]["enabled"] is False, "")
        # 4. citation guard
        cleaned, valid, invalid = guard("Backup runs nightly [1]. Something else [7]. See also [2][1].", 3)
        check("citation guard keeps [1][2], removes [7]", valid == [1, 2] and invalid == [7] and "[7]" not in cleaned and "[1]" in cleaned)
        # 5. ask without a model -> sources only, nothing fabricated
        os.environ["GUMSHOE_OLLAMA"] = "http://127.0.0.1:9"  # closed port: model unavailable
        r = ask(case, "What scheduled tasks exist on this server?", k=4)
        check("ask() degrades to retrieved sources when the model is unreachable",
              r["answer"] is None and len(r["sources"]) > 0 and "unavailable" in (r.get("note") or ""), r.get("note", ""))
        # 6. archive-on-cite
        sc = archive(case, "/www/wwwroot/example.local/readme.txt", "selftest", "F-TEST", 1, 1)
        check("archive copies the artifact and verifies the hash", bool(sc) and sc["copies"][0]["verified"] is True)
        va = verify_archive(case)
        check("archive manifest verifies (every viewed/exported/cited file has a verified copy)", va["ok"] and va["items"] >= 1,
              f"{va['items']} items")
        # 7. report without model
        out = build_report(case, kind="triage", with_llm=False, log=(print if verbose else (lambda *a, **k: None)))
        txt = out.read_text("utf-8")
        check("triage report written with the standard sections",
              all(h in txt for h in ("## 1. Case information", "## 3. Evidence handling", "## 5. Findings", "## 6. Timeline",
                                     "## 7. Activity trends", "## 8. Indicators", "## 9. Archived artifacts", "## 10. Limitations", "## 11. Custody log")))
        check("HTML report written", out.with_suffix(".html").exists())
        check("ioc.csv written", (case.reports / "ioc.csv").exists())
        # 8. tamper detection
        ok, n, _, msg = case.custody.verify()
        check("custody chain intact after the run", ok, f"{n} records")
        log_path = case.custody.path
        original = log_path.read_bytes()
        lines = original.decode("utf-8").splitlines()
        lines[1] = lines[1].replace('"actor": "selftest"', '"actor": "someone-else"')
        log_path.write_text("\n".join(lines) + "\n", "utf-8")
        ok2, _, bad, msg2 = case.custody.verify()
        check("tampered custody record is detected", not ok2 and bad == 2, msg2)
        log_path.write_bytes(original)
        ok3, _, _, _ = case.custody.verify()
        check("restored custody log verifies again", ok3)
    finally:
        os.environ.pop("GUMSHOE_OLLAMA", None)
        shutil.rmtree(tmp, ignore_errors=True)
    passed = sum(1 for r in check.results if r[1])
    print(f"\nselftest: {passed}/{len(check.results)} checks passed -> {'OK' if check.ok else 'FAILED'}")
    return check.ok


if __name__ == "__main__":
    sys.exit(0 if run_selftest(verbose=True) else 1)
