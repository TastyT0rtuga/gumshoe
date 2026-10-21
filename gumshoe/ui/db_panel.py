"""The Databases tab: what databases the evidence holds, extract any of them to CSV folders, browse and search the result.

Sources come from `gumshoe db scan` (data directories, SQL dumps, sqlite and Access files found on the mount or
dropped in the hopper). Extraction runs in the background (`gumshoe db extract`), writes Excel-ready CSV folders
to the exports folder (one folder per source, one per database, one CSV per table, 1,000,000 rows per file),
and keeps an index in the case. Search greps every exported CSV.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from gumshoe import dbexport
from gumshoe.ui.run_panel import _logs, _alive, progress_of_text, tail_log
from gumshoe.winpath import to_windows

DB_MILESTONES = [("start:", 2, "starting"), ("[db] scan", 4, "scanning the evidence for databases"), ("[db] extracting", 8, "extracting"),
                 ("[db] hashing", 10, "hashing the source"), ("[db] copying", 12, "copying the data directory"),
                 ("[db] datadir", 14, "preparing the data directory"), ("[db] private server up", 18, "private server started"),
                 ("[db] worker", 30, "parsing the dump"), ("rows so far", 40, "streaming tables"), ("[db] [", 45, "tables"),
                 ("[db] done", 98, "finishing"), ("finished with exit", 100, "done")]


def _start(root: Path, cases_root: Path, case_dir: Path, step: str, argv: list[str]) -> dict:
    log = _logs(case_dir) / f"{step}.log"
    cmd = [sys.executable, str(root / "gumshoe.py"), "--cases-root", str(cases_root), "--case", case_dir.name] + argv
    wrapper = 'echo "[$(date -u +%FT%TZ)] start: $*"; "$@"; rc=$?; echo "[$(date -u +%FT%TZ)] finished with exit $rc"; exit $rc'
    with open(log, "ab") as lf:
        p = subprocess.Popen(["bash", "-c", wrapper, "gumshoe-ui"] + cmd, stdout=lf, stderr=subprocess.STDOUT, cwd=str(root), start_new_session=True)
    state = {"pid": p.pid, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "cmd": cmd}
    (_logs(case_dir) / f"{step}.json").write_text(json.dumps(state, indent=2), "utf-8")
    return state


def _status(case_dir: Path, step: str) -> tuple[str, dict]:
    f = _logs(case_dir) / f"{step}.json"
    if not f.exists():
        return "idle", {}
    try:
        s = json.loads(f.read_text("utf-8"))
    except Exception:  # noqa: BLE001
        return "idle", {}
    if _alive(int(s.get("pid", -1))):
        return "running", s
    log = _logs(case_dir) / f"{step}.log"
    tail = log.read_text("utf-8", errors="replace")[-400:] if log.exists() else ""
    import re
    m = re.findall(r"finished with exit (\d+)", tail)
    return ("done" if (m and m[-1] == "0") else "failed"), s


def _kind_label(k: str) -> str:
    return {"mariadb-datadir": "MariaDB/MySQL data directory", "mysql8-datadir": "MySQL 8.0 data directory (needs MySQL 8 engine)",
            "mysql-dump": "SQL dump (MySQL/MariaDB)", "pg-dump": "SQL dump (PostgreSQL)", "sqlite": "SQLite", "access": "Access"}.get(k, k)


def render_db_tab(case, root: Path, cases_root: Path):
    out_root = dbexport.export_root(case)
    st.markdown(f"CSV folders go to **`{to_windows(str(out_root))}`** (one folder per source, one per database, one CSV per table; "
                f"tables over 1,000,000 rows are split into `.partNNN.csv` files for Excel). Explorer also reaches the case at "
                f"`\\\\wsl.localhost\\DFIR\\opt\\dfir\\cases\\{case.meta.get('case_id')}`.")
    running_steps = [s for s in ("dbscan", "dbextract") if _status(case.dir, s)[0] == "running"]
    frag = st.fragment(lambda: _body(case, root, cases_root), run_every="5s" if running_steps else None)
    frag()


def _body(case, root: Path, cases_root: Path):
    # ---- 1. sources
    st.subheader("1. Databases on the evidence")
    saved = case.read_json("db_sources.json", {}) or {}
    sources = saved.get("sources") or []
    scan_status, scan_state = _status(case.dir, "dbscan")
    c1, c2, c3 = st.columns([1.4, 1.4, 4])
    if c1.button("Scan the evidence" if not sources else "Scan again", key="db_scan", disabled=(scan_status == "running")):
        _start(root, cases_root, case.dir, "dbscan", ["db", "scan"])
        st.rerun(scope="app")
    ext_status, ext_state = _status(case.dir, "dbextract")
    if sources and c2.button("Extract all picks to CSV", key="db_extract_all", type="primary", disabled=(ext_status == "running"),
                             help="every data directory, sqlite and Access file, and the newest dump of each name"):
        _start(root, cases_root, case.dir, "dbextract", ["db", "extract"])
        st.rerun(scope="app")
    if scan_status == "running":
        st.progress(0.3, text="scanning the evidence (a few minutes on a large image)...")
        with st.expander("scan log", expanded=False):
            st.code(tail_log(case.dir, "dbscan") or "(empty)")
    elif saved:
        c3.caption(f"scanned {saved.get('scanned', '')} under `{saved.get('root', '')}`: {len(sources)} source(s)")
    if ext_status == "running":
        text = (_logs(case.dir) / "dbextract.log").read_text("utf-8", errors="replace") if (_logs(case.dir) / "dbextract.log").exists() else ""
        pct, label = progress_of_text(text, DB_MILESTONES)
        last = [l for l in text.splitlines() if l.startswith("[db]")][-1:]
        st.progress(min(max(pct, 1), 99) / 100, text=f"{label} - {last[0][:140] if last else ''}")
        if st.button("Stop extraction", key="db_stop"):
            import os, signal
            try:
                os.killpg(int(ext_state["pid"]), signal.SIGTERM)
            except Exception as e:  # noqa: BLE001
                st.warning(str(e))
            st.rerun(scope="app")
        with st.expander("extraction log", expanded=True):
            st.code("\n".join(text.splitlines()[-30:]) or "(empty)")
    elif ext_status == "failed":
        st.error("the last extraction stopped with an error; see the log")
        with st.expander("extraction log"):
            st.code(tail_log(case.dir, "dbextract") or "(empty)")
    if sources:
        picks = {s["path"] for s in dbexport.auto_pick([dict(x) for x in sources])}
        rows = [{"#": i, "what": _kind_label(s["kind"]), "where": s.get("rel", s["path"]), "size": dbexport.human(s.get("size", 0)),
                 "databases": ", ".join(s.get("databases", [])[:6]), "auto": "yes" if s["path"] in picks else ""} for i, s in enumerate(sources)]
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        idx = st.multiselect("Extract only these (by #)", [r["#"] for r in rows], key="db_pick")
        if idx and st.button(f"Extract {len(idx)} selected", key="db_extract_sel", disabled=(ext_status == "running")):
            _start(root, cases_root, case.dir, "dbextract", ["db", "extract", "--index", ",".join(str(i) for i in idx)])
            st.rerun(scope="app")
    elif scan_status != "running":
        st.info("Not scanned yet. Intakes scan automatically; press Scan the evidence for a case created by hand.")
    with st.expander("Or extract a file or folder by path (a .sql / .sql.gz dump, an sqlite file, a data directory)"):
        from gumshoe.ui.run_panel import to_wsl_path
        pth = st.text_input("Path", key="db_path", placeholder=r"\\server\share\case\backup.sql.gz  or  /mnt/evidence/www/backup/db.sql.gz")
        if pth.strip():
            wp = to_wsl_path(pth)
            note = st.session_state.pop("path_note", None)
            if note:
                st.warning(note)
            if Path(wp).exists():
                if st.button("Extract this", key="db_extract_path", type="primary", disabled=(ext_status == "running")):
                    _start(root, cases_root, case.dir, "dbextract", ["db", "extract", wp])
                    st.rerun(scope="app")
            else:
                st.error(f"not found inside the distro: `{wp}`")

    # ---- 2. what has been extracted
    st.subheader("2. Extracted databases")
    exports = dbexport.list_exports(case)
    if not exports:
        st.caption("nothing extracted yet")
    for e in exports:
        title = f"{'🔴 ' if e.get('error') else ''}{e['name']} - {_kind_label(e.get('kind', ''))}: {e.get('tables_total', 0)} tables, {e.get('rows_total', 0):,} rows"
        with st.expander(title, expanded=False):
            if e.get("error"):
                st.error(e["error"])
            st.markdown(f"source `{e.get('source')}`" + (f" · SHA-256 `{e['sha256'][:16]}…`" if e.get("sha256") else "") +
                        (f" · server {e['server_version']} (innodb_force_recovery={e.get('force_recovery')})" if e.get("server_version") else "") +
                        f" · {e.get('seconds', 0):.0f} s  \nfolder **`{to_windows(e.get('out', ''))}`**")
            out = Path(e.get("out", ""))
            tcsv = Path(e["dir"]) / "tables.csv"
            if tcsv.exists():
                tdf = pd.read_csv(tcsv, dtype=str, keep_default_na=False)
                st.dataframe(tdf, hide_index=True, use_container_width=True)
                choices = [f"{r['database']}/{r['table']}" for _, r in tdf.iterrows() if r["files"]]
                pick = st.selectbox("Preview a table (first 200 rows)", ["-"] + choices, key=f"pv_{e['name']}")
                if pick != "-":
                    dbn, tbl = pick.split("/", 1)
                    row = tdf[(tdf["database"] == dbn) & (tdf["table"] == tbl)].iloc[0]
                    first = row["files"].split(";")[0].strip()
                    fp = out / dbexport.slug(dbn) / first
                    if fp.exists():
                        hdr, rows = dbexport.preview(fp, 200)
                        st.dataframe(pd.DataFrame(rows, columns=hdr if hdr and all(len(r) == len(hdr) for r in rows) else None), use_container_width=True, hide_index=True)
                        if fp.stat().st_size <= 50 * 2**20:
                            st.download_button(f"Download {first}", fp.read_bytes(), file_name=first, key=f"dl_{e['name']}_{tbl}")
                        else:
                            st.caption(f"{first} is {dbexport.human(fp.stat().st_size)}; open it from the folder above")
                    else:
                        st.warning(f"file not found: {fp}")
            sch = Path(e["dir"]) / "schema.sql"
            if sch.exists() and sch.stat().st_size:
                with st.expander("schema.sql"):
                    st.code(sch.read_text("utf-8", errors="replace")[:20000], language="sql")

    # ---- 3. search
    st.subheader("3. Search every extracted table")
    q = st.text_input("Text to find (name, e-mail, phone, IP, hash ...; case-insensitive, any script)", key="db_q")
    if q.strip():
        with st.spinner("searching..."):
            hits = dbexport.search(case, q.strip(), max_hits=500)
        st.caption(f"{len(hits)} hit(s)" + (" (first 500)" if len(hits) >= 500 else ""))
        if hits:
            st.dataframe(pd.DataFrame([{"export": h["export"], "database": h["database"], "table": h["table"], "line": h["line"], "row": h["text"]} for h in hits]),
                         hide_index=True, use_container_width=True)
            sel = st.selectbox("Show a hit as a row", ["-"] + [f"{i}: {h['database']}/{h['table']}:{h['line']}" for i, h in enumerate(hits[:200])], key="db_hit")
            if sel != "-":
                h = hits[int(sel.split(":", 1)[0])]
                try:
                    with open(h["file"], "r", encoding="utf-8-sig", newline="") as f:
                        hdr = next(csv.reader(f))
                    cells = next(csv.reader([h["text"]]))
                    st.dataframe(pd.DataFrame([cells], columns=hdr if len(hdr) == len(cells) else None).T.rename(columns={0: "value"}), use_container_width=True)
                except Exception as ex:  # noqa: BLE001
                    st.code(h["text"])
                    st.caption(str(ex))
