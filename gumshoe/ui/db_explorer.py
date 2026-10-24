"""Explore the extracted databases from the Databases tab, without SQL, Docker or a database server:

  Explore  - one catalog of every table across every export (filter by table or column name), tick tables, open one
             in a paged viewer with per-column filters and sorting, export the rows you see or whole tables to a folder
  Search   - a term, words or a regex across every table (or the ticked ones): hits per table, the matching rows of
             any table with the table's own columns, and one click to export every matching row of every table to a
             folder with a summary and a custody record
  SQL      - for those who want it: tick tables, load them into the read-only SQLite workbench, and type SELECTs;
             results export to CSV. No Docker, no MariaDB, nothing typed in a terminal.

Everything reads the CSV exports that extraction wrote; nothing touches the evidence. Long jobs (loading big tables,
exporting a search with many rows) run in the background like extraction, with their log in the tab.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from gumshoe import dbexplore, dbexport
from gumshoe.ui.run_panel import _logs, tail_log
from gumshoe.winpath import to_windows

PAGE_SIZES = (100, 200, 500, 1000)
INLINE_EXPORT_MAX = 20_000        # a search export with more candidate lines than this runs in the background


def _cat(case):
    """The catalog, cached per export set (the exports' source.json files) for the session."""
    exports = dbexport.list_exports(case)
    stamp = tuple((e["name"], e.get("finished"), e.get("rows_total")) for e in exports)
    if st.session_state.get("dbx_cat_stamp") != stamp:
        st.session_state["dbx_cat"] = dbexplore.catalog(case)
        st.session_state["dbx_cat_stamp"] = stamp
    return st.session_state["dbx_cat"]


def _selected() -> set[str]:
    return st.session_state.setdefault("dbx_selected", set())


def _df_rows(header, rows, locators: bool = True) -> pd.DataFrame:
    cols = (["_file", "_line"] if locators else []) + list(header)
    fixed = [r if len(r) == len(cols) else (list(r) + [""] * len(cols))[:len(cols)] for r in rows]
    return pd.DataFrame(fixed, columns=cols)


def render_explorer(case, root: Path, cases_root: Path, start_job, status_of):
    cat = _cat(case)
    if not cat:
        st.info("Nothing extracted yet: extract the databases first (section 1 above). Then every table can be browsed, searched and exported here.")
        return
    tabs = st.tabs(["Explore", "Search", "SQL workbench"])
    with tabs[0]:
        _explore(case, cat)
    with tabs[1]:
        _search(case, cat, root, cases_root, start_job, status_of)
    with tabs[2]:
        _workbench(case, cat, root, cases_root, start_job, status_of)


# --------------------------------------------------------------------------- Explore
def _explore(case, cat):
    sel = _selected()
    c1, c2, c3 = st.columns([3, 1.2, 1.2])
    flt = c1.text_input("Find a table (part of its name, its database, or a column name - e.g. wallet, phone, users)", key="dbx_flt")
    only_sel = c2.checkbox("only ticked", key="dbx_only_sel", value=False)
    fl = flt.strip().lower()
    rows = [t for t in cat if (not fl or fl in t["table"].lower() or fl in t["database"].lower() or fl in t["export"].lower() or any(fl in c.lower() for c in t["columns"]))
            and (not only_sel or t["key"] in sel)]
    c3.caption(f"{len(rows)} of {len(cat)} tables · {sum(t['rows'] for t in cat):,} rows in all")
    df = pd.DataFrame([{"✓": t["key"] in sel, "export": t["export"], "database": t["database"], "table": t["table"], "rows": t["rows"],
                        "columns": ", ".join(t["columns"][:12]) + (" …" if len(t["columns"]) > 12 else ""), "size": dbexport.human(t["bytes"]),
                        "notes": ("; ".join(x for x in (f"{t['rejected']} rejected rows" if t["rejected"] else "", f"{t['blobs']} blobs" if t["blobs"] else "", t["error"]) if x)),
                        "key": t["key"]} for t in rows])
    # the editor's remembered edits are per view: a new key whenever the shown rows or the ticks change programmatically
    view_key = f"dbx_catalog_{abs(hash(tuple(t['key'] for t in rows)))}_{st.session_state.get('dbx_cat_ver', 0)}"
    ed = st.data_editor(df, hide_index=True, width="stretch", key=view_key,
                        column_config={"✓": st.column_config.CheckboxColumn("✓", help="tick tables to search, load or export together"),
                                       "key": None},
                        disabled=["export", "database", "table", "rows", "columns", "size", "notes"], height=min(520, 60 + 35 * max(len(df), 1)))
    if len(ed):
        now = {k for k, v in zip(ed["key"], ed["✓"]) if v}
        shown = set(ed["key"])
        new_sel = (sel - shown) | now
        if new_sel != sel:
            st.session_state["dbx_selected"] = new_sel
            st.rerun()
    b1, b2, b3, b4 = st.columns([1, 1, 1, 3])
    if b1.button("Tick all shown", key="dbx_tick_all"):
        st.session_state["dbx_selected"] = sel | {t["key"] for t in rows}
        st.session_state["dbx_cat_ver"] = st.session_state.get("dbx_cat_ver", 0) + 1
        st.rerun()
    if b2.button("Clear ticks", key="dbx_tick_none"):
        st.session_state["dbx_selected"] = set()
        st.session_state["dbx_cat_ver"] = st.session_state.get("dbx_cat_ver", 0) + 1
        st.rerun()
    if sel and b3.button(f"Export {len(sel)} ticked table(s) to a folder", key="dbx_export_sel", help="copies of the tables' CSV files (and their blobs) into a new folder under the exports folder, with a manifest and a custody record"):
        with st.spinner("copying..."):
            r = dbexplore.export_tables(case, sorted(sel), log=lambda s: None)
        st.success(f"{r['files']} file(s) from {r['tables']} table(s) -> `{to_windows(r['out'])}`")
    b4.caption(f"{len(sel)} ticked" if sel else "tick tables to search only those, to load them into the SQL workbench, or to export them together")

    # ---- the viewer
    st.markdown("---")
    keys = [t["key"] for t in rows] if rows else [t["key"] for t in cat]
    default = st.session_state.get("dbx_open")
    pick = st.selectbox("Open a table", ["-"] + keys, index=(keys.index(default) + 1) if default in keys else 0, key="dbx_open_pick")
    if pick == "-":
        return
    st.session_state["dbx_open"] = pick
    t = next(x for x in cat if x["key"] == pick)
    in_wb = dbexplore.loaded(case).get(pick)
    hdr = t["columns"]
    st.caption(f"**{t['database']}.{t['table']}** - {t['rows']:,} rows, {len(hdr)} columns, {dbexport.human(t['bytes'])}"
               + (" · loaded in the SQL workbench (instant paging and sorting)" if in_wb else " · read from the CSV (a page deep in a big table takes a scan to it; load it in the SQL workbench for instant paging)"))
    f1, f2, f3, f4 = st.columns([2, 2, 1, 1])
    fcol = f1.selectbox("Filter column", ["(any)"] + hdr, key="dbx_fcol")
    ftext = f2.text_input("contains", key="dbx_ftext")
    size = f3.selectbox("rows per page", PAGE_SIZES, index=1, key="dbx_psize")
    pageno = f4.number_input("page", min_value=1, value=1, step=1, key="dbx_pageno")
    filters = {}
    if ftext.strip():
        if fcol == "(any)":
            filters = {}
        else:
            filters = {fcol: ftext.strip()}
    offset = (int(pageno) - 1) * int(size)
    if in_wb:
        s1, s2, s3 = st.columns([2, 1, 1])
        order = s1.selectbox("sort by", ["(file order)"] + hdr, key="dbx_sort")
        desc = s2.checkbox("descending", key="dbx_desc")
        numeric = s3.checkbox("as numbers", key="dbx_numeric", help="every column is text; tick to sort amounts and ids by value (5.5 before 100)")
        r = dbexplore.sql_page(case, pick, offset, int(size), filters, None if order == "(file order)" else order, desc, numeric)
        if ftext.strip() and fcol == "(any)":
            # any column: a LIKE over every column through SQL
            r = _sql_any_filter(case, pick, ftext.strip(), offset, int(size), None if order == "(file order)" else order, desc, numeric)
        st.caption(f"{r.get('total', 0):,} row(s)" + (" match" if filters or ftext.strip() else "") + f" · page {pageno}")
        st.dataframe(_df_rows(r["header"], r["rows"], locators=False), hide_index=True, width="stretch")
    else:
        if ftext.strip() and fcol == "(any)":
            r = dbexplore.search_rows(t, ftext.strip(), "phrase", limit=int(size), offset=offset)
            st.caption(f"{r['shown']} row(s) on this page" + (" (more pages)" if r["truncated"] else f" · {r['matched']} match in all"))
        else:
            r = dbexplore.page(t, offset, int(size), filters)
            st.caption(f"{len(r['rows'])} row(s) on this page" + (" (more)" if r["more"] else "") + (f" · {r['matched_so_far']:,} match so far" if filters else ""))
        st.dataframe(_df_rows(r["header"], r["rows"]), hide_index=True, width="stretch")
    e1, e2 = st.columns([1, 3])
    if r.get("rows") and e1.button("Export these rows to CSV", key="dbx_export_page"):
        full = r["header"] if r["header"][:2] == ["_file", "_line"] else ["_file", "_line"] + list(r["header"])
        out = dbexplore.export_rows(case, full, r["rows"], f"{t['database']}.{t['table']}" + (f" {fcol}={ftext}" if ftext.strip() else ""), kind="db-selection",
                                    note=f"rows of {t['database']}.{t['table']} shown in the viewer (page {pageno}, filter {fcol}={ftext!r})")
        st.success(f"written -> `{to_windows(str(out))}`")
    e2.caption("_file / _line say which exported CSV file and line each row came from, so a row can be found again in the full export.")


def _sql_any_filter(case, key, text, offset, limit, order_by, desc, numeric=False):
    import sqlite3
    info = dbexplore.loaded(case).get(key)
    p = dbexplore.workbench_path(case)
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{info["name"]}")')]
    cmap = dbexplore._colmap(info)
    like = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    where = " OR ".join(f'"{c}" LIKE ? ESCAPE \'\\\'' for c in cols if c not in ("_file", "_line"))
    args = [like] * (len(cols) - 2)
    total = con.execute(f'SELECT COUNT(*) FROM "{info["name"]}" WHERE {where}', args).fetchone()[0]
    oc = cmap.get(order_by, order_by) if order_by else None
    col = f'CAST("{oc}" AS REAL)' if numeric else f'"{oc}"'
    ob = f' ORDER BY {col} {"DESC" if desc else "ASC"}' if oc in cols else ""
    rows = [list(r) for r in con.execute(f'SELECT * FROM "{info["name"]}" WHERE {where}{ob} LIMIT ? OFFSET ?', args + [limit, offset])]
    con.close()
    back = {v: k for k, v in cmap.items()}
    return {"header": [back.get(c, c) for c in cols], "rows": rows, "total": total, "more": offset + len(rows) < total}


# --------------------------------------------------------------------------- Search
def _search(case, cat, root, cases_root, start_job, status_of):
    sel = _selected()
    c1, c2, c3 = st.columns([3, 1.3, 1.3])
    q = c1.text_input("Search every table (a name, e-mail, phone, wallet, IP, hash, a Cyrillic word ...)", key="dbx_q")
    mode = c2.selectbox("match", ["phrase", "all words", "any word", "regex"], key="dbx_mode",
                        help="phrase: the text as typed · all words: every word, in any cell of the row · any word: one of them · regex: a pattern")
    mode_key = {"phrase": "phrase", "all words": "all", "any word": "any", "regex": "regex"}[mode]
    scope = c3.selectbox("in", ["all tables", f"ticked tables ({len(sel)})"], key="dbx_scope", disabled=not sel)
    keys = sel if scope.startswith("ticked") and sel else None
    if not q.strip():
        st.caption("Results come per table first (how many lines hold the text), then any table's matching rows with its own columns; "
                   "Export writes every matching row of every table to a folder with a summary and a custody record.")
        return
    ck = (q.strip(), mode_key, tuple(sorted(keys)) if keys else None)
    if st.session_state.get("dbx_counts_key") != ck:
        with st.spinner(f"searching {len(keys) if keys else len(cat)} tables..."):
            t0 = time.time()
            try:
                st.session_state["dbx_counts"] = dbexplore.search_counts(case, q.strip(), mode_key, keys, cat)
            except dbexplore.BadQuery as e:
                st.error(str(e))
                return
            st.session_state["dbx_counts_secs"] = round(time.time() - t0, 1)
        st.session_state["dbx_counts_key"] = ck
        case.custody.append("db_search", {"query": q.strip(), "mode": mode_key, "tables": len(keys) if keys else len(cat), "hits": len(st.session_state["dbx_counts"])})
    hits = st.session_state["dbx_counts"]
    total_lines = sum(h["candidate_lines"] for h in hits)
    st.caption(f"{len(hits)} table(s) hold the text, ~{total_lines:,} line(s) in all ({st.session_state.get('dbx_counts_secs', 0)} s)"
               + (" - counts are lines; rows with long text cells can span several" if total_lines else ""))
    if not hits:
        return
    hdf = pd.DataFrame([{"export": h["export"], "database": h["database"], "table": h["table"], "~lines": h["candidate_lines"], "rows in table": h["rows"],
                         "columns": ", ".join(h["columns"][:10]) + (" …" if len(h["columns"]) > 10 else ""), "key": h["key"]} for h in hits])
    ev = st.dataframe(hdf.drop(columns=["key"]), hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row", key="dbx_hits")
    x1, x2, x3 = st.columns([1.4, 1.4, 3])
    cols_only = x2.text_input("only in columns (names, comma-separated)", key="dbx_cols", placeholder="email, phone",
                              help="rows match only when the text is in one of these columns; applies to the rows shown and to both exports")
    cols = [c.strip() for c in cols_only.split(",") if c.strip()] or None
    if x1.button("Export every matching row (all tables)", key="dbx_export_all", type="primary"):
        if total_lines <= INLINE_EXPORT_MAX:
            with st.spinner("writing..."):
                r = dbexplore.export_search(case, q.strip(), mode_key, keys, cols, log=lambda s: None)
            st.success(f"{r['matching_rows']:,} rows from {r['tables_with_matches']} table(s) -> `{to_windows(r['out'])}` (summary.csv, query.json, README.txt alongside)")
        else:
            argv = ["db", "search", q.strip(), "--mode", mode_key, "--export"] + (["--tables", ",".join(sorted(keys))] if keys else []) + (["--columns", ",".join(cols)] if cols else [])
            start_job(root, cases_root, case.dir, "dbsearch", argv)
            st.info("a big export: running in the background (the log appears below; the folder is named in it when done)")
            st.rerun(scope="app")
    status, state = status_of(case.dir, "dbsearch")
    if status == "running":
        st.progress(0.5, text="export running in the background...")
        st.code(tail_log(case.dir, "dbsearch") or "(starting)")
    elif status in ("done", "failed") and state.get("cmd") and "search" in state["cmd"]:
        with st.expander("last background export" + (" - done" if status == "done" else " - FAILED")):
            st.code(tail_log(case.dir, "dbsearch") or "(empty)")
    # ---- rows of the picked table
    srows = ev.selection.rows if ev and ev.selection else []
    if not srows:
        x3.caption("click a table for its matching rows")
        return
    h = hits[srows[0]]
    t = next(x for x in cat if x["key"] == h["key"])
    p1, p2 = st.columns([1, 1])
    size = p1.selectbox("rows per page", PAGE_SIZES, index=2, key="dbx_srows")
    pageno = p2.number_input("page", min_value=1, value=1, step=1, key="dbx_spage")
    with st.spinner(f"reading {t['database']}.{t['table']}..."):
        r = dbexplore.search_rows(t, q.strip(), mode_key, limit=int(size), offset=(int(pageno) - 1) * int(size), columns=cols)
    st.markdown(f"**{t['database']}.{t['table']}** - {r['shown']} matching row(s) on this page" + (" (more pages)" if r["truncated"] else f" · {r['matched']} in all"))
    st.dataframe(_df_rows(r["header"], r["rows"]), hide_index=True, width="stretch")
    y1, y2 = st.columns([1.4, 3])
    if r["rows"] and y1.button(f"Export all matching rows of {t['table']}", key="dbx_export_one"):
        with st.spinner("writing..."):
            res = dbexplore.export_search(case, q.strip(), mode_key, {t["key"]}, cols, log=lambda s: None)
        st.success(f"{res['matching_rows']:,} rows -> `{to_windows(res['out'])}`")
    y2.caption("_file / _line locate each row in the exported CSV; the export carries them too.")


# --------------------------------------------------------------------------- SQL workbench
def _workbench(case, cat, root, cases_root, start_job, status_of):
    sel = _selected()
    wb = dbexplore.loaded(case)
    st.caption("The workbench is a read-only SQLite file in the case: tick tables in Explore, load them here, then sort, filter and query "
               "them instantly - or type SELECTs. Column names are the tables' own; every table also has `_file` and `_line`.")
    status, state = status_of(case.dir, "dbload")
    c1, c2, c3 = st.columns([1.6, 1.6, 3])
    sel_size = sum(t["bytes"] for t in cat if t["key"] in sel)
    if sel and c1.button(f"Load {len(sel)} ticked table(s) ({dbexport.human(sel_size)})", key="dbx_load", disabled=(status == "running"), type="primary"):
        argv = ["db", "load", "--tables", ",".join(sorted(sel))]
        start_job(root, cases_root, case.dir, "dbload", argv)
        st.rerun(scope="app")
    all_size = sum(t["bytes"] for t in cat)
    if c2.button(f"Load every table ({dbexport.human(all_size)})", key="dbx_load_all", disabled=(status == "running"),
                 help="tables over 2 GB of CSV are skipped (load those one at a time from Explore)"):
        start_job(root, cases_root, case.dir, "dbload", ["db", "load", "--all"])
        st.rerun(scope="app")
    if status == "running":
        st.progress(0.5, text="loading in the background (about ten seconds per million rows)...")
        st.code(tail_log(case.dir, "dbload") or "(starting)")
    elif status == "failed":
        with st.expander("the last load FAILED"):
            st.code(tail_log(case.dir, "dbload") or "(empty)")
    if wb:
        c3.caption(f"loaded: {len(wb)} table(s), {sum(v['rows'] for v in wb.values()):,} rows · file `{to_windows(str(dbexplore.workbench_path(case)))}`")
        with st.expander(f"tables in the workbench ({len(wb)}) - their SQL names"):
            st.dataframe(pd.DataFrame([{"SQL name": v["name"], "database": v["database"], "table": v["table"], "rows": v["rows"], "loaded": v["loaded_at"]} for v in wb.values()]),
                         hide_index=True, width="stretch")
            if st.button("Unload everything (frees the space; the CSV exports stay)", key="dbx_unload"):
                n = dbexplore.unload(case)
                st.success(f"{n} table(s) dropped")
                st.rerun()
    else:
        c3.caption("nothing loaded yet")
        return
    st.markdown("**SQL** (SELECT / WITH only; the file is opened read-only; 2,000 rows and 120 s per query)")
    first = next(iter(wb.values()))["name"]
    stmt = st.text_area("statement", value=st.session_state.get("dbx_sql", f'SELECT * FROM "{first}" LIMIT 50'), height=120, key="dbx_sql_in", label_visibility="collapsed")
    r1, r2 = st.columns([1, 4])
    if r1.button("Run", key="dbx_sql_run", type="primary") and stmt.strip():
        st.session_state["dbx_sql"] = stmt
        t0 = time.time()
        res = dbexplore.sql(case, stmt)
        st.session_state["dbx_sql_res"] = res
        case.custody.append("db_sql", {"statement": stmt.strip()[:2000], "rows": len(res.get("rows") or []), "error": res.get("error"), "seconds": round(time.time() - t0, 2)})
    res = st.session_state.get("dbx_sql_res")
    if res:
        if res.get("error"):
            st.error(res["error"])
        else:
            st.caption(f"{len(res['rows'])} row(s)" + (" (first 2,000; add a WHERE or a LIMIT)" if res.get("truncated") else "") + f" · {res.get('seconds', 0)} s")
            st.dataframe(_df_rows(res["header"], res["rows"], locators=False), hide_index=True, width="stretch")
            if res["rows"] and r2.button("Export this result to CSV", key="dbx_sql_export"):
                out = dbexplore.export_rows(case, res["header"], res["rows"], "sql-result", kind="db-selection", note=f"SQL result: {st.session_state.get('dbx_sql', '')[:500]}")
                st.success(f"written -> `{to_windows(str(out))}`")
    with st.expander("examples"):
        st.code(f'SELECT email, COUNT(*) AS n FROM "{first}" GROUP BY email ORDER BY n DESC LIMIT 20;\n'
                f'SELECT * FROM "{first}" WHERE email LIKE \'%@mail.ru\' LIMIT 100;\n'
                '-- every column is text: compare or sort amounts as numbers with CAST\n'
                '-- SELECT * FROM "shop__orders" WHERE CAST(amount AS REAL) > 1000 ORDER BY CAST(amount AS REAL) DESC;\n'
                '-- a join across two loaded tables (names from the list above):\n'
                '-- SELECT u.email, o.amount FROM "shop__users" u JOIN "shop__orders" o ON o.user_id = u.id;', language="sql")
