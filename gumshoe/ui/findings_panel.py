"""The Findings tab: filter, read, mark and export.

Filters narrow the table; ticking rows selects findings; the bar under the table acts on the selection
(flag / dismiss / reopen with a note, archive the artifacts, export); below it every selected finding is
shown in full - description, excerpt, translation, the artifact itself - with its own note box.
Export writes Markdown/HTML/CSV/JSON (+ the artifacts, hashed) into the case and, if asked, into a
Windows or network folder.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from gumshoe.normalize.base import SEVERITIES
from gumshoe.review import export_findings, load_review, set_note, set_status, status_of
from gumshoe.ui.run_panel import to_wsl_path

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_ICON = {"flagged": "🚩", "dismissed": "✖", "open": ""}
DEFAULT_EXPORT_WIN = r"C:\DFIR\exports"


def _export_dir_file(cases_root: Path) -> Path:
    return cases_root / ".export_dir"


def remembered_export_dir(cases_root: Path, case_id: str) -> str:
    """The last folder exports were copied to, else the settings' exports folder plus the case id."""
    try:
        d = _export_dir_file(cases_root).read_text("utf-8").strip()
        if d:
            return d
    except OSError:
        pass
    from gumshoe import settings as cfgstore
    base = (cfgstore.load(cases_root).get("exports") or DEFAULT_EXPORT_WIN).rstrip("\\/")
    return base + "\\" + case_id


def _matches(f: dict, text: str) -> bool:
    if not text:
        return True
    t = text.lower()
    hay = " ".join(str(f.get(k) or "") for k in ("title", "path", "description", "excerpt", "rule", "source", "id")).lower()
    return t in hay or t in json.dumps(f.get("extra") or {}, ensure_ascii=False).lower()


def render_findings_tab(case, findings: list[dict], show_preview, cases_root: Path):
    rev = load_review(case)
    n_flag = sum(1 for f in findings if status_of(rev, f["id"]) == "flagged")
    n_dis = sum(1 for f in findings if status_of(rev, f["id"]) == "dismissed")
    if not findings:
        st.info("No findings yet: run Collect (or an intake) on the Run tab.")
        return

    # ---- filters
    c1, c2, c3 = st.columns([2.2, 2, 3])
    sev = c1.pills("Severity", list(reversed(SEVERITIES)), selection_mode="multi", default=["critical", "high", "medium"], key="fx_sev")
    srcs = c2.multiselect("Source", sorted({f["source"] for f in findings}), key="fx_src")
    text = c3.text_input("Search (title, path, description, excerpt; any script)", key="fx_text")
    c4, c5, c6, c7 = st.columns([2, 2, 1.6, 1.6])
    rules = c4.multiselect("Rule", sorted({f.get("rule") or "-" for f in findings}), key="fx_rule")
    show = c5.pills("Show", ["open", "flagged", "dismissed"], selection_mode="multi", default=["open", "flagged"], key="fx_status")
    sort = c6.selectbox("Sort", ["severity", "newest first", "oldest first", "source", "path"], key="fx_sort")
    script = c7.multiselect("Script", ["cyrillic", "cjk", "arabic", "machine-translated"], key="fx_script")
    sev = sev or list(SEVERITIES)
    show = show or ["open", "flagged", "dismissed"]
    rows = [f for f in findings if f["severity"] in sev and (not srcs or f["source"] in srcs)
            and (not rules or (f.get("rule") or "-") in rules) and status_of(rev, f["id"]) in show
            and _matches(f, text) and (not script or any(s in (f.get("tags") or []) for s in script))]
    if sort == "severity":
        rows.sort(key=lambda f: (_ORDER.get(f["severity"], 9), f["source"], f["title"]))
    elif sort == "newest first":
        rows.sort(key=lambda f: (f.get("ctime") or f.get("mtime") or ""), reverse=True)
    elif sort == "oldest first":
        rows.sort(key=lambda f: (f.get("ctime") or f.get("mtime") or "~"))
    elif sort == "source":
        rows.sort(key=lambda f: (f["source"], _ORDER.get(f["severity"], 9)))
    else:
        rows.sort(key=lambda f: (f.get("path") or "~", f.get("line") or 0))
    st.caption(f"{len(rows)} of {len(findings)} findings shown · {n_flag} flagged · {n_dis} dismissed · tick rows to act on them")
    if not rows:
        st.info("Nothing matches these filters.")
        return

    # ---- the table (tick rows to select)
    df = pd.DataFrame([{"": _ICON[status_of(rev, f["id"])], "severity": f["severity"], "source": f["source"], "title": f["title"],
                        "path": f.get("path") or "", "line": str(f.get("line") or ""), "when": str(f.get("ctime") or f.get("mtime") or ""),
                        "note": (rev.get(f["id"]) or {}).get("note", ""), "id": f["id"]} for f in rows])
    ev = st.dataframe(df, use_container_width=True, hide_index=True, on_select="rerun", selection_mode="multi-row", key="fx_table",
                      column_config={"": st.column_config.TextColumn("", width="small"), "severity": st.column_config.TextColumn(width="small"),
                                     "title": st.column_config.TextColumn(width="large"), "path": st.column_config.TextColumn(width="medium"),
                                     "id": st.column_config.TextColumn(width="small")})
    picked = [rows[i] for i in (ev.selection.rows if ev and ev.selection else [])]
    ids = [f["id"] for f in picked]

    # ---- actions on the selection (or on everything shown)
    target_ids = ids or [f["id"] for f in rows]
    label = f"{len(ids)} selected" if ids else f"all {len(rows)} shown"
    st.markdown(f"**Act on {label}:**")
    a1, a2, a3, a4, a5, a6 = st.columns([1, 1, 1, 1.3, 1.3, 1.3])
    note = st.text_input("Note to save with Flag / Dismiss (optional)", key="fx_note", placeholder="why it matters, or why it is noise")
    examiner = case.meta.get("examiner")
    if a1.button("🚩 Flag", key="fx_flag"):
        set_status(case, target_ids, "flagged", note, examiner)
        st.rerun()
    if a2.button("✖ Dismiss", key="fx_dismiss"):
        set_status(case, target_ids, "dismissed", note, examiner)
        st.rerun()
    if a3.button("Reopen", key="fx_reopen"):
        set_status(case, target_ids, "open", note, examiner)
        st.rerun()
    if a4.button("Archive artifacts", key="fx_archive", help="copy the files these findings cite into the case's evidence folder, hashed and logged"):
        from gumshoe.archive import archive
        n = 0
        for f in (picked or rows):
            if f.get("path") and archive(case, f["path"], f"UI: finding {f['id']}", f["id"], f.get("line"), f.get("line")):
                n += 1
        st.success(f"archived {n} file(s) into evidence/")
    if a5.button("Add files to export set", key="fx_expset"):
        for f in (picked or rows):
            if f.get("path"):
                st.session_state.export_set[f["path"]] = f"finding {f['id']}"
        st.success(f"export set: {len(st.session_state.export_set)} file(s) (Export tab)")
    if a6.button("Export…", key="fx_export", type="primary"):
        _export_dialog(case, target_ids, cases_root)

    # ---- the selected findings in full
    if not picked:
        st.caption("Tick one or more rows to read them in full here (description, excerpt, the artifact itself) and to add notes.")
        return
    for f in picked[:25]:
        _render_one(case, f, rev, show_preview)
    if len(picked) > 25:
        st.caption(f"{len(picked) - 25} more selected; narrow the selection to read them.")


def _render_one(case, f: dict, rev: dict, show_preview):
    r = rev.get(f["id"]) or {}
    head = f"{_ICON[status_of(rev, f['id'])]} [{f['severity']}] {f['title']}  ·  {f['source']}"
    with st.expander(head, expanded=True):
        st.markdown(f"`{f.get('path') or '-'}`" + (f" line {f['line']}" if f.get("line") else "") +
                    (f"  \nSHA-256 `{f['sha256']}`" if f.get("sha256") else "") +
                    f"  \nmtime {f.get('mtime') or '-'} · ctime {f.get('ctime') or '-'} · crtime {f.get('crtime') or '-'}  \n"
                    f"rule `{f.get('rule')}` · id `{f['id']}` · tags {', '.join(f.get('tags') or []) or '-'} · related {', '.join(f.get('related') or []) or '-'}")
        if f.get("description"):
            st.write(f["description"])
        if f.get("excerpt"):
            st.code(f["excerpt"])
        tr = (f.get("extra") or {}).get("translation_en")
        if tr:
            st.markdown(f"**Machine translation ({tr.get('model')}) — investigative aid, verify against the original**")
            st.code(tr["translation"])
            if tr.get("tokens_missing"):
                st.warning("not reproduced verbatim: " + ", ".join(tr["tokens_missing"]))
        ex = f.get("extra") or {}
        ex_show = {k: v for k, v in ex.items() if k != "translation_en"}
        if ex_show:
            with st.expander("details"):
                st.json(ex_show)
        n1, n2 = st.columns([4, 1])
        new_note = n1.text_input("Examiner note", value=r.get("note", ""), key=f"note_{f['id']}")
        if n2.button("Save note", key=f"savenote_{f['id']}"):
            set_note(case, f["id"], new_note, case.meta.get("examiner"))
            st.rerun()
        b1, b2, b3, b4 = st.columns(4)
        if f.get("path") and b1.button("Archive this artifact", key="arch_" + f["id"]):
            from gumshoe.archive import archive
            sc = archive(case, f["path"], f"UI: finding {f['id']}", f["id"], f.get("line"), f.get("line"))
            st.success("archived" if sc else "not a file on the mount")
        from gumshoe.memory import read_pins, set_pin
        pinned_now = f["id"] in read_pins(case)
        if b2.button(("Unpin" if pinned_now else "Pin") + " for Ask", key="pin_" + f["id"], help="pinned findings are always offered to the model as sources"):
            set_pin(case, f["id"], pinned=not pinned_now)
            st.rerun()
        if any(t in (f.get("tags") or []) for t in ("cyrillic", "cjk", "arabic")) and b3.button("Translate to English (7B)", key="tr_" + f["id"]):
            from gumshoe.translate import translate_findings
            with st.spinner("translating..."):
                res = translate_findings(case, finding_ids=[f["id"]])
            st.success(f"translated {res.get('translated', 0)}; reload to view") if res.get("translated") else st.warning(res.get("note", "nothing translated"))
        if f.get("path") and b4.checkbox("View the artifact", key="view_" + f["id"]):
            show_preview(f["path"], "f" + f["id"])
        with st.expander("raw"):
            st.json(f)


@st.dialog("Export findings", width="large")
def _export_dialog(case, ids: list[str], cases_root: Path):
    st.write(f"{len(ids)} finding(s) will be written as Markdown, HTML, CSV and JSON (with your notes and statuses) into the case "
             f"under `reports/exports/`, and can be copied to a folder you can reach from Windows.")
    name = st.text_input("Export name", value=f"findings-{len(ids)}", key="xd_name")
    with_art = st.checkbox("also copy the files these findings cite (hashed manifest + zip)", value=True, key="xd_art")
    win = st.text_input("Copy to (Windows or \\\\server\\share folder; leave empty to keep it in the case only)",
                        value=remembered_export_dir(cases_root, case.meta.get("case_id", "")), key="xd_win")
    st.caption(f"The case folder itself is reachable from Explorer at `\\\\wsl.localhost\\DFIR\\opt\\dfir\\cases\\{case.meta.get('case_id')}\\reports\\exports`.")
    if st.button("Export now", type="primary", key="xd_go"):
        dest = None
        if win.strip():
            st.session_state.pop("path_note", None)
            dest = Path(to_wsl_path(win))
            note = st.session_state.get("path_note")
            if note:
                st.warning(note)
            try:
                _export_dir_file(cases_root).write_text(win.strip(), "utf-8")
            except OSError:
                pass
        with st.spinner("exporting..."):
            r = export_findings(case, ids, name, with_artifacts=with_art, copy_to=dest, log=lambda s: None)
        if r.get("error"):
            st.error(r["error"])
            return
        st.success(f"{r['count']} finding(s) exported: {Path(r['zip']).name} (sha256 {r['zip_sha256'][:16]}…)")
        if r.get("copied_to"):
            st.success(f"copies placed in {win.strip()}")
        if r.get("copy_error"):
            st.warning(f"could not copy to {win.strip()}: {r['copy_error']} (the export is still in the case folder)")
        zp = Path(r["zip"])
        if zp.exists():
            st.download_button("Download the zip", zp.read_bytes(), file_name=zp.name, key="xd_dl")
        md = Path(r["files"][0])
        if md.exists():
            st.download_button("Download findings.md", md.read_bytes(), file_name=f"{r['name']}-findings.md", key="xd_dlmd")
