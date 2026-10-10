"""Gumshoe browser UI (Streamlit). Launch with `python gumshoe.py ui`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent.parent   # clone root (package lives at ROOT/gumshoe)
sys.path.insert(0, str(ROOT))

from gumshoe.case import Case, load_config  # noqa: E402
from gumshoe.llm import Ollama  # noqa: E402
from gumshoe.normalize.base import SEVERITIES  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--cases-root", default=str(ROOT / "cases"))
ap.add_argument("--config", default=str(ROOT / "config.yaml"))
args, _ = ap.parse_known_args()
CFG = load_config(args.config or None)
CASES = Path(args.cases_root)

st.set_page_config(page_title="Gumshoe", layout="wide")
st.title("Gumshoe — cited forensic triage")

case_ids = sorted(p.name for p in CASES.iterdir() if (p / "case.json").exists()) if CASES.exists() else []
if not case_ids:
    st.warning("No cases yet. Create one: `python gumshoe.py init --case CASE-001 --examiner you --mount /mnt/evidence`")
    st.stop()
case_id = st.sidebar.selectbox("Case", case_ids)
case = Case.open(CASES / case_id, CFG)
summary = case.read_json("summary.json", {}) or {}
ol = Ollama(case.cfg["llm"])
ok_chain, n_chain, _, chain_msg = case.custody.verify()

with st.sidebar:
    st.markdown(f"**Examiner:** {case.meta.get('examiner')}  \n**Mode:** {case.mode}  \n**Root:** `{case.mount_root}`")
    ih = case.meta.get("image_hashes") or {}
    st.markdown("**Image hash:** " + {True: "✅ matches acquisition", False: "❌ MISMATCH", None: "not compared"}.get(ih.get("match"), "not compared"))
    ro = case.meta.get("readonly_check") or {}
    st.markdown("**Read-only:** " + ("✅ " if ro.get("ok") else "⚠️ ") + str(ro.get("reason", "not checked")))
    st.markdown(f"**Custody:** {'✅' if ok_chain else '❌'} {chain_msg}")
    st.markdown(f"**Model:** {'✅ reachable' if ol.available() else '⚠️ Ollama not reachable'}")
    st.markdown(f"**Findings:** {summary.get('total', 0)}")
    for s in reversed(SEVERITIES):
        st.markdown(f"- {s}: {summary.get('by_severity', {}).get(s, 0)}")
    from gumshoe.memory import read_notes, write_notes, read_pins
    with st.expander("Examiner notes (context for the model, never evidence)"):
        notes_text = st.text_area("notes.md", read_notes(case), height=220, label_visibility="collapsed")
        if st.button("Save notes"):
            h = write_notes(case, notes_text)
            st.success(f"saved (sha256 {h[:12]})")
        pins = read_pins(case)
        st.caption("pinned findings: " + (", ".join(pins) if pins else "none"))

tabs = st.tabs(["Findings", "Ask", "Documents", "Browse", "Panel", "Trends", "Timeline", "Reports", "Evidence", "Export", "Custody"])
findings = case.read_findings()
if "export_set" not in st.session_state:
    st.session_state.export_set = {}


def show_preview(relpath: str, key: str):
    """Render any file from the image: tables (xlsx/csv), text, markdown, images; always with a download of the original."""
    from gumshoe.documents import preview, open_bytes
    pv = preview(case, relpath)
    if pv["kind"] == "table":
        sheet = st.selectbox("Sheet", list(pv["sheets"]), key="sheet_" + key) if len(pv["sheets"]) > 1 else list(pv["sheets"])[0]
        rows = pv["sheets"][sheet]
        if rows:
            width = max(len(r) for r in rows)
            st.dataframe(pd.DataFrame([list(r) + [""] * (width - len(r)) for r in rows]), use_container_width=True)
        else:
            st.info("empty sheet")
    elif pv["kind"] == "markdown":
        st.markdown(pv["text"])
        with st.expander("raw text"):
            st.code(pv["text"])
    elif pv["kind"] == "text":
        st.caption(f"text extracted with {pv.get('method')}")
        st.code(pv["text"])
    elif pv["kind"] == "image":
        st.image(pv["bytes"])
    elif pv["kind"] == "missing":
        st.error("not a file on the mount")
    else:
        st.info(f"no preview ({pv.get('note', '')}); download the original below")
    data = open_bytes(case, relpath, "downloaded from UI")
    if data is not None:
        st.download_button("Download original (archived + logged)", data, file_name=Path(relpath).name, key="dl_" + key)
    if st.button("Add to export set", key="exp_" + key):
        st.session_state.export_set[relpath] = "added from viewer"
        st.success(f"added; export set now {len(st.session_state.export_set)} file(s) — see the Export tab")

with tabs[0]:
    c1, c2, c3, c4 = st.columns(4)
    sev = c1.multiselect("Severity", SEVERITIES, default=["critical", "high", "medium"])
    src = c2.multiselect("Source", sorted({f["source"] for f in findings}))
    text = c3.text_input("Filter text (any script)")
    script = c4.multiselect("Script", ["cyrillic", "cjk", "arabic", "machine-translated"])
    rows = [f for f in findings if f["severity"] in sev and (not src or f["source"] in src)
            and (not text or text.lower() in json.dumps(f, ensure_ascii=False).lower())
            and (not script or any(s in (f.get("tags") or []) for s in script))]
    if rows:
        df = pd.DataFrame([{"id": f["id"], "severity": f["severity"], "source": f["source"], "title": f["title"],
                            "path": f.get("path"), "line": f.get("line"), "ctime": f.get("ctime"), "rule": f.get("rule")} for f in rows])
        st.dataframe(df, use_container_width=True, hide_index=True)
        pick = st.selectbox("Open finding", [f["id"] for f in rows])
        f = next(x for x in rows if x["id"] == pick)
        st.markdown(f"### {f['title']}")
        st.markdown(f"`{f.get('path') or '-'}`" + (f" line {f['line']}" if f.get("line") else "") +
                    f"  \nSHA-256 `{f.get('sha256') or '-'}`  \nmtime {f.get('mtime')} · ctime {f.get('ctime')} · crtime {f.get('crtime')}  \n"
                    f"rule `{f.get('rule')}` · tags {', '.join(f.get('tags') or [])} · related {', '.join(f.get('related') or [])}")
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
        b1, b2, b3 = st.columns(3)
        if f.get("path") and b1.button("Archive this artifact", key="arch_" + f["id"]):
            from gumshoe.archive import archive
            sc = archive(case, f["path"], f"UI: finding {f['id']}", f["id"], f.get("line"), f.get("line"))
            st.success("archived" if sc else "not a file on the mount")
        if f.get("path") and b3.button("Add to export set", key="expf_" + f["id"]):
            st.session_state.export_set[f["path"]] = f"finding {f['id']}"
            st.success(f"export set: {len(st.session_state.export_set)} file(s)")
        from gumshoe.memory import read_pins, set_pin
        pinned_now = f["id"] in read_pins(case)
        if b2.button(("Unpin" if pinned_now else "Pin") + " (always offered as a source)", key="pin_" + f["id"]):
            set_pin(case, f["id"], pinned=not pinned_now)
            st.rerun()
        if f.get("path") and st.checkbox("View the artifact", key="view_" + f["id"]):
            show_preview(f["path"], "f" + f["id"])
        if any(t in (f.get("tags") or []) for t in ("cyrillic", "cjk", "arabic")) and b2.button("Translate to English (7B)", key="tr_" + f["id"]):
            from gumshoe.translate import translate_findings
            with st.spinner("translating..."):
                r = translate_findings(case, finding_ids=[f["id"]])
            st.success(f"translated {r.get('translated', 0)}; reload to view") if r.get("translated") else st.warning(r.get("note", "nothing translated"))
        with st.expander("raw"):
            st.json(f)
    else:
        st.info("No findings match. Run `gumshoe collect` first.")

with tabs[1]:
    st.caption("Answers come only from indexed sources and must cite them; citations outside the retrieved set are removed. "
               "Cited files are archived automatically.")
    from gumshoe.memory import read_session, clear_session, list_sessions, read_notes
    cs1, cs2, cs3 = st.columns([2, 1, 1])
    session = cs1.text_input("Session (follow-ups carry earlier turns and their cited sources)", st.session_state.get("ask_session", "work"))
    st.session_state["ask_session"] = session
    use_memory = cs2.checkbox("Case brief + notes + pins", value=True, help="Fixed context first in the prompt (cached by Ollama); never citable")
    if cs3.button("New session"):
        clear_session(case, session)
        st.session_state.pop("last_answer", None)
        st.success(f"session '{session}' cleared")
    turns = read_session(case, session, last=6)
    if turns:
        with st.expander(f"session '{session}': last {len(turns)} turn(s)"):
            for t in turns:
                st.markdown(f"**Q:** {t['question']}  \n**A:** {(t.get('answer') or '(no answer)')[:600]}")
    q = st.text_area("Question", placeholder="Which addresses posted to files that Loki flagged, and when?")
    tier = st.radio("Model", ["fast (3B)", "deep (7B)"], horizontal=True)
    if st.button("Ask") and q.strip():
        from gumshoe.rag import ask
        with st.spinner("retrieving and generating..."):
            r = ask(case, q.strip(), tier="report" if tier.startswith("deep") else "interactive", session=session or None, use_memory=use_memory)
        if r.get("answer"):
            st.markdown(("✅ supported" if r["supported"] else "⚠️ unsupported in part") + f" · model {r['model']}")
            st.markdown(r["answer"])
        else:
            st.warning(r.get("note", "no answer"))
        st.markdown("**Sources** — every excerpt the model was given; cited ones are marked")
        st.session_state["last_answer"] = r
        if r.get("archived"):
            st.caption("archived: " + ", ".join(r["archived"]))
        st.caption(f"answer packet saved: {r.get('packet')}")
    r = st.session_state.get("last_answer")
    if r:
        from gumshoe.index import Index
        idx = Index(case)
        valid = set(r.get("valid_citations") or [])
        for s in r["sources"]:
            mark = ("✅ cited" if s["n"] in valid else "not cited") + f" · {s.get('origin', 'retrieved')}"
            loc = s["relpath"] + (f" lines {s['line_start']}-{s['line_end']}" if s.get("line_start") else "")
            with st.expander(f"[{s['n']}] {loc}  —  {mark}  ·  sha256 {(s.get('sha256') or '')[:16]}"):
                row = idx.con.execute("SELECT text FROM chunks WHERE id=?", (s["chunk_id"],)).fetchone()
                if row:
                    st.code(row[0])
                if not s["relpath"].startswith(("finding://", "summary://")):
                    if st.checkbox("View the file", key=f"srcview_{r.get('question_index')}_{s['n']}"):
                        show_preview(s["relpath"], f"q{r.get('question_index')}s{s['n']}")
        idx.close()
        if st.button("Add all cited files to export set"):
            for s in r["sources"]:
                if s["n"] in valid and not s["relpath"].startswith(("finding://", "summary://")):
                    st.session_state.export_set[s["relpath"]] = f"cited [{s['n']}] question {r.get('question_index')}"
            st.success(f"export set: {len(st.session_state.export_set)} file(s)")
    qlog = case.reports / "questions.jsonl"
    if qlog.exists():
        with st.expander("previous questions"):
            for line in qlog.read_text("utf-8").splitlines()[-20:]:
                d = json.loads(line)
                st.markdown(f"- {d['asked_at']} — {d['question']} → {'answered' if d.get('answer') else 'no model'}")

with tabs[2]:
    doc = case.read_json("documents.json", {}) or {}
    items = doc.get("items", [])
    if not items:
        st.info("No document inventory yet: `gumshoe documents` (or `gumshoe collect`) then `gumshoe index`.")
    else:
        st.caption(f"{doc.get('count')} files · {doc.get('extracted')} extracted to text · by kind {doc.get('by_kind')}")
        c1, c2 = st.columns(2)
        kinds = c1.multiselect("Kind", sorted({i['kind'] for i in items}), default=[k for k in ("spreadsheet", "document", "pdf", "table") if k in {i['kind'] for i in items}])
        q = c2.text_input("Path contains", "")
        rows = [i for i in items if (not kinds or i["kind"] in kinds) and (not q or q.lower() in i["path"].lower())]
        df = pd.DataFrame([{"path": i["path"], "kind": i["kind"], "size": i["size"], "mtime": i["mtime"], "ctime": i["ctime"],
                            "text": bool((i.get("extracted") or {}).get("text_file")), "sha256": (i.get("sha256") or "")[:16]} for i in rows])
        st.dataframe(df, use_container_width=True, hide_index=True)
        if rows:
            pick = st.selectbox("Open", [i["path"] for i in rows])
            show_preview(pick, "doc" + str(abs(hash(pick))))

with tabs[3]:
    from gumshoe.integrity import stat_times
    st.caption("Every file on the image, read-only. Open anything; viewing or downloading archives it and logs it.")
    if "browse_path" not in st.session_state:
        st.session_state.browse_path = "/"
    cur = st.text_input("Path", st.session_state.browse_path, key="browse_input")
    st.session_state.browse_path = cur if cur.startswith("/") else "/" + cur
    base = case.abs(st.session_state.browse_path)
    if not base.exists():
        st.error("no such path on the mount")
    elif base.is_file():
        show_preview(st.session_state.browse_path, "br" + str(abs(hash(st.session_state.browse_path))))
    else:
        entries = []
        for p in sorted(base.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))[:3000]:
            try:
                s = stat_times(p)
                entries.append({"name": p.name + ("/" if p.is_dir() else ""), "size": s["size"] if p.is_file() else "", "mtime": s["mtime"],
                                "ctime": s["ctime"], "mode": s["mode"]})
            except OSError:
                continue
        st.dataframe(pd.DataFrame(entries), use_container_width=True, hide_index=True, height=320)
        names = [e["name"] for e in entries]
        c1, c2 = st.columns([3, 1])
        pick = c1.selectbox("Open", [".."] + names, key="browse_pick")
        if c2.button("Go"):
            if pick == "..":
                st.session_state.browse_path = str(Path(st.session_state.browse_path).parent).replace("\\", "/") or "/"
            else:
                st.session_state.browse_path = (st.session_state.browse_path.rstrip("/") + "/" + pick.rstrip("/"))
            st.rerun()
        if st.button("Add this whole directory to export set"):
            st.session_state.export_set[st.session_state.browse_path] = "directory from browser"
            st.success(f"export set: {len(st.session_state.export_set)} entries (directories export every file under them)")

with tabs[4]:
    inv = case.read_json("inventory.json", {}) or {}
    aa = inv.get("aapanel") or {}
    if not aa.get("present"):
        st.info("No aaPanel inventory yet (run collect).")
    else:
        st.caption("What the panel would show, reconstructed read-only from /www/server/panel/data/default.db and the panel files. "
                   "Credential columns are never read.")
        s = aa.get("settings") or {}
        st.markdown(f"**Panel:** port `{s.get('port.pl')}` · entrance `{s.get('admin_path.pl')}` · SSL {'on' if 'ssl.pl' in s else 'off'} · "
                    f"IP limit `{s.get('limitip.conf') or 'none'}` · plugins: {', '.join(s.get('plugins', [])[:30])}")
        for title, key in (("Sites", "sites"), ("Domains", "domain"), ("Bindings", "binding"), ("FTP accounts", "ftps"),
                           ("Databases", "databases"), ("Firewall rules", "firewall"), ("Panel accounts", "users")):
            rows = aa.get(key) or []
            if rows:
                st.markdown(f"**{title}** ({len(rows)})")
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        crons = aa.get("panel_cron") or []
        if crons:
            st.markdown(f"**Scheduled tasks** ({len(crons)})")
            st.dataframe(pd.DataFrame([{k: v for k, v in c.items() if k != "sBody"} for c in crons]), use_container_width=True, hide_index=True)
            for c in crons:
                if c.get("sBody"):
                    with st.expander(f"script of '{c.get('name')}' (id {c.get('echo')})"):
                        st.code(c["sBody"])
                        logp = f"/{case.cfg['paths']['panel_cron'].strip('/')}/{c.get('echo')}.log"
                        if case.abs(logp).exists():
                            st.caption(f"last output ({logp})")
                            st.code((case.abs(logp).read_text("utf-8", errors="replace"))[-4000:])
        oplog = aa.get("operation_log") or {}
        if oplog.get("by_ip"):
            st.markdown(f"**Operation log** — {oplog.get('rows')} entries; by type {oplog.get('by_type')}")
            st.dataframe(pd.DataFrame([{"ip": ip, **{k: v for k, v in e.items() if k != 'types'}, "types": ", ".join(e.get("types", []))}
                                       for ip, e in oplog["by_ip"].items()]).sort_values("count", ascending=False), use_container_width=True, hide_index=True)
            sample = aa.get("operation_log_sample") or []
            if sample:
                q = st.text_input("filter operation log entries (type, text, IP)", "")
                rows = [r for r in sample if not q or q.lower() in json.dumps(r, ensure_ascii=False).lower()]
                st.dataframe(pd.DataFrame(rows[-500:]), use_container_width=True, hide_index=True)
        vh = aa.get("vhosts") or []
        if vh:
            st.markdown(f"**Web server vhost configs** ({len(vh)})")
            for v in vh:
                with st.expander(v["file"]):
                    st.dataframe(pd.DataFrame(v["directives"]), hide_index=True, use_container_width=True)
        webapps = (inv.get("webapps") or {}).get("sites") or []
        if webapps:
            st.markdown(f"**Web applications** ({len(webapps)})")
            for w in webapps:
                with st.expander(f"{w['site']} — {w['framework']} {w.get('version') or ''} · {w['php']['php_files']} PHP files"):
                    if w.get("configs"):
                        st.markdown("configuration (secrets masked)")
                        for c in w["configs"]:
                            st.json({c["file"]: c["facts"]})
                    if w.get("plugins"):
                        st.markdown("plugins"); st.dataframe(pd.DataFrame(w["plugins"]), hide_index=True, use_container_width=True)
                    if w.get("themes"):
                        st.markdown("themes"); st.dataframe(pd.DataFrame(w["themes"]), hide_index=True, use_container_width=True)
                    st.markdown("entry points: " + ", ".join(w["php"]["entry_points"][:40]))
                    if w["php"]["external_hosts"]:
                        st.markdown("external hosts referenced in code: " + ", ".join(f"{h} ({n})" for h, n in w["php"]["external_hosts"][:30]))
                    if w["php"]["special_files"]:
                        st.dataframe(pd.DataFrame(w["php"]["special_files"]), hide_index=True, use_container_width=True)
        ini = (inv.get("webapps") or {}).get("php_ini") or []
        if ini:
            st.markdown("**PHP configuration**")
            for i in ini:
                st.json({i["file"]: i["facts"]})

with tabs[5]:
    trends = case.read_json("trends.json", {}) or {}
    inv = case.read_json("inventory.json", {}) or {}
    for site, s in (trends.get("sites") or {}).items():
        st.subheader(f"Web: {site}")
        g = s.get("general", {})
        st.caption(f"{g.get('total_requests')} requests · {g.get('unique_visitors')} visitors · {g.get('start_date')} → {g.get('end_date')}")
        if s.get("per_day"):
            df = pd.DataFrame(s["per_day"]).set_index("date")
            st.line_chart(df[["hits", "visitors"]])
        c1, c2 = st.columns(2)
        if s.get("top_ips"):
            c1.markdown("**Top addresses**"); c1.dataframe(pd.DataFrame(s["top_ips"][:25]), hide_index=True)
        if s.get("top_paths"):
            c2.markdown("**Top paths**"); c2.dataframe(pd.DataFrame(s["top_paths"][:25]), hide_index=True)
        if s.get("status"):
            st.bar_chart(pd.DataFrame(s["status"]).set_index("status")["hits"])
    auth = inv.get("auth") or {}
    if auth.get("sources"):
        st.subheader("SSH authentication by source")
        rows = [{"ip": ip, "failed": v["failed"], "accepted": len(v["accepted"]), "first": (v.get("first") or {}).get("ts"),
                 "last": (v.get("last") or {}).get("ts")} for ip, v in auth["sources"].items()]
        df = pd.DataFrame(rows).sort_values("failed", ascending=False)
        st.dataframe(df.head(50), hide_index=True)
        st.bar_chart(df.head(20).set_index("ip")["failed"])
    if not trends and not auth:
        st.info("No trends yet: run `gumshoe collect` with GoAccess and the auth converter.")

with tabs[6]:
    import sqlite3
    tldb = case.collected / "timeline.db"
    bursts = case.read_json("bursts.json", []) or []
    if bursts:
        st.markdown("**Change bursts (ctime)**")
        st.dataframe(pd.DataFrame([{k: v for k, v in b.items() if k != "sample"} for b in bursts]), hide_index=True)
    if tldb.exists():
        con = sqlite3.connect(tldb)
        total = con.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        st.caption(f"{total:,} files in timeline.db (queried on demand; nothing is loaded whole)")
        c1, c2, c3 = st.columns(3)
        filt = c1.text_input("path contains", "")
        since = c2.text_input("ctime from (YYYY-MM-DD)", "")
        until = c3.text_input("ctime to (YYYY-MM-DD)", "")
        where, params = ["1=1"], []
        if filt:
            where.append("path LIKE ?"); params.append(f"%{filt}%")
        for col, val, op in (("ctime", since, ">="), ("ctime", until, "<")):
            if val:
                try:
                    from datetime import datetime, timezone
                    params.append(int(datetime.fromisoformat(val).replace(tzinfo=timezone.utc).timestamp()))
                    where.append(f"{col} {op} ?")
                except ValueError:
                    st.warning(f"bad date: {val}")
        n = st.slider("rows", 100, 50000, 2000, step=100)
        q = (f"SELECT datetime(ctime,'unixepoch') AS ctime, datetime(mtime,'unixepoch') AS mtime, datetime(crtime,'unixepoch') AS crtime, "
             f"size, mode, uid, gid, path FROM files WHERE {' AND '.join(where)} ORDER BY ctime DESC LIMIT ?")
        df = pd.read_sql_query(q, con, params=params + [n])
        st.dataframe(df, use_container_width=True, hide_index=True)
        days = pd.read_sql_query(f"SELECT date(ctime,'unixepoch') AS day, COUNT(*) AS files FROM files WHERE {' AND '.join(where)} "
                                 f"AND ctime IS NOT NULL GROUP BY day ORDER BY day", con, params=params)
        if not days.empty:
            st.bar_chart(days.set_index("day")["files"])
        con.close()
    else:
        st.info("No timeline yet (UAC bodyfile not normalized).")

with tabs[7]:
    kind = st.selectbox("Report", ["triage", "trends", "ioc"])
    use_llm = st.checkbox("Include AI narrative sections (labelled, cited, 7B model)", value=False)
    if st.button("Generate"):
        from gumshoe.report import build
        with st.spinner("building report..."):
            out = build(case, kind=kind, with_llm=use_llm)
        st.success(f"wrote {out.name}")
    for p in sorted(case.reports.glob("*.md"), reverse=True)[:10]:
        with st.expander(p.name):
            st.download_button("download markdown", p.read_bytes(), file_name=p.name, key="dl" + p.name)
            h = p.with_suffix(".html")
            if h.exists():
                st.download_button("download HTML", h.read_bytes(), file_name=h.name, key="dlh" + p.name)
            st.markdown(p.read_text("utf-8")[:20000])

with tabs[8]:
    mp = case.evidence / "manifest.json"
    if mp.exists():
        m = json.loads(mp.read_text("utf-8"))
        rows = [{"sha256": k[:16], **{kk: vv for kk, vv in v.items() if kk != "copies"}, "copies": len(v["copies"])} for k, v in m["items"].items()]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        if st.button("Verify archive hashes"):
            from gumshoe.archive import verify_archive
            st.json(verify_archive(case))
    else:
        st.info("Nothing archived yet. Cited sources and high/critical findings are archived automatically.")

with tabs[9]:
    es = st.session_state.export_set
    st.caption("Files added from findings, answers or the document viewer. Building copies the originals (tree preserved) with a "
               "hashed manifest and a zip, and logs it.")
    if es:
        st.dataframe(pd.DataFrame([{"path": p, "why": w} for p, w in es.items()]), hide_index=True, use_container_width=True)
        name = st.text_input("Export name", f"export-{len(es)}-files")
        c1, c2 = st.columns(2)
        if c1.button("Build export zip"):
            from gumshoe.export import assemble
            r = assemble(case, name, paths=list(es))
            st.success(f"{r.get('files')} file(s) → {r.get('zip')}  sha256 {r.get('zip_sha256', '')[:16]}")
            zp = Path(r["zip"]) if r.get("zip") else None
            if zp and zp.exists():
                st.download_button("Download zip", zp.read_bytes(), file_name=zp.name)
        if c2.button("Clear set"):
            st.session_state.export_set = {}
    else:
        st.info("Export set is empty.")
    prev = sorted((case.reports / "exports").glob("*.zip")) if (case.reports / "exports").exists() else []
    if prev:
        st.markdown("**Previous exports**")
        for zp in prev:
            st.download_button(zp.name, zp.read_bytes(), file_name=zp.name, key="pz" + zp.name)

with tabs[10]:
    st.markdown(("✅ " if ok_chain else "❌ ") + chain_msg)
    recs = case.custody.tail(200)
    st.dataframe(pd.DataFrame([{"seq": r.seq, "ts": r.ts, "action": r.action, "details": json.dumps(r.details, default=str)[:200]} for r in recs]),
                 use_container_width=True, hide_index=True)
