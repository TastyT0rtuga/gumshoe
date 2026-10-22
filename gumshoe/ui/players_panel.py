"""The Players tab: who is in the evidence, how they connect, when they were active, where the money went.

Everything here is a query over players.db (deterministic, every fact carries its row/line locator). The build runs in the
background (`gumshoe players build`) after Collect / an intake; Rebuild redoes it when more databases were extracted.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

import pandas as pd
import streamlit as st

from gumshoe import players
from gumshoe.ui.db_panel import _start, _status
from gumshoe.ui.run_panel import _logs, tail_log
from gumshoe.winpath import to_windows

PL_MILESTONES = [("start:", 2, "starting"), ("[players] start", 4, "reading the database exports"), ("join table", 8, "join tables"),
                 ("[players] [", 20, "scanning tables"), ("auth log", 70, "logs"), ("documents scanned", 80, "documents"),
                 ("players from", 90, "deriving players"), ("CSV folders", 96, "writing CSV folders"), ("finished with exit", 100, "done")]


def _money_str(m: dict) -> str:
    return "; ".join(f"{c}: {v['sum']:,.2f} ({v['n']})" for c, v in m.items()) if m else ""


def render_players_tab(case, root: Path, cases_root: Path):
    status, state = _status(case.dir, "players")
    con = players.open_db(case)
    c1, c2, c3 = st.columns([1.3, 1.3, 4])
    if c1.button("Build players" if con is None else "Rebuild", key="pl_build", type="primary" if con is None else "secondary", disabled=(status == "running")):
        _start(root, cases_root, case.dir, "players", ["players", "build"])
        st.rerun(scope="app")
    if status == "running":
        from gumshoe.ui.run_panel import progress_of_text
        text = (_logs(case.dir) / "players.log").read_text("utf-8", errors="replace") if (_logs(case.dir) / "players.log").exists() else ""
        pct, label = progress_of_text(text, PL_MILESTONES)
        st.progress(min(max(pct, 1), 99) / 100, text=f"{label} ({pct}%)")
        with st.expander("log", expanded=True):
            st.code("\n".join(text.splitlines()[-20:]) or "(empty)")
        st.fragment(lambda: None, run_every="5s")()
        if con is None:
            return
    elif status == "failed":
        st.error("the last build stopped with an error; see the log")
        with st.expander("log"):
            st.code(tail_log(case.dir, "players") or "(empty)")
    if con is None:
        st.info("Not built yet. Players are derived from the extracted databases (Databases tab), the logs, the panel inventory and the documents: "
                "press Build players after the databases are extracted (an intake does this by itself).")
        return
    meta = {k: v for k, v in con.execute("SELECT key, value FROM meta")}
    exp = players.exports_dir(case)
    c3.caption(f"{meta.get('players', '?')} players · {meta.get('entities', '?')} identifiers · {meta.get('links', '?')} links · {meta.get('money_rows', '?')} money rows · "
               f"built {str(meta.get('built', ''))[:19]}" + (f" · CSVs in `{to_windows(exp)}`" if exp else ""))
    sub = st.tabs(["Players", "Look up an identifier", "Trends and money"])
    with sub[0]:
        _players_list(case, con)
    with sub[1]:
        _lookup(case, con)
    with sub[2]:
        _trends(con)
    con.close()


def _players_list(case, con):
    q = st.text_input("Filter players (any identifier, name, wallet, IP ...)", key="pl_q")
    rows = players.list_players(con, limit=500, q=q.strip())
    if not rows:
        st.info("no players match")
        return
    df = pd.DataFrame([{"#": p["id"], "player": p["label"], "e-mails": "; ".join(p["emails"][:3]), "phones": "; ".join(p["phones"][:2]),
                        "usernames": "; ".join(p["usernames"][:3]), "wallets": len(p["wallets"]), "IPs": len(p["ips"]), "shared IPs": len(p["shared_ips"]),
                        "money": _money_str(p["money"]), "first": str(p["first_seen"] or "")[:10], "last": str(p["last_seen"] or "")[:10], "score": round(p["score"])} for p in rows])
    ev = st.dataframe(df, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row", key="pl_table")
    sel = ev.selection.rows if ev and ev.selection else []
    if not sel:
        st.caption("Tick a row for the full dossier: every identifier with where it was seen, linked IPs/wallets, the activity timeline, money, source rows.")
        return
    _dossier(case, con, rows[sel[0]]["id"])


def _dossier(case, con, pid: int):
    d = players.player_detail(con, pid)
    if not d:
        return
    p = d["player"]
    st.markdown(f"### Player {pid}: {p['label']}")
    st.caption(f"{p['kind']} · active {p['first_seen'] or '?'} → {p['last_seen'] or '?'} · {p['n_entities']} identifiers · rows from {json.loads(p['sources'] or '{}')}")
    by = defaultdict(list)
    for e in d["entities"]:
        by[e["role"]].append(e)
    cols = st.columns(2)
    with cols[0]:
        st.markdown("**Identifiers (the merge keys)**")
        for e in by.get("strong", []):
            st.markdown(f"- `{e['type']}` **{e['value']}** ×{e['count']} · {str(e['first_seen'] or '?')[:16]} → {str(e['last_seen'] or '?')[:16]}")
        if by.get("attribute"):
            st.markdown("**Names, usernames, handles, domains**")
            for e in by["attribute"][:40]:
                st.markdown(f"- `{e['type']}` {e['value']} ×{e['count']}")
    with cols[1]:
        if by.get("linked"):
            st.markdown("**Linked through rows and log lines**")
            for e in by["linked"][:60]:
                st.markdown(f"- `{e['type']}` {e['value']} ×{e['count']} · {str(e['first_seen'] or '?')[:10]} → {str(e['last_seen'] or '?')[:10]}" +
                            (f" · also with {e['shared_with']} other player(s)" if e["shared_with"] else ""))
        if by.get("shared"):
            st.markdown("**Shared infrastructure** (IPs used by many players - proxies, NAT, the office)")
            for e in by["shared"][:30]:
                st.markdown(f"- `{e['type']}` {e['value']} ×{e['count']} · shared with {e['shared_with']} players")
    if d.get("glue"):
        st.markdown("**Merged over** (the identifier that joins these account rows - check it before relying on the merge)")
        for g in d["glue"]:
            st.markdown(f"- `{g['type']}` {g['norm']} → rows " + ", ".join(json.loads(g["rows"] or "[]")[:8]))
    if d["activity"]:
        st.markdown("**Activity by day** (rows and log lines carrying this player's identifiers)")
        adf = pd.DataFrame(d["activity"]).set_index("day")
        st.bar_chart(adf["n"], height=180)
    if d["money_summary"]:
        st.markdown("**Money**")
        st.dataframe(pd.DataFrame(d["money_summary"]), hide_index=True, width="stretch")
        with st.expander(f"transactions ({len(d['money'])})"):
            st.dataframe(pd.DataFrame([{"ts": m["ts"], "amount": m["amount"], "currency": m["currency"], "table": f"{m['db']}.{m['table_']}", "row": m["row"],
                                        "identifiers": "; ".join(f"{t}={v}" for t, v in json.loads(m["idents"] or "[]"))} for m in d["money"][:2000]]),
                         hide_index=True, width="stretch")
    with st.expander(f"where each identifier was seen ({len(d['entities'])})"):
        for e in d["entities"][:120]:
            for m in e["mentions"][:4]:
                locs = json.loads(m["locators"] or "[]")
                st.markdown(f"- `{e['type']}` {e['value']} — {m['source']} ×{m['count']} ({json.loads(m['roles'] or '{}')}) e.g. {', '.join(locs[:4])}")
    if d["account_rows"]:
        with st.expander(f"account rows ({len(d['account_rows'])})"):
            st.dataframe(pd.DataFrame(d["account_rows"]), hide_index=True, width="stretch")
    st.download_button("Download dossier (Markdown)", players.dossier_text(con, pid).encode("utf-8"), file_name=f"player-{pid}.md", key=f"pl_dl_{pid}")


def _lookup(case, con):
    t = st.text_input("Identifier (e-mail, phone, IP, wallet, name, username, IBAN, card, hash ...)", key="pl_lookup")
    if not t.strip():
        st.caption("Pivot on anything: where it appears (table/row, log line, document), what it co-occurs with, which players hold it.")
        return
    hits = players.entity_lookup(con, t.strip())
    if not hits:
        st.info("not found among the extracted identifiers")
        return
    for e in hits[:20]:
        with st.expander(f"{e['type']}: {e['value']}  ×{e['count']} · {str(e['first_seen'] or '?')[:16]} → {str(e['last_seen'] or '?')[:16]} · players {[(x['id'], x['label']) for x in e['players']]}", expanded=(len(hits) == 1)):
            if e["mentions"]:
                st.markdown("**Seen in**")
                st.dataframe(pd.DataFrame([{"source": m["source"], "count": m["count"], "first": m["first_seen"], "last": m["last_seen"],
                                            "roles": json.dumps(json.loads(m["roles"] or "{}"), ensure_ascii=False), "e.g.": ", ".join(json.loads(m["locators"] or "[]")[:5])} for m in e["mentions"]]),
                             hide_index=True, width="stretch")
            if e["linked"]:
                st.markdown("**Co-occurs with**")
                st.dataframe(pd.DataFrame([{"type": l["type"], "value": l["value"], "times": l["n"], "first": l["first"], "last": l["last"], "where": l["where_"]} for l in e["linked"]]),
                             hide_index=True, width="stretch")


def _trends(con):
    tr = players.trends(con)
    c1, c2 = st.columns([2, 1])
    with c1:
        if tr["days"]:
            st.markdown("**Activity by day, all sources** (dated rows and log lines carrying any identifier)")
            st.bar_chart(pd.DataFrame(tr["days"]).set_index("day")["n"], height=200)
            if tr["bursts"]:
                st.caption("bursts (more than 4× the median day): " + ", ".join(f"{b['day']} ({b['n']})" for b in tr["bursts"][:12]))
        if tr["new_accounts"]:
            st.markdown("**New account rows per month**")
            st.bar_chart(pd.DataFrame(tr["new_accounts"]).set_index("month")["n"], height=150)
    with c2:
        st.markdown("**Identifiers by type**")
        st.dataframe(pd.DataFrame([{"type": k, "count": v} for k, v in sorted(tr["by_type"].items(), key=lambda x: -x[1])]), hide_index=True, width="stretch")
    if tr["money"]:
        st.markdown("**Money by currency** (transaction-like tables)")
        st.dataframe(pd.DataFrame(tr["money"]), hide_index=True, width="stretch")
    if tr["wallets"]:
        st.markdown(f"**Wallets** ({len(tr['wallets'])} shown)")
        st.dataframe(pd.DataFrame([{"address": w["value"], "network": "", "mentions": w["count"], "players": w["players"], "first": w["first_seen"], "last": w["last_seen"]} for w in tr["wallets"]]),
                     hide_index=True, width="stretch")
    if tr["top_ips"]:
        st.markdown("**IPs by how many players used them** (high = shared infrastructure or one operator behind many accounts)")
        st.dataframe(pd.DataFrame(tr["top_ips"]), hide_index=True, width="stretch")
    if tr["recent"]:
        st.markdown(f"**Most active identifiers in the last 7 days before {tr['last_day']}**")
        st.dataframe(pd.DataFrame(tr["recent"]), hide_index=True, width="stretch")
