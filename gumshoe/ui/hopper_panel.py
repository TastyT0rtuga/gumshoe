"""The hopper, in the browser: what is lying in C:\\DFIR\\hopper, what each item is, one button per item.

An intake runs `gumshoe intake <item>` in the background (it survives a browser reload), its progress is
read from the log, and when it finishes the new case is one click away. The manual route (mount an image
yourself, create a case by hand) stays available under "Manual".
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import streamlit as st

from gumshoe import settings as cfgstore
from gumshoe.intake import human, mounted_now, scan_hopper, sniff
from gumshoe.ui.run_panel import _alive, any_running, progress_of_text, to_wsl_path
from gumshoe.winpath import windows_username

JOBS_DIRNAME = ".hopper"
INTAKE_MILESTONES = [
    ("[intake] detect", 2, "looking at the item"), ("[intake] extracting", 4, "extracting the archive"), ("[intake] extracted", 18, "extracted"),
    ("[intake] joining", 6, "joining split segments"), ("[intake] converting", 6, "converting the virtual disk to raw"),
    ("[intake] unmounting", 19, "unmounting the previous evidence"), ("[intake] mounting", 20, "mounting read-only"), ("[intake] mounted", 22, "mounted"),
    ("[intake] volumes in", 23, "looking for other volumes"), ("[intake] assembled", 24, "second volume mounted"),
    ("[intake] probe", 25, "looking at the file system"), ("[intake] case", 27, "case created"),
    ("[intake] verify", 28, "read-only check"), ("[intake] hashing", 29, "hashing the image(s)"), ("[intake] hashed", 40, "hashed"),
    ("[intake] databases", 41, "databases: scanning"), ("[db] extracting", 42, "databases: extracting"), ("[db] private server up", 44, "databases: private server up"),
    ("[db] worker", 46, "databases: parsing a dump"), ("rows so far", 48, "databases: streaming tables"), ("[db] done", 50, "databases: done"),
    ("[intake] collect", 51, "starting the tools"), ("[intake] fingerprint", 93, "what it is built on"), ("[intake] players", 95, "building the players graph"), ("versions recorded", 42, "recording tool versions"),
    ("running uac", 43, "UAC collecting artifacts"), ("uac done", 52, "UAC done"), ("running loki", 53, "Loki scanning for IOCs (the long step)"),
    ("loki done", 74, "Loki done"), ("running goaccess", 75, "GoAccess web statistics"), ("goaccess done", 77, "GoAccess done"),
    ("converting web and auth logs", 78, "Chainsaw + Sigma over the logs"), ("chainsaw done", 82, "Chainsaw done"),
    ("[dbreview] copying", 83, "MariaDB review: copying the datadir"), ("[dbreview]", 86, "MariaDB review"),
    ("[normalize] uac", 89, "normalizing"), ("[normalize] aapanel", 92, "normalizing (panel)"), ("[normalize] documents", 94, "normalizing (documents)"),
    ("correlating", 96, "correlating"), ("[intake] deep", 97, "deep run"), ("[intake] done", 99, "finishing"), ("finished with exit", 100, "done"),
]


def jobs_dir(cases_root: Path) -> Path:
    d = cases_root / JOBS_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def examiner_file(cases_root: Path) -> Path:
    return cases_root / ".examiner"


def remembered_examiner(cases_root: Path) -> str:
    """The examiner name: settings, then the last intake, then the newest case, then the Windows account."""
    try:
        v = cfgstore.load(cases_root).get("examiner", "").strip()
        if v:
            return v
        v = examiner_file(cases_root).read_text("utf-8").strip()
        if v:
            return v
    except OSError:
        pass
    try:
        cases = sorted((d for d in cases_root.iterdir() if (d / "case.json").exists()), key=lambda d: d.stat().st_mtime, reverse=True)
        for d in cases:
            v = (json.loads((d / "case.json").read_text("utf-8")).get("examiner") or "").strip()
            if v:
                return v
    except OSError:
        pass
    return windows_username() or ""


def start_intake(root: Path, cases_root: Path, path: str, examiner: str, deep: bool, replace: bool, notes: str = "",
                 databases: bool = True, db_only: bool = False) -> dict:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(path).name)[:40] or "item"
    job = f"{slug}-{time.strftime('%Y%m%d-%H%M%S')}"
    log = jobs_dir(cases_root) / f"{job}.log"
    cmd = [sys.executable, str(root / "gumshoe.py"), "--cases-root", str(cases_root), "intake", path, "--examiner", examiner]
    if deep:
        cmd.append("--deep")
    if replace:
        cmd.append("--replace-mount")
    if not databases:
        cmd.append("--no-db")
    if db_only:
        cmd.append("--db-only")
    if notes:
        cmd += ["--notes", notes]
    wrapper = 'echo "[$(date -u +%FT%TZ)] start: $*"; "$@"; rc=$?; echo "[$(date -u +%FT%TZ)] finished with exit $rc"; exit $rc'
    with open(log, "ab") as lf:
        p = subprocess.Popen(["bash", "-c", wrapper, "gumshoe-ui"] + cmd, stdout=lf, stderr=subprocess.STDOUT, cwd=str(root), start_new_session=True)
    state = {"job": job, "pid": p.pid, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "path": path, "cmd": cmd}
    (jobs_dir(cases_root) / f"{job}.json").write_text(json.dumps(state, indent=2), "utf-8")
    try:
        examiner_file(cases_root).write_text(examiner, "utf-8")
        cfgstore.save(cases_root, {"examiner": examiner})
    except OSError:
        pass
    return state


def list_jobs(cases_root: Path) -> list[dict]:
    out = []
    for f in sorted(jobs_dir(cases_root).glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            s = json.loads(f.read_text("utf-8"))
        except Exception:  # noqa: BLE001
            continue
        log = f.with_suffix(".log")
        text = log.read_text("utf-8", errors="replace") if log.exists() else ""
        s["log"] = text
        if _alive(int(s.get("pid", -1))):
            s["status"] = "running"
        else:
            m = re.findall(r"finished with exit (\d+)", text[-400:])
            s["status"] = "done" if (m and m[-1] == "0") else "failed"
        m = re.search(r"\[intake\] case (\S+) created", text)
        s["case_id"] = m.group(1) if m else None
        m = re.search(r"\[intake\] done: (.*)", text)
        s["outcome"] = m.group(1) if m else ""
        s["pct"], s["label"] = progress_of_text(text, INTAKE_MILESTONES)
        out.append(s)
    return out


def any_job_running(cases_root: Path) -> bool:
    return any(j["status"] == "running" for j in list_jobs(cases_root))


def _item_row(it: dict) -> str:
    kind = {"disk": "disk image", "ewf": "E01 image", "vmdisk": "virtual disk", "archive": "archive", "split": "split image", "database": "database",
            "set": "folder of disk images", "tree": "folder of files", "unsupported": "cannot use", "unknown": "unknown", "missing": "missing"}.get(it["kind"], it["kind"])
    fmt = it.get("format", "")
    if it["kind"] == "archive":
        fmt = f"{fmt} of {'a disk image' if it.get('contains') == 'image' else 'files'}"
    return f"**{it['name']}** — {kind} ({fmt})" + (f", {human(it['size'])}" if it.get("size") else "")


def render_folders(cases_root: Path):
    """Where things live: the hopper, the work folder for extracted images, the exports folder - each with free space.
    Any drive letter or \\\\server\\share works; empty work folder = inside the distro's own disk."""
    cur = cfgstore.load(cases_root)
    with st.expander("Folders (hopper, extracted images, exports) - move them to a drive with room", expanded=False):
        c1, c2, c3 = st.columns(3)
        hop = c1.text_input("Hopper (drop evidence here)", value=cur["hopper"], key="set_hopper")
        work = c2.text_input("Work folder for extracted images/trees (empty = inside the distro, on C:)", value=cur["work"], key="set_work",
                             placeholder=r"D:\DFIR\work")
        exp = c3.text_input("Exports go to", value=cur["exports"], key="set_exports")
        for label, val in (("hopper", hop), ("work folder", work or "(the distro's disk, /opt/dfir)"), ("exports", exp)):
            w = to_wsl_path(val) if val and not val.startswith("(") else "/opt/dfir"
            free, total = cfgstore.free_space(Path(w))
            st.caption(f"{label}: `{val}` - {free:.0f} GB free of {total:.0f} GB" if total else f"{label}: `{val}` - drive not reachable yet")
        if st.button("Save folders", key="set_save"):
            cfgstore.save(cases_root, {"hopper": hop, "work": work, "exports": exp})
            for val in (hop, work):
                if val:
                    try:
                        Path(to_wsl_path(val)).mkdir(parents=True, exist_ok=True)
                    except OSError as e:
                        st.warning(f"could not create {val}: {e}")
            st.success("saved; the hopper list below uses the new folder")
            st.rerun(scope="app")
        st.caption("The distro's own disk (cases, tools, the extraction work folder when left empty) lives on C:. "
                   "If C: is full, move the whole distro to another drive once: close Gumshoe, then run  Gumshoe-MoveToDrive.bat  from the bundle "
                   "(it runs `wsl --manage DFIR --move D:\\DFIR\\wsl` and moves the Ollama models too).")


def render_hopper(root: Path, cases_root: Path, cfg: dict, compact: bool = False):
    hopper, hop_note = cfgstore.hopper_dir(cases_root)
    hopper_win = cfgstore.load(cases_root)["hopper"]
    if not compact:
        st.subheader("1. Drop the evidence in the hopper")
        st.caption(f"Put anything into **{hopper_win}**: an E01, a raw/dd/img (any name), a VHDX/VMDK, a zip/7z/gz holding an image, "
                   "a folder that is an extracted file system, or the folder with all the disks of one server (drive-scsi0, drive-scsi1 ...). "
                   "Gumshoe works out what it is, mounts it read-only (second volumes included), creates the case, hashes the image(s) "
                   "and runs Collect. Nothing in the hopper is modified.")
    render_folders(cases_root)
    ex = st.text_input("Examiner (goes on the case and every custody record)", value=remembered_examiner(cases_root), key="hopper_examiner")
    ex = ex.strip() or "examiner"
    c1, c2 = st.columns(2)
    dbs = c1.checkbox("databases to CSV (every data directory, dump and sqlite file found; the data comes out first)", value=True, key="hopper_db")
    db_only = c1.checkbox("only the databases - skip the triage tools (UAC, Loki, Chainsaw ...)", value=False, key="hopper_dbonly")
    deep = c1.checkbox("also run Deep afterwards (walk-away: documents, vectors, translations, report)", key="hopper_deep")
    mounted = mounted_now()
    replace = True
    if mounted:
        replace = c2.checkbox(f"replace what is mounted now ({Path(mounted.get('IMAGE', mounted.get('TARGET', '?'))).name}); its case keeps its results",
                              value=True, key="hopper_replace")
    running = any_job_running(cases_root)
    busy = [d.name for d in cases_root.iterdir() if (d / "case.json").exists() and any_running(d)] if cases_root.exists() else []
    if busy and mounted:
        st.warning(f"A run is in progress on case {', '.join(busy)}; its evidence must stay mounted. Intake of disk images waits until it finishes "
                   "(folders of files can go ahead).")

    def intake_button(it: dict, key: str, label: str = "Intake") -> bool:
        usable = it["kind"] in ("disk", "ewf", "vmdisk", "archive", "split", "set", "tree", "database")
        if not usable:
            return False
        needs_mount = not (it["kind"] in ("tree", "database") or (it["kind"] == "archive" and it.get("contains") == "tree"))
        why = ""
        if running:
            why = "an intake is already running"
        elif needs_mount and busy and mounted:
            why = f"a run on case {busy[0]} still needs the current mount"
        clicked = st.button(label, key=key, type="primary", disabled=bool(why), help=why or None)
        if why:
            st.caption(f"waiting: {why}")
        return clicked

    if hop_note:
        st.warning(hop_note + " - set another hopper folder under Folders, or paste a path below.")
    if not hopper.is_dir():
        try:
            hopper.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    items = scan_hopper(hopper) if hopper.is_dir() else []
    if not items:
        st.info(f"The hopper ({hopper_win}) is empty. Copy the evidence there (Explorer) and press Refresh, or paste a path below.")
    for i, it in enumerate(items):
        cc1, cc2 = st.columns([5, 1])
        cc1.markdown(_item_row(it))
        for n in it.get("notes", []):
            cc1.caption(n)
        with cc2:
            if intake_button(it, f"intake_{i}"):
                start_intake(root, cases_root, it["path"], ex, deep, replace, databases=dbs, db_only=db_only)
                st.rerun(scope="app")
    if st.button("Refresh the hopper"):
        st.rerun(scope="app")

    st.markdown("**Or paste a path** (Windows `C:\\...`, a mapped drive `Z:\\...`, a share `\\\\server\\share\\...`, or `/mnt/...`) "
                "- then press Enter; the item is identified and an Intake button appears.")
    raw = st.text_input("Path to an image, archive or folder", key="hopper_path", placeholder=r"\\server\cases\case1\Work\drive-scsi0.raw")
    if raw.strip():
        st.session_state.pop("path_note", None)
        wp = to_wsl_path(raw)
        note = st.session_state.get("path_note")
        if note:
            st.warning(note)
        if Path(wp).exists():
            it = sniff(Path(wp))
            st.markdown(_item_row(it))
            for n in it.get("notes", []):
                st.caption(n)
            if it["kind"] not in ("disk", "ewf", "vmdisk", "archive", "split", "set", "tree", "database"):
                st.error("this item cannot be taken in: " + (it.get("format") or it["kind"]))
            elif intake_button(it, "intake_path", "Intake this path"):
                start_intake(root, cases_root, wp, ex, deep, replace, databases=dbs, db_only=db_only)
                st.rerun(scope="app")
        else:
            st.error(f"not found inside the distro: `{wp}`")

    # the intake list refreshes itself while one is running (a fragment: the rest of the page is left alone)
    st.fragment(lambda: render_jobs(cases_root), run_every="4s" if running else None)()


def render_jobs(cases_root: Path, limit: int = 6):
    jobs = list_jobs(cases_root)
    if not jobs:
        return
    st.markdown("**Intakes**")
    for j in jobs[:limit]:
        icon = {"running": "🟡", "done": "🟢", "failed": "🔴"}[j["status"]]
        head = f"{icon} {Path(j['path']).name} — {j['status']}" + (f" → case **{j['case_id']}**" if j.get("case_id") else "") + f"  (started {j['started']})"
        st.markdown(head)
        if j["status"] == "running":
            st.progress(min(max(j["pct"], 1), 99) / 100, text=f"{j['label'] or 'running'} ({j['pct']}%)")
        elif j["status"] == "done" and j.get("outcome"):
            st.success(j["outcome"])
        elif j["status"] == "failed":
            tail = [l for l in j["log"].splitlines() if l.strip()][-3:]
            st.error("stopped: " + (tail[-2] if len(tail) > 1 else (tail[-1] if tail else "see the log")))
        b1, b2, _ = st.columns([1, 1, 4])
        if j.get("case_id") and j["status"] != "running" and b1.button(f"Open case {j['case_id']}", key=f"open_{j['job']}"):
            st.session_state["case_select"] = j["case_id"]
            st.rerun(scope="app")
        if j["status"] == "running" and b2.button("Stop", key=f"stop_{j['job']}"):
            try:
                os.killpg(int(j["pid"]), 15)
            except Exception as e:  # noqa: BLE001
                st.warning(str(e))
            st.rerun(scope="app")
        with st.expander("log", expanded=(j["status"] == "failed")):
            st.code("\n".join(j["log"].splitlines()[-40:]) or "(empty)")


def render_remount(case, root: Path):
    """For a mounted-mode case whose evidence is no longer mounted (reboot): put it back with one click."""
    if case.mode != "mount" or os.path.ismount(case.mount_root):
        return
    st.warning(f"The evidence of this case is not mounted right now (`{case.mount_root}` is empty): after a reboot the mount is gone. "
               "Findings and reports are still here; Browse, Ask (file preview) and new runs need the mount.")
    mounted = mounted_now()
    replace = st.checkbox("unmount what is mounted now first", value=True, key="remount_replace") if mounted else True
    if st.button("Remount this case's evidence", type="primary", key="remount_btn"):
        cmd = [sys.executable, str(root / "gumshoe.py"), "--cases-root", str(case.dir.parent), "--case", case.dir.name, "remount"]
        if replace:
            cmd.append("--replace-mount")
        with st.spinner("mounting..."):
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", cwd=str(root))
        (st.success if r.returncode == 0 else st.error)(("mounted" if r.returncode == 0 else "remount failed") + f" (exit {r.returncode})")
        st.code((r.stdout + r.stderr)[-3000:] or "(no output)")
        if r.returncode == 0:
            st.rerun()
