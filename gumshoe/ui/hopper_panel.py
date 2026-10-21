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

from gumshoe.intake import HOPPER, HOPPER_WIN, human, mounted_now, scan_hopper, sniff
from gumshoe.ui.run_panel import _alive, any_running, progress_of_text, to_wsl_path

JOBS_DIRNAME = ".hopper"
INTAKE_MILESTONES = [
    ("[intake] detect", 2, "looking at the item"), ("[intake] extracting", 4, "extracting the archive"), ("[intake] extracted", 18, "extracted"),
    ("[intake] joining", 6, "joining split segments"), ("[intake] converting", 6, "converting the virtual disk to raw"),
    ("[intake] unmounting", 19, "unmounting the previous evidence"), ("[intake] mounting", 20, "mounting read-only"), ("[intake] mounted", 22, "mounted"),
    ("[intake] volumes in", 23, "looking for other volumes"), ("[intake] assembled", 24, "second volume mounted"),
    ("[intake] probe", 25, "looking at the file system"), ("[intake] case", 27, "case created"),
    ("[intake] verify", 28, "read-only check"), ("[intake] hashing", 29, "hashing the image(s)"), ("[intake] hashed", 40, "hashed"),
    ("[intake] collect", 41, "starting the tools"), ("versions recorded", 42, "recording tool versions"),
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
    try:
        return examiner_file(cases_root).read_text("utf-8").strip()
    except OSError:
        return ""


def start_intake(root: Path, cases_root: Path, path: str, examiner: str, deep: bool, replace: bool, notes: str = "") -> dict:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(path).name)[:40] or "item"
    job = f"{slug}-{time.strftime('%Y%m%d-%H%M%S')}"
    log = jobs_dir(cases_root) / f"{job}.log"
    cmd = [sys.executable, str(root / "gumshoe.py"), "--cases-root", str(cases_root), "intake", path, "--examiner", examiner]
    if deep:
        cmd.append("--deep")
    if replace:
        cmd.append("--replace-mount")
    if notes:
        cmd += ["--notes", notes]
    wrapper = 'echo "[$(date -u +%FT%TZ)] start: $*"; "$@"; rc=$?; echo "[$(date -u +%FT%TZ)] finished with exit $rc"; exit $rc'
    with open(log, "ab") as lf:
        p = subprocess.Popen(["bash", "-c", wrapper, "gumshoe-ui"] + cmd, stdout=lf, stderr=subprocess.STDOUT, cwd=str(root), start_new_session=True)
    state = {"job": job, "pid": p.pid, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "path": path, "cmd": cmd}
    (jobs_dir(cases_root) / f"{job}.json").write_text(json.dumps(state, indent=2), "utf-8")
    try:
        examiner_file(cases_root).write_text(examiner, "utf-8")
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
    kind = {"disk": "disk image", "ewf": "E01 image", "vmdisk": "virtual disk", "archive": "archive", "split": "split image",
            "set": "folder of disk images", "tree": "folder of files", "unsupported": "cannot use", "unknown": "unknown", "missing": "missing"}.get(it["kind"], it["kind"])
    fmt = it.get("format", "")
    if it["kind"] == "archive":
        fmt = f"{fmt} of {'a disk image' if it.get('contains') == 'image' else 'files'}"
    return f"**{it['name']}** — {kind} ({fmt})" + (f", {human(it['size'])}" if it.get("size") else "")


def render_hopper(root: Path, cases_root: Path, cfg: dict, compact: bool = False):
    if not compact:
        st.subheader("1. Drop the evidence in the hopper")
        st.caption(f"Put anything into **{HOPPER_WIN}**: an E01, a raw/dd/img (any name), a VHDX/VMDK, a zip/7z/gz holding an image, "
                   "a folder that is an extracted file system, or the folder with all the disks of one server (drive-scsi0, drive-scsi1 ...). "
                   "Gumshoe works out what it is, mounts it read-only (second volumes included), creates the case, hashes the image(s) "
                   "and runs Collect. Nothing in the hopper is modified.")
    ex = st.text_input("Examiner (goes on the case and every custody record)", value=remembered_examiner(cases_root), key="hopper_examiner")
    c1, c2 = st.columns(2)
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

    items = scan_hopper(HOPPER)
    if not HOPPER.is_dir():
        try:
            HOPPER.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    if not items:
        st.info(f"The hopper is empty. Copy the evidence into {HOPPER_WIN} (Explorer) and press Refresh, or paste a path below.")
    for i, it in enumerate(items):
        cc1, cc2 = st.columns([5, 1])
        cc1.markdown(_item_row(it))
        for n in it.get("notes", []):
            cc1.caption(n)
        usable = it["kind"] in ("disk", "ewf", "vmdisk", "archive", "split", "set", "tree")
        needs_mount = not (it["kind"] == "tree" or (it["kind"] == "archive" and it.get("contains") == "tree"))
        blocked = running or not ex.strip() or (needs_mount and bool(busy) and bool(mounted))
        if usable and cc2.button("Intake", key=f"intake_{i}", type="primary", disabled=blocked):
            start_intake(root, cases_root, it["path"], ex.strip(), deep, replace)
            st.rerun()
    if not ex.strip():
        st.caption("Enter the examiner name to enable the Intake buttons.")
    if running:
        st.caption("An intake is running; the next one can start when it is finished.")
    if st.button("Refresh the hopper"):
        st.rerun()

    with st.expander("Or paste a path (Windows, \\\\server\\share, or /mnt/...)"):
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
                if it["kind"] in ("disk", "ewf", "vmdisk", "archive", "split", "set", "tree") and \
                        st.button("Intake this path", key="intake_path", type="primary", disabled=running or not ex.strip()):
                    start_intake(root, cases_root, wp, ex.strip(), deep, replace)
                    st.rerun()
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
