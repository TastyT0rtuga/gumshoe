"""The UI's "Run" side: mount an image, create a case, and launch verify / collect / deep as background
jobs with their logs on screen. Everything here shells out to the same `gumshoe` CLI and `mount_image`
script the runbook describes, so the custody log records exactly the same actions."""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import streamlit as st

STEPS = {
    "verify":  ("Verify", "check the mount is read-only and hash the image (minutes)",
                lambda c: ["verify", "--hash-image"]),
    "collect": ("Collect", "run every enabled tool and normalize (hours on a large image; safe to leave)",
                lambda c: ["collect", "--db"]),
    "deep":    ("Deep (walk-away)", "every tool, every document, vectors, translations, 7B report (overnight)",
                lambda c: ["deep"]),
    "reanalyze": ("Re-analyze", "redo the database review and the analysis of what Collect already gathered, without re-running the tools (minutes)",
                lambda c: ["collect", "--normalize-only", "--db"]),
}


def to_wsl_path(p: str) -> str:
    """C:\\x\\y -> /mnt/c/x/y (the UI runs inside WSL); Linux paths pass through."""
    p = (p or "").strip().strip('"').strip("'")
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", p)
    if m:
        return f"/mnt/{m.group(1).lower()}/" + m.group(2).replace("\\", "/")
    return p


def _logs(case_dir: Path) -> Path:
    d = case_dir / "logs"
    d.mkdir(exist_ok=True)
    return d


def _state(case_dir: Path, step: str) -> dict:
    f = _logs(case_dir) / f"{step}.json"
    try:
        return json.loads(f.read_text("utf-8"))
    except Exception:
        return {}


_PROCS: dict[int, subprocess.Popen] = {}   # children started by this UI process, so they get reaped


def _alive(pid: int) -> bool:
    p = _PROCS.get(pid)
    if p is not None:
        return p.poll() is None          # poll() reaps a finished child; None means still running
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:                                  # started by an earlier UI process: a zombie counts as finished
        return "Z" not in Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0]
    except Exception:  # noqa: BLE001
        return True


def start_step(root: Path, cases_root: Path, case_dir: Path, step: str) -> dict:
    """Launch `gumshoe <step> ...` detached from the UI so it survives a browser or UI restart."""
    name, _, argv = STEPS[step]
    log = _logs(case_dir) / f"{step}.log"
    cmd = [sys.executable, str(root / "gumshoe.py"), "--cases-root", str(cases_root), "--case", case_dir.name] + argv(case_dir)
    # a shell wrapper appends the exit status so the UI can tell "finished" from "running"
    wrapper = 'echo "[$(date -u +%FT%TZ)] start: $*"; "$@"; rc=$?; echo "[$(date -u +%FT%TZ)] finished with exit $rc"; exit $rc'
    with open(log, "ab") as lf:
        p = subprocess.Popen(["bash", "-c", wrapper, "gumshoe-ui"] + cmd, stdout=lf, stderr=subprocess.STDOUT,
                             cwd=str(root), start_new_session=True)
    _PROCS[p.pid] = p
    state = {"pid": p.pid, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "cmd": cmd}
    (_logs(case_dir) / f"{step}.json").write_text(json.dumps(state, indent=2), "utf-8")
    return state


def step_status(case_dir: Path, step: str) -> tuple[str, dict]:
    """'idle' | 'running' | 'done' | 'failed', plus the recorded state."""
    s = _state(case_dir, step)
    if not s:
        return "idle", s
    if _alive(int(s.get("pid", -1))):
        return "running", s
    log = _logs(case_dir) / f"{step}.log"
    tail = log.read_text("utf-8", errors="replace")[-400:] if log.exists() else ""
    m = re.findall(r"finished with exit (\d+)", tail)
    if m and m[-1] == "0":
        return "done", s
    return "failed", s


# progress milestones: (substring in the log, percent, what is happening). The last one found wins.
MILESTONES = {
    "verify":  [("start:", 5, "starting"), ("hashing", 20, "hashing the image"), ("readonly", 60, "read-only check"),
                ("finished with exit", 100, "done")],
    "collect": [("start:", 2, "starting"), ("versions recorded", 4, "recording tool versions"),
                ("running uac", 6, "UAC collecting artifacts"), ("uac done", 20, "UAC done"),
                ("running loki", 22, "Loki scanning for IOCs (the long step)"), ("loki done", 56, "Loki done"),
                ("running goaccess", 58, "GoAccess web statistics"), ("goaccess done", 63, "GoAccess done"),
                ("converting web and auth logs", 64, "Chainsaw + Sigma over the logs"), ("chainsaw done", 72, "Chainsaw done"),
                ("[dbreview] copying", 74, "MariaDB review: copying the datadir"), ("[dbreview]", 80, "MariaDB review"),
                ("[normalize] uac", 86, "normalizing"), ("[normalize] aapanel", 90, "normalizing (panel)"),
                ("[normalize] documents", 93, "normalizing (documents)"), ("correlating", 97, "correlating"),
                ("finished with exit", 100, "done")],
    "reanalyze": [("start:", 5, "starting"), ("[dbreview] copying", 10, "MariaDB review: copying the datadir"),
                  ("[dbreview]", 30, "MariaDB review"), ("[normalize]", 60, "normalizing"), ("correlating", 90, "correlating"),
                  ("finished with exit", 100, "done")],
    "deep":    [("start:", 2, "starting"), ("running uac", 4, "UAC"), ("running loki", 8, "Loki (intense)"), ("loki done", 40, "Loki done"),
                ("chainsaw done", 48, "Chainsaw done"), ("[dbreview]", 50, "MariaDB review"), ("[normalize]", 58, "normalizing"),
                ("[documents]", 64, "documents"), ("[index]", 72, "indexing"), ("[vectors]", 80, "vectors"),
                ("[translate]", 86, "translating"), ("[report]", 94, "report"), ("finished with exit", 100, "done")],
}


def progress_of(case_dir: Path, step: str) -> tuple[int, str]:
    """(percent, label) from the newest milestone in the step's log."""
    log = _logs(case_dir) / f"{step}.log"
    if not log.exists():
        return 0, ""
    text = log.read_text("utf-8", errors="replace")
    # only the last run (logs are appended across runs)
    cut = text.rfind("] start:")
    text = text[cut:] if cut >= 0 else text
    best = (0, "")
    for needle, pct, label in MILESTONES.get(step, []):
        pos = text.rfind(needle)
        if pos >= 0 and (pct >= best[0]):
            best = (pct, label)
    return best


def tail_log(case_dir: Path, step: str, lines: int = 60) -> str:
    log = _logs(case_dir) / f"{step}.log"
    if not log.exists():
        return ""
    data = log.read_text("utf-8", errors="replace").splitlines()
    return "\n".join(data[-lines:])


def _run(cmd: list[str], timeout: int = 600) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


# ---------------------------------------------------------------------------------------------------
def render_mount(root: Path):
    st.subheader("1. Mount the evidence image (read-only)")
    st.caption("Any E01, raw/dd or VHDX. Paste the Windows path (e.g. `C:\\DFIR\\evidence\\server.E01`) or the "
               "WSL path (`/mnt/c/DFIR/evidence/server.E01`). Mounted at `/mnt/evidence` unless changed.")
    img = st.text_input("Image file", key="mount_img", placeholder=r"C:\DFIR\evidence\server.E01")
    with st.expander("Advanced (only if the automatic pick is wrong)"):
        part = st.text_input("--part N", key="mount_part")
        lv = st.text_input("--lv VG/LV", key="mount_lv")
        target = st.text_input("--target", value="/mnt/evidence", key="mount_target")
    c1, c2, c3 = st.columns([1, 1, 3])
    script = str(root / "setup" / "wsl" / "mount_image.sh")
    if c1.button("Mount read-only", type="primary"):
        path = to_wsl_path(img)
        if not path or not Path(path).exists():
            st.error(f"file not found inside the distro: `{path or '(empty)'}` - is the drive attached, and the path right?")
        else:
            cmd = ["bash", script, path]
            if part.strip(): cmd += ["--part", part.strip()]
            if lv.strip(): cmd += ["--lv", lv.strip()]
            if target.strip(): cmd += ["--target", target.strip()]
            with st.spinner("mounting..."):
                rc, out = _run(cmd)
            (st.success if rc == 0 else st.error)(("mounted" if rc == 0 else "mount failed") + f" (exit {rc})")
            st.code(out or "(no output)")
    if c2.button("Unmount"):
        rc, out = _run(["bash", script, "--umount"])
        (st.success if rc == 0 else st.warning)(out or f"exit {rc}")
    mp = (st.session_state.get("mount_target") or "/mnt/evidence").strip()
    if Path(mp).is_dir() and any(Path(mp).iterdir()):
        st.info(f"`{mp}` currently has content: " + ", ".join(sorted(p.name for p in Path(mp).iterdir())[:12]))


def render_new_case(cases_root: Path, cfg: dict, compact: bool = False):
    if not compact:
        st.subheader("2. Create the case")
    with st.form("new_case", clear_on_submit=False):
        c1, c2 = st.columns(2)
        case_id = c1.text_input("Case ID (folder name)", value="CASE-001")
        examiner = c2.text_input("Examiner", value="")
        mount = c1.text_input("Mounted evidence root", value="/mnt/evidence")
        mode = c2.selectbox("Mode", ["mount", "export"], help="mount: a read-only mounted image; export: a folder of exported files")
        image = st.text_input("Image file (optional; recorded and hashed)", placeholder=r"C:\DFIR\evidence\server.E01")
        sha = st.text_input("Expected SHA-256 from the acquisition form (optional)")
        notes = st.text_area("Scope / objectives (becomes the examiner notes)", height=80)
        ok = st.form_submit_button("Create case", type="primary")
    if ok:
        from gumshoe.case import Case
        cid = re.sub(r"[^A-Za-z0-9._-]+", "-", case_id.strip()) or "CASE-001"
        if not examiner.strip():
            st.error("examiner name is required (it goes into the custody log)"); return
        mroot = to_wsl_path(mount)
        if not Path(mroot).is_dir():
            st.error(f"`{mroot}` is not a directory; mount the image first (step 1)"); return
        try:
            c = Case.create(cases_root, cid, examiner.strip(), to_wsl_path(image) or None, mroot, mode, cfg, notes=notes or "")
        except FileExistsError as e:
            st.error(str(e)); return
        if sha.strip():
            try:
                r = c.verify_image({"sha256": sha.strip().lower(), "md5": ""})
                st.info("image hash " + ("matches" if r.get("match") else "DOES NOT MATCH") + " the expected value")
            except Exception as e:  # noqa: BLE001
                st.warning(f"could not hash the image now: {e}")
        st.success(f"created {c.dir}")
        time.sleep(0.5)
        st.rerun()


def any_running(case_dir: Path) -> list[str]:
    return [s for s in STEPS if step_status(case_dir, s)[0] == "running"]


def render_sidebar_status(case):
    """Compact status + progress for every tab; refreshes itself every few seconds while something runs."""
    running = any_running(case.dir)

    def body():
        now_running = any_running(case.dir)
        if not now_running:
            last = [(s, step_status(case.dir, s)) for s in STEPS]
            done = [STEPS[s][0] for s, (st_, _) in last if st_ == "done"]
            failed = [STEPS[s][0] for s, (st_, _) in last if st_ == "failed"]
            st.caption("**Run:** " + (", ".join(done) + " done" if done else "nothing run yet") + ("; FAILED: " + ", ".join(failed) if failed else ""))
            return
        for s in now_running:
            pct, label = progress_of(case.dir, s)
            started = _state(case.dir, s).get("started", "")
            st.progress(min(max(pct, 1), 99) / 100, text=f"{STEPS[s][0]}: {label or 'running'} ({pct}%)")
            st.caption(f"started {started}")
    st.fragment(body, run_every="4s" if running else None)()


def render_run_tab(case, root: Path, cases_root: Path):
    st.subheader("3. Run the case")
    st.caption("Each step is the same command the runbook uses, started in the background and logged under "
               "`logs/` in the case folder. Close the browser if you like; the step keeps running. "
               "While a step runs this panel refreshes itself every few seconds.")
    running = any_running(case.dir)
    st.fragment(lambda: _render_steps(case, root, cases_root), run_every="4s" if running else None)()


def _render_steps(case, root: Path, cases_root: Path):
    for step, (name, blurb, _) in STEPS.items():
        status, state = step_status(case.dir, step)
        c1, c2, c3 = st.columns([1.2, 3, 1])
        c1.markdown(f"**{name}**")
        c2.caption(blurb)
        badge = {"idle": "not run", "running": "running", "done": "done", "failed": "FAILED"}[status]
        c3.markdown({"idle": "⚪", "running": "🟡", "done": "🟢", "failed": "🔴"}[status] + " " + badge)
        if status == "running":
            pct, label = progress_of(case.dir, step)
            st.progress(min(max(pct, 1), 99) / 100, text=f"{label or 'running'} ({pct}%)")
        b1, b2, b3 = st.columns([1, 1, 4])
        if status != "running" and b1.button("Start", key=f"start_{step}", type="primary" if status in ("idle", "failed") else "secondary"):
            st.session_state[f"state_{step}"] = start_step(root, cases_root, case.dir, step)
            st.rerun(scope="app")
        if status == "running" and b1.button("Stop", key=f"stop_{step}"):
            try:
                os.killpg(int(state["pid"]), signal.SIGTERM)
            except Exception as e:  # noqa: BLE001
                st.warning(str(e))
            st.rerun(scope="app")
        if b2.button("Refresh", key=f"refresh_{step}"):
            st.rerun(scope="app")
        if state:
            with st.expander(f"log: logs/{step}.log  (started {state.get('started')})", expanded=(status == "running")):
                st.code(tail_log(case.dir, step) or "(empty)")
        st.divider()
    st.caption("Order: Verify, then Collect. Deep is optional and repeats the heavy parts unattended. "
               "After Collect finishes, the Findings, Ask, Reports and Export tabs are live.")
