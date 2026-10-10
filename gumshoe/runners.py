"""Run the external tools and keep their raw output under collected/raw/<tool>/.

Every run is logged to the custody chain with the exact command line, exit
code, duration, and SHA-256 of each output file. Tools are optional: a missing
binary is recorded and the normalizer for that tool reports "not run".

Command lines follow each tool's documented CLI as of 2025; `--help` on the box
is the authority if a flag has moved (see docs/TOOLS.md).
"""
from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

from .integrity import hash_file, utc_now, elapsed_ms


class ToolMissing(RuntimeError):
    pass


def which(binary: str) -> Optional[str]:
    if os.path.sep in binary or (binary.endswith(".py")):
        return binary if Path(binary).exists() else None
    return shutil.which(binary)


def _record_outputs(out_dir: Path) -> list[dict[str, Any]]:
    outs = []
    for p in sorted(out_dir.rglob("*")):
        if p.is_file() and p.stat().st_size < 4 * 1024 * 1024 * 1024:
            outs.append({"file": str(p.relative_to(out_dir)), "size": p.stat().st_size, "sha256": hash_file(p)})
        if len(outs) >= 500:
            outs.append({"note": "more than 500 output files; remainder not hashed individually"})
            break
    return outs


def run_cmd(case, tool: str, cmd: list[str], out_dir: Path, stdin_path: Optional[Path] = None, cwd: Optional[Path] = None,
            timeout: Optional[int] = None, env: Optional[dict[str, str]] = None) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    start = time.time()
    stdout_path = out_dir / f"{tool}.stdout.txt"
    stderr_path = out_dir / f"{tool}.stderr.txt"
    rec: dict[str, Any] = {"tool": tool, "cmd": cmd, "started": utc_now(), "cwd": str(cwd) if cwd else None}
    case.custody.append("tool_start", rec)
    try:
        with open(stdout_path, "wb") as so, open(stderr_path, "wb") as se:
            stdin = open(stdin_path, "rb") if stdin_path else None
            try:
                proc = subprocess.run(cmd, stdin=stdin, stdout=so, stderr=se, cwd=cwd, timeout=timeout,
                                      env={**os.environ, **(env or {})})
            finally:
                if stdin:
                    stdin.close()
        rec.update({"exit_code": proc.returncode, "duration_ms": elapsed_ms(start)})
    except (FileNotFoundError, PermissionError) as e:
        rec.update({"error": str(e), "duration_ms": elapsed_ms(start)})
    except subprocess.TimeoutExpired:
        rec.update({"error": "timeout", "duration_ms": elapsed_ms(start)})
    rec["outputs"] = _record_outputs(out_dir)
    case.custody.append("tool_end", rec)
    return rec


# ---- UAC -----------------------------------------------------------------------
def run_uac(case) -> dict[str, Any]:
    t = case.cfg["tools"]["uac"]
    binary = which(t.get("bin", "uac"))
    if not binary:
        raise ToolMissing("uac not found on PATH (tools/uac/uac)")
    out = case.raw / "uac"
    cmd = [binary, "-p", t.get("profile", "ir_triage"), "-m", str(case.mount_root), "-s", "linux",
           "--hash-collected", str(out)]
    if sys.platform.startswith("linux") and os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd  # UAC needs root to read every file; -n fails fast if no sudo rights
    return run_cmd(case, "uac", cmd, out, timeout=t.get("timeout_s"))


# ---- Loki ----------------------------------------------------------------------
def run_loki(case) -> dict[str, Any]:
    t = case.cfg["tools"]["loki"]
    binary = which(t.get("bin", "loki"))
    if not binary:
        raise ToolMissing("loki not found on PATH (tools/loki/loki.py or loki binary)")
    out = case.raw / "loki"
    out.mkdir(parents=True, exist_ok=True)
    targets = []
    for rel in case.cfg["paths"]["web_roots"] + case.cfg["paths"]["temp_dirs"] + ["root", "home", "opt", "var/www",
                                                                                     case.cfg["paths"]["panel"]] + case.cfg["paths"]["mariadb_plugin"]:
        p = case.abs(rel)
        if p.exists():
            targets.append(p)
    recs = []
    base = [binary] if not binary.endswith(".py") else [sys.executable, binary]
    cwd = Path(binary).parent if binary.endswith(".py") else None
    for i, target in enumerate(targets):
        logf = out / f"loki_{i:02d}_{target.name}.log"
        cmd = base + ["-p", str(target), "-l", str(logf)] + list(t.get("extra_args", []))
        recs.append(run_cmd(case, f"loki_{i:02d}", cmd, out, cwd=cwd, timeout=t.get("timeout_s")))
    # second, --intense pass (every file regardless of extension) only over upload-type directories,
    # where scripts hidden as images live; intense over a whole media tree would take days
    intense = []
    for g in t.get("intense_globs", []):
        intense += [p for p in case.mount_root.glob(g) if p.is_dir()]
    for j, target in enumerate(intense):
        logf = out / f"loki_intense_{j:02d}_{target.parent.name}_{target.name}.log"
        cmd = base + ["-p", str(target), "-l", str(logf), "--intense"] + [a for a in t.get("extra_args", []) if a != "--intense"]
        recs.append(run_cmd(case, f"loki_intense_{j:02d}", cmd, out, cwd=cwd, timeout=t.get("timeout_s")))
    return {"runs": recs, "targets": [str(x) for x in targets], "intense_targets": [str(x) for x in intense]}


# ---- GoAccess ------------------------------------------------------------------
def _concat_logs(files: list[Path], dest: Path) -> int:
    n = 0
    with open(dest, "wb") as w:
        for f in files:
            opener = gzip.open if f.suffix == ".gz" else open
            with opener(f, "rb") as r:
                shutil.copyfileobj(r, w)
                n += 1
    return n


def run_goaccess(case) -> dict[str, Any]:
    """Streams every log file (plain and .gz) of a site into GoAccess over a pipe: no merged copy on disk,
    so tens of GB of logs cost no extra space."""
    import shlex
    from .normalize.weblog2jsonl import iter_log_files
    t = case.cfg["tools"]["goaccess"]
    binary = which(t.get("bin", "goaccess"))
    if not binary:
        raise ToolMissing("goaccess not found on PATH (apt install goaccess inside the distro)")
    out = case.raw / "goaccess"
    out.mkdir(parents=True, exist_ok=True)
    by_site: dict[str, list[Path]] = {}
    for site, p in iter_log_files(case):
        by_site.setdefault(site, []).append(p)
    recs = []
    for site, files in by_site.items():
        report = out / f"{site}.json"
        dashboard = out / f"{site}.html"   # self-contained interactive dashboard; open it directly in a browser
        readers = " ; ".join(("zcat " if f.suffix == ".gz" else "cat ") + shlex.quote(str(f)) for f in sorted(files))
        ga = " ".join(shlex.quote(x) for x in [binary, "-", "--log-format=" + t.get("log_format", "COMBINED"), "-o", str(report),
                                              "-o", str(dashboard), "--no-global-config"] + list(t.get("extra_args", [])))
        pipeline = f"( {readers} ) | {ga}"
        recs.append(run_cmd(case, f"goaccess_{site}", ["bash", "-c", pipeline], out, timeout=t.get("timeout_s")))
    return {"runs": recs, "sites": list(by_site)}


# ---- Chainsaw ------------------------------------------------------------------
def run_chainsaw(case) -> dict[str, Any]:
    from .case import project_root, package_dir
    t = case.cfg["tools"]["chainsaw"]
    binary = which(t.get("bin", "chainsaw"))
    if not binary:
        raise ToolMissing("chainsaw not found on PATH (tools/chainsaw/chainsaw)")
    rules = Path(t.get("sigma_rules", "tools/sigma/rules"))
    if not rules.is_absolute():
        rules = project_root() / rules
    mappings = Path(t.get("mappings_dir", "rules/chainsaw-mappings"))
    if not mappings.is_absolute():
        mappings = (project_root() / mappings) if (project_root() / mappings).exists() else (package_dir() / mappings)
    out = case.raw / "chainsaw"
    out.mkdir(parents=True, exist_ok=True)
    recs = []
    jobs = [("web", case.jsonl / "web", rules / "web", mappings / "gumshoe-web.yml"),
            ("auth", case.jsonl / "auth", rules / "linux", mappings / "gumshoe-auth.yml")]
    for name, src, rule_dir, mapping in jobs:
        if not src.exists() or not any(src.glob("*.jsonl")):
            continue
        if not rule_dir.exists():
            rule_dir = rules
        cmd = [binary, "hunt", str(src), "-s", str(rule_dir), "--mapping", str(mapping), "--json", "-o",
               str(out / f"{name}.json"), "--skip-errors"]
        recs.append(run_cmd(case, f"chainsaw_{name}", cmd, out, timeout=t.get("timeout_s")))
    return {"runs": recs}


# ---- optional: ClamAV, Plaso ---------------------------------------------------
def run_clamscan(case) -> dict[str, Any]:
    t = case.cfg["tools"]["clamav"]
    binary = which(t.get("bin", "clamscan"))
    if not binary:
        raise ToolMissing("clamscan not found")
    out = case.raw / "clamav"
    targets = [str(case.abs(r)) for r in case.cfg["paths"]["web_roots"] + case.cfg["paths"]["temp_dirs"] + ["root", "home"]
               if case.abs(r).exists()]
    cmd = [binary, "-r", "--infected", "--no-summary", "-l", str(out / "clamscan.log")] + targets
    return run_cmd(case, "clamscan", cmd, out, timeout=t.get("timeout_s"))


def run_plaso(case) -> dict[str, Any]:
    t = case.cfg["tools"]["plaso"]
    binary = which(t.get("bin", "log2timeline.py"))
    if not binary:
        raise ToolMissing("log2timeline.py not found")
    out = case.raw / "plaso"
    out.mkdir(parents=True, exist_ok=True)
    storage = out / "timeline.plaso"
    r1 = run_cmd(case, "log2timeline", [binary, "--storage-file", str(storage), str(case.mount_root)], out,
                 timeout=t.get("timeout_s"))
    psort = which("psort.py") or "psort.py"
    r2 = run_cmd(case, "psort", [psort, "-o", "l2tcsv", "-w", str(out / "supertimeline.csv"), str(storage)], out,
                 timeout=t.get("timeout_s"))
    return {"runs": [r1, r2]}


RUNNERS = {"uac": run_uac, "loki": run_loki, "goaccess": run_goaccess, "chainsaw": run_chainsaw,
           "clamav": run_clamscan, "plaso": run_plaso}
