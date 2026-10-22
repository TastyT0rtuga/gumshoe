"""Case directory, configuration and paths.

Layout of a case directory (the only place Gumshoe ever writes):

    cases/<CASE_ID>/
      case.json              metadata, image hashes, examiner, mode
      custody.log            hash-chained, append-only
      collected/
        raw/<tool>/          untouched tool output (UAC, Loki, GoAccess, Chainsaw, ...)
        jsonl/               converted logs for Chainsaw (web + auth)
        findings.jsonl       normalized findings
        timeline.csv         bodyfile-derived timeline
        trends.json          GoAccess-derived statistics
        inventory.json       accounts, keys, cron, units, sites, DB users ...
      index/gumshoe.db       SQLite FTS5 (+ optional vectors)
      evidence/              archived copies + sidecars + manifest.json
      reports/               generated reports
"""
from __future__ import annotations

import json
import os
import platform
from pathlib import Path, PurePosixPath
from typing import Any, Optional

import yaml

from .integrity import CustodyLog, hash_file, utc_now

DEFAULT_CONFIG: dict[str, Any] = {
    "profile": "linux-aapanel",
    "normalizers": ["uac", "documents", "loki", "goaccess", "weblog", "auth", "chainsaw", "aapanel", "webapp"],
    "mode": "mount",  # mount | export
    "mount": {"root": "/mnt/evidence"},
    "paths": {
        "web_roots": ["www/wwwroot", "var/www"],
        "web_logs": ["www/wwwlogs"],
        "panel": "www/server/panel",
        "panel_cron": "www/server/cron",
        "mariadb_data": ["www/server/data", "var/lib/mysql"],
        "mariadb_plugin": ["www/server/mysql/lib/plugin", "usr/lib/mysql/plugin"],
        "var_log": "var/log",
        "temp_dirs": ["tmp", "dev/shm", "var/tmp"],
    },
    "tools": {
        "uac": {"enabled": True, "bin": "uac", "profile": "ir_triage"},
        "loki": {"enabled": True, "bin": "loki", "extra_args": ["--noprocscan", "--dontwait", "--csv"],
                  # --intense (scan every file regardless of extension, catches scripts hidden as images) only here,
                  # because it is slow over large media trees
                  "intense_globs": ["www/wwwroot/*/wp-content/uploads", "www/wwwroot/*/uploads", "www/wwwroot/*/upload",
                                    "www/wwwroot/*/public/uploads", "www/wwwroot/*/storage", "www/wwwroot/*/files"]},
        "goaccess": {"enabled": True, "bin": "goaccess", "log_format": "COMBINED"},
        "chainsaw": {"enabled": True, "bin": "chainsaw", "sigma_rules": "tools/sigma/rules",
                      "mappings_dir": "rules/chainsaw-mappings"},
        "plaso": {"enabled": False, "bin": "log2timeline.py"},
        "clamav": {"enabled": False, "bin": "clamscan"},
    },
    "llm": {
        "base_url": "http://127.0.0.1:11434",
        "models": {"interactive": "qwen2.5:3b-instruct", "report": "qwen2.5:7b-instruct-q4_K_M",
                   "embed": "nomic-embed-text"},
        "num_ctx_interactive": 4096,
        "num_ctx_report": 8192,
        "num_thread": 8,
        "temperature": 0.1,
        "keep_alive": "30m",
        "timeout_s": 900,
        "use_embeddings": False,
    },
    "index": {
        "chunk_chars": 1500,
        "chunk_overlap": 200,
        "max_file_bytes": 50 * 1024 * 1024,
        "sample_head_bytes": 2 * 1024 * 1024,
        "sample_tail_bytes": 2 * 1024 * 1024,
        "include_globs": [
            "etc/passwd", "etc/group", "etc/hosts", "etc/crontab", "etc/cron.d/*", "etc/cron.*/*",
            "var/spool/cron/crontabs/*", "etc/systemd/system/*.service", "etc/rc.local",
            "etc/ssh/sshd_config", "root/.bash_history", "root/.mysql_history", "home/*/.bash_history",
            "var/mail/.bash_history", "var/www/.bash_history", "var/spool/*/.bash_history", "home/*/.mysql_history",
            "root/.ssh/authorized_keys", "home/*/.ssh/authorized_keys",
            "www/server/panel/vhost/nginx/*.conf", "www/server/panel/vhost/apache/*.conf",
            "www/server/cron/*", "www/server/panel/logs/request/*.log",
            "www/wwwlogs/*.log", "www/wwwlogs/*.gz",
            "var/log/auth.log*", "var/log/syslog*", "var/log/nginx/*", "var/log/apache2/*",
            "etc/my.cnf", "www/server/mysql/etc/my.cnf", "www/server/php/*/etc/php.ini",
            # site source and text (any script/encoding); binaries and files over the size cap are skipped or sampled
            "www/wwwroot/**/*.php", "www/wwwroot/**/*.txt", "www/wwwroot/**/*.md", "www/wwwroot/**/*.ini",
            "www/wwwroot/**/.htaccess", "www/wwwroot/**/.user.ini", "var/www/**/*.php",
            "tmp/*", "dev/shm/*", "var/tmp/*", "root/.*history", "home/*/.*history", "root/*.txt", "root/*.sh",
        ],
    },
    "archive": {"max_file_bytes": 200 * 1024 * 1024, "excerpt_context_lines": 50},
    "logs": {
        "since": None,            # ISO date/time: skip web/auth log lines before this (large images: narrow the window)
        "until": None,
        "keep_jsonl": True,       # False: delete the converted JSONL after Chainsaw has hunted it (saves ~2x the log size)
        "max_post_stems": 500000, # bound on distinct POST/PUT targets tracked for correlation
    },
    "timeline": {"csv_max_rows": 500000},  # full timeline stays in timeline.db; the CSV is a bounded, filtered export
    "dbreview": {"max_copy_gb": 20, "databases": []},  # over the cap: copy system schema + only the named databases
    "heuristics": {
        "suspicious_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"],
        "pipe_to_shell_tokens": ["| sh", "|sh", "| bash", "|bash", "| /bin/sh", "| /bin/bash"],
        "service_accounts_expected_nologin": ["www", "www-data", "mysql", "nobody", "daemon", "bin", "sys",
                                               "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
                                               "backup", "list", "irc", "gnats", "_apt", "redis", "postgres",
                                               "ftp", "sshd", "systemd-network", "systemd-resolve", "messagebus"],
        "login_shells": ["/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/zsh", "/bin/dash"],
        "ssh_failure_threshold": 20,
        "timestomp_gap_seconds": 5,
        "burst_window_seconds": 600,
        "burst_min_files": 25,
        "dump_extensions": [".sql", ".sql.gz", ".zip", ".tar.gz", ".tgz", ".bak", ".7z", ".rar"],
        "panel_default_ports": [7800, 8888],
    },
    "retrieval": {"top_k": 8},
    "report": {"include_llm_narrative": True, "min_severity_to_archive": "high"},
    # `gumshoe deep` applies these on top of everything above for the unattended run; interactive use is untouched
    "deep": {
        "tools": {"plaso": {"enabled": True}, "clamav": {"enabled": True}},
        "loki_intense_everywhere": True,
        "documents": {"max_extract_files": 1000000, "max_extract_bytes": 200 * 1024 * 1024, "max_files": 2000000},
        "index": {"max_file_bytes": 500 * 1024 * 1024, "sample_head_bytes": 16 * 1024 * 1024, "sample_tail_bytes": 16 * 1024 * 1024},
        "vectors": True,
        "translate_all": True,
        "report_llm": True,
        "min_severity_to_archive": "medium",
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def list_profiles() -> list[dict[str, Any]]:
    out = []
    for p in sorted((package_dir() / "profiles").glob("*.yaml")):
        try:
            d = yaml.safe_load(p.read_text("utf-8")) or {}
            out.append({"name": d.get("name", p.stem), "description": d.get("description", ""), "file": str(p)})
        except yaml.YAMLError:
            continue
    return out


def load_profile(name: str) -> dict[str, Any]:
    p = package_dir() / "profiles" / f"{name}.yaml"
    if not p.exists():
        raise FileNotFoundError(f"no profile '{name}' (have: {', '.join(x['name'] for x in list_profiles()) or 'none'})")
    d = yaml.safe_load(p.read_text("utf-8")) or {}
    return {k: v for k, v in d.items() if k not in ("name", "description")}


def load_config(path: Optional[os.PathLike | str], profile: Optional[str] = None) -> dict[str, Any]:
    """defaults <- profiles/<profile>.yaml <- config.yaml. The profile comes from the argument,
    else config.yaml's `profile:` key, else linux-aapanel."""
    cfg = dict(DEFAULT_CONFIG)
    user: dict[str, Any] = {}
    if path and Path(path).exists():
        with open(path, "r", encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
    prof = profile or user.get("profile") or "linux-aapanel"
    try:
        cfg = deep_merge(cfg, load_profile(prof))
    except FileNotFoundError:
        if profile:
            raise
    cfg = deep_merge(cfg, user)
    cfg["profile"] = prof
    return cfg


def project_root() -> Path:
    """The clone's top directory (holds config.yaml, cases/, setup/, docs/)."""
    return Path(__file__).resolve().parent.parent


def package_dir() -> Path:
    """Shipped resources (profiles/, rules/, ui/) live inside the package so `pip install` carries them."""
    return Path(__file__).resolve().parent


def running_from_clone() -> bool:
    return (project_root() / "config.yaml").exists() and (project_root() / "gumshoe.py").exists()


class Case:
    def __init__(self, case_dir: Path, cfg: dict[str, Any]):
        self.dir = Path(case_dir)
        self.cfg = cfg
        self.meta_path = self.dir / "case.json"
        self.meta: dict[str, Any] = json.loads(self.meta_path.read_text("utf-8")) if self.meta_path.exists() else {}
        # the anchor lives outside the case folder: <cases root>/../custody-anchors/<case>.jsonl (/opt/dfir/custody-anchors on the sandbox)
        self.custody = CustodyLog(self.dir / "custody.log", actor=self.meta.get("examiner") or "gumshoe",
                                  anchor=self.dir.parent.parent / "custody-anchors" / f"{self.dir.name}.jsonl")
        for sub in ("collected/raw", "collected/jsonl", "index", "evidence", "reports"):
            (self.dir / sub).mkdir(parents=True, exist_ok=True)

    # ---- construction -----------------------------------------------------
    @classmethod
    def create(cls, cases_root: Path, case_id: str, examiner: str, image_path: Optional[str],
               mount_root: str, mode: str, cfg: dict[str, Any], notes: str = "") -> "Case":
        case_dir = Path(cases_root) / case_id
        if case_dir.exists() and (case_dir / "case.json").exists():
            raise FileExistsError(f"case already exists: {case_dir}")
        case_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "case_id": case_id,
            "examiner": examiner,
            "created": utc_now(),
            "image_path": image_path,
            "mount_root": mount_root,
            "mode": mode,
            "profile": cfg.get("profile"),
            "notes": notes,
            "host": platform.node(),
            "platform": platform.platform(),
            "image_hashes": {},
            "verified": False,
        }
        (case_dir / "case.json").write_text(json.dumps(meta, indent=2), "utf-8")
        c = cls(case_dir, cfg)
        c.custody.append("case_created", {k: meta[k] for k in ("case_id", "examiner", "image_path", "mount_root", "mode")})
        # keep a copy of the effective config with the case for reproducibility
        (case_dir / "config.effective.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), "utf-8")
        return c

    @classmethod
    def open(cls, case_dir: Path, cfg: dict[str, Any]) -> "Case":
        if not (Path(case_dir) / "case.json").exists():
            raise FileNotFoundError(f"not a case directory: {case_dir}")
        return cls(case_dir, cfg)

    def save_meta(self) -> None:
        self.meta_path.write_text(json.dumps(self.meta, indent=2), "utf-8")

    # ---- paths ------------------------------------------------------------
    @property
    def mount_root(self) -> Path:
        return Path(self.meta.get("mount_root") or self.cfg["mount"]["root"])

    @property
    def mode(self) -> str:
        return self.meta.get("mode") or self.cfg.get("mode", "mount")

    @property
    def collected(self) -> Path:
        return self.dir / "collected"

    @property
    def raw(self) -> Path:
        return self.dir / "collected" / "raw"

    @property
    def jsonl(self) -> Path:
        return self.dir / "collected" / "jsonl"

    @property
    def findings_path(self) -> Path:
        return self.dir / "collected" / "findings.jsonl"

    @property
    def index_db(self) -> Path:
        return self.dir / "index" / "gumshoe.db"

    @property
    def evidence(self) -> Path:
        return self.dir / "evidence"

    @property
    def reports(self) -> Path:
        return self.dir / "reports"

    def abs(self, relpath: str) -> Path:
        """Mount-relative (posix) path -> absolute path on this host."""
        rel = str(relpath).lstrip("/")
        return self.mount_root / Path(*PurePosixPath(rel).parts)

    def rel(self, abspath: os.PathLike | str) -> str:
        """Absolute path on this host -> mount-relative posix path (JSON-safe even for
        file names with undecodable bytes)."""
        from .textenc import safe_str
        p = Path(abspath).resolve()
        try:
            r = p.relative_to(self.mount_root.resolve())
        except ValueError:
            return safe_str(p.as_posix())
        return safe_str("/" + r.as_posix())

    # ---- image verification --------------------------------------------
    def verify_image(self, expected: Optional[dict[str, str]] = None) -> dict[str, Any]:
        img = self.meta.get("image_path")
        result: dict[str, Any] = {"image_path": img, "computed": {}, "expected": expected or {}, "match": None}
        if not img or not Path(img).exists():
            result["note"] = "image path not set or not reachable from this host; skipped hashing"
            self.custody.append("image_hash_skipped", result)
            return result
        from .integrity import hash_file_multi
        size = Path(img).stat().st_size
        result["image_bytes"] = size
        result["computed"] = hash_file_multi(img, ("sha256", "md5"),
                                             progress=lambda d: print(f"  hashing image: {d / 2**30:.1f} / {size / 2**30:.1f} GB", end="\r"))
        print()
        if expected:
            matches = []
            for algo, val in expected.items():
                if val:
                    matches.append(result["computed"].get(algo, "").lower() == val.strip().lower())
            result["match"] = all(matches) if matches else None
        self.meta["image_hashes"] = {"computed": result["computed"], "expected": expected or {}, "match": result["match"],
                                     "at": utc_now()}
        self.meta["verified"] = bool(result["match"]) if expected else None
        self.save_meta()
        self.custody.append("image_hashed", result)
        return result

    # ---- findings I/O -----------------------------------------------------
    def write_findings(self, findings: list[dict[str, Any]], append: bool = False) -> int:
        mode = "a" if append else "w"
        with open(self.findings_path, mode, encoding="utf-8") as f:
            for d in findings:
                f.write(json.dumps(d, ensure_ascii=False, sort_keys=True) + "\n")
        return len(findings)

    def read_findings(self) -> list[dict[str, Any]]:
        if not self.findings_path.exists():
            return []
        out = []
        with open(self.findings_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def write_json(self, name: str, obj: Any) -> Path:
        p = self.collected / name
        p.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), "utf-8")
        return p

    def read_json(self, name: str, default: Any = None) -> Any:
        p = self.collected / name
        if not p.exists():
            return default
        return json.loads(p.read_text("utf-8"))
