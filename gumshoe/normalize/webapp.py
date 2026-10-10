"""Web application and PHP stack inventory for an aaPanel host: what an examiner
normally wants to see about each site, read from the files themselves.

Per site under the web roots:
  * framework detection (WordPress, Drupal, Joomla, Laravel, generic PHP, static) and version, nested apps included
  * configuration files located (wp-config.php, .env, config.php ...): database name,
    user, host and table prefix are recorded; passwords and secrets are MASKED
  * WordPress plugins and themes with versions (from their headers / readme Stable tag)
  * PHP file inventory: counts, entry points in the site root, include/require graph
    summary, external host names referenced in code (bounded)
  * .htaccess / .user.ini files with their change times
Per PHP version installed by the panel (/www/server/php/<ver>/etc/php.ini):
  * disable_functions, allow_url_include, allow_url_fopen, open_basedir, expose_php,
    upload_max_filesize -> hardening facts (info/low findings)
No signature matching happens here; that is Loki's job.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from .base import Finding, with_provenance, read_lines, is_binary_file, iter_files
from ..integrity import stat_times

DEFINE = re.compile(r"""define\s*\(\s*['"](?P<k>[A-Z0-9_]+)['"]\s*,\s*['"](?P<v>[^'"]*)['"]""")
ASSIGN = re.compile(r"""\$(?P<k>table_prefix|db_host|db_name|db_user|dbhost|dbname|dbuser|dbpass|db_pass|password)\s*=\s*['"](?P<v>[^'"]*)['"]""", re.I)
INCLUDE = re.compile(r"""\b(?:include|require)(?:_once)?\s*\(?\s*(?:__DIR__\s*\.\s*)?['"]([^'"]+)['"]""")
HOST = re.compile(r"""https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?[/'"\s]""")
HEADER_VERSION = re.compile(r"^\s*\*?\s*Version:\s*(\S+)", re.M)
STABLE_TAG = re.compile(r"^Stable tag:\s*(\S+)", re.M | re.I)
SECRET_KEYS = re.compile(r"(PASS|PASSWORD|SECRET|KEY|SALT|TOKEN|NONCE)", re.I)


def _mask(k: str, v: str) -> str:
    return "***masked***" if SECRET_KEYS.search(k) and v else v


def _read(p: Path, limit: int = 4000) -> str:
    try:
        return "\n".join(l for _, l in read_lines(p, limit=limit))
    except OSError:
        return ""


def detect_framework(site: Path) -> tuple[str, Optional[str]]:
    if (site / "wp-config.php").exists() or (site / "wp-includes").exists():
        ver = None
        vf = site / "wp-includes" / "version.php"
        if vf.exists():
            m = re.search(r"\$wp_version\s*=\s*'([^']+)'", _read(vf, 200))
            ver = m.group(1) if m else None
        return "wordpress", ver
    if (site / "includes" / "bootstrap.inc").exists() or (site / "core" / "lib" / "Drupal.php").exists():
        ver = None
        for vf in (site / "includes" / "bootstrap.inc", site / "core" / "lib" / "Drupal.php"):
            if vf.exists():
                m = re.search(r"(?:define\('VERSION',\s*'|const VERSION = ')([^']+)'", _read(vf, 400))
                if m:
                    ver = m.group(1)
                    break
        return "drupal", ver
    if (site / "configuration.php").exists() and (site / "administrator").is_dir():
        ver = None
        for vf in (site / "libraries" / "src" / "Version.php", site / "libraries" / "cms" / "version" / "version.php",
                   site / "administrator" / "manifests" / "files" / "joomla.xml"):
            if vf.exists():
                txt = _read(vf, 400)
                m = re.search(r"<version>([^<]+)</version>", txt) or re.search(r"(?:MAJOR_VERSION|RELEASE)\s*=\s*'?([\d.]+)", txt)
                if m:
                    ver = m.group(1)
                    break
        return "joomla", ver
    if (site / "artisan").exists():
        return "laravel", None
    if (site / "composer.json").exists() or any(site.glob("*.php")):
        return "php", None
    if (site / "index.html").exists():
        return "static", None
    return "unknown", None


FRAMEWORKS = ("wordpress", "drupal", "joomla", "laravel")


def discover_sites(root: Path, max_depth: int = 2) -> list[Path]:
    """Site directories under a web root: each immediate child, plus any nested directory (to
    max_depth) that is itself a framework root, e.g. /var/www/html/jabc holding a Drupal install."""
    out: list[Path] = []
    for site in sorted(d for d in root.iterdir() if d.is_dir()):
        out.append(site)
        if detect_framework(site)[0] in FRAMEWORKS:
            continue
        stack = [(site, 1)]
        while stack:
            d, depth = stack.pop()
            if depth > max_depth:
                continue
            try:
                children = sorted(c for c in d.iterdir() if c.is_dir() and not c.name.startswith("."))
            except OSError:
                continue
            for c in children:
                if detect_framework(c)[0] in FRAMEWORKS:
                    out.append(c)
                elif depth < max_depth:
                    stack.append((c, depth + 1))
    return out


def config_facts(site: Path, case) -> list[dict[str, Any]]:
    out = []
    for name in ("wp-config.php", ".env", "config.php", "configuration.php", "settings.php", "sites/default/settings.php",
                 "config/database.php", "db.php", "conn.php"):
        p = site / name
        if not p.is_file() or is_binary_file(p):
            continue
        text = _read(p, 600)
        facts: dict[str, str] = {}
        for m in DEFINE.finditer(text):
            if m.group("k").startswith(("DB_", "WP_", "AUTH_", "SECURE_", "LOGGED_", "NONCE_", "FS_", "DISALLOW_", "WP_DEBUG")):
                facts[m.group("k")] = _mask(m.group("k"), m.group("v"))
        for m in ASSIGN.finditer(text):
            facts[m.group("k")] = _mask(m.group("k"), m.group("v"))
        if name == ".env":
            for _, line in read_lines(p, limit=300):
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.split("=", 1)
                    facts[k.strip()] = _mask(k.strip(), v.strip().strip('"'))
        out.append({"file": case.rel(p), "facts": facts})
    return out


def wp_components(site: Path, case) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {"plugins": [], "themes": []}
    for kind, sub in (("plugins", "wp-content/plugins"), ("themes", "wp-content/themes")):
        d = site / sub
        if not d.is_dir():
            continue
        for item in sorted(d.iterdir()):
            if not item.is_dir():
                continue
            ver = None
            for cand in list(item.glob("*.php"))[:20] + [item / "style.css", item / "readme.txt"]:
                if cand.is_file() and not is_binary_file(cand):
                    text = _read(cand, 60)
                    m = HEADER_VERSION.search(text) or STABLE_TAG.search(text)
                    if m:
                        ver = m.group(1)
                        break
            try:
                st = stat_times(item)
            except OSError:
                st = {}
            out[kind].append({"name": item.name, "version": ver, "ctime": st.get("ctime"), "mtime": st.get("mtime"),
                              "path": case.rel(item)})
    return out


def php_inventory(site: Path, case, max_files: int = 20000) -> dict[str, Any]:
    n, entry, includes, hosts = 0, [], Counter(), Counter()
    special = []
    for p in iter_files(site):
        name = p.name
        if name in (".htaccess", ".user.ini", "php.ini"):
            try:
                st = stat_times(p)
            except OSError:
                st = {}
            special.append({"path": case.rel(p), "ctime": st.get("ctime"), "mtime": st.get("mtime")})
        if p.suffix.lower() not in (".php", ".phtml", ".php5", ".php7", ".inc"):
            continue
        n += 1
        if n > max_files:
            continue
        if p.parent == site:
            entry.append(name)
        if p.stat().st_size > 2 * 2**20 or is_binary_file(p):
            continue
        text = _read(p, 2000)
        for m in INCLUDE.finditer(text):
            includes[m.group(1).rsplit("/", 1)[-1]] += 1
        for m in HOST.finditer(text):
            hosts[m.group(1).lower()] += 1
    return {"php_files": n, "capped": n > max_files, "entry_points": sorted(entry)[:200],
            "top_includes": includes.most_common(40), "external_hosts": hosts.most_common(60), "special_files": special[:500]}


def php_ini_facts(case) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    inv: list[dict[str, Any]] = []
    candidates = list(case.abs("www/server/php").glob("*/etc/php.ini")) if case.abs("www/server/php").exists() else []
    candidates += list(case.abs("etc/php").glob("*/fpm/php.ini")) if case.abs("etc/php").exists() else []
    keys = ("disable_functions", "allow_url_include", "allow_url_fopen", "open_basedir", "expose_php", "upload_max_filesize",
            "post_max_size", "max_execution_time", "display_errors", "auto_prepend_file", "auto_append_file")
    for ini in sorted(candidates):
        rel = case.rel(ini)
        facts: dict[str, str] = {}
        lines: dict[str, int] = {}
        for no, line in read_lines(ini):
            s = line.strip()
            if not s or s.startswith((";", "[")) or "=" not in s:
                continue
            k, v = s.split("=", 1)
            k = k.strip()
            if k in keys:
                facts[k] = v.strip()
                lines[k] = no
        inv.append({"file": rel, "facts": facts})
        if facts.get("allow_url_include", "").lower() in ("on", "1", "true"):
            findings.append(with_provenance(case, Finding(source="webapp", severity="low", rule="php.allow_url_include",
                                                          title=f"PHP allow_url_include is On ({rel})", path=rel, line=lines.get("allow_url_include"),
                                                          excerpt=f"allow_url_include = {facts['allow_url_include']}", tags=["php", "hardening"])))
        if "disable_functions" in facts and not facts["disable_functions"].strip():
            findings.append(with_provenance(case, Finding(source="webapp", severity="low", rule="php.disable_functions_empty",
                                                          title=f"PHP disable_functions is empty ({rel})", path=rel, line=lines.get("disable_functions"),
                                                          description="aaPanel ships a non-empty disable_functions list; an empty value is a change from the default.",
                                                          tags=["php", "hardening"])))
        for k in ("auto_prepend_file", "auto_append_file"):
            if facts.get(k, "").strip():
                findings.append(with_provenance(case, Finding(source="webapp", severity="medium", rule=f"php.{k}",
                                                              title=f"PHP {k} is set to {facts[k]} ({rel})", path=rel, line=lines.get(k),
                                                              description="Every PHP request first runs this file; confirm it is expected.",
                                                              tags=["php", "configuration"])))
    return findings, inv


def run(case) -> list[Finding]:
    findings: list[Finding] = []
    sites_inv: list[dict[str, Any]] = []
    for wr in case.cfg["paths"]["web_roots"]:
        root = case.abs(wr)
        if not root.is_dir():
            continue
        for site in discover_sites(root):
            fw, ver = detect_framework(site)
            entry = {"site": case.rel(site), "framework": fw, "version": ver, "configs": config_facts(site, case)}
            if fw == "wordpress":
                entry.update(wp_components(site, case))
            entry["php"] = php_inventory(site, case)
            sites_inv.append(entry)
            cfg_names = [c["file"].rsplit("/", 1)[-1] for c in entry["configs"]]
            summary = (f"Site {site.name}: {fw}" + (f" {ver}" if ver else "") + f", {entry['php']['php_files']} PHP files"
                       + (f", {len(entry.get('plugins', []))} plugins, {len(entry.get('themes', []))} themes" if fw == "wordpress" else "")
                       + (f", config: {', '.join(cfg_names)}" if cfg_names else ""))
            findings.append(Finding(source="webapp", severity="info", rule="webapp.site", title=summary, path=case.rel(site),
                                    description="Framework, configuration locations (secrets masked), components with versions, PHP entry points, "
                                                "include graph summary and external host names are in inventory.json under webapps.",
                                    tags=["webapp", fw], extra={"entry_points": entry["php"]["entry_points"][:30],
                                                                "external_hosts": entry["php"]["external_hosts"][:20]}))
    f, ini = php_ini_facts(case)
    findings += f
    inv = case.read_json("inventory.json", {}) or {}
    inv["webapps"] = {"sites": sites_inv, "php_ini": ini}
    case.write_json("inventory.json", inv)
    return findings
