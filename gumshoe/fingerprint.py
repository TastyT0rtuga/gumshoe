"""What this server and its applications are built on - scored, with the evidence behind every score.

Three levels, each a list of candidates with a percentage (matched weight / total weight of that candidate's
indicators) and the indicators that matched, naming the file or directory each one came from:

  * the HOST: which control panel(s) are installed (aaPanel, BT Panel, cPanel, Plesk, DirectAdmin, CyberPanel,
    HestiaCP/VestaCP, ISPConfig, CloudPanel, 1Panel, CWP, Webmin/Virtualmin, Froxlor, mdserver-web, RunCloud,
    ServerPilot, Forge, Ploi, Dokku, CapRover, Coolify, Easypanel, Cockpit ...), whether the apps live in Docker
    containers (listed with their images), the services (nginx/apache/OpenLiteSpeed, PHP versions, MySQL/MariaDB,
    PostgreSQL, Redis, MongoDB, Node, PM2 apps, supervisor programs, custom systemd units)
  * each APPLICATION root (from the web roots and from every nginx/apache/OLS vhost `root`/`DocumentRoot`, with
    its domains): framework / CMS / admin framework with version (ThinkPHP, Laravel, Symfony, CodeIgniter, Yii,
    CakePHP, Hyperf, Webman, FastAdmin, BuildAdmin, Dcat/laravel-admin, Filament, Nova, WordPress, Joomla,
    Drupal, Magento, PrestaShop, OpenCart, Discuz!, DedeCMS, EmpireCMS, PHPCMS, EyouCMS, CRMEB, likeadmin,
    phpMyAdmin, Roundcube, WHMCS, Pterodactyl, Django, Next/Nuxt/NestJS/Express ...), the packages it is built on
    (composer `vendor/composer/installed.json`, composer.json, package.json, requirements.txt) with the notable ones
    grouped by what they do (crypto/blockchain, trading, payments, Telegram/Discord, SMS, e-mail, cloud storage,
    real-time, geo/device, auth), the UI kits (layui, AdminLTE, Element, Ant Design, Bootstrap, Vue/React builds),
    the language make-up by bytes and by files - all code, and own code with vendor/node_modules/uploads left out -
    and the newest-changed code files
  * each extracted DATABASE: table-name signatures (FastAdmin, Laravel, WordPress, Joomla, Drupal, PrestaShop,
    OpenCart, Magento, Discuz!, DedeCMS, CRMEB, likeadmin, Dcat, Yii, Django, Rails, Sequelize/Knex/Prisma, WHMCS,
    Pterodactyl ...), table prefixes, and the "investment / trading platform" table pattern (recharge, withdraw,
    wallet, coin, kline, leverage, agent/commission ...), scored the same way.

Read-only, bounded (existence checks are O(1); the composition walk stops at MAX_FILES per app or a time budget).
No model is involved; the result is written to <case>/collected/fingerprint.json, summarised in one finding
(`stack.fingerprint`), shown under the evidence check in the Run tab and printed by `gumshoe fingerprint`.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from stat import S_ISREG as _S_ISREG
from typing import Any, Callable, Iterator, Optional

from .integrity import utc_now
from .probe import WEB_ROOTS, _nonempty_dir, os_release, _read_small

Log = Callable[[str], None]
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))   # exported rows can carry cells far beyond csv's 128 KB default
MAX_FILES = 100_000            # composition walk per application root
WALK_BUDGET_S = 15.0           # per application root
TOTAL_BUDGET_S = 300.0         # all compositions together; later roots get candidates and packages only
READ_LIMIT = 64 * 1024         # text indicators read this much of a file

# ---------------------------------------------------------------------------------------------- indicator engine
# An indicator is a tuple: (kind, target, weight[, pattern]) with kind in
#   d  directory exists         f  file exists          g  glob matches (relative to the root)
#   t  file exists and its first 64 KB match the regex (a (?P<ver>...) group gives the version)
#   pkg composer package installed (installed.json / composer.json require)
#   npm package in package.json dependencies      py  package in requirements.txt / Pipfile
# Candidates: name, kind (panel|framework|admin|cms|app|runtime|pattern), indicators, optional version files.


# ---- paths inside the evidence. A symlink in a seized image points where it pointed on the seized machine: an absolute
# target (/etc/nginx/sites-available/x, /lib/systemd/system/y.service, /data/www/site) must be followed under the
# evidence root, not on the examiner's own system - Path.resolve()/open() would do the latter and lose the file.
_EVIDENCE_ROOT: Optional[Path] = None


def set_root(root: Optional[Path]) -> None:
    global _EVIDENCE_ROOT
    _EVIDENCE_ROOT = Path(root).resolve() if root else None


def inroot(p: Path, root: Optional[Path] = None, hops: int = 40) -> Optional[Path]:
    """`p` with every symlink on its way followed inside the evidence root; None when it leaves the root, loops, or
    cannot be read. Outside a root (plain host paths) the path is returned as it is."""
    root = Path(root).resolve() if root else _EVIDENCE_ROOT
    if root is None:
        return p
    try:
        rel = Path(os.path.abspath(p)).relative_to(root)
    except ValueError:
        return p if not str(p).startswith(str(root)) else None
    cur = root
    rs = str(root)
    for part in rel.parts:
        cur = cur / part
        n = 0
        while os.path.islink(cur):
            try:
                target = os.readlink(cur)
            except OSError:
                return None
            cur = Path(os.path.normpath((root / target.lstrip("/")) if target.startswith("/") else (cur.parent / target)))
            if not (str(cur) == rs or str(cur).startswith(rs + "/")):
                return None
            n += 1
            if n > hops:
                return None
    return cur


def _is_file(p: Path) -> bool:
    q = inroot(p)
    return q is not None and q.is_file()


def _is_dir(p: Path) -> bool:
    q = inroot(p)
    return q is not None and q.is_dir()


def _glob(root: Path, pat: str, limit: int = 5) -> list[str]:
    out = []
    try:
        for p in root.glob(pat):
            out.append(str(p.relative_to(root)))
            if len(out) >= limit:
                break
    except (OSError, ValueError):
        pass
    return out


def _text(root: Path, rel: str) -> str:
    p = inroot(root / rel, root)
    try:
        if p is None or not p.is_file() or p.stat().st_size > 50 * 2**20:      # is_file: regular files only (a FIFO would block open)
            return ""
        with open(p, "rb") as f:
            return f.read(READ_LIMIT).decode("utf-8", errors="replace")
    except OSError:
        return ""


class Ctx:
    """Everything an indicator can look at for one root: the filesystem plus the dependency lists."""

    def __init__(self, root: Path, composer: Optional[dict[str, str]] = None, npm: Optional[dict[str, str]] = None,
                 py: Optional[dict[str, str]] = None):
        self.root = Path(root)
        self.composer = composer or {}
        self.npm = npm or {}
        self.py = py or {}
        self._cache: dict[tuple, Any] = {}

    def check(self, ind: tuple) -> tuple[bool, str, Optional[str]]:
        """(matched, evidence text, version or None)."""
        kind, target, w = ind[0], ind[1], ind[2]
        if kind == "d":
            ok = _is_dir(self.root / target)
            return ok, f"dir {target}", None
        if kind == "f":
            ok = _is_file(self.root / target)
            return ok, f"file {target}", None
        if kind == "g":
            hits = _glob(self.root, target)
            return bool(hits), f"{target} -> {', '.join(hits[:3])}" if hits else f"{target}", None
        if kind == "t":
            pat = ind[3]
            key = ("t", target)
            txt = self._cache.get(key)
            if txt is None:
                txt = self._cache[key] = _text(self.root, target)
            if not txt:
                return False, f"{target} matches /{pat}/", None
            m = re.search(pat, txt, re.I | re.M)
            if not m:
                return False, f"{target} matches /{pat}/", None
            ver = m.groupdict().get("ver") if m.groupdict() else None
            return True, f"{target} matches /{pat}/" + (f" (version {ver})" if ver else ""), ver
        if kind == "pkg":
            v = self.composer.get(target.lower())
            return v is not None, f"composer package {target}" + (f" {v}" if v else ""), (v or None)
        if kind == "npm":
            v = self.npm.get(target.lower())
            return v is not None, f"npm package {target}" + (f" {v}" if v else ""), (v or None)
        if kind == "py":
            v = self.py.get(target.lower())
            return v is not None, f"python package {target}" + (f" {v}" if v else ""), (v or None)
        return False, f"{kind} {target}", None


def score(ctx: Ctx, candidates: list[dict[str, Any]], min_pct: int = 15) -> list[dict[str, Any]]:
    """Every candidate with a percentage and its evidence; sorted best first; weak ones (< min_pct, or only one
    low-weight indicator) dropped."""
    out = []
    for c in candidates:
        total = sum(i[2] for i in c["ind"])
        got = 0
        strong = 0
        matched, missed = [], []
        ver = None
        content_hit = False
        for i in c["ind"]:
            ok, ev, v = ctx.check(i)
            if ok:
                got += i[2]
                strong = max(strong, i[2])
                matched.append(ev)
                if i[0] in ("t", "pkg", "npm", "py"):
                    content_hit = True
                if v and not ver:
                    ver = v
            else:
                missed.append(ev)
        if not got:
            continue
        pct = int(round(100 * got / total)) if total else 0
        if pct < min_pct or (len(matched) == 1 and strong < 3):
            continue
        note = c.get("note", "")
        has_content_ind = any(i[0] in ("t", "pkg", "npm", "py") for i in c["ind"])
        if has_content_ind and not content_hit and pct >= 50:
            # directories and file names alone (app/, config/, public/) fit several frameworks: without one content or
            # package indicator the score stays below the half mark and says so
            pct = 49
            note = (note + "; " if note else "") + f"path checks only ({len(matched)} of {len(c['ind'])}), no content or package evidence matched"
        d = {"name": c["name"], "kind": c.get("kind", ""), "pct": pct, "version": ver, "matched": matched, "missed": missed[:12],
             "weight": got, "of": total}
        if note:
            d["note"] = note
        out.append(d)
    out.sort(key=lambda d: (-d["pct"], -d["weight"], d["name"]))
    return out


# ---------------------------------------------------------------------------------------------- host: panels
PANELS: list[dict[str, Any]] = [
    {"name": "aaPanel", "kind": "panel", "ind": [("d", "www/server/panel", 3), ("f", "www/server/panel/BT-Panel", 3), ("f", "www/server/panel/class/common.py", 2),
                                               ("t", "www/server/panel/class/common.py", 4, r"aapanel"), ("f", "www/server/panel/data/default.db", 2),
                                               ("f", "etc/init.d/bt", 2), ("g", "www/server/panel/plugin/*", 1), ("d", "www/wwwroot", 1), ("d", "www/server/php", 1),
                                               ("t", "www/server/panel/class/common.py", 1, r"version\s*=\s*['\"](?P<ver>[\d.]+)")]},
    {"name": "BT Panel (宝塔)", "kind": "panel", "ind": [("d", "www/server/panel", 3), ("f", "www/server/panel/BT-Panel", 3), ("f", "www/server/panel/class/common.py", 2),
                                                        ("t", "www/server/panel/class/common.py", 4, r"宝塔|bt\.cn"), ("f", "www/server/panel/data/default.db", 2),
                                                        ("f", "etc/init.d/bt", 2), ("g", "www/server/panel/plugin/*", 1), ("d", "www/wwwroot", 1),
                                                        ("t", "www/server/panel/class/common.py", 1, r"version\s*=\s*['\"](?P<ver>[\d.]+)")]},
    {"name": "mdserver-web", "kind": "panel", "ind": [("d", "www/server/mdserver-web", 5), ("f", "www/server/mdserver-web/app.py", 2)]},
    {"name": "1Panel", "kind": "panel", "ind": [("d", "opt/1panel", 4), ("f", "opt/1panel/conf/app.yaml", 2), ("d", "opt/1panel/apps", 2), ("f", "usr/local/bin/1panel", 2)]},
    {"name": "cPanel/WHM", "kind": "panel", "ind": [("d", "usr/local/cpanel", 4), ("t", "usr/local/cpanel/version", 3, r"(?P<ver>[\d.]+)"), ("d", "var/cpanel", 2),
                                                   ("f", "etc/wwwacct.conf", 2), ("d", "usr/local/cpanel/whostmgr", 2), ("g", "home/*/public_html", 1)]},
    {"name": "Plesk", "kind": "panel", "ind": [("d", "usr/local/psa", 4), ("t", "usr/local/psa/version", 3, r"(?P<ver>[\d.]+)"), ("d", "etc/psa", 2), ("d", "opt/psa", 2),
                                              ("d", "var/www/vhosts", 2), ("d", "usr/local/psa/admin", 1)]},
    {"name": "DirectAdmin", "kind": "panel", "ind": [("d", "usr/local/directadmin", 4), ("f", "usr/local/directadmin/conf/directadmin.conf", 3),
                                                    ("f", "usr/local/directadmin/directadmin", 2), ("d", "etc/virtual", 1), ("g", "home/*/domains", 1)]},
    {"name": "CyberPanel", "kind": "panel", "ind": [("d", "usr/local/CyberCP", 4), ("t", "usr/local/CyberCP/version.txt", 3, r"(?P<ver>[\d.]+)"), ("d", "usr/local/lsws", 2),
                                                   ("d", "etc/cyberpanel", 2), ("d", "usr/local/lscp", 2)]},
    {"name": "HestiaCP", "kind": "panel", "ind": [("d", "usr/local/hestia", 4), ("t", "usr/local/hestia/conf/hestia.conf", 3, r"VERSION='(?P<ver>[^']+)'"), ("g", "home/*/web", 1)]},
    {"name": "VestaCP", "kind": "panel", "ind": [("d", "usr/local/vesta", 4), ("t", "usr/local/vesta/conf/vesta.conf", 3, r"VERSION='(?P<ver>[^']+)'"), ("g", "home/*/web", 1)]},
    {"name": "ISPConfig", "kind": "panel", "ind": [("d", "usr/local/ispconfig", 4), ("t", "usr/local/ispconfig/server/lib/config.inc.php", 3, r"ISPC_APP_VERSION',\s*'(?P<ver>[^']+)'"),
                                                  ("d", "var/www/clients", 2)]},
    {"name": "Webmin", "kind": "panel", "ind": [("d", "etc/webmin", 4), ("t", "etc/webmin/version", 3, r"(?P<ver>[\d.]+)"), ("d", "usr/share/webmin", 2), ("d", "usr/libexec/webmin", 2)]},
    {"name": "Virtualmin", "kind": "panel", "ind": [("d", "etc/webmin/virtual-server", 4), ("d", "etc/webmin", 2), ("g", "home/*/public_html", 1)]},
    {"name": "CloudPanel", "kind": "panel", "ind": [("d", "home/clp", 4), ("d", "home/clp/htdocs/app", 3), ("g", "home/*/htdocs", 1), ("d", "etc/clp", 2)]},
    {"name": "CentOS Web Panel", "kind": "panel", "ind": [("d", "usr/local/cwpsrv", 4), ("d", "usr/local/cwp", 3), ("d", "etc/csf", 1)]},
    {"name": "Froxlor", "kind": "panel", "ind": [("f", "var/www/froxlor/lib/userdata.inc.php", 4), ("d", "var/www/froxlor", 3), ("g", "var/customers/webs/*", 2)]},
    {"name": "Ajenti", "kind": "panel", "ind": [("d", "etc/ajenti", 4), ("d", "usr/local/ajenti", 1)]},
    {"name": "KeyHelp", "kind": "panel", "ind": [("d", "home/keyhelp", 4), ("d", "home/keyhelp/www/keyhelp", 3)]},
    {"name": "i-MSCP", "kind": "panel", "ind": [("d", "var/www/imscp", 4), ("d", "etc/imscp", 3)]},
    {"name": "Sentora/ZPanel", "kind": "panel", "ind": [("d", "etc/sentora", 4), ("d", "etc/zpanel", 4)]},
    {"name": "Kloxo", "kind": "panel", "ind": [("d", "usr/local/lxlabs", 5)]},
    {"name": "RunCloud", "kind": "panel", "ind": [("d", "RunCloud", 4), ("d", "home/runcloud", 3), ("g", "home/runcloud/webapps/*", 2)]},
    {"name": "ServerPilot", "kind": "panel", "ind": [("d", "etc/serverpilot", 4), ("g", "srv/users/*/apps/*", 3), ("d", "opt/sp", 2)]},
    {"name": "Laravel Forge", "kind": "panel", "ind": [("d", "etc/nginx/forge-conf", 4), ("d", "home/forge", 3)]},
    {"name": "Ploi", "kind": "panel", "ind": [("d", "home/ploi", 4), ("d", "etc/nginx/ploi", 2)]},
    {"name": "Easypanel", "kind": "panel", "ind": [("d", "etc/easypanel", 5)]},
    {"name": "Coolify", "kind": "panel", "ind": [("d", "data/coolify", 5)]},
    {"name": "CapRover", "kind": "panel", "ind": [("d", "captain", 5)]},
    {"name": "Dokku", "kind": "panel", "ind": [("d", "home/dokku", 4), ("d", "var/lib/dokku", 3)]},
    {"name": "Cockpit", "kind": "panel", "ind": [("d", "etc/cockpit", 3), ("d", "usr/share/cockpit", 3)]},
    {"name": "Portainer", "kind": "panel", "ind": [("d", "var/lib/docker/volumes/portainer_data", 4), ("d", "opt/portainer", 3)]},
    {"name": "Docker (containers on this host)", "kind": "runtime", "ind": [("d", "var/lib/docker/containers", 3), ("g", "var/lib/docker/containers/*/config.v2.json", 3),
                                                                           ("d", "var/lib/docker/overlay2", 2), ("f", "etc/docker/daemon.json", 1)],
     "note": "the applications may live inside the containers; see the container list"},
    {"name": "Kubernetes node", "kind": "runtime", "ind": [("d", "var/lib/kubelet", 4), ("d", "etc/kubernetes", 3), ("d", "var/lib/rancher/k3s", 4)]},
]

SERVICES: list[dict[str, Any]] = [
    {"name": "nginx", "kind": "service", "ind": [("f", "etc/nginx/nginx.conf", 3), ("d", "www/server/nginx", 3), ("t", "www/server/nginx/version.pl", 1, r"(?P<ver>[\d.]+)"),
                                                ("d", "usr/local/nginx/conf", 2)]},
    {"name": "Apache httpd", "kind": "service", "ind": [("f", "etc/apache2/apache2.conf", 3), ("f", "etc/httpd/conf/httpd.conf", 3), ("d", "www/server/apache", 3),
                                                       ("t", "www/server/apache/version.pl", 1, r"(?P<ver>[\d.]+)")]},
    {"name": "OpenLiteSpeed/LiteSpeed", "kind": "service", "ind": [("d", "usr/local/lsws", 4), ("t", "usr/local/lsws/VERSION", 2, r"(?P<ver>[\d.]+)")]},
    {"name": "PHP", "kind": "service", "ind": [("g", "www/server/php/*/bin/php", 3), ("g", "etc/php/*/fpm", 3), ("g", "usr/local/lsws/lsphp*", 2), ("f", "usr/bin/php", 1),
                                              ("f", "etc/php.ini", 1), ("d", "etc/php-fpm.d", 1)]},
    {"name": "MySQL/MariaDB", "kind": "service", "ind": [("d", "var/lib/mysql", 3), ("d", "www/server/mysql", 3), ("t", "www/server/mysql/version.pl", 1, r"(?P<ver>[\d.]+)"),
                                                        ("d", "www/server/data", 1), ("f", "etc/mysql/mariadb.cnf", 1), ("f", "etc/my.cnf", 1)]},
    {"name": "PostgreSQL", "kind": "service", "ind": [("d", "var/lib/postgresql", 4), ("d", "www/server/pgsql", 4), ("d", "etc/postgresql", 1)]},
    {"name": "Redis", "kind": "service", "ind": [("d", "var/lib/redis", 3), ("d", "www/server/redis", 3), ("f", "etc/redis/redis.conf", 1)]},
    {"name": "MongoDB", "kind": "service", "ind": [("d", "var/lib/mongodb", 4), ("d", "www/server/mongodb", 4), ("f", "etc/mongod.conf", 1)]},
    {"name": "Node.js", "kind": "service", "ind": [("d", "usr/lib/node_modules", 2), ("d", "www/server/nodejs", 3), ("d", "root/.nvm", 2), ("f", "usr/bin/node", 1), ("f", "usr/local/bin/node", 1)]},
    {"name": "PM2 (Node process manager)", "kind": "service", "ind": [("d", "root/.pm2", 3), ("f", "root/.pm2/dump.pm2", 3), ("g", "home/*/.pm2", 2)]},
    {"name": "Supervisor", "kind": "service", "ind": [("d", "etc/supervisor/conf.d", 3), ("f", "etc/supervisord.conf", 2), ("g", "etc/supervisord.d/*.ini", 2)]},
    {"name": "Python (venv/apps)", "kind": "service", "ind": [("g", "opt/*/venv/bin/python", 2), ("g", "root/*/venv/bin/python", 2), ("g", "home/*/*/venv/bin/python", 2),
                                                            ("f", "usr/bin/python3", 1), ("g", "root/.local/lib/python3*/site-packages", 1)]},
    {"name": "Java", "kind": "service", "ind": [("g", "usr/lib/jvm/*", 3), ("g", "opt/*/*.jar", 2), ("g", "root/*.jar", 2), ("g", "home/*/*.jar", 2)]},
    {"name": "Go binaries", "kind": "service", "ind": [("d", "root/go", 2), ("d", "usr/local/go", 3)]},
    {"name": "Fail2ban", "kind": "service", "ind": [("d", "etc/fail2ban", 3)]},
    {"name": "Certbot / Let's Encrypt", "kind": "service", "ind": [("d", "etc/letsencrypt/live", 3), ("d", "www/server/panel/vhost/cert", 2), ("d", "root/.acme.sh", 3)]},
    {"name": "Cloudflare tunnel / frp / ngrok", "kind": "service", "ind": [("d", "etc/cloudflared", 3), ("g", "root/.cloudflared", 3), ("g", "opt/frp*/frpc*", 2), ("g", "root/frp*/frpc*", 2), ("g", "root/.ngrok2", 3), ("g", "root/.config/ngrok", 3)]},
    {"name": "Tor", "kind": "service", "ind": [("d", "var/lib/tor", 4), ("f", "etc/tor/torrc", 2)]},
    {"name": "VPN (WireGuard/OpenVPN/xray/v2ray)", "kind": "service", "ind": [("d", "etc/wireguard", 3), ("d", "etc/openvpn", 3), ("g", "usr/local/etc/xray/*", 3), ("g", "usr/local/etc/v2ray/*", 3),
                                                                           ("g", "etc/x-ui/*", 3), ("d", "usr/local/x-ui", 3), ("d", "opt/3x-ui", 3)]},
    {"name": "Mail server", "kind": "service", "ind": [("d", "etc/postfix", 3), ("d", "etc/dovecot", 3), ("d", "etc/exim4", 3)]},
]


# ---------------------------------------------------------------------------------------------- applications
# indicators are relative to the APPLICATION root; "pkg" uses the composer package list of that root
APPS: list[dict[str, Any]] = [
    # PHP frameworks
    {"name": "ThinkPHP 6/8", "kind": "framework", "ind": [("pkg", "topthink/framework", 4), ("f", "think", 2), ("d", "app", 1), ("f", "config/app.php", 1),
                                                         ("t", "vendor/topthink/framework/src/think/App.php", 2, r"const VERSION\s*=\s*'(?P<ver>[^']+)'"), ("f", "route/app.php", 1)]},
    {"name": "ThinkPHP 5", "kind": "framework", "ind": [("f", "thinkphp/base.php", 4), ("t", "thinkphp/base.php", 2, r"THINK_VERSION\s*=\s*'(?P<ver>[^']+)'"), ("f", "think", 2),
                                                       ("d", "application", 2), ("f", "build.php", 1), ("d", "thinkphp/library/think", 2)]},
    {"name": "ThinkPHP 3", "kind": "framework", "ind": [("f", "ThinkPHP/ThinkPHP.php", 4), ("t", "ThinkPHP/ThinkPHP.php", 2, r"THINK_VERSION',\s*'(?P<ver>[^']+)'"), ("d", "Application", 2),
                                                       ("d", "ThinkPHP/Library/Think", 2)]},
    {"name": "Laravel", "kind": "framework", "ind": [("pkg", "laravel/framework", 4), ("f", "artisan", 3), ("f", "bootstrap/app.php", 2), ("f", "config/app.php", 1), ("d", "routes", 1),
                                                    ("t", "vendor/laravel/framework/src/Illuminate/Foundation/Application.php", 2, r"const VERSION\s*=\s*'(?P<ver>[^']+)'")]},
    {"name": "Lumen", "kind": "framework", "ind": [("pkg", "laravel/lumen-framework", 5), ("f", "artisan", 1)]},
    {"name": "Symfony", "kind": "framework", "ind": [("pkg", "symfony/framework-bundle", 4), ("f", "bin/console", 2), ("f", "symfony.lock", 2), ("d", "config/packages", 1), ("f", "src/Kernel.php", 1),
                                                    ("t", "vendor/symfony/http-kernel/Kernel.php", 2, r"const VERSION\s*=\s*'(?P<ver>[^']+)'")]},
    {"name": "CodeIgniter 4", "kind": "framework", "ind": [("f", "spark", 3), ("pkg", "codeigniter4/framework", 4), ("t", "system/CodeIgniter.php", 3, r"CI_VERSION\s*=\s*'(?P<ver>[^']+)'"),
                                                          ("d", "app/Controllers", 2)]},
    {"name": "CodeIgniter 3", "kind": "framework", "ind": [("t", "system/core/CodeIgniter.php", 4, r"CI_VERSION',\s*'(?P<ver>[^']+)'"), ("d", "application/controllers", 2), ("f", "system/core/Loader.php", 2)]},
    {"name": "Yii 2", "kind": "framework", "ind": [("pkg", "yiisoft/yii2", 4), ("f", "yii", 2), ("t", "vendor/yiisoft/yii2/BaseYii.php", 2, r"return '(?P<ver>[\d.]+)'"), ("f", "config/web.php", 1), ("d", "web", 1)]},
    {"name": "Yii 1", "kind": "framework", "ind": [("f", "framework/yii.php", 4), ("d", "protected", 2), ("f", "protected/config/main.php", 2)]},
    {"name": "CakePHP", "kind": "framework", "ind": [("pkg", "cakephp/cakephp", 4), ("f", "bin/cake", 3), ("d", "src/Controller", 1), ("f", "config/app.php", 1)]},
    {"name": "Slim", "kind": "framework", "ind": [("pkg", "slim/slim", 5), ("f", "public/index.php", 1)]},
    {"name": "Phalcon", "kind": "framework", "ind": [("t", "public/index.php", 4, r"Phalcon\\"), ("d", "app/controllers", 2)]},
    {"name": "Hyperf", "kind": "framework", "ind": [("f", "bin/hyperf.php", 4), ("pkg", "hyperf/framework", 4), ("d", "config/autoload", 2), ("d", "app", 1)]},
    {"name": "Webman", "kind": "framework", "ind": [("pkg", "workerman/webman-framework", 4), ("f", "start.php", 2), ("d", "app/controller", 1), ("f", "config/app.php", 1)]},
    {"name": "Workerman", "kind": "framework", "ind": [("pkg", "workerman/workerman", 3), ("pkg", "workerman/gateway-worker", 3), ("f", "start.php", 1)]},
    {"name": "EasySwoole", "kind": "framework", "ind": [("f", "easyswoole", 3), ("pkg", "easyswoole/easyswoole", 4)]},
    {"name": "Swoft", "kind": "framework", "ind": [("pkg", "swoft/framework", 5)]},
    {"name": "Laminas/Zend", "kind": "framework", "ind": [("pkg", "laminas/laminas-mvc", 4), ("pkg", "zendframework/zend-mvc", 4), ("d", "module", 1)]},
    # PHP admin frameworks (what the "panel" is usually built with)
    {"name": "FastAdmin", "kind": "admin", "ind": [("f", "application/extra/fastadmin.php", 4), ("f", "public/assets/js/fast.js", 3), ("f", "application/admin/library/Auth.php", 2),
                                                  ("f", "application/common/library/Auth.php", 1), ("d", "addons", 1), ("f", "think", 1),
                                                  ("t", "application/config.php", 1, r"'version'\s*=>\s*'(?P<ver>[\d.]+)'")],
     "note": "ThinkPHP 5 admin framework; the back office is usually at /admin.php or a renamed copy of it"},
    {"name": "BuildAdmin", "kind": "admin", "ind": [("t", "composer.json", 3, r"build-?admin"), ("f", "app/admin/library/Auth.php", 2), ("d", "web/src", 2), ("t", "web/package.json", 3, r"buildadmin")]},
    {"name": "EasyAdmin (ThinkPHP)", "kind": "admin", "ind": [("t", "composer.json", 3, r"easyadmin"), ("d", "app/admin", 1), ("g", "public/static/plugs/layui*", 2)]},
    {"name": "CatchAdmin", "kind": "admin", "ind": [("t", "composer.json", 3, r"catchadmin"), ("d", "catch", 3)]},
    {"name": "Pear Admin", "kind": "admin", "ind": [("t", "composer.json", 3, r"pear-?admin"), ("g", "public/static/admin/*", 1)]},
    {"name": "Dcat Admin", "kind": "admin", "ind": [("pkg", "dcat/laravel-admin", 5), ("d", "app/Admin", 2)]},
    {"name": "laravel-admin", "kind": "admin", "ind": [("pkg", "encore/laravel-admin", 5), ("d", "app/Admin", 2)]},
    {"name": "Filament", "kind": "admin", "ind": [("pkg", "filament/filament", 5), ("d", "app/Filament", 2)]},
    {"name": "Laravel Nova", "kind": "admin", "ind": [("pkg", "laravel/nova", 5), ("d", "app/Nova", 2)]},
    {"name": "Voyager", "kind": "admin", "ind": [("pkg", "tcg/voyager", 5)]},
    {"name": "Backpack", "kind": "admin", "ind": [("pkg", "backpack/crud", 5)]},
    {"name": "Orchid", "kind": "admin", "ind": [("pkg", "orchid/platform", 5)]},
    {"name": "EasyAdmin (Symfony)", "kind": "admin", "ind": [("pkg", "easycorp/easyadmin-bundle", 5)]},
    {"name": "Sonata Admin", "kind": "admin", "ind": [("pkg", "sonata-project/admin-bundle", 5)]},
    # PHP applications: e-commerce / investment platform families seen in fraud cases
    {"name": "CRMEB", "kind": "app", "ind": [("t", "composer.json", 3, r"crmeb"), ("d", "crmeb", 3), ("d", "app/adminapi", 1), ("t", "public/index.php", 1, r"crmeb")]},
    {"name": "likeadmin / likeshop", "kind": "app", "ind": [("t", "composer.json", 3, r"likeadmin|likeshop"), ("d", "app/adminapi", 2), ("d", "app/api", 1), ("t", "public/index.php", 1, r"likeadmin|likeshop")]},
    {"name": "NiuShop / niucloud", "kind": "app", "ind": [("t", "public/index.php", 3, r"niushop|niucloud"), ("t", "composer.json", 3, r"niushop|niucloud"), ("d", "niucloud", 3)]},
    {"name": "ShopXO", "kind": "app", "ind": [("t", "public/index.php", 4, r"shopxo"), ("t", "composer.json", 2, r"shopxo")]},
    {"name": "DSShop / DSMall", "kind": "app", "ind": [("t", "public/index.php", 4, r"dsshop|dsmall|csdeshang")]},
    {"name": "xinhu OA", "kind": "app", "ind": [("t", "index.php", 4, r"xinhu"), ("d", "webmain", 2)]},
    {"name": "WHMCS", "kind": "app", "ind": [("d", "vendor/whmcs", 3), ("t", "init.php", 3, r"whmcs"), ("d", "modules/gateways", 2), ("d", "modules/servers", 2), ("f", "configuration.php", 1)]},
    {"name": "Blesta", "kind": "app", "ind": [("f", "config/blesta.php", 5)]},
    {"name": "Pterodactyl panel", "kind": "app", "ind": [("f", "config/pterodactyl.php", 4), ("t", "composer.json", 3, r"pterodactyl/panel")]},
    {"name": "Invoice Ninja", "kind": "app", "ind": [("t", "composer.json", 5, r"invoiceninja")]},
    {"name": "Akaunting", "kind": "app", "ind": [("t", "composer.json", 5, r"akaunting")]},
    {"name": "Bagisto", "kind": "app", "ind": [("t", "composer.json", 5, r"bagisto")]},
    {"name": "Mautic", "kind": "app", "ind": [("pkg", "mautic/core-lib", 4), ("d", "app/bundles", 2)]},
    {"name": "SuiteCRM", "kind": "app", "ind": [("f", "suitecrm_version.php", 5)]},
    {"name": "vTiger", "kind": "app", "ind": [("f", "vtigerversion.php", 5)]},
    {"name": "Dolibarr", "kind": "app", "ind": [("f", "htdocs/main.inc.php", 3), ("t", "htdocs/filefunc.inc.php", 3, r"DOL_VERSION',\s*'(?P<ver>[^']+)'")]},
    {"name": "GLPI", "kind": "app", "ind": [("t", "inc/define.php", 5, r"GLPI_VERSION',\s*'(?P<ver>[^']+)'")]},
    {"name": "Zabbix frontend", "kind": "app", "ind": [("t", "include/defines.inc.php", 5, r"ZABBIX_VERSION',\s*'(?P<ver>[^']+)'")]},
    {"name": "osTicket", "kind": "app", "ind": [("f", "include/class.osticket.php", 5)]},
    {"name": "phpMyAdmin", "kind": "app", "ind": [("f", "libraries/classes/Config.php", 3), ("t", "libraries/classes/Version.php", 3, r"VERSION\s*=\s*'(?P<ver>[^']+)'"),
                                                 ("t", "index.php", 2, r"phpMyAdmin"), ("f", "config.inc.php", 1), ("d", "sql", 1)]},
    {"name": "Adminer", "kind": "app", "ind": [("t", "adminer.php", 5, r"@version\s+(?P<ver>[\d.]+)"), ("g", "adminer-*.php", 3)]},
    {"name": "Roundcube", "kind": "app", "ind": [("t", "program/include/iniset.php", 4, r"RCMAIL_VERSION',\s*'(?P<ver>[^']+)'"), ("d", "program/lib/Roundcube", 3), ("f", "config/config.inc.php", 1)]},
    {"name": "Nextcloud / ownCloud", "kind": "app", "ind": [("t", "version.php", 4, r"OC_VersionString\s*=\s*'(?P<ver>[^']+)'"), ("f", "occ", 3), ("d", "lib/private", 2), ("f", "config/config.php", 1)]},
    # CMS
    {"name": "WordPress", "kind": "cms", "ind": [("f", "wp-config.php", 3), ("d", "wp-includes", 3), ("t", "wp-includes/version.php", 3, r"\$wp_version\s*=\s*'(?P<ver>[^']+)'"), ("d", "wp-content", 1), ("d", "wp-admin", 1)]},
    {"name": "Joomla", "kind": "cms", "ind": [("f", "configuration.php", 2), ("d", "administrator", 2), ("t", "libraries/src/Version.php", 3, r"(?:MAJOR_VERSION|RELEASE)\s*=\s*'?(?P<ver>[\d.]+)"),
                                             ("t", "administrator/manifests/files/joomla.xml", 2, r"<version>(?P<ver>[^<]+)</version>"), ("d", "components", 1)]},
    {"name": "Drupal", "kind": "cms", "ind": [("t", "core/lib/Drupal.php", 4, r"const VERSION\s*=\s*'(?P<ver>[^']+)'"), ("t", "includes/bootstrap.inc", 4, r"define\('VERSION',\s*'(?P<ver>[^']+)'"),
                                             ("f", "sites/default/settings.php", 1), ("d", "modules", 1)]},
    {"name": "Magento", "kind": "cms", "ind": [("f", "bin/magento", 3), ("f", "app/etc/env.php", 3), ("pkg", "magento/product-community-edition", 4), ("pkg", "magento/magento2-base", 2), ("d", "app/code", 1)]},
    {"name": "PrestaShop", "kind": "cms", "ind": [("t", "config/settings.inc.php", 3, r"_PS_VERSION_',\s*'(?P<ver>[^']+)'"), ("t", "app/AppKernel.php", 3, r"VERSION\s*=\s*'(?P<ver>[^']+)'"),
                                                 ("f", "config/defines.inc.php", 2), ("d", "classes", 1), ("d", "modules", 1), ("g", "admin*/ajax-tab.php", 2)]},
    {"name": "OpenCart", "kind": "cms", "ind": [("t", "system/startup.php", 3, r"define\('VERSION',\s*'(?P<ver>[^']+)'"), ("d", "system/engine", 2), ("d", "catalog", 1), ("f", "admin/config.php", 2)]},
    {"name": "Shopware", "kind": "cms", "ind": [("pkg", "shopware/core", 5), ("d", "custom/plugins", 2)]},
    {"name": "TYPO3", "kind": "cms", "ind": [("pkg", "typo3/cms-core", 4), ("d", "typo3conf", 3), ("d", "typo3/sysext", 3)]},
    {"name": "Moodle", "kind": "cms", "ind": [("f", "lib/moodlelib.php", 4), ("t", "version.php", 3, r"\$release\s*=\s*'(?P<ver>[^']+)'"), ("d", "mod", 1), ("f", "config.php", 1)]},
    {"name": "MediaWiki", "kind": "cms", "ind": [("f", "includes/Defines.php", 3), ("t", "includes/DefaultSettings.php", 2, r"\$wgVersion\s*=\s*'(?P<ver>[^']+)'"), ("f", "LocalSettings.php", 2), ("d", "maintenance", 1)]},
    {"name": "phpBB", "kind": "cms", "ind": [("t", "includes/constants.php", 3, r"PHPBB_VERSION',\s*'(?P<ver>[^']+)'"), ("d", "phpbb", 2), ("d", "styles/prosilver", 2), ("f", "config.php", 1)]},
    {"name": "Discuz!", "kind": "cms", "ind": [("f", "source/class/class_core.php", 4), ("t", "source/discuz_version.php", 3, r"DISCUZ_VERSION',\s*'(?P<ver>[^']+)'"), ("f", "config/config_global.php", 2), ("d", "uc_server", 2)]},
    {"name": "DedeCMS", "kind": "cms", "ind": [("d", "dede", 3), ("t", "include/common.inc.php", 3, r"DedeCMS|DEDEVERSION"), ("f", "data/admin/ver.txt", 2), ("d", "plus", 1)]},
    {"name": "EmpireCMS", "kind": "cms", "ind": [("d", "e/admin", 3), ("f", "e/class/connect.php", 3), ("d", "e/data", 1)]},
    {"name": "PHPCMS", "kind": "cms", "ind": [("d", "phpcms", 3), ("f", "phpcms/base.php", 3), ("d", "caches", 1)]},
    {"name": "EyouCMS", "kind": "cms", "ind": [("t", "index.php", 4, r"eyoucms"), ("d", "core/library/think", 2), ("d", "data/conf", 2), ("f", "application/common.php", 1)]},
    {"name": "PbootCMS", "kind": "cms", "ind": [("t", "index.php", 4, r"pbootcms"), ("d", "apps", 1), ("f", "config/config.php", 1)]},
    {"name": "MetInfo", "kind": "cms", "ind": [("t", "index.php", 4, r"metinfo"), ("d", "app/system", 2)]},
    {"name": "Typecho", "kind": "cms", "ind": [("t", "var/Typecho/Common.php", 5, r"VERSION\s*=\s*'(?P<ver>[^']+)'")]},
    {"name": "Z-BlogPHP", "kind": "cms", "ind": [("f", "zb_system/function/c_system_base.php", 5)]},
    {"name": "ECShop", "kind": "cms", "ind": [("t", "includes/init.php", 3, r"ECSHOP|ECS"), ("f", "includes/lib_base.php", 2), ("d", "admin", 1)]},
    # Node / Python / Java / .NET / Go / static builds
    {"name": "Next.js", "kind": "framework", "ind": [("npm", "next", 4), ("d", ".next", 2), ("g", "next.config.*", 2)]},
    {"name": "Nuxt", "kind": "framework", "ind": [("npm", "nuxt", 4), ("d", ".nuxt", 2), ("g", "nuxt.config.*", 2)]},
    {"name": "NestJS", "kind": "framework", "ind": [("npm", "@nestjs/core", 4), ("f", "nest-cli.json", 2)]},
    {"name": "Express", "kind": "framework", "ind": [("npm", "express", 4), ("f", "package.json", 1)]},
    {"name": "Koa / Fastify / Hapi", "kind": "framework", "ind": [("npm", "koa", 3), ("npm", "fastify", 3), ("npm", "@hapi/hapi", 3)]},
    {"name": "Strapi", "kind": "framework", "ind": [("npm", "@strapi/strapi", 5)]},
    {"name": "Ghost", "kind": "cms", "ind": [("npm", "ghost", 4), ("d", "content/themes", 2)]},
    {"name": "Vue / React / Angular build", "kind": "framework", "ind": [("npm", "vue", 2), ("npm", "react", 2), ("npm", "@angular/core", 2), ("g", "assets/index-*.js", 2),
                                                                         ("g", "static/js/main.*.js", 2), ("t", "index.html", 1, r'id="(app|root)"'), ("d", "_next", 2), ("f", "umi.js", 2)]},
    {"name": "Django", "kind": "framework", "ind": [("f", "manage.py", 3), ("py", "django", 4), ("g", "*/settings.py", 2), ("g", "*/wsgi.py", 1)]},
    {"name": "Flask / FastAPI", "kind": "framework", "ind": [("py", "flask", 4), ("py", "fastapi", 4), ("f", "app.py", 1), ("f", "main.py", 1), ("f", "wsgi.py", 1)]},
    {"name": "Ruby on Rails", "kind": "framework", "ind": [("f", "config/routes.rb", 3), ("f", "Gemfile", 2), ("d", "app/controllers", 2), ("f", "bin/rails", 3)]},
    {"name": "Java web app", "kind": "framework", "ind": [("g", "*.war", 3), ("g", "*.jar", 2), ("d", "WEB-INF", 3), ("g", "application.properties", 2), ("g", "application.yml", 2)]},
    {"name": ".NET application", "kind": "framework", "ind": [("g", "*.runtimeconfig.json", 4), ("g", "*.deps.json", 2), ("g", "*.dll", 1), ("f", "web.config", 2)]},
    {"name": "Go binary application", "kind": "framework", "ind": [("f", "go.mod", 3), ("g", "*.go", 2)]},
]

# notable dependencies by what they are for (composer / npm / pip names, lower case; substring match)
NOTABLE: dict[str, list[str]] = {
    "crypto / blockchain": ["web3", "ethers", "bitcoin", "bitwasp", "tron", "ethereum", "solana", "kornrunner", "bitcoinjs", "walletconnect", "blockcypher", "coinbase", "binance",
                            "okx", "bybit", "kucoin", "huobi", "ccxt", "coingecko", "coinmarketcap", "usdt", "trc20", "erc20", "blockchain", "wallet", "mnemonic", "bip39", "bip32",
                            "ethereumjs", "tronweb", "tronpy", "web3.py", "bitcoinlib", "simple-bitcoin"],
    "trading / finance": ["ccxt", "tradingview", "lightweight-charts", "klinecharts", "kline", "ta-lib", "metatrader", "mt4", "mt5", "forex", "alpaca", "ibapi", "polygon", "finnhub", "yfinance"],
    "payments": ["stripe", "paypal", "braintree", "razorpay", "adyen", "square", "omnipay", "yansongda/pay", "alipay", "wechatpay", "wxpay", "overtrue/wechat", "easywechat", "unionpay",
                 "paystack", "flutterwave", "mollie", "payu", "nowpayments", "coinpayments", "cryptomus", "plisio", "paddle"],
    "Telegram / Discord / messaging": ["telegram", "telegraf", "telethon", "pyrogram", "aiogram", "discord", "whatsapp", "twilio", "signal", "matrix-", "slack", "line-bot", "viber"],
    "SMS": ["twilio", "nexmo", "vonage", "plivo", "aliyun-sms", "alibabacloud-dysmsapi", "tencentcloud", "sms", "qcloud/sms", "textmagic", "clickatell"],
    "e-mail": ["phpmailer", "swiftmailer", "symfony/mailer", "nodemailer", "sendgrid", "mailgun", "postmark", "ses", "smtplib", "aws-sdk-php", "resend"],
    "cloud storage / CDN": ["aliyuncs/oss", "qiniu", "qcloud/cos", "tencentcloud", "alibabacloud", "aws-sdk", "google-cloud-storage", "azure-storage", "minio", "upyun", "cloudflare", "backblaze"],
    "real-time / queues": ["workerman", "gateway-worker", "swoole", "socket.io", "pusher", "ratchet", "predis", "ioredis", "bull", "bullmq", "think-queue", "laravel/horizon", "rabbitmq", "amqp", "amqplib", "kafka", "celery"],
    "geo / device / fingerprinting": ["geoip", "maxmind", "ip2location", "ipinfo", "jenssegers/agent", "mobiledetect", "ua-parser", "device-detector", "fingerprintjs", "browser-detect"],
    "auth / tokens": ["firebase/php-jwt", "tymon/jwt-auth", "jsonwebtoken", "passport", "sanctum", "oauth", "pyjwt", "lcobucci/jwt", "google-authenticator", "pragmarx/google2fa", "otp", "otplib", "2fa", "speakeasy", "jwt"],
    "scraping / automation": ["puppeteer", "playwright", "selenium", "scrapy", "guzzle", "requests", "cheerio", "beautifulsoup", "symfony/dom-crawler", "goutte", "curl"],
    "exports / documents": ["phpspreadsheet", "phpexcel", "dompdf", "mpdf", "tcpdf", "snappy", "xlsx", "exceljs", "openpyxl", "reportlab", "qr-code", "qrcode", "simple-qrcode", "barcode"],
    "images / captcha": ["intervention/image", "gregwar/captcha", "mews/captcha", "topthink/think-captcha", "captcha", "sharp", "jimp", "pillow", "imagick", "gd"],
    "proxies / anonymity": ["proxy-agent", "socks", "tor", "rotating-proxy", "proxy-chain", "shadowsocks", "v2ray", "xray"],
}

CODE_EXT = {
    "PHP": {".php", ".phtml", ".php5", ".php7", ".inc"}, "Blade/Twig/Smarty templates": {".blade.php", ".twig", ".tpl", ".html.twig"},
    "JavaScript": {".js", ".mjs", ".cjs", ".jsx"}, "TypeScript": {".ts", ".tsx"}, "Vue": {".vue"}, "HTML": {".html", ".htm"}, "CSS": {".css", ".scss", ".less", ".sass"},
    "Python": {".py"}, "Go": {".go"}, "Java": {".java", ".class", ".jar", ".war"}, "Ruby": {".rb"}, "C#/.NET": {".cs", ".dll", ".cshtml"}, "Shell": {".sh", ".bash"},
    "SQL": {".sql"}, "Config/data": {".json", ".yml", ".yaml", ".xml", ".ini", ".env", ".toml", ".lock", ".conf"}, "Lua": {".lua"}, "Perl": {".pl", ".pm"}, "WebAssembly": {".wasm"},
}
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".mp4", ".mp3", ".webm", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".zip", ".gz", ".tar", ".7z",
             ".rar", ".apk", ".ipa", ".exe", ".bin", ".map", ".log", ".txt", ".md", ".csv"}
VENDOR_DIRS = {"vendor", "node_modules", ".git", "storage", "runtime", "cache", "caches", "logs", "log", "tmp", "temp", "uploads", "upload", "attachments", "bower_components",
               "__pycache__", ".idea", ".vscode", "venv", ".venv", "site-packages"}
UI_KITS = [("layui", r"layui(?:\.all)?\.js$"), ("AdminLTE", r"adminlte(?:\.min)?\.js$"), ("Element UI/Plus", r"element-(?:ui|plus)"), ("Ant Design", r"antd"), ("Bootstrap", r"bootstrap(?:\.bundle)?(?:\.min)?\.js$"),
           ("jQuery", r"jquery(?:-[\d.]+)?(?:\.min)?\.js$"), ("Vue (runtime)", r"vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js$"), ("React (runtime)", r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js$"),
           ("Tailwind", r"tailwind(?:css)?(?:\.min)?\.(?:js|css)$"), ("ECharts", r"echarts(?:\.min)?\.js$"), ("TradingView lightweight-charts", r"lightweight-charts"), ("TradingView charting_library", r"charting_library"),
           ("KLineChart", r"klinechart"), ("Socket.IO client", r"socket\.io(?:\.min)?\.js$"), ("Swiper", r"swiper(?:-bundle)?(?:\.min)?\.js$"), ("vant (mobile UI)", r"vant"), ("mui", r"\bmui(?:\.min)?\.js$"),
           ("Font Awesome", r"font-?awesome"), ("DataTables", r"datatables")]


# ---------------------------------------------------------------------------------------------- host-level facts
def vhost_roots(root: Path) -> list[dict[str, Any]]:
    """Document roots and server names from every nginx/apache/OLS vhost file found under the usual places."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    nginx_globs = ["www/server/panel/vhost/nginx/*.conf", "etc/nginx/sites-enabled/*", "etc/nginx/sites-available/*", "etc/nginx/conf.d/*.conf", "etc/nginx/nginx.conf",
                   "etc/nginx/vhost/*.conf", "usr/local/nginx/conf/vhost/*.conf", "usr/local/nginx/conf/nginx.conf", "etc/nginx/conf.d/*/*.conf", "www/server/nginx/conf/vhost/*.conf",
                   "etc/nginx/forge-conf/*", "home/*/conf/web/*/nginx.conf", "etc/nginx/vhosts/*.conf"]
    apache_globs = ["www/server/panel/vhost/apache/*.conf", "etc/apache2/sites-enabled/*", "etc/apache2/sites-available/*", "etc/httpd/conf.d/*.conf", "etc/httpd/conf/httpd.conf",
                    "etc/apache2/apache2.conf", "usr/local/apache/conf/vhost/*.conf", "etc/apache2/conf.d/*.conf", "usr/local/lsws/conf/vhosts/*/vhconf.conf"]
    for kind, globs in (("nginx", nginx_globs), ("apache", apache_globs)):
        files: list[Path] = []
        for g in globs:
            try:
                files += [p for p in root.glob(g) if _is_file(p)][:400]
            except (OSError, ValueError):
                continue
        for f in files[:1500]:
            txt = _text(root, str(f.relative_to(root)))
            if not txt:
                continue
            if kind == "nginx":
                roots = re.findall(r"^\s*root\s+([^;\s]+)\s*;", txt, re.M)
                names = re.findall(r"^\s*server_name\s+([^;]+);", txt, re.M)
                proxies = re.findall(r"^\s*proxy_pass\s+([^;\s]+)\s*;", txt, re.M)
            else:
                roots = re.findall(r"^\s*(?:DocumentRoot|docRoot)\s+\"?([^\"\s]+)", txt, re.M)
                names = re.findall(r"^\s*(?:ServerName|ServerAlias)\s+([^\n]+)", txt, re.M)
                proxies = re.findall(r"^\s*ProxyPass\s+\S+\s+(\S+)", txt, re.M)
            domains = sorted({n for line in names for n in line.split() if n and n not in ("_", "default_server", "localhost")})[:30]
            for r in dict.fromkeys(roots):
                r = r.strip().rstrip("/")
                r = r.replace("$VH_ROOT", "").replace("$SERVER_ROOT", "")
                key = (r, str(f.relative_to(root)))
                if key in seen or not r.startswith("/"):
                    continue
                seen.add(key)
                out.append({"docroot": r, "domains": domains, "conf": str(f.relative_to(root)), "server": kind, "exists": _is_dir(root / r.lstrip("/"))})
            for p in dict.fromkeys(proxies):
                out.append({"docroot": None, "proxy_pass": p, "domains": domains, "conf": str(f.relative_to(root)), "server": kind, "exists": False})
            if len(out) >= 2000:
                return out
    return out


def docker_containers(root: Path, limit: int = 200) -> list[dict[str, Any]]:
    out = []
    for cfg in sorted(root.glob("var/lib/docker/containers/*/config.v2.json"))[:limit]:
        try:
            d = json.loads(cfg.read_text("utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        c = d.get("Config") or {}
        out.append({"name": (d.get("Name") or "").lstrip("/"), "image": c.get("Image"), "cmd": " ".join(c.get("Cmd") or [])[:200], "created": d.get("Created"),
                    "running": (d.get("State") or {}).get("Running"), "ports": sorted((c.get("ExposedPorts") or {}).keys())[:20], "id": cfg.parent.name[:12],
                    "labels": {k: v for k, v in (c.get("Labels") or {}).items() if k.startswith(("com.docker.compose.project", "com.docker.compose.service"))}})
    return out


def pm2_apps(root: Path) -> list[dict[str, Any]]:
    out = []
    for dump in list(root.glob("root/.pm2/dump.pm2")) + list(root.glob("home/*/.pm2/dump.pm2")):
        try:
            for a in json.loads(dump.read_text("utf-8", errors="replace"))[:100]:
                out.append({"name": a.get("name"), "script": a.get("pm_exec_path") or a.get("script"), "cwd": a.get("pm_cwd") or a.get("cwd"), "interpreter": a.get("exec_interpreter"),
                            "from": str(dump.relative_to(root))})
        except (OSError, ValueError):
            continue
    return out


def supervisor_programs(root: Path) -> list[dict[str, Any]]:
    out = []
    files = list(root.glob("etc/supervisor/conf.d/*")) + list(root.glob("etc/supervisord.d/*.ini")) + list(root.glob("etc/supervisord.conf"))
    for f in files[:200]:
        txt = _text(root, str(f.relative_to(root)))
        for m in re.finditer(r"^\[program:([^\]]+)\]\s*\n(.*?)(?=^\[|\Z)", txt, re.M | re.S):
            body = m.group(2)
            cmd = re.search(r"^\s*command\s*=\s*(.+)$", body, re.M)
            cwd = re.search(r"^\s*directory\s*=\s*(.+)$", body, re.M)
            out.append({"program": m.group(1), "command": (cmd.group(1).strip() if cmd else "")[:200], "directory": cwd.group(1).strip() if cwd else None, "from": str(f.relative_to(root))})
    return out


_STD_UNITS = re.compile(r"^(ssh|sshd|cron|crond|rsyslog|systemd-|dbus|networkd|NetworkManager|snapd|apt-|ufw|fail2ban|unattended|getty|serial-getty|multipathd|lvm2|mdmonitor|"
                        r"polkit|udisks|cloud-|chrony|ntp|qemu-guest|open-vm|vmtoolsd|irqbalance|accounts-daemon|thermald|fwupd|ModemManager|wpa_|bluetooth|cups|avahi|"
                        r"e2scrub|fstrim|logrotate|man-db|motd|apport|setvtrgb|keyboard|console|plymouth|rc-local|emergency|rescue|basic|sysinit|default|halt|poweroff|"
                        r"reboot|shutdown|final|dm-|initrd|kmod|user@|user-runtime|sys-|dev-|proc-|run-|tmp|var-|boot|snap-|docker|containerd|nginx|apache2|httpd|php|"
                        r"mariadb|mysql|mysqld|redis|postgresql|mongod|memcached|postfix|dovecot|exim|named|bind9|bt|btpanel|ollama|supervisor|pm2|hestia|vesta|cpanel|"
                        r"psa|sw-|plesk|webmin|lsws|lscpd|cyberpanel|1panel|clp|frr|dnsmasq|resolved|timesyncd|journald|tuned|auditd|selinux|firewalld|iptables|nftables|"
                        r"packagekit|grub|netplan|wsl|hv-|hyperv|walinuxagent|waagent|google-|amazon-|ec2|do-agent|droplet|linode|vultr|oracle|rhsm|insights|"
                        r"zfs|nfs|rpc|smb|nmb|winbind|samba|lxd|lxc|snap\.|ceph|libvirt|virt|qemu|uuidd|ssh-agent|x11|gdm|lightdm|sddm|mysqlrouter|elasticsearch|kibana|"
                        r"filebeat|node_exporter|prometheus|grafana|zabbix|netdata|telegraf|monit|supervisord|rc\.local|dkms|lm-sensors|ntpsec|systemd)", re.I)


def custom_units(root: Path) -> list[dict[str, Any]]:
    """systemd units that are not part of the OS or the common services: where custom apps/bots are registered."""
    out = []
    for d in ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system", "root/.config/systemd/user"):
        p = root / d
        if not p.is_dir():
            continue
        try:
            for u in sorted(p.iterdir())[:800]:
                if not _is_file(u) or not u.name.endswith(".service") or _STD_UNITS.match(u.name):
                    continue
                txt = _text(root, str(u.relative_to(root)))
                ex = re.search(r"^\s*ExecStart\s*=\s*(.+)$", txt, re.M)
                wd = re.search(r"^\s*WorkingDirectory\s*=\s*(.+)$", txt, re.M)
                desc = re.search(r"^\s*Description\s*=\s*(.+)$", txt, re.M)
                out.append({"unit": u.name, "exec": (ex.group(1).strip() if ex else "")[:200], "cwd": wd.group(1).strip() if wd else None, "description": (desc.group(1).strip() if desc else "")[:120],
                            "from": str(u.relative_to(root)), "enabled": (root / "etc/systemd/system/multi-user.target.wants" / u.name).exists()})
        except OSError:
            continue
    return out


# ---------------------------------------------------------------------------------------------- applications
def composer_packages(app: Path) -> dict[str, str]:
    """name -> version from vendor/composer/installed.json (exact), else the composer.json require lists (constraints)."""
    pk: dict[str, str] = {}
    inst = app / "vendor" / "composer" / "installed.json"
    try:
        inst = inroot(inst) or inst
        if inst.is_file() and inst.stat().st_size < 60 * 2**20:
            d = json.loads(inst.read_text("utf-8", errors="replace"))
            items = d.get("packages") if isinstance(d, dict) else d
            for it in items or []:
                if isinstance(it, dict) and it.get("name"):
                    pk[str(it["name"]).lower()] = str(it.get("version") or "")
    except (OSError, ValueError):
        pass
    cj = app / "composer.json"
    try:
        cj = inroot(cj) or cj
        if cj.is_file() and cj.stat().st_size < 2**20:
            d = json.loads(cj.read_text("utf-8", errors="replace"))
            for sec in ("require", "require-dev"):
                for k, v in (d.get(sec) or {}).items():
                    if "/" in k:
                        pk.setdefault(k.lower(), str(v))
            if d.get("name"):
                pk.setdefault("__name__", str(d["name"]))
    except (OSError, ValueError):
        pass
    return pk


def npm_packages(app: Path) -> dict[str, str]:
    pk: dict[str, str] = {}
    for pj in (app / "package.json", app / "web" / "package.json", app / "frontend" / "package.json", app / "client" / "package.json", app / "admin" / "package.json"):
        try:
            pj = inroot(pj) or pj
            if pj.is_file() and pj.stat().st_size < 2**20:
                d = json.loads(pj.read_text("utf-8", errors="replace"))
                for sec in ("dependencies", "devDependencies"):
                    for k, v in (d.get(sec) or {}).items():
                        pk.setdefault(k.lower(), str(v))
                if d.get("name"):
                    pk.setdefault("__name__", str(d["name"]))
        except (OSError, ValueError):
            continue
    return pk


def py_packages(app: Path) -> dict[str, str]:
    pk: dict[str, str] = {}
    for rq in (app / "requirements.txt", app / "requirements" / "base.txt", app / "Pipfile", app / "pyproject.toml"):
        try:
            rq = inroot(rq) or rq
            if rq.is_file() and rq.stat().st_size < 2**20:
                for line in rq.read_text("utf-8", errors="replace").splitlines()[:2000]:
                    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]+\s*([^\s;#]+))?", line)
                    if m and not line.strip().startswith(("#", "[", "-")):
                        pk.setdefault(m.group(1).lower().replace("_", "-"), m.group(2) or "")
        except OSError:
            continue
    return pk


def _needle_hit(name: str, needle: str) -> bool:
    """A needle matches a package name as a whole token (split on / - _ . @), as a substring when it is 5+ characters,
    or as a substring when it names a vendor/package pair."""
    if "/" in needle:
        return needle in name
    if needle in re.split(r"[/_.@\-]+", name):
        return True
    return len(needle) >= 5 and needle in name


def notable_packages(pk: dict[str, str], npm: dict[str, str], py: dict[str, str]) -> dict[str, list[str]]:
    names = [n for n in list(pk) + list(npm) + list(py) if not n.startswith("__")]
    out: dict[str, list[str]] = defaultdict(list)
    for cat, needles in NOTABLE.items():
        for n in names:
            if any(_needle_hit(n, nd) for nd in needles) and n not in out[cat]:
                out[cat].append(n)
    return {k: sorted(v)[:25] for k, v in out.items() if v}


def composition(app: Path, max_files: int = MAX_FILES, budget_s: float = WALK_BUDGET_S) -> dict[str, Any]:
    """Language make-up by bytes and files: all code, and own code (vendor/node_modules/uploads/... left out); newest code files; UI kits."""
    t0 = time.time()
    all_b: Counter = Counter(); all_n: Counter = Counter()
    own_b: Counter = Counter(); own_n: Counter = Counter()
    kits: Counter = Counter()
    newest: list[tuple[float, str]] = []
    n = 0
    capped = False
    ext_map = {}
    for lang, exts in CODE_EXT.items():
        for e in exts:
            ext_map[e] = lang
    for dirpath, dirnames, filenames in os.walk(app):
        rel_dir = os.path.relpath(dirpath, app)
        parts = set(rel_dir.split(os.sep)) if rel_dir != "." else set()
        in_vendor = bool(parts & VENDOR_DIRS)
        dirnames[:] = [d for d in dirnames if not d.startswith(".git")]
        for fn in filenames:
            n += 1
            if n > max_files or time.time() - t0 > budget_s:
                capped = True
                break
            low = fn.lower()
            if low.endswith(".blade.php"):
                lang = "Blade/Twig/Smarty templates"
            else:
                ext = os.path.splitext(low)[1]
                lang = ext_map.get(ext)
                if lang is None:
                    lang = "media/other" if ext in MEDIA_EXT or not ext else "other"
            try:
                st = os.lstat(os.path.join(dirpath, fn))
            except OSError:
                continue
            if not _S_ISREG(st.st_mode):          # symlinks (they point into the seized machine's tree), FIFOs, sockets, devices: not code
                continue
            all_b[lang] += st.st_size; all_n[lang] += 1
            if not in_vendor:
                own_b[lang] += st.st_size; own_n[lang] += 1
                if lang in ("PHP", "JavaScript", "TypeScript", "Vue", "Python", "Go", "Java", "Ruby", "C#/.NET", "HTML", "Blade/Twig/Smarty templates"):
                    newest.append((st.st_mtime, os.path.join(rel_dir, fn) if rel_dir != "." else fn))
                    if len(newest) > 4000:
                        newest.sort(reverse=True); del newest[400:]
            for kit, pat in UI_KITS:
                if re.search(pat, low):
                    kits[kit] += 1
        if capped:
            break

    def pct_table(b: Counter, c: Counter) -> list[dict[str, Any]]:
        code_b = {k: v for k, v in b.items() if k not in ("media/other", "other", "Config/data")}
        tb = sum(code_b.values()) or 1
        tn = sum(v for k, v in c.items() if k in code_b) or 1
        return [{"language": k, "bytes": v, "files": c[k], "pct_bytes": round(100 * v / tb, 1), "pct_files": round(100 * c[k] / tn, 1)}
                for k, v in sorted(code_b.items(), key=lambda x: -x[1])]
    newest.sort(reverse=True)
    return {"files_seen": n, "capped": capped, "note": (f"percentages from the first {n} files walked ({'file limit' if n > max_files else 'time budget'} reached): a sample, not the whole tree" if capped else ""),
            "all": pct_table(all_b, all_n), "own": pct_table(own_b, own_n),
            "other_bytes": {k: v for k, v in all_b.items() if k in ("media/other", "other", "Config/data")},
            "newest_code": [{"mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(m)), "path": p} for m, p in newest[:15]],
            "ui_kits": [{"kit": k, "files": v} for k, v in kits.most_common(12)]}


APP_MARKERS = ("composer.json", "artisan", "think", "wp-config.php", "index.php", "package.json", "manage.py", "requirements.txt", "configuration.php", "config.php", "app.py",
               "main.py", "go.mod", "Gemfile", "web.config", "start.php", "spark", "yii", "bin/console", "bin/hyperf.php")
DOCROOT_NAMES = {"public", "web", "htdocs", "html", "webroot", "www", "public_html", "httpdocs", "dist", "build", "wwwroot"}
NESTED_MARKERS = ("composer.json", "wp-config.php", "artisan", "think", "package.json", "manage.py", "includes/bootstrap.inc", "core/lib/Drupal.php", "configuration.php",
                  "system/startup.php", "config/settings.inc.php", "source/class/class_core.php", "dede/index.php", "thinkphp/base.php", "ThinkPHP/ThinkPHP.php", "bin/console")


def _is_app_root(p: Path) -> bool:
    try:
        return _is_dir(p) and any(_is_file(p / m) for m in APP_MARKERS)
    except OSError:
        return False


def app_root_of(docroot: Path) -> Path:
    """The application root for a document root: the parent when the docroot is `public`/`web`/... of a framework tree."""
    if docroot.name in DOCROOT_NAMES and _is_app_root(docroot.parent) and not _is_file(docroot / "composer.json") and not _is_file(docroot / "wp-config.php"):
        return docroot.parent
    return docroot


def discover_app_roots(root: Path, vhosts: list[dict[str, Any]], max_roots: int = 400) -> list[dict[str, Any]]:
    """Application roots: every vhost docroot (with its domains) plus the children of the usual web roots and the
    panel-specific layouts, plus nested apps one or two levels below a site (an /admin or /api app of its own)."""
    found: dict[str, dict[str, Any]] = {}

    def add(p: Path, how: str, domains: Optional[list[str]] = None, conf: Optional[str] = None, docroot: Optional[Path] = None):
        p = inroot(p, root)              # a docroot that is a symlink (/www/wwwroot/site -> /data/site) is followed inside the image
        if p is None or not p.is_dir():
            return
        try:
            rel = "/" + str(p.relative_to(root.resolve()))
        except ValueError:
            return
        e = found.get(rel)
        if e is None:
            if len(found) >= max_roots:
                return
            dr = inroot(docroot, root) if docroot else None
            try:
                drel = ("/" + str(dr.relative_to(root.resolve()))) if dr else rel
            except ValueError:
                drel = rel
            e = found[rel] = {"root": rel, "docroot": drel, "domains": [], "confs": [], "how": how}
        for d in domains or []:
            if d not in e["domains"]:
                e["domains"].append(d)
        if conf and conf not in e["confs"]:
            e["confs"].append(conf)

    for v in vhosts:
        if v.get("docroot") and v.get("exists"):
            dr = inroot(root / v["docroot"].lstrip("/"), root)        # a symlinked docroot is followed inside the image first,
            if dr is None:                                             # so /www/wwwroot/site -> /data/site/public finds /data/site
                continue
            add(app_root_of(dr), "vhost", v.get("domains"), v.get("conf"), dr)
    layouts = list(WEB_ROOTS) + ["home/*/public_html", "home/*/web/*/public_html", "var/www/vhosts/*/httpdocs", "home/*/domains/*/public_html", "home/*/htdocs",
                                 "home/forge/*", "home/runcloud/webapps/*", "srv/users/*/apps/*/public", "var/www/clients/client*/web*/web", "opt/1panel/apps/*/*",
                                 "home/*/web", "var/www/html", "var/www/*", "srv/*", "opt/*", "home/*/*", "root/*", "www/wwwroot/*", "data/wwwroot/*", "home/wwwroot/*",
                                 "www/*", "data/*", "app", "apps/*", "usr/share/nginx/html", "var/www/*/public_html"]
    for lay in layouts:
        if "*" in lay:
            try:
                cands = [p for p in root.glob(lay) if _is_dir(p)][:300]
            except (OSError, ValueError):
                continue
        else:
            cands = [root / lay] if _is_dir(root / lay) else []
        for c in cands:
            if c.name in (".", "..") or c.name.startswith("."):
                continue
            if _is_app_root(c):
                add(app_root_of(c), "layout")
            elif lay in WEB_ROOTS or lay.endswith(("wwwroot", "html")):
                # a web root itself: its children are sites
                try:
                    for s in sorted(c.iterdir())[:300]:
                        if _is_dir(s) and _is_app_root(s):
                            add(app_root_of(s), "webroot")
                except OSError:
                    continue
    # an export tree that IS an application (a dropped repository or web root), and the applications / repositories
    # one to three levels under an export folder (source_code/<repo>, a legal return's layout, not a server's):
    # a server image keeps the layouts above; a tree without /etc/passwd gets this walk as well
    if not any(_is_file(root / h) for h in ("etc/passwd", "etc/os-release", "usr/lib/os-release")):
        if _is_app_root(root) or _is_dir(root / ".git"):
            add(root, "root")
        stack = [(root, 0)]
        seen_dirs = 0
        while stack and seen_dirs < 3000:
            d, depth = stack.pop()
            try:
                children = sorted(d.iterdir())[:400]
            except OSError:
                continue
            for c in children:
                seen_dirs += 1
                if not _is_dir(c) or c.name in VENDOR_DIRS or c.name.startswith("."):
                    continue
                if _is_app_root(c) or _is_dir(c / ".git"):
                    add(app_root_of(c) if c.name in DOCROOT_NAMES else c, "folder")
                elif depth < 2:
                    stack.append((c, depth + 1))
    # nested apps (one or two levels below a site)
    for rel in list(found)[:200]:
        base = root / rel.lstrip("/")
        stack = [(base, 0)]
        while stack:
            d, depth = stack.pop()
            if depth >= 2:
                continue
            try:
                for c in sorted(d.iterdir())[:200]:
                    if not _is_dir(c) or c.name in VENDOR_DIRS or c.name.startswith(".") or c.name in DOCROOT_NAMES:
                        continue
                    if any(_is_file(c / m) for m in NESTED_MARKERS):
                        add(c, "nested")
                    else:
                        stack.append((c, depth + 1))
            except OSError:
                continue
    return list(found.values())


def app_candidates(app: Path) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str], dict[str, str]]:
    pk, npm, py = composer_packages(app), npm_packages(app), py_packages(app)
    ctx = Ctx(app, pk, npm, py)
    return score(ctx, APPS, min_pct=25), pk, npm, py


# files that instruct an AI coding agent: their presence says the code was (at least partly) written with one
AGENT_FILES = ("AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".cursor/rules", ".windsurfrules", ".clinerules", ".github/copilot-instructions.md",
               ".aider.conf.yml", ".codex", ".continue")
LOCALE_DIRS = ("translations", "lang", "resources/lang", "locale", "locales", "i18n", "languages", "app/lang", "app/language", "language", "src/locales", "public/locales")
LANG_NAMES = {"en": "English", "ru": "Russian", "uk": "Ukrainian", "be": "Belarusian", "kk": "Kazakh", "zh": "Chinese", "zh-cn": "Chinese", "zh_cn": "Chinese", "zh-tw": "Chinese (trad.)",
              "de": "German", "fr": "French", "es": "Spanish", "pt": "Portuguese", "pt-br": "Portuguese (BR)", "pt_br": "Portuguese (BR)", "it": "Italian", "tr": "Turkish", "fa": "Persian",
              "ar": "Arabic", "hi": "Hindi", "id": "Indonesian", "vi": "Vietnamese", "th": "Thai", "pl": "Polish", "ro": "Romanian", "nl": "Dutch", "ja": "Japanese", "ko": "Korean",
              "ms": "Malay", "bn": "Bengali", "ur": "Urdu", "he": "Hebrew", "el": "Greek", "cs": "Czech", "hu": "Hungarian", "sv": "Swedish", "bg": "Bulgarian", "sr": "Serbian",
              "hr": "Croatian", "lt": "Lithuanian", "lv": "Latvian", "et": "Estonian", "ka": "Georgian", "hy": "Armenian", "az": "Azerbaijani", "uz": "Uzbek", "tg": "Tajik", "ky": "Kyrgyz",
              "mn": "Mongolian", "my": "Burmese", "km": "Khmer", "tl": "Filipino", "sw": "Swahili", "am": "Amharic", "fi": "Finnish", "da": "Danish", "no": "Norwegian", "sk": "Slovak",
              "sl": "Slovenian", "mk": "Macedonian", "sq": "Albanian"}
_LOCALE_CODE_RE = re.compile(r"^([a-z]{2,3})(?:[_-]([A-Za-z]{2,4}))?$")
_LOCALE_FILE_RE = re.compile(r"^[A-Za-z0-9_+-]+\.([a-z]{2,3}(?:[_-][A-Za-z]{2,4})?)\.(?:ya?ml|xlf|xliff|php|json|po|mo|ini|csv|txt)$")


def app_locales(app: Path, max_entries: int = 400) -> list[dict[str, Any]]:
    """The languages the application is translated into, from its translation folders: [{code, name, files}]."""
    found: Counter = Counter()
    for rel in LOCALE_DIRS:
        d = app / rel
        if not _is_dir(d):
            continue
        try:
            entries = sorted(d.iterdir())[:max_entries]
        except OSError:
            continue
        for e in entries:
            name = e.name
            if _is_dir(e) and _LOCALE_CODE_RE.match(name) and name not in ("js", "css", "src", "lib", "app", "bin", "doc", "api", "cli", "dev", "tmp", "src", "etc", "var", "log", "img"):
                found[name.lower()] += 1
            else:
                m = _LOCALE_FILE_RE.match(name)
                if m:
                    found[m.group(1).lower()] += 1
    out = []
    for code, n in found.most_common(40):
        base = code.split("_")[0].split("-")[0]
        out.append({"code": code, "name": LANG_NAMES.get(code) or LANG_NAMES.get(base) or "", "files": n})
    return out


_GIT_SECTION_RE = re.compile(r"^\s*\[([^\]\s\"]+)(?:\s+\"([^\"]*)\")?\]\s*$")


def parse_git_config(text: str) -> dict[str, dict[str, str]]:
    """A git config file as text -> {section[.subsection]: {key: value}}. Never executed, never handed to git."""
    out: dict[str, dict[str, str]] = {}
    cur = ""
    for raw in text.splitlines()[:5000]:
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = _GIT_SECTION_RE.match(line)
        if m:
            cur = m.group(1).lower() + (f'.{m.group(2)}' if m.group(2) is not None else "")
            out.setdefault(cur, {})
            continue
        if "=" in line and cur:
            k, v = line.split("=", 1)
            out[cur][k.strip().lower()] = v.strip().strip('"')
    return out


def repo_facts(app: Path) -> dict[str, Any]:
    """What .git says without running git: remotes, the checked-out branch, shallow clone, config keys that would
    run a command when git opens the repository (core.fsmonitor, core.sshCommand, hooksPath, diff.external ...)."""
    g = app / ".git"
    gitdir: Optional[Path] = None
    if _is_dir(g):
        gitdir = g
    elif _is_file(g):                                   # a worktree / submodule: "gitdir: ../.git/modules/x"
        try:
            t = g.read_text("utf-8", errors="replace")[:4096]
        except OSError:
            t = ""
        m = re.match(r"\s*gitdir:\s*(.+)", t)
        if m:
            cand = inroot((app / m.group(1).strip()) if not m.group(1).strip().startswith("/") else Path(m.group(1).strip()), _EVIDENCE_ROOT or app)
            gitdir = cand if cand and _is_dir(cand) else None
    if gitdir is None:
        return {}
    facts: dict[str, Any] = {"gitdir": str(gitdir), "remotes": [], "branch": "", "shallow": _is_file(gitdir / "shallow"), "command_keys": [], "hooks": []}
    try:
        cfg = parse_git_config((gitdir / "config").read_text("utf-8", errors="replace")[:262144]) if _is_file(gitdir / "config") else {}
    except OSError:
        cfg = {}
    for sec, kv in cfg.items():
        if sec.startswith("remote."):
            facts["remotes"].append({"name": sec[7:], "url": kv.get("url", ""), "pushurl": kv.get("pushurl", "")})
        if sec == "user" and (kv.get("name") or kv.get("email")):
            facts["user"] = {"name": kv.get("name", ""), "email": kv.get("email", "")}
    for sec, kv in cfg.items():
        for k in kv:
            full = f"{sec}.{k}"
            if full in ("core.fsmonitor", "core.sshcommand", "core.hookspath", "core.pager", "core.editor", "core.gitproxy", "core.askpass", "diff.external", "credential.helper",
                        "gpg.program", "uploadpack.packobjectshook", "receive.denycurrentbranch") or sec.startswith(("filter.", "diff.", "alias.", "includeif", "include")) \
                    and k in ("clean", "smudge", "process", "textconv", "command", "path") or sec.startswith("alias."):
                facts["command_keys"].append(f"{full} = {kv[k][:200]}")
    try:
        facts["branch"] = (gitdir / "HEAD").read_text("utf-8", errors="replace")[:200].strip().replace("ref: refs/heads/", "")
    except OSError:
        pass
    hooks = gitdir / "hooks"
    if _is_dir(hooks):
        try:
            facts["hooks"] = sorted(h.name for h in hooks.iterdir() if _is_file(h) and not h.name.endswith(".sample"))[:40]
        except OSError:
            pass
    return facts


def fingerprint_app(root: Path, entry: dict[str, Any], with_composition: bool = True) -> dict[str, Any]:
    app = root / entry["root"].lstrip("/")
    cands, pk, npm, py = app_candidates(app)
    d = dict(entry)
    d["candidates"] = cands[:8]
    d["packages"] = {"composer": {k: v for k, v in sorted(pk.items()) if not k.startswith("__")}, "npm": {k: v for k, v in sorted(npm.items()) if not k.startswith("__")},
                     "python": {k: v for k, v in sorted(py.items())}}
    d["package_names"] = {"composer": pk.get("__name__"), "npm": npm.get("__name__")}
    d["notable"] = notable_packages(pk, npm, py)
    d["repo"] = repo_facts(app)
    d["locales"] = app_locales(app)
    d["agent_files"] = [f for f in AGENT_FILES if _is_file(app / f) or _is_dir(app / f)]
    if with_composition:
        d["composition"] = composition(app)
    try:
        st = app.stat()
        d["mtime"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(st.st_mtime))
    except OSError:
        pass
    return d


# ---------------------------------------------------------------------------------------------- databases
DB_SIGS: list[dict[str, Any]] = [
    {"name": "FastAdmin", "kind": "admin", "tables": ["admin", "admin_log", "auth_group", "auth_group_access", "auth_rule", "attachment", "category", "config", "ems", "sms", "user",
                                                       "user_group", "user_money_log", "user_rule", "user_score_log", "user_token", "version", "area"], "prefix": "fa_", "min": 6},
    {"name": "Laravel", "kind": "framework", "tables": ["migrations", "failed_jobs", "password_resets", "password_reset_tokens", "personal_access_tokens", "jobs", "sessions", "cache", "cache_locks", "job_batches"], "min": 2},
    {"name": "spatie/laravel-permission", "kind": "framework", "tables": ["permissions", "roles", "model_has_roles", "role_has_permissions", "model_has_permissions"], "min": 3},
    {"name": "Dcat Admin / laravel-admin", "kind": "admin", "tables": ["admin_users", "admin_roles", "admin_permissions", "admin_menu", "admin_role_users", "admin_role_permissions", "admin_role_menu",
                                                                       "admin_user_permissions", "admin_settings", "admin_extensions", "admin_extension_histories", "admin_operation_log"], "min": 4},
    {"name": "ThinkPHP application (think_/tp_ prefix)", "kind": "framework", "tables": [], "prefix_only": ["think_", "tp_"], "min": 1},
    {"name": "CRMEB", "kind": "app", "tables": ["system_admin", "system_config", "system_menus", "system_role", "store_product", "store_order", "user_bill", "user_extract", "user_recharge",
                                               "user_brokerage", "user_money", "member_card", "system_attachment", "wechat_user", "store_cart"], "prefix": "eb_", "min": 5},
    {"name": "likeadmin / likeshop", "kind": "app", "tables": ["admin", "admin_dept", "admin_jobs", "admin_role", "admin_session", "system_menu", "system_role_menu", "config", "user", "user_auth",
                                                               "user_session", "account_log", "dict_type", "dict_data", "notice_record", "notice_setting", "operation_log", "decorate_page"], "prefix": "la_", "min": 6},
    {"name": "WordPress", "kind": "cms", "tables": ["posts", "postmeta", "options", "users", "usermeta", "terms", "term_taxonomy", "term_relationships", "comments", "commentmeta", "links"], "prefix": "wp_", "min": 5},
    {"name": "WooCommerce", "kind": "cms", "tables": ["woocommerce_sessions", "woocommerce_order_items", "woocommerce_order_itemmeta", "wc_order_stats", "wc_customer_lookup", "wc_orders"], "min": 2},
    {"name": "Joomla", "kind": "cms", "tables": ["assets", "banners", "content", "extensions", "menu", "menu_types", "modules", "template_styles", "user_usergroup_map", "usergroups", "viewlevels", "session", "update_sites"], "min": 6},
    {"name": "Drupal", "kind": "cms", "tables": ["node", "node_field_data", "users_field_data", "cache_bootstrap", "key_value", "watchdog", "router", "config", "cache_config", "path_alias", "taxonomy_term_data"], "min": 5},
    {"name": "PrestaShop", "kind": "cms", "tables": ["configuration", "customer", "orders", "cart", "product", "product_lang", "employee", "module", "address", "carrier", "order_detail", "shop", "lang"], "prefix": "ps_", "min": 7},
    {"name": "OpenCart", "kind": "cms", "tables": ["product_description", "customer", "order", "setting", "extension", "user", "zone", "category_description", "store", "language", "currency", "session"], "prefix": "oc_", "min": 7},
    {"name": "Magento", "kind": "cms", "tables": ["core_config_data", "catalog_product_entity", "sales_order", "customer_entity", "eav_attribute", "admin_user", "quote", "store", "cms_page"], "min": 4},
    {"name": "Discuz!", "kind": "cms", "tables": ["common_member", "forum_post", "forum_thread", "common_setting", "ucenter_members", "common_admincp_member", "forum_forum", "common_session"], "prefix": "pre_", "min": 4},
    {"name": "DedeCMS", "kind": "cms", "tables": ["addonarticle", "archives", "arctype", "admin", "sysconfig", "member", "channeltype", "arcatt"], "prefix": "dede_", "min": 4},
    {"name": "EmpireCMS", "kind": "cms", "tables": ["enewsclass", "enewsuser", "ecms_news", "enewspublic", "enewsinfo"], "prefix": "phome_", "min": 2},
    {"name": "PHPCMS", "kind": "cms", "tables": ["admin", "category", "model", "module", "menu", "news", "member", "site"], "prefix": "v9_", "min": 5},
    {"name": "EyouCMS", "kind": "cms", "tables": ["archives", "arctype", "admin", "config", "users", "users_level", "article_content", "channeltype"], "prefix": "ey_", "min": 5},
    {"name": "Typecho", "kind": "cms", "tables": ["contents", "metas", "relationships", "comments", "options", "users", "fields"], "prefix": "typecho_", "min": 4},
    {"name": "ECShop", "kind": "cms", "tables": ["goods", "order_info", "users", "admin_user", "shop_config", "category", "order_goods", "sessions"], "prefix": "ecs_", "min": 5},
    {"name": "phpBB", "kind": "cms", "tables": ["users", "posts", "topics", "forums", "config", "sessions", "acl_groups", "styles"], "prefix": "phpbb_", "min": 6},
    {"name": "MyBB", "kind": "cms", "tables": ["users", "posts", "threads", "forums", "settings", "sessions", "usergroups"], "prefix": "mybb_", "min": 5},
    {"name": "Yii 2", "kind": "framework", "tables": ["migration", "auth_assignment", "auth_item", "auth_item_child", "auth_rule", "session"], "min": 3},
    {"name": "Symfony / Doctrine", "kind": "framework", "tables": ["doctrine_migration_versions", "messenger_messages", "migration_versions"], "min": 1},
    {"name": "CodeIgniter", "kind": "framework", "tables": ["ci_sessions", "migrations"], "min": 1},
    {"name": "Django", "kind": "framework", "tables": ["django_migrations", "auth_user", "django_session", "django_admin_log", "django_content_type", "auth_permission", "auth_group"], "min": 3},
    {"name": "Ruby on Rails", "kind": "framework", "tables": ["schema_migrations", "ar_internal_metadata"], "min": 2},
    {"name": "Flask / SQLAlchemy (Alembic)", "kind": "framework", "tables": ["alembic_version"], "min": 1},
    {"name": "Node: Sequelize / Knex / Prisma / TypeORM", "kind": "framework", "tables": ["sequelizemeta", "knex_migrations", "knex_migrations_lock", "_prisma_migrations", "typeorm_metadata"], "min": 1},
    {"name": "WHMCS", "kind": "app", "tables": ["tblclients", "tblinvoices", "tblhosting", "tbladmins", "tblconfiguration", "tblorders", "tbltickets", "tblproducts"], "min": 4},
    {"name": "Pterodactyl", "kind": "app", "tables": ["servers", "nodes", "eggs", "nests", "allocations", "api_keys", "egg_variables", "server_variables", "locations"], "min": 5},
    {"name": "aaPanel / BT panel database", "kind": "panel", "tables": ["sites", "domain", "ftps", "databases", "users", "config", "crontab", "logs", "firewall", "backup", "binding", "tasks", "task_list"], "min": 8},
    {"name": "Investment / trading platform pattern (not a product name)", "kind": "pattern",
     "tables": ["recharge", "user_recharge", "recharge_order", "withdraw", "withdrawal", "user_withdraw", "user_extract", "wallet", "user_wallet", "wallet_log", "coin", "coins", "coin_type",
                "currency", "kline", "market", "contract", "contract_order", "lever", "leverage", "lever_order", "mining", "miner", "miner_order", "invite", "invite_log", "agent", "agent_level",
                "commission", "commission_log", "vip", "vip_level", "level", "task", "task_log", "bank_card", "user_bank", "usdt", "trc20", "erc20", "address", "user_address", "transfer",
                "profit", "profit_log", "income", "income_log", "product", "products", "investment", "invest", "invest_order", "fund", "finance", "financial", "order", "orders", "trade",
                "trade_log", "bonus", "reward", "team", "team_level", "robot", "customer_service", "kefu", "notice", "banner", "verify", "kyc", "real_name", "identity", "auth"],
     "min": 8, "note": "tables that recur in crypto investment / pig-butchering platforms; a pattern score, not an identification"},
]


def _strip_prefix(name: str, prefix: str) -> str:
    return name[len(prefix):] if prefix and name.startswith(prefix) else name


def db_candidates(table_names: list[str]) -> dict[str, Any]:
    """Prefix statistics and signature scores over a list of table names (one database)."""
    names = [t.lower() for t in table_names]
    nameset = set(names)
    # prefixes: the part before the first '_' when at least 3 tables share it
    pre: Counter = Counter()
    for n in names:
        if "_" in n:
            pre[n.split("_", 1)[0] + "_"] += 1
    prefixes = {p: c for p, c in pre.most_common(8) if c >= 3}
    out = []
    for sig in DB_SIGS:
        if sig.get("prefix_only"):
            hit = [p for p in sig["prefix_only"] if any(n.startswith(p) for n in names)]
            if hit:
                cnt = sum(1 for n in names if n.startswith(tuple(hit)))
                out.append({"name": sig["name"], "kind": sig["kind"], "pct": min(100, 40 + 10 * min(cnt, 6)), "matched": [f"{cnt} tables with prefix {', '.join(hit)}"], "missed": [], "prefix": hit[0]})
            continue
        best = None
        for prefix in [sig.get("prefix", "")] + list(prefixes) + [""]:
            stripped = {_strip_prefix(n, prefix) for n in names} if prefix else nameset
            got = [t for t in sig["tables"] if t in stripped]
            if best is None or len(got) > len(best[1]):
                best = (prefix, got)
        prefix, got = best
        if len(got) < sig["min"]:
            continue
        pct = int(round(100 * len(got) / len(sig["tables"])))
        if sig["kind"] == "pattern":
            pct = min(100, int(round(100 * len(got) / 20)))      # 20 of the pattern tables = certain
        d = {"name": sig["name"], "kind": sig["kind"], "pct": max(pct, 10), "matched": [(prefix + t) for t in got][:40], "missed": [t for t in sig["tables"] if t not in got][:12], "prefix": prefix}
        if sig.get("note"):
            d["note"] = sig["note"]
        out.append(d)
    out.sort(key=lambda d: (-d["pct"], d["name"]))
    return {"tables": len(names), "prefixes": prefixes, "candidates": out}


def fingerprint_databases(case) -> list[dict[str, Any]]:
    from . import dbexport
    out = []
    for e in dbexport.list_exports(case):
        tcsv = Path(e["dir"]) / "tables.csv"
        if not tcsv.exists():
            continue
        by_db: dict[str, list[str]] = defaultdict(list)
        try:
            with open(tcsv, "r", encoding="utf-8-sig", newline="") as f:
                for r in csv.DictReader(f):
                    if r.get("table"):
                        by_db[r.get("database") or ""].append(r["table"])
        except OSError:
            continue
        for db, tables in by_db.items():
            d = db_candidates(tables)
            d.update({"export": e["name"], "database": db, "source": e.get("source")})
            out.append(d)
    return out


# ---------------------------------------------------------------------------------------------- run / explain
def fingerprint_host(root: Path) -> dict[str, Any]:
    set_root(root)
    ctx = Ctx(root)
    panels = score(ctx, PANELS)
    # aaPanel and BT Panel share one tree: keep the one whose own text marker matched (the higher score) when both score;
    # when both score the same (an upgraded panel carries both marker sets) both stay and the tie is said
    names = {p["name"]: p for p in panels}
    if "aaPanel" in names and "BT Panel (宝塔)" in names:
        if names["aaPanel"]["pct"] != names["BT Panel (宝塔)"]["pct"]:
            loser = "BT Panel (宝塔)" if names["aaPanel"]["pct"] > names["BT Panel (宝塔)"]["pct"] else "aaPanel"
            panels = [p for p in panels if p["name"] != loser]
        else:
            for p in panels:
                if p["name"] in ("aaPanel", "BT Panel (宝塔)"):
                    p["note"] = "tie with " + ("BT Panel (宝塔)" if p["name"] == "aaPanel" else "aaPanel") + ": both marker sets present (an upgraded or rebranded panel); decide from the panel's own text"
    services = score(ctx, SERVICES, min_pct=10)
    php_versions = sorted({p.split("/")[-3] for p in _glob(root, "www/server/php/*/bin/php", 20)} | {p.split("/")[-2] for p in _glob(root, "etc/php/*/fpm", 20)})
    return {"os": os_release(root), "hostname": (_read_small(root / "etc" / "hostname").strip().splitlines() or [""])[0], "panels": panels, "services": services,
            "php_versions": php_versions, "containers": docker_containers(root), "pm2": pm2_apps(root), "supervisor": supervisor_programs(root), "units": custom_units(root)}


def fingerprint_tree(root: Path, log: Log = print, with_composition: bool = True, max_apps: int = 60) -> dict[str, Any]:
    """Host + applications for a mounted filesystem or an extracted tree (no case needed)."""
    root = Path(root)
    set_root(root)
    t0 = time.time()
    host = fingerprint_host(root)
    vh = vhost_roots(root)
    roots = discover_app_roots(root, vh)
    # the biggest / vhost-backed first; composition only for the first max_apps
    roots.sort(key=lambda e: (0 if e["how"] == "vhost" else 1, e["root"]))
    apps = []
    for i, e in enumerate(roots):
        apps.append(fingerprint_app(root, e, with_composition=with_composition and i < max_apps and (time.time() - t0) < TOTAL_BUDGET_S))
    log(f"[fingerprint] host: {', '.join(p['name'] + ' ' + str(p['pct']) + '%' for p in host['panels'][:3]) or 'no control panel recognised'}; "
        f"{len(vh)} vhost entries, {len(apps)} application roots, {len(host['containers'])} containers in {time.time() - t0:.1f} s")
    return {"generated": utc_now(), "root": str(root), "host": host, "vhosts": vh[:500], "apps": apps, "seconds": round(time.time() - t0, 1)}


def _app_line(a: dict[str, Any]) -> str:
    top = a.get("candidates") or []
    fw = ", ".join(f"{c['name']}{(' ' + c['version']) if c.get('version') else ''} ({c['pct']}%)" for c in top[:3]) or "no known framework/CMS"
    comp = a.get("composition") or {}
    own = comp.get("own") or []
    mix = " / ".join(f"{r['language']} {r['pct_bytes']:.0f}%" for r in own[:4])
    dom = ", ".join(a.get("domains", [])[:4])
    return f"{a['root']}" + (f" [{dom}]" if dom else "") + f": {fw}" + (f"; own code {mix}" if mix else "")


def explain(fp: dict[str, Any]) -> str:
    """A readable report (Markdown-ish) of a fingerprint result."""
    L: list[str] = []
    h = fp.get("host") or {}
    if h:
        L.append(f"HOST: {h.get('os') or '?'}" + (f", hostname {h['hostname']}" if h.get("hostname") else ""))
        if h.get("panels"):
            for p in h["panels"][:6]:
                L.append(f"  panel/runtime: {p['name']}" + (f" {p['version']}" if p.get("version") else "") + f" - {p['pct']}% ({len(p['matched'])} of {len(p['matched']) + len(p['missed'])} indicators: "
                         + "; ".join(p["matched"][:4]) + ")" + (f" - {p['note']}" if p.get("note") else ""))
        else:
            L.append("  no known control panel (aaPanel/BT, cPanel, Plesk, DirectAdmin, CyberPanel, Hestia, ISPConfig, CloudPanel, 1Panel, CWP, Webmin ... none of their trees exist)")
        if h.get("services"):
            L.append("  services: " + ", ".join(f"{s['name']}{(' ' + s['version']) if s.get('version') else ''}" for s in h["services"][:14]) + (f"; PHP {', '.join(h['php_versions'])}" if h.get("php_versions") else ""))
        if h.get("containers"):
            L.append(f"  Docker containers ({len(h['containers'])}): " + "; ".join(f"{c['name']} = {c['image']}" for c in h["containers"][:12]))
        if h.get("pm2"):
            L.append("  PM2 apps: " + "; ".join(f"{a['name']} ({a['script']})" for a in h["pm2"][:10]))
        if h.get("supervisor"):
            L.append("  supervisor programs: " + "; ".join(f"{a['program']}: {a['command']}" for a in h["supervisor"][:10]))
        if h.get("units"):
            L.append("  custom systemd units: " + "; ".join(f"{u['unit']}: {u['exec']}" for u in h["units"][:10]))
    apps = fp.get("apps") or []
    if apps:
        L.append(f"APPLICATIONS ({len(apps)} roots):")
        for a in apps[:40]:
            L.append("  " + _app_line(a))
            for c in (a.get("candidates") or [])[:3]:
                L.append(f"      {c['name']}: {c['pct']}% - " + "; ".join(c["matched"][:5]) + (f" - {c['note']}" if c.get("note") else ""))
            if a.get("notable"):
                L.append("      notable packages: " + "; ".join(f"{k}: {', '.join(v[:6])}" for k, v in a["notable"].items()))
            rp = a.get("repo") or {}
            if rp:
                L.append("      git repository: " + (", ".join(f"{r['name']} = {r['url']}" for r in rp.get("remotes", [])[:4]) or "no remote configured")
                         + (f"; branch {rp['branch']}" if rp.get("branch") else "") + ("; shallow clone" if rp.get("shallow") else "")
                         + (f"; local user {rp['user'].get('name', '')} <{rp['user'].get('email', '')}>" if rp.get("user") else "")
                         + (f"; CUSTOM HOOKS: {', '.join(rp['hooks'][:6])}" if rp.get("hooks") else "")
                         + (f"; CONFIG RUNS COMMANDS: {'; '.join(rp['command_keys'][:4])}" if rp.get("command_keys") else ""))
            if a.get("locales"):
                L.append("      translated into: " + ", ".join(f"{l['code']}" + (f" ({l['name']})" if l.get("name") else "") for l in a["locales"][:12]))
            if a.get("agent_files"):
                L.append("      AI coding-agent instruction files: " + ", ".join(a["agent_files"]) + " (the code was written at least partly with an AI coding agent)")
            comp = a.get("composition") or {}
            if comp.get("ui_kits"):
                L.append("      UI kits: " + ", ".join(k["kit"] for k in comp["ui_kits"][:8]))
            if comp.get("newest_code"):
                L.append("      newest code: " + "; ".join(f"{n['mtime']} {n['path']}" for n in comp["newest_code"][:3]))
    dbs = fp.get("databases") or []
    if dbs:
        L.append(f"DATABASES ({len(dbs)}):")
        for d in dbs[:30]:
            cands = d.get("candidates") or []
            L.append(f"  {d.get('export')}/{d.get('database')}: {d['tables']} tables" + (f", prefixes {', '.join(f'{p} ({c})' for p, c in d['prefixes'].items())}" if d.get("prefixes") else "")
                     + (" - " + "; ".join(f"{c['name']} {c['pct']}% ({len(c['matched'])} tables)" for c in cands[:4]) if cands else " - no known table signature"))
    return "\n".join(L)


def summary_line(fp: dict[str, Any]) -> str:
    h = fp.get("host") or {}
    parts = []
    if h.get("panels"):
        parts.append(" / ".join(f"{p['name']}{(' ' + p['version']) if p.get('version') else ''} {p['pct']}%" for p in h["panels"][:2]))
    elif fp.get("host"):
        parts.append("no known control panel")
    apps = fp.get("apps") or []
    named = [a for a in apps if a.get("candidates")]
    if named:
        best = sorted(named, key=lambda a: -a["candidates"][0]["pct"])[:3]
        parts.append("; ".join(f"{a['root']}: " + ", ".join(f"{c['name']} {c['pct']}%" for c in a["candidates"][:2]) for a in best))
    elif apps:
        parts.append(f"{len(apps)} application root(s), no known framework")
    dbs = [d for d in (fp.get("databases") or []) if d.get("candidates")]
    if dbs:
        parts.append("; ".join(f"db {d['database']}: {d['candidates'][0]['name']} {d['candidates'][0]['pct']}%" for d in dbs[:3]))
    return " · ".join(parts) if parts else "nothing recognised"


def run(case, log: Log = print, root: Optional[Path] = None) -> dict[str, Any]:
    """Fingerprint the case: its mount/tree root (when readable) plus its database exports; writes collected/fingerprint.json
    and appends/replaces the `stack.fingerprint` finding."""
    from .normalize.base import Finding
    r = Path(root) if root else case.mount_root
    fp: dict[str, Any] = {"generated": utc_now(), "root": str(r)}
    if r and r.is_dir() and _nonempty_dir(r):
        fp.update(fingerprint_tree(r, log))
    else:
        fp.update({"host": {}, "vhosts": [], "apps": []})
        log(f"[fingerprint] {r} is not readable; databases only")
    fp["databases"] = fingerprint_databases(case)
    fp["summary"] = summary_line(fp)
    fp["report"] = explain(fp)
    case.write_json("fingerprint.json", fp)
    # the finding: one per case, replaced on re-run
    findings = [f for f in case.read_findings() if f.get("rule") not in ("stack.fingerprint", "stack.platform_pattern")]
    f = Finding(source="fingerprint", severity="info", rule="stack.fingerprint", title=f"What it is built on: {fp['summary']}"[:300],
                description=fp["report"][:6000], tags=["stack", "fingerprint"], extra={"summary": fp["summary"]})
    findings.append(f.to_dict())
    pats = [(d, c) for d in fp["databases"] for c in d.get("candidates", []) if c["kind"] == "pattern" and c["pct"] >= 40]
    if pats:
        d, c = max(pats, key=lambda x: x[1]["pct"])
        f2 = Finding(source="fingerprint", severity="low", rule="stack.platform_pattern",
                     title=f"Database {d['database']} has the table pattern of an investment / trading platform ({c['pct']}%: {len(c['matched'])} typical tables)",
                     description="Tables such as " + ", ".join(c["matched"][:20]) + ". This is a pattern score over table names, not an identification of a product; "
                                 "look at the Players tab (wallets, money) and the Databases tab (recharge/withdraw tables) for what moved.",
                     tags=["stack", "platform-pattern"], extra={"tables": c["matched"]})
        findings.append(f2.to_dict())
    case.write_findings(findings)
    try:
        from .collect import write_summary
        write_summary(case, findings)            # the sidebar's counts follow the findings file
    except Exception:  # noqa: BLE001 - the summary is a convenience; the findings are written
        pass
    case.custody.append("fingerprinted", {"summary": fp["summary"], "apps": len(fp.get("apps") or []), "databases": len(fp["databases"])})
    log(f"[fingerprint] {fp['summary']}")
    return fp


def load(case) -> Optional[dict[str, Any]]:
    return case.read_json("fingerprint.json", None)
