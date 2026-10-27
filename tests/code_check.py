"""The source-code stage on a small export tree with two git repositories, configuration and code (review-driven):
repositories read without loading the seized config, deleted secrets recovered from history, endpoints classified,
configuration database names matched to an extracted database, and the result searchable as a "code" export.
`python tests/code_check.py` - needs git in PATH; no model, evidence or network."""
import csv, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gumshoe import code as codemod, dbexport, dbexplore, fingerprint  # noqa: E402
from gumshoe.case import Case, load_config  # noqa: E402

ok = True


def check(name, cond, detail=""):
    global ok
    ok = ok and bool(cond)
    print(("  [PASS] " if cond else "  [FAIL] ") + name + (f" - {detail}" if detail and not cond else ""))


def git(repo, *args, env=None):
    e = dict(os.environ, GIT_AUTHOR_DATE=env.get("D") if env else "2026-02-01T10:00:00+0300",
             GIT_COMMITTER_DATE=env.get("D") if env else "2026-02-01T10:00:00+0300",
             GIT_AUTHOR_NAME=(env or {}).get("N", "Dev One"), GIT_AUTHOR_EMAIL=(env or {}).get("E", "dev1@ecopanel.su"),
             GIT_COMMITTER_NAME=(env or {}).get("N", "Dev One"), GIT_COMMITTER_EMAIL=(env or {}).get("E", "dev1@ecopanel.su"),
             GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    subprocess.run(["git", *args], cwd=repo, env=e, check=True, capture_output=True)


if not shutil.which("git"):
    print("git not installed; skipping code_check")
    sys.exit(0)

tmp = Path(tempfile.mkdtemp(prefix="gc-"))
src = tmp / "source_code"
# repo 1: ep — a deleted .env secret, a dangerous config key, a Telegram token in code, an AGENTS.md
ep = src / "ep"
(ep / "config").mkdir(parents=True)
(ep / "src").mkdir()
git(ep, "init", "-q", "-b", "main")
git(ep, "remote", "add", "origin", "https://ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@github.com/ecopanel/ep.git")
(ep / ".env").write_text("APP_ENV=prod\nDB_HOST=127.0.0.1\nDB_DATABASE=sw\nDB_USERNAME=app\nDB_PASSWORD=S3cretDbPass!\n"
                         "TELEGRAM_BOT_TOKEN=7111111111:AAHfiqksKZ8WmR2zSjiQ7_v4TVAKyXg9w1Abcd\nAFTERSHIP_API_KEY=asat_0123456789abcdef0123456789abcdef\n"
                         "SMS_ACTIVATE_KEY=0123456789abcdef0123456789abcdef\n", "utf-8")
(ep / "AGENTS.md").write_text("# Instructions for the coding agent\nUse Symfony. The bot lives in EcopanelBot.\n", "utf-8")
(ep / "src" / "Bot.php").write_text("<?php\n// talks to Telegram and the SMS provider\n$u='https://api.telegram.org/bot7222222222:BBHfiqksKZ8WmR2zSjiQ7_v4TVAKyXg9w1Axyz/sendMessage';\n"
                                    "$sms='https://api.sms-activate.org/stubs/handler_api.php';\n$ip='http://185.220.101.5:8080/gate';\n$admin='admin@ecopanel.su';\n", "utf-8")
(ep / "composer.json").write_text(json.dumps({"name": "ecopanel/ep", "require": {"symfony/framework-bundle": "^6.4", "aftership/aftership-sdk-php": "^2.0"}}), "utf-8")
(ep / "config" / "services.yaml").write_text("parameters:\n  telegram:\n    token: 7333333333:CCHfiqksKZ8WmR2zSjiQ7_v4TVAKyXg9w1Auvw\n  payments:\n    perfect_money: PM-ACCT-1234\n", "utf-8")
git(ep, "add", "-A")
git(ep, "commit", "-q", "-m", "initial import with .env", env={"D": "2026-02-01T10:00:00+0300", "N": "Dev One", "E": "dev1@ecopanel.su"})
# second commit by a second developer in another timezone: remove the committed .env (secret now only in history)
(ep / ".gitignore").write_text(".env\n", "utf-8")
git(ep, "rm", "-q", "--cached", ".env")
git(ep, "add", "-A")
git(ep, "commit", "-q", "-m", "stop tracking .env", env={"D": "2026-02-05T09:30:00-0500", "N": "Vlad Two", "E": "vlad@protonmail.com"})
(ep / ".env").write_text("APP_ENV=prod\nDB_HOST=127.0.0.1\nDB_DATABASE=sw\nDB_USERNAME=app\nDB_PASSWORD=RotatedPass2026!\n"
                         "TELEGRAM_BOT_TOKEN=7111111111:AAHfiqksKZ8WmR2zSjiQ7_v4TVAKyXg9w1Abcd\n", "utf-8")   # rotated on disk, not committed
# a dangerous local config key, and a reflog entry from a reset
subprocess.run(["git", "config", "core.fsmonitor", "/tmp/evil.sh"], cwd=ep, check=True, capture_output=True,
               env=dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null"))
(ep / "src" / "temp.php").write_text("<?php // scratch\n", "utf-8")
git(ep, "add", "-A")
git(ep, "commit", "-q", "-m", "scratch (will be reset)", env={"D": "2026-02-06T11:00:00-0500", "N": "Vlad Two", "E": "vlad@protonmail.com"})
git(ep, "reset", "-q", "--hard", "HEAD~1")              # the scratch commit is now unreachable / reflog-only

# repo 2: EcopanelBot — just so there are two
bot = src / "EcopanelBot"
(bot).mkdir(parents=True)
git(bot, "init", "-q", "-b", "main")
git(bot, "remote", "add", "origin", "git@github.com:ecopanel/EcopanelBot.git")
(bot / ".env").write_text("BOT_TOKEN=7444444444:DDHfiqksKZ8WmR2zSjiQ7_v4TVAKyXg9w1Arst\nMYSQL_DATABASE=ewmanager\nPROXY=socks5://user:pass@185.100.87.202:9050\n", "utf-8")
(bot / "setup.php").write_text("<?php $db='mysql://bot:pw@127.0.0.1/ewmanager'; $track='https://api.aftership.com/v4/trackings';\n", "utf-8")
git(bot, "add", "-A")
git(bot, "commit", "-q", "-m", "bot", env={"D": "2026-02-02T12:00:00+0300", "N": "Dev One", "E": "dev1@ecopanel.su"})

# a case whose extracted databases include `sw` and `ewmanager`, so config/export_links matches
cases = tmp / "cases"; cases.mkdir()
case = Case.create(cases, "EP1", "tester", None, str(src), "export", load_config(None))
for dumpname, dbs in (("dump_sw.sql", ["sw"]), ("dumps_ewmanager.sql", ["ewmanager"])):
    d = case.dir / "db" / dbexport.slug(dumpname)
    d.mkdir(parents=True)
    (d / "source.json").write_text(json.dumps({"kind": "mysql-dump", "name": dbexport.slug(dumpname), "out": str(d / "out"),
                                               "tables": [{"database": db, "table": "users", "rows": 1, "files": []} for db in dbs]}), "utf-8")

code = codemod.run(case, log=lambda s: None, root=src)

check("both repositories found", len(code["repos"]) == 2 and {r["name"] for r in code["repos"]} == {"ep", "EcopanelBot"}, str([r["name"] for r in code["repos"]]))
epr = next(r for r in code["repos"] if r["name"] == "ep")
check("ep remote URL read from config", any("github.com/ecopanel/ep" in x["url"] for x in epr["remotes"]), str(epr["remotes"]))
check("the dangerous core.fsmonitor key is reported, and git never ran it", any("core.fsmonitor" in k for k in epr["command_keys"]), str(epr["command_keys"]))
check("AGENTS.md flagged as AI-agent instructions", "AGENTS.md" in epr["agent_files"], str(epr["agent_files"]))
check("the reset scratch commit is reflog-only or unreachable", epr["reflog_only"] >= 1 or epr["unreachable_commits"] >= 1, f"reflog_only={epr['reflog_only']} unreachable={epr['unreachable_commits']}")

out = Path(code["out"])


def rows(db, tbl):
    p = out / dbexport.slug(db) / f"{tbl}.csv"
    with open(p, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


commits = rows("git", "commits")
check("commits carry the author's UTC offset (two timezones seen)", {c["author_tz"] for c in commits} >= {"+03:00", "-05:00"}, str({c["author_tz"] for c in commits}))
authors = rows("git", "authors")
check("two authors, by e-mail", {a["email"] for a in authors} >= {"dev1@ecopanel.su", "vlad@protonmail.com"}, str([a["email"] for a in authors]))
hsec = rows("git", "history_secrets")
check("the deleted DB password is recovered from history and marked not-in-file",
      any(h["key"] == "DB_PASSWORD" and "S3cretDbPass" in h["value"] and h["value_still_in_file"] == "False" for h in hsec), str([(h["key"], h["value_still_in_file"]) for h in hsec]))
check("the removed .env's Telegram token is in history_secrets with the commit that introduced it",
      any(h["service"] == "telegram" and h["introduced_by"] == "dev1@ecopanel.su" and h["introduced_by_commit"] for h in hsec), str([(h.get("service"), h.get("introduced_by")) for h in hsec]))
deleted = rows("git", "deleted")
check(".env recorded as deleted from history", any(d["path"] == ".env" for d in deleted), str([d["path"] for d in deleted]))

eps = rows("code", "endpoints")
by_host = {e["host"]: e for e in eps}
check("Telegram endpoint classified messaging", by_host.get("api.telegram.org", {}).get("class") == "messaging")
check("SMS-activate endpoint classified sms", by_host.get("api.sms-activate.org", {}).get("class") == "sms")
check("AfterShip endpoint classified shipping", by_host.get("api.aftership.com", {}).get("class") == "shipping")
check("public IP:port endpoint kept and classed ip", any(h.startswith("185.220.101.5") for h in by_host) and by_host[next(h for h in by_host if h.startswith('185.220.101.5'))]["class"] == "ip", str(list(by_host)))
check("GitHub is code-hosting, jsdelivr-style CDN would be noise", by_host.get("github.com", {}).get("class") in ("code-hosting", None))

vals = rows("config", "values")
check("live Telegram token found in services.yaml with its nested key", any(v["service"] == "telegram" and "telegram.token" in v["key"] for v in vals), str([v["key"] for v in vals if v["service"] == "telegram"]))
dbrows = rows("config", "databases")
check("database connections parsed (sw and ewmanager)", {d["database"] for d in dbrows} >= {"sw", "ewmanager"}, str([d["database"] for d in dbrows]))
links = rows("config", "export_links")
check("config DB names matched to the extracted exports", {l["database"] for l in links} >= {"sw", "ewmanager"}, str([(l["database"], l["export"]) for l in links]))

# the code export is a first-class export: catalog and search see it
cat = dbexplore.catalog(case)
code_tables = {t["table"] for t in cat if t["export"] == code["export"]}
check("the code export is in the Databases-tab catalog", {"commits", "endpoints", "values", "repositories"} <= code_tables, str(sorted(code_tables)))
hits = dbexplore.search_counts(case, "protonmail", "phrase", cat=cat)
check("searching the case finds the developer's e-mail in the code export", any(h["export"] == code["export"] for h in hits), str(hits))

# fingerprint now treats the dropped repositories as application roots
fp = fingerprint.fingerprint_tree(src, log=lambda s: None, with_composition=False)
app_roots = {a["root"] for a in fp["apps"]}
check("fingerprint found the repositories as application roots", any(r.endswith("/ep") for r in app_roots) and any(r.endswith("/EcopanelBot") for r in app_roots), str(app_roots))
epapp = next((a for a in fp["apps"] if a["root"].endswith("/ep")), None)
check("the app record carries the git remote", epapp and epapp.get("repo", {}).get("remotes"), str(epapp.get("repo") if epapp else None))

# findings
fids = [f for f in case.read_findings() if str(f.get("rule", "")).startswith("code.")]
rules = {f["rule"] for f in fids}
check("findings cover repo, git-config command, history secret, endpoint, database link",
      {"code.repo", "code.git_config_command", "code.history_secret", "code.endpoint_service", "code.database_link"} <= rules, str(sorted(rules)))

shutil.rmtree(tmp, ignore_errors=True)
print("code check:", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
