"""Source code intake: repositories, configuration and the services the code talks to. Deterministic, no model.

For an export tree (a dropped repository, a `source_code` folder of a legal return, a web root) or a mounted image:

  * REPOSITORIES - every .git under the root (bounded walk). Read with the distro's git against a SHADOW git
    directory: the seized config is never loaded (a .git/config can carry core.fsmonitor, core.sshCommand,
    core.hooksPath, diff.external, filter.*.clean ... that run a command whenever git - or an IDE's git
    integration - opens the repository), the seized objects are reached through objects/info/alternates and
    nothing is ever written into the evidence. Per repository: the remotes (parsed from the config as text), the
    refs, every commit reachable from refs AND from the reflog (amended / reset commits included, marked
    `reflog-only`) with author, e-mail, date and the author's UTC offset, the reflog itself (the identity and
    actions of whoever worked in that clone), files deleted from history, unreachable commits (git fsck), and the
    secrets and identifiers in historical configuration blobs with the commit that introduced them.
  * CONFIGURATION - .env*, config/, docker-compose, wp-config.php, settings.py, *.ini / .yml / .json / .toml ...:
    every key/value that looks like a credential, token, DSN, host or endpoint, classified by what it is for
    (database, messaging, SMS, shipping, payments, crypto, mail, captcha, geo/IP, cloud, proxy ...); DSNs parsed;
    database names matched against the case's database exports (which dump belongs to which application).
  * ENDPOINTS - every URL, DSN, t.me link and IP the code refers to (vendor / node_modules left out), grouped by
    host and classified the same way, with documentation / CDN / schema links marked as noise.
  * CALLS & WEBHOOKS - every outbound network/service call (curl/fetch/requests/Guzzle/Http, sockets, mail, shell
    curl|sh and wget, Telegram/Discord notifies, license/heartbeat checks, cron fetches) including calls whose host
    or URL is a variable resolved from configuration, plus inbound webhook / IPN / callback handlers.
  * PIVOTS - one row per external provider / contact joining live and historical credentials, account/bot IDs,
    outbound calls, inbound webhooks, what data is sent, and what records that provider holds on its side.
  * IDENTIFIERS - e-mails, wallets, handles, IPs in code and configuration.

Everything is written as CSV tables under a "code" export of the case (<case>/db/code-<name>/ -> git.commits,
git.authors, git.reflog, git.deleted, git.unreachable, git.history_secrets, config.values, config.databases,
code.endpoints, code.endpoint_hits, code.calls, code.webhooks, code.pivots, code.identifiers), so the Databases tab searches them with the extracted
databases and Players scans them (a developer's e-mail meets the users table), plus collected/code.json with the
summary, findings (code.*) and a custody record. `gumshoe code`.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Iterator, Optional
from urllib.parse import urlsplit

from .fingerprint import AGENT_FILES, VENDOR_DIRS, parse_git_config
from .identifiers import DOMAIN_RE, IPV4_RE, scan_text
from .integrity import utc_now
from .normalize.base import Finding

Log = Callable[[str], None]
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

MAX_REPOS = 100
MAX_COMMITS = 100_000                 # per repository (log pass)
MAX_HISTORY_BLOBS = 20_000            # configuration blobs scanned per repository
MAX_HISTORY_BYTES = 300 * 2**20
MAX_BLOB_BYTES = 512 * 1024
MAX_UNREACHABLE = 2_000
MAX_CONFIG_FILES = 5_000
MAX_CODE_FILES = 60_000
MAX_CODE_BYTES = 800 * 2**20
MAX_FILE_BYTES = 2 * 2**20
MAX_WALK_DIRS = 200_000
GIT_TIMEOUT = 900
SKIP_DIRS = (VENDOR_DIRS - {".git", "uploads", "upload", "attachments", "storage", "logs", "log"}) | {"dist", "build", ".next", ".nuxt", "coverage"}
# system paths of a mounted rootfs: never a target application's code or configuration, and huge
SYS_REL = {"proc", "sys", "dev", "run", "boot", "snap", "lost+found", "usr/lib", "usr/lib64", "usr/libexec", "usr/share", "usr/include", "usr/src", "usr/bin", "usr/sbin", "lib", "lib64",
           "lib32", "libx32", "bin", "sbin", "var/cache", "var/lib/apt", "var/lib/dpkg", "var/lib/docker/overlay2", "var/lib/mysql", "var/lib/postgresql", "var/lib/mongodb", "var/lib/snapd",
           "sys/kernel", "usr/local/lib", "usr/local/share", "var/lib/containerd"}
CODE_EXT = {".php", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".py", ".rb", ".go", ".java", ".kt", ".cs", ".rs", ".sh", ".bash", ".ps1", ".bat", ".cmd",
            ".html", ".htm", ".twig", ".blade.php", ".tpl", ".ejs", ".hbs", ".jinja", ".jinja2", ".j2", ".xml", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
            ".env", ".txt", ".md", ".sql", ".properties", ".neon", ".lock", ".csv", ".ipynb", ".pl", ".lua", ".swift", ".m", ".dart", ".scala", ".ex", ".exs", ".erl",
            ".clj", ".r", ".jl", ".vb", ".asp", ".aspx", ".jsp", ".cshtml", ".razor", ".sol"}
CONFIG_NAME_RE = re.compile(r"(^\.env(\..*)?$|\.env$|^docker-compose.*\.ya?ml$|^compose.*\.ya?ml$|^wp-config\.php$|^configuration\.php$|^settings(\.local|_local|\.prod|\.dev)?\.(py|php)$"
                            r"|^local_settings\.py$|^config(\.(php|js|json|ya?ml|ini|py|rb|toml|local\.php))?$|^database\.(php|yml|yaml|json)$|^db(\.config)?\.php$|^conn(ect)?\.php$"
                            r"|^constants\.php$|^env\.(php|js|json)$|^parameters(\.ya?ml|\.php)$|^services\.ya?ml$|^secrets?(\..+)?$|^credentials?(\..+)?$|^\.htpasswd$|^\.netrc$"
                            r"|^\.npmrc$|^\.pypirc$|^\.my\.cnf$|^my\.cnf$|^application(-.+)?\.(properties|ya?ml)$|^appsettings(\..+)?\.json$|^app\.config$|^web\.config$|^\.htaccess$"
                            r"|\.(pem|key|p12|pfx|jks|keystore|ppk)$|^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|^known_hosts$|^authorized_keys$|^\.git-credentials$|^\.bash_history$"
                            r"|^\.mysql_history$|^\.psql_history$|^\.python_history$|^\.zsh_history$|^\.lesshst$|^\.wget-hsts$|^\.pgpass$|^\.env\.example$|^setup\.php$|^install\.php$"
                            r"|^first-install.*\.php$|^cron.*\.php$|^importmap\.php$|^phpunit\.xml(\.dist)?$|^config\.inc\.php$|^LocalSettings\.php$|^\.user\.ini$)", re.I)
CONFIG_DIR_RE = re.compile(r"(^|/)(config|configs|conf|settings|app/config|app/etc|\.config|etc|env|environments)(/|$)", re.I)
SECRET_PATH_RE = re.compile(r"(^|/)(\.env[^/]*|[^/]*\.(pem|key|p12|pfx|ppk|ini|ya?ml|json|toml|properties|cfg|conf|neon)|wp-config\.php|configuration\.php|settings[^/]*\.py"
                            r"|config[^/]*\.(php|js|py|rb)|database\.php|db\.php|connect\.php|constants\.php|env\.(php|js)|parameters\.(ya?ml|php)|docker-compose[^/]*|compose[^/]*\.ya?ml"
                            r"|\.htpasswd|\.netrc|\.npmrc|\.pypirc|\.my\.cnf|id_(rsa|dsa|ecdsa|ed25519)|credentials[^/]*|secrets?[^/]*|\.git-credentials|setup\.php|install\.php"
                            r"|first-install[^/]*\.php|Dockerfile[^/]*|\.gitlab-ci\.yml|[^/]*\.sql)$", re.I)
SECRET_KEY_RE = re.compile(r"(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|(^|_)key$|_key(_|$)|auth|dsn|database|(^|_)db(_|$)|mysql|maria|postgres|pgsql|mongo|redis|rabbit|amqp"
                           r"|smtp|imap|mail|(^|_)bot|telegram|tg_|twilio|nexmo|vonage|plivo|sms|aftership|shippo|easypost|stripe|paypal|perfect_?money|payment|coinbase|binance|aws|s3_|bucket|cloudflare|captcha"
                           r"|proxy|socks|webhook|private|credential|login|(^|_)user(name)?$|host(name)?$|_host|endpoint|url$|_url|uri$|_uri|domain$|wallet|address|licen[cs]e|jwt|session"
                           r"|salt|seed|mnemonic|cookie|openai|anthropic|gemini|deepseek|client_id|client_secret|app_id|account_sid|merchant|shop_id|api_id|api_hash|phone|port$)", re.I)
PLACEHOLDER_RE = re.compile(r"^(|\s*|xxx+|yyy+|zzz+|\*+|\.\.\.|null|none|nil|undefined|false|true|0|1|change[_-]?me|changeit|your[_-].*|<.*>|\[.*\]|\$\{.*\}|%.*%|example.*|sample.*|dummy.*|placeholder.*|secret|password|passw0rd|root|admin|test|localhost|127\.0\.0\.1|todo|tbd|fixme|~|-)$", re.I)
DSN_RE = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.-]{1,24})://(?:(?P<user>[^:@/\s]*)(?::(?P<pw>[^@/\s]*))?@)?(?P<host>\[[0-9a-fA-F:.]+\]|[^:/?#\s]+)?(?::(?P<port>\d{1,5}))?(?:/(?P<db>[^?#\s]*))?(?:\?(?P<q>[^#\s]*))?", re.I)
TG_TOKEN_RE = re.compile(r"(?<![\w:])(\d{8,10}:[A-Za-z0-9_-]{35,45})(?![\w-])")
TME_RE = re.compile(r"(?<![\w/])(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/(\+?[A-Za-z0-9_]{3,64})(?:/\d+)?", re.I)
URL_ANY_RE = re.compile(r"(?<![\w])((?:https?|wss?|ftp|sftp|ssh|mysql2?|mariadb|postgres(?:ql)?|pgsql|redis|rediss|amqps?|mongodb(?:\+srv)?|smtps?|imaps?|ldaps?|tg|socks[45]?|tcp)://[^\s\"'<>)\]\\`,;|}{]{3,400})", re.I)
HOSTY_RE = re.compile(r"['\"]((?:api|www|app|gateway|smtp|mail|imap|pop3?|cdn|ws|wss|hook|webhook|bot|panel|admin|sms|track|tracking|pay|payment|merchant|node|rpc|proxy|socks|auth|sso|login|dev|stage|staging|test|m)\.(?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d{2,5})?['\"]", re.I)
IP_PORT_RE = re.compile(r"(?<![\d.\w])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?::(\d{2,5}))?(?![\d.\w])")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")
VERSION_LIKE_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# value shapes that name their service on their own: (core pattern, class, service, note). VALUE_SHAPES anchors them
# to a whole configuration value; VALUE_SHAPES_LOOSE finds them anywhere in text whose structure is unknown (an
# unreachable blob, a code file), where key=value harvesting would only produce garbage
_SHAPES: list[tuple[str, str, str, str]] = [
    (r"\d{8,10}:[A-Za-z0-9_-]{35,45}", "messaging", "telegram", "Telegram bot token"),
    (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "cloud", "aws", "AWS access key id"),
    (r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}", "payments", "stripe", "Stripe key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "messaging", "slack", "Slack token"),
    (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}", "messaging", "discord", "Discord bot token"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "code-hosting", "github", "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{60,}", "code-hosting", "github", "GitHub token"),
    (r"glpat-[A-Za-z0-9_-]{20,}", "code-hosting", "gitlab", "GitLab token"),
    (r"SG\.[\w-]{16,}\.[\w-]{16,}", "mail", "sendgrid", "SendGrid key"),
    (r"key-[0-9a-f]{32}", "mail", "mailgun", "Mailgun key"),
    (r"AC[0-9a-f]{32}", "sms", "twilio", "Twilio account SID"),
    (r"SK[0-9a-f]{32}", "sms", "twilio", "Twilio API key"),
    (r"AIza[0-9A-Za-z_-]{35}", "geo", "google", "Google API key"),
    (r"sk-ant-[A-Za-z0-9_-]{20,}", "ai", "anthropic", "Anthropic API key"),
    (r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}", "ai", "openai", "OpenAI-style key"),
    (r"sk-or-v1-[0-9a-f]{40,}", "ai", "openrouter", "OpenRouter key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "auth", "jwt", "JSON web token"),
]
VALUE_SHAPES: list[tuple[re.Pattern, str, str, str]] = [(re.compile("^" + core + "$"), cls, svc, note) for core, cls, svc, note in _SHAPES]
VALUE_SHAPES_LOOSE: list[tuple[re.Pattern, str, str, str]] = [(re.compile(r"(?<![A-Za-z0-9_/.-])" + core + r"(?![A-Za-z0-9_-])"), cls, svc, note) for core, cls, svc, note in _SHAPES]
DSN_CRED_RE = re.compile(r"(?<![\w])(?P<scheme>mysql2?|mariadb|postgres(?:ql)?|pgsql|mongodb(?:\+srv)?|redis|rediss|amqps?|smtps?|imaps?|ftp|sftp|ssh|socks[45]?|https?)://(?P<user>[^:@/\s\"']{1,64}):(?P<pw>[^@/\s\"']{1,128})@(?P<host>[^:/?#\s\"']+)", re.I)


def scan_blob_strict(text: str) -> list[dict[str, Any]]:
    """Secrets with a shape of their own in text of unknown structure: service tokens, credentials inside a DSN/URL,
    private keys. No key=value harvesting (source code would turn into false 'credentials')."""
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rx, cls, svc, note in VALUE_SHAPES_LOOSE:
        for m in rx.finditer(text):
            v = m.group(0)
            if v in seen:
                continue
            seen.add(v)
            rows.append({"key": note, "value": v, "line": text.count("\n", 0, m.start()) + 1, "how": "shape", "class": cls, "service": svc, "note": note, "placeholder": False})
    for m in DSN_CRED_RE.finditer(text):
        v = m.group(0)
        if v in seen or PLACEHOLDER_RE.match(m.group("pw")) or m.group("pw").lower() in ("password", "pass", "secret", "xxx", "changeme", "example"):
            continue
        seen.add(v)
        cls, svc, note = classify_key_value(m.group("scheme") + "_dsn", v)
        rows.append({"key": f"{m.group('scheme')} credentials in URL", "value": v, "line": text.count("\n", 0, m.start()) + 1, "how": "dsn", "class": cls if cls != "other" else "endpoint",
                     "service": svc or m.group("scheme").lower(), "note": "user:password@host", "placeholder": False})
    pk = PRIVATE_KEY_RE.search(text)
    if pk:
        rows.append({"key": pk.group(0), "value": "(private key material, not copied)", "line": text.count("\n", 0, pk.start()) + 1, "how": "pem", "class": "auth",
                     "service": "private key", "note": "private key material", "placeholder": False})
    return rows


# host -> (class, service) ; longest suffix match wins
HOST_CLASSES: list[tuple[str, str, str]] = [
    ("api.telegram.org", "messaging", "telegram"), ("telegram.org", "messaging", "telegram"), ("t.me", "messaging", "telegram"), ("telegram.me", "messaging", "telegram"),
    ("tdesktop.com", "messaging", "telegram"), ("telegram.dog", "messaging", "telegram"), ("discord.com", "messaging", "discord"), ("discordapp.com", "messaging", "discord"),
    ("discord.gg", "messaging", "discord"), ("graph.facebook.com", "messaging", "meta"), ("wa.me", "messaging", "whatsapp"), ("api.whatsapp.com", "messaging", "whatsapp"),
    ("slack.com", "messaging", "slack"), ("viber.com", "messaging", "viber"), ("signal.org", "messaging", "signal"), ("matrix.org", "messaging", "matrix"), ("jabber.ru", "messaging", "xmpp"),
    ("xmpp.jp", "messaging", "xmpp"), ("exploit.im", "messaging", "xmpp"), ("thesecure.biz", "messaging", "xmpp"), ("line.me", "messaging", "line"), ("max.ru", "messaging", "max"),
    ("twilio.com", "sms", "twilio"), ("nexmo.com", "sms", "vonage"), ("vonage.com", "sms", "vonage"), ("plivo.com", "sms", "plivo"), ("smsaero.ru", "sms", "smsaero"),
    ("sms-activate.org", "sms", "sms-activate"), ("sms-activate.io", "sms", "sms-activate"), ("sms-activate.ru", "sms", "sms-activate"), ("sms-activate.guru", "sms", "sms-activate"),
    ("sms-activate.ae", "sms", "sms-activate"), ("5sim.net", "sms", "5sim"), ("5sim.biz", "sms", "5sim"), ("onlinesim.io", "sms", "onlinesim"), ("onlinesim.ru", "sms", "onlinesim"),
    ("textverified.com", "sms", "textverified"), ("smspva.com", "sms", "smspva"), ("smshub.org", "sms", "smshub"), ("grizzlysms.com", "sms", "grizzlysms"), ("textmagic.com", "sms", "textmagic"),
    ("clicksend.com", "sms", "clicksend"), ("bulksms.com", "sms", "bulksms"), ("smsc.ru", "sms", "smsc"), ("sms.ru", "sms", "sms.ru"), ("turbosms.ua", "sms", "turbosms"),
    ("smsapi.com", "sms", "smsapi"), ("messagebird.com", "sms", "messagebird"), ("telnyx.com", "sms", "telnyx"), ("bandwidth.com", "sms", "bandwidth"), ("sinch.com", "sms", "sinch"),
    ("infobip.com", "sms", "infobip"), ("seven.io", "sms", "seven"), ("sms77.io", "sms", "seven"), ("daisysms.com", "sms", "daisysms"), ("tiger-sms.com", "sms", "tigersms"),
    ("hero-sms.com", "sms", "herosms"), ("getsmscode.com", "sms", "getsmscode"), ("sms-man.com", "sms", "sms-man"), ("vak-sms.com", "sms", "vak-sms"), ("smsbower.com", "sms", "smsbower"),
    ("temp-number.com", "sms", "temp-number"), ("receive-sms-online.info", "sms", "receive-sms"), ("textnow.com", "sms", "textnow"), ("textfree.us", "sms", "textfree"),
    ("aftership.com", "shipping", "aftership"), ("17track.net", "shipping", "17track"), ("trackingmore.com", "shipping", "trackingmore"), ("parcelsapp.com", "shipping", "parcelsapp"),
    ("parcelmonitor.com", "shipping", "parcelmonitor"), ("ups.com", "shipping", "ups"), ("usps.com", "shipping", "usps"), ("fedex.com", "shipping", "fedex"), ("dhl.com", "shipping", "dhl"),
    ("dhl.de", "shipping", "dhl"), ("easypost.com", "shipping", "easypost"), ("goshippo.com", "shipping", "shippo"), ("shipstation.com", "shipping", "shipstation"),
    ("stamps.com", "shipping", "stamps"), ("pirateship.com", "shipping", "pirateship"), ("shipengine.com", "shipping", "shipengine"), ("sendcloud.com", "shipping", "sendcloud"),
    ("canadapost-postescanada.ca", "shipping", "canada post"), ("royalmail.com", "shipping", "royal mail"), ("dpd.com", "shipping", "dpd"), ("gls-group.eu", "shipping", "gls"),
    ("auspost.com.au", "shipping", "auspost"), ("ontrac.com", "shipping", "ontrac"), ("lasership.com", "shipping", "lasership"), ("shipbob.com", "shipping", "shipbob"),
    ("easyship.com", "shipping", "easyship"), ("shippingeasy.com", "shipping", "shippingeasy"), ("rollo.com", "shipping", "rollo"), ("veeqo.com", "shipping", "veeqo"),
    ("stripe.com", "payments", "stripe"), ("paypal.com", "payments", "paypal"), ("paypalobjects.com", "payments", "paypal"), ("squareup.com", "payments", "square"),
    ("braintreegateway.com", "payments", "braintree"), ("adyen.com", "payments", "adyen"), ("checkout.com", "payments", "checkout.com"), ("authorize.net", "payments", "authorize.net"),
    ("2checkout.com", "payments", "2checkout"), ("payoneer.com", "payments", "payoneer"), ("wise.com", "payments", "wise"), ("revolut.com", "payments", "revolut"), ("skrill.com", "payments", "skrill"),
    ("perfectmoney.com", "payments", "perfect money"), ("perfectmoney.is", "payments", "perfect money"), ("webmoney.ru", "payments", "webmoney"), ("wmtransfer.com", "payments", "webmoney"),
    ("qiwi.com", "payments", "qiwi"), ("yoomoney.ru", "payments", "yoomoney"), ("payeer.com", "payments", "payeer"), ("advcash.com", "payments", "advcash"), ("volet.com", "payments", "volet"),
    ("cash.app", "payments", "cash app"), ("venmo.com", "payments", "venmo"), ("zellepay.com", "payments", "zelle"), ("plaid.com", "payments", "plaid"),
    ("blockchain.info", "crypto", "blockchain.com"), ("blockchain.com", "crypto", "blockchain.com"), ("blockchair.com", "crypto", "blockchair"), ("blockcypher.com", "crypto", "blockcypher"),
    ("blockstream.info", "crypto", "blockstream"), ("mempool.space", "crypto", "mempool"), ("etherscan.io", "crypto", "etherscan"), ("bscscan.com", "crypto", "bscscan"),
    ("trongrid.io", "crypto", "tron"), ("tronscan.org", "crypto", "tron"), ("tronscan.io", "crypto", "tron"), ("coinbase.com", "crypto", "coinbase"), ("binance.com", "crypto", "binance"),
    ("binance.us", "crypto", "binance"), ("kraken.com", "crypto", "kraken"), ("kucoin.com", "crypto", "kucoin"), ("bybit.com", "crypto", "bybit"), ("okx.com", "crypto", "okx"),
    ("htx.com", "crypto", "htx"), ("huobi.com", "crypto", "htx"), ("gate.io", "crypto", "gate"), ("mexc.com", "crypto", "mexc"), ("coinpayments.net", "crypto", "coinpayments"),
    ("nowpayments.io", "crypto", "nowpayments"), ("cryptomus.com", "crypto", "cryptomus"), ("plisio.net", "crypto", "plisio"), ("btcpayserver.org", "crypto", "btcpay"),
    ("coingate.com", "crypto", "coingate"), ("coingecko.com", "crypto", "coingecko"), ("coinmarketcap.com", "crypto", "coinmarketcap"), ("bestchange.com", "crypto", "bestchange"),
    ("bestchange.ru", "crypto", "bestchange"), ("garantex.org", "crypto", "garantex"), ("grinex.io", "crypto", "grinex"), ("exodus.com", "crypto", "exodus"), ("trustwallet.com", "crypto", "trust wallet"),
    ("infura.io", "crypto", "infura"), ("alchemy.com", "crypto", "alchemy"), ("ankr.com", "crypto", "ankr"), ("moralis.io", "crypto", "moralis"), ("sochain.com", "crypto", "sochain"),
    ("bitcoin.org", "crypto", "bitcoin"), ("bitpay.com", "crypto", "bitpay"), ("paxful.com", "crypto", "paxful"), ("localbitcoins.com", "crypto", "localbitcoins"), ("noones.com", "crypto", "noones"),
    ("2captcha.com", "captcha", "2captcha"), ("rucaptcha.com", "captcha", "rucaptcha"), ("anti-captcha.com", "captcha", "anti-captcha"), ("capmonster.cloud", "captcha", "capmonster"),
    ("capsolver.com", "captcha", "capsolver"), ("hcaptcha.com", "captcha", "hcaptcha"), ("recaptcha.net", "captcha", "recaptcha"), ("challenges.cloudflare.com", "captcha", "turnstile"),
    ("deathbycaptcha.com", "captcha", "deathbycaptcha"), ("nopecha.com", "captcha", "nopecha"), ("capguru.com", "captcha", "capguru"),
    ("ip-api.com", "geo", "ip-api"), ("ipinfo.io", "geo", "ipinfo"), ("ipgeolocation.io", "geo", "ipgeolocation"), ("ipapi.co", "geo", "ipapi"), ("ipdata.co", "geo", "ipdata"),
    ("maxmind.com", "geo", "maxmind"), ("ipstack.com", "geo", "ipstack"), ("ip2location.com", "geo", "ip2location"), ("ipqualityscore.com", "geo", "ipqualityscore"),
    ("scamalytics.com", "geo", "scamalytics"), ("maps.googleapis.com", "geo", "google maps"), ("nominatim.openstreetmap.org", "geo", "nominatim"), ("mapbox.com", "geo", "mapbox"),
    ("here.com", "geo", "here"), ("opencagedata.com", "geo", "opencage"), ("geocode.maps.co", "geo", "maps.co"), ("dadata.ru", "geo", "dadata"), ("smartystreets.com", "geo", "smarty"),
    ("smarty.com", "geo", "smarty"), ("melissa.com", "geo", "melissa"), ("loqate.com", "geo", "loqate"), ("ipify.org", "geo", "ipify"), ("ifconfig.me", "geo", "ifconfig"),
    ("icanhazip.com", "geo", "icanhazip"), ("whatismyip.com", "geo", "whatismyip"), ("ipwho.is", "geo", "ipwhois"), ("ipwhois.app", "geo", "ipwhois"), ("abstractapi.com", "geo", "abstract"),
    ("zipcodeapi.com", "geo", "zipcodeapi"), ("geonames.org", "geo", "geonames"), ("positionstack.com", "geo", "positionstack"),
    ("sendgrid.net", "mail", "sendgrid"), ("sendgrid.com", "mail", "sendgrid"), ("mailgun.net", "mail", "mailgun"), ("mailgun.org", "mail", "mailgun"), ("postmarkapp.com", "mail", "postmark"),
    ("amazonses.com", "mail", "amazon ses"), ("mailjet.com", "mail", "mailjet"), ("mandrillapp.com", "mail", "mandrill"), ("sparkpost.com", "mail", "sparkpost"), ("smtp.gmail.com", "mail", "gmail"),
    ("outlook.office365.com", "mail", "office365"), ("smtp.yandex.ru", "mail", "yandex"), ("smtp.mail.ru", "mail", "mail.ru"), ("protonmail.com", "mail", "proton"), ("proton.me", "mail", "proton"),
    ("temp-mail.org", "mail", "temp-mail"), ("1secmail.com", "mail", "1secmail"), ("mail.tm", "mail", "mail.tm"), ("guerrillamail.com", "mail", "guerrillamail"), ("kickbox.com", "mail", "kickbox"),
    ("zerobounce.net", "mail", "zerobounce"), ("hunter.io", "mail", "hunter"), ("emailable.com", "mail", "emailable"), ("brevo.com", "mail", "brevo"), ("sendinblue.com", "mail", "brevo"),
    ("resend.com", "mail", "resend"), ("elasticemail.com", "mail", "elastic email"), ("mailtrap.io", "mail", "mailtrap"), ("smtp2go.com", "mail", "smtp2go"),
    ("amazonaws.com", "cloud", "aws"), ("digitaloceanspaces.com", "cloud", "digitalocean spaces"), ("backblazeb2.com", "cloud", "backblaze"), ("wasabisys.com", "cloud", "wasabi"),
    ("storage.googleapis.com", "cloud", "google cloud storage"), ("blob.core.windows.net", "cloud", "azure"), ("r2.cloudflarestorage.com", "cloud", "cloudflare r2"), ("bunny.net", "cloud", "bunny"),
    ("b-cdn.net", "cloud", "bunny"), ("dropboxapi.com", "cloud", "dropbox"), ("dropbox.com", "cloud", "dropbox"), ("mega.nz", "cloud", "mega"), ("mega.io", "cloud", "mega"),
    ("cloudinary.com", "cloud", "cloudinary"), ("imgbb.com", "cloud", "imgbb"), ("imgur.com", "cloud", "imgur"), ("anonfiles.com", "cloud", "anonfiles"), ("gofile.io", "cloud", "gofile"),
    ("brightdata.com", "proxy", "bright data"), ("luminati.io", "proxy", "bright data"), ("oxylabs.io", "proxy", "oxylabs"), ("smartproxy.com", "proxy", "smartproxy"),
    ("decodo.com", "proxy", "smartproxy"), ("proxy-seller.com", "proxy", "proxy-seller"), ("proxy6.net", "proxy", "proxy6"), ("iproyal.com", "proxy", "iproyal"), ("soax.com", "proxy", "soax"),
    ("packetstream.io", "proxy", "packetstream"), ("nstproxy.com", "proxy", "nstproxy"), ("922proxy.com", "proxy", "922proxy"), ("piaproxy.com", "proxy", "pia s5"), ("webshare.io", "proxy", "webshare"),
    ("proxyrack.com", "proxy", "proxyrack"), ("proxy-cheap.com", "proxy", "proxy-cheap"), ("multilogin.com", "proxy", "multilogin (anti-detect browser)"), ("gologin.com", "proxy", "gologin (anti-detect browser)"),
    ("dolphin-anty.com", "proxy", "dolphin anty (anti-detect browser)"), ("adspower.com", "proxy", "adspower (anti-detect browser)"), ("adspower.net", "proxy", "adspower (anti-detect browser)"),
    ("incogniton.com", "proxy", "incogniton (anti-detect browser)"), ("octobrowser.net", "proxy", "octo browser (anti-detect)"), ("nordvpn.com", "proxy", "nordvpn"), ("mullvad.net", "proxy", "mullvad"),
    ("github.com", "code-hosting", "github"), ("githubusercontent.com", "code-hosting", "github"), ("api.github.com", "code-hosting", "github"), ("gitlab.com", "code-hosting", "gitlab"),
    ("bitbucket.org", "code-hosting", "bitbucket"), ("codeberg.org", "code-hosting", "codeberg"), ("gitea.com", "code-hosting", "gitea"), ("sourceforge.net", "code-hosting", "sourceforge"),
    ("pastebin.com", "code-hosting", "pastebin"), ("gist.github.com", "code-hosting", "github"),
    ("hetzner.com", "hosting", "hetzner"), ("hetzner.cloud", "hosting", "hetzner"), ("digitalocean.com", "hosting", "digitalocean"), ("vultr.com", "hosting", "vultr"), ("linode.com", "hosting", "linode"),
    ("akamai.com", "hosting", "akamai"), ("ovh.com", "hosting", "ovh"), ("ovh.net", "hosting", "ovh"), ("ovhcloud.com", "hosting", "ovh"), ("contabo.com", "hosting", "contabo"), ("timeweb.com", "hosting", "timeweb"),
    ("timeweb.cloud", "hosting", "timeweb"), ("reg.ru", "hosting", "reg.ru"), ("selectel.ru", "hosting", "selectel"), ("aeza.net", "hosting", "aeza"), ("ishosting.com", "hosting", "is*hosting"),
    ("cloudflare.com", "hosting", "cloudflare"), ("namecheap.com", "hosting", "namecheap"), ("godaddy.com", "hosting", "godaddy"), ("njal.la", "hosting", "njalla"), ("porkbun.com", "hosting", "porkbun"),
    ("dynadot.com", "hosting", "dynadot"), ("hostinger.com", "hosting", "hostinger"), ("ionos.com", "hosting", "ionos"), ("scaleway.com", "hosting", "scaleway"), ("upcloud.com", "hosting", "upcloud"),
    ("hostkey.com", "hosting", "hostkey"), ("serverspace.io", "hosting", "serverspace"), ("4vps.su", "hosting", "4vps"), ("pq.hosting", "hosting", "pq.hosting"), ("alexhost.com", "hosting", "alexhost"),
    ("baxet.ru", "hosting", "baxet"), ("ihor.ru", "hosting", "ihor"), ("firstvds.ru", "hosting", "firstvds"), ("beget.com", "hosting", "beget"), ("sprinthost.ru", "hosting", "sprinthost"),
    ("api.openai.com", "ai", "openai"), ("openai.com", "ai", "openai"), ("api.anthropic.com", "ai", "anthropic"), ("anthropic.com", "ai", "anthropic"), ("openrouter.ai", "ai", "openrouter"),
    ("generativelanguage.googleapis.com", "ai", "google gemini"), ("api.deepseek.com", "ai", "deepseek"), ("api.mistral.ai", "ai", "mistral"), ("api.groq.com", "ai", "groq"),
    ("api.together.xyz", "ai", "together"), ("huggingface.co", "ai", "hugging face"), ("api.x.ai", "ai", "xai"), ("api.cohere.com", "ai", "cohere"), ("api.perplexity.ai", "ai", "perplexity"),
    ("googletagmanager.com", "analytics", "google tag manager"), ("google-analytics.com", "analytics", "google analytics"), ("analytics.google.com", "analytics", "google analytics"),
    ("mc.yandex.ru", "analytics", "yandex metrica"), ("hotjar.com", "analytics", "hotjar"), ("sentry.io", "analytics", "sentry"), ("mixpanel.com", "analytics", "mixpanel"),
    ("w3.org", "noise", "schema"), ("purl.org", "noise", "schema"), ("xmlsoap.org", "noise", "schema"), ("json-schema.org", "noise", "schema"), ("schema.org", "noise", "schema"),
    ("schemas.microsoft.com", "noise", "schema"), ("schemas.xmlsoap.org", "noise", "schema"), ("schemas.openxmlformats.org", "noise", "schema"), ("getcomposer.org", "noise", "docs"),
    ("packagist.org", "noise", "docs"), ("php.net", "noise", "docs"), ("symfony.com", "noise", "docs"), ("laravel.com", "noise", "docs"), ("npmjs.com", "noise", "docs"), ("nodejs.org", "noise", "docs"),
    ("yarnpkg.com", "noise", "docs"), ("mozilla.org", "noise", "docs"), ("stackoverflow.com", "noise", "docs"), ("jsdelivr.net", "noise", "cdn"), ("unpkg.com", "noise", "cdn"),
    ("cdnjs.cloudflare.com", "noise", "cdn"), ("fonts.googleapis.com", "noise", "cdn"), ("fonts.gstatic.com", "noise", "cdn"), ("ajax.googleapis.com", "noise", "cdn"), ("code.jquery.com", "noise", "cdn"),
    ("bootstrapcdn.com", "noise", "cdn"), ("fontawesome.com", "noise", "cdn"), ("gravatar.com", "noise", "cdn"), ("opensource.org", "noise", "license"), ("gnu.org", "noise", "license"),
    ("apache.org", "noise", "license"), ("creativecommons.org", "noise", "license"), ("example.com", "noise", "placeholder"), ("example.org", "noise", "placeholder"), ("example.net", "noise", "placeholder"),
    ("localhost", "internal", "localhost"), ("wikipedia.org", "noise", "docs"), ("tailwindcss.com", "noise", "docs"), ("getbootstrap.com", "noise", "docs"), ("jquery.com", "noise", "docs"),
    ("vuejs.org", "noise", "docs"), ("reactjs.org", "noise", "docs"), ("react.dev", "noise", "docs"), ("angular.io", "noise", "docs"), ("python.org", "noise", "docs"), ("pypi.org", "noise", "docs"),
    ("readthedocs.io", "noise", "docs"), ("docker.com", "noise", "docs"), ("docker.io", "noise", "docs"), ("ubuntu.com", "noise", "docs"), ("debian.org", "noise", "docs"), ("microsoft.com", "noise", "docs"),
    ("apple.com", "noise", "docs"), ("google.com", "noise", "google"), ("googleapis.com", "noise", "google api"), ("gstatic.com", "noise", "cdn"), ("youtube.com", "noise", "social"),
    ("facebook.com", "noise", "social"), ("twitter.com", "noise", "social"), ("x.com", "noise", "social"), ("instagram.com", "noise", "social"), ("linkedin.com", "noise", "social"),
    ("tiktok.com", "noise", "social"), ("vk.com", "noise", "social"), ("ok.ru", "noise", "social"), ("pinterest.com", "noise", "social"), ("medium.com", "noise", "docs"), ("sentry-cdn.com", "noise", "cdn"),
    ("polyfill.io", "noise", "cdn"), ("cloudfront.net", "cloud", "aws cloudfront"), ("akamaihd.net", "noise", "cdn"), ("fastly.net", "noise", "cdn"), ("jquery.org", "noise", "docs"),
    ("momentjs.com", "noise", "docs"), ("lodash.com", "noise", "docs"), ("vitejs.dev", "noise", "docs"), ("webpack.js.org", "noise", "docs"), ("eslint.org", "noise", "docs"), ("prettier.io", "noise", "docs"),
    ("typescriptlang.org", "noise", "docs"), ("doctrine-project.org", "noise", "docs"), ("twig.symfony.com", "noise", "docs"), ("phpunit.de", "noise", "docs"), ("phpstan.org", "noise", "docs"),
    ("getrector.org", "noise", "docs"), ("rector.org", "noise", "docs"), ("openstreetmap.org", "geo", "openstreetmap"), ("tile.openstreetmap.org", "noise", "cdn"), ("gravatar.org", "noise", "cdn"),
]
_HOST_INDEX = sorted(HOST_CLASSES, key=lambda t: -len(t[0]))
DOC_NET_RE = re.compile(r"^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|233\.252\.0\.)")
PRIVATE_NET_RE = re.compile(r"^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|224\.|255\.)")
KEY_CLASSES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"telegram|(^|_)tg(_|$)|bot_?token|bot_?api|telebot|tgbot", re.I), "messaging", "telegram"),
    (re.compile(r"discord", re.I), "messaging", "discord"), (re.compile(r"whatsapp|(^|_)wa_", re.I), "messaging", "whatsapp"), (re.compile(r"slack", re.I), "messaging", "slack"),
    (re.compile(r"twilio", re.I), "sms", "twilio"), (re.compile(r"nexmo|vonage", re.I), "sms", "vonage"), (re.compile(r"plivo", re.I), "sms", "plivo"), (re.compile(r"smsaero", re.I), "sms", "smsaero"),
    (re.compile(r"sms[_-]?activate", re.I), "sms", "sms-activate"), (re.compile(r"5sim", re.I), "sms", "5sim"), (re.compile(r"onlinesim", re.I), "sms", "onlinesim"),
    (re.compile(r"textverified", re.I), "sms", "textverified"), (re.compile(r"smshub", re.I), "sms", "smshub"), (re.compile(r"(^|_)sms(_|$)|sms_?(api|key|token|gateway|provider|user|pass|login|sender)", re.I), "sms", "sms"),
    (re.compile(r"aftership", re.I), "shipping", "aftership"), (re.compile(r"17track", re.I), "shipping", "17track"), (re.compile(r"trackingmore", re.I), "shipping", "trackingmore"),
    (re.compile(r"shippo", re.I), "shipping", "shippo"), (re.compile(r"easypost", re.I), "shipping", "easypost"), (re.compile(r"shipstation", re.I), "shipping", "shipstation"),
    (re.compile(r"(^|_)(ups|usps|fedex|dhl)(_|$)", re.I), "shipping", "carrier"), (re.compile(r"shipping|carrier|tracking|label|parcel", re.I), "shipping", "shipping"),
    (re.compile(r"stripe", re.I), "payments", "stripe"), (re.compile(r"paypal", re.I), "payments", "paypal"), (re.compile(r"square", re.I), "payments", "square"),
    (re.compile(r"braintree", re.I), "payments", "braintree"), (re.compile(r"adyen", re.I), "payments", "adyen"), (re.compile(r"perfect_?money|(^|_)pm_", re.I), "payments", "perfect money"),
    (re.compile(r"qiwi|yoomoney|payeer|advcash|webmoney|skrill|payoneer|wise_", re.I), "payments", "e-money"), (re.compile(r"merchant|payment|checkout|invoice", re.I), "payments", "payments"),
    (re.compile(r"coinbase", re.I), "crypto", "coinbase"), (re.compile(r"binance", re.I), "crypto", "binance"), (re.compile(r"nowpayments", re.I), "crypto", "nowpayments"),
    (re.compile(r"coinpayments", re.I), "crypto", "coinpayments"), (re.compile(r"cryptomus", re.I), "crypto", "cryptomus"), (re.compile(r"plisio", re.I), "crypto", "plisio"),
    (re.compile(r"btcpay", re.I), "crypto", "btcpay"), (re.compile(r"blockchain|blockchair|blockcypher|etherscan|bscscan|trongrid|tron|infura|alchemy", re.I), "crypto", "chain api"),
    (re.compile(r"(^|_)(btc|eth|usdt|trc20|erc20|bep20|ltc|xmr|sol|ton)(_|$)|wallet|crypto|mnemonic|seed_?phrase|private_?key", re.I), "crypto", "crypto"),
    (re.compile(r"2captcha|rucaptcha|anti_?captcha|capmonster|capsolver|hcaptcha|recaptcha|captcha", re.I), "captcha", "captcha"),
    (re.compile(r"maxmind|geoip|ipinfo|ip_?api|ipgeolocation|ipstack|ip2location|ipqualityscore|google_?maps|mapbox|geocod|dadata|smarty", re.I), "geo", "geo"),
    (re.compile(r"mailer_dsn|smtp|imap|pop3|sendgrid|mailgun|postmark|(^|_)ses(_|$)|mailjet|mandrill|sparkpost|brevo|sendinblue|resend_|mail_(host|port|user|pass|from|encryption|driver|mailer)|(^|_)mail(_|$)", re.I), "mail", "mail"),
    (re.compile(r"aws|s3_|_s3|bucket|spaces_|minio|backblaze|b2_|wasabi|gcs_|google_cloud|azure_|cloudinary|cloudflare_|r2_", re.I), "cloud", "cloud storage"),
    (re.compile(r"proxy|socks", re.I), "proxy", "proxy"),
    (re.compile(r"database_url|db_(host|port|name|user|pass|password|database|dsn|connection|driver)|mysql|maria|postgres|pgsql|pg_|mongo|sqlite|(^|_)dsn$|(^|_)db(_|$)|database|doctrine|typeorm|prisma", re.I), "database", "database"),
    (re.compile(r"redis|rabbit|amqp|kafka|memcache|messenger_transport|queue_|celery|broker", re.I), "queue", "queue/cache"),
    (re.compile(r"github|gitlab|gitea|bitbucket|(^|_)git_", re.I), "code-hosting", "code hosting"),
    (re.compile(r"openai|anthropic|claude|gemini|deepseek|mistral|openrouter|groq|huggingface|(^|_)llm|(^|_)ai_", re.I), "ai", "ai api"),
    (re.compile(r"app_secret|app_key|secret_key|jwt|session|encryption_key|csrf|salt|signing|hmac|api_(key|secret|token|id|hash)|access_?token|refresh_?token|auth|client_(id|secret)|license|oauth", re.I), "auth", "application secret"),
    (re.compile(r"admin|root|login|user(name)?$|pass(word)?$|pwd$|credential", re.I), "auth", "login"),
    (re.compile(r"webhook|callback|notify_url|ipn", re.I), "endpoint", "webhook"),
    (re.compile(r"host$|_host|hostname|endpoint|url$|_url|uri$|_uri|domain|base_?url|site_?url|app_?url|server", re.I), "endpoint", "host/url"),
]
CLASS_SEVERITY = {"messaging": "medium", "sms": "medium", "shipping": "medium", "payments": "medium", "crypto": "medium", "mail": "low", "captcha": "low", "geo": "low", "cloud": "medium",
                  "proxy": "medium", "database": "medium", "queue": "low", "code-hosting": "medium", "ai": "low", "auth": "low", "hosting": "low", "endpoint": "info", "internal": "info",
                  "analytics": "info", "noise": "info", "other": "info"}
LEAD_CLASSES = ("messaging", "sms", "shipping", "payments", "crypto", "captcha", "geo", "mail", "cloud", "proxy", "code-hosting", "hosting", "ai")


# ------------------------------------------------------------------------------------------------ small helpers
def _rel(p: Path, root: Path) -> str:
    try:
        return "/" + str(p.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(p)


def _read_text(p: Path, limit: int = MAX_FILE_BYTES) -> str:
    try:
        with open(p, "rb") as f:
            b = f.read(limit)
    except OSError:
        return ""
    if b"\x00" in b[:4096] and not p.name.endswith((".pem", ".key")):
        return ""
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", errors="replace")


def classify_host(host: str) -> tuple[str, str]:
    h = (host or "").lower().strip(".").strip("[]")
    if not h:
        return "other", ""
    if IPV4_RE.fullmatch(h):
        if DOC_NET_RE.match(h):
            return "noise", "documentation address (RFC 5737)"
        return ("internal", "private address") if PRIVATE_NET_RE.match(h) else ("ip", "public address")
    if h in ("localhost", "::1") or h.endswith((".local", ".internal", ".lan", ".localhost", ".test", ".invalid")):
        return "internal", "local"
    if re.search(r"(^|\.)(example|your-?domain|yourdomain|domain|mydomain|mysite|yoursite|site|placeholder|xxx|test)\.(com|org|net|tld|ru|io)$", h) or h in ("domain.tld", "your.domain"):
        return "noise", "placeholder"
    for suf, cls, svc in _HOST_INDEX:
        if h == suf or h.endswith("." + suf):
            return cls, svc
    if "." not in h:
        return "internal", "service name"
    return "other", ""


def classify_key_value(key: str, value: str) -> tuple[str, str, str]:
    """(class, service, note) for a configuration key and its value: the value's shape first, then the key's name,
    then the value's host."""
    v = (value or "").strip()
    for rx, cls, svc, note in VALUE_SHAPES:
        if rx.fullmatch(v) or (rx is TG_TOKEN_RE and rx.search(v)):
            return cls, svc, note
    if PRIVATE_KEY_RE.search(v):
        return "auth", "private key", "private key material"
    m = DSN_RE.match(v)
    if m and m.group("host"):
        scheme = m.group("scheme").lower()
        if scheme in ("mysql", "mysql2", "mariadb", "postgres", "postgresql", "pgsql", "mongodb", "mongodb+srv", "sqlite", "sqlsrv", "mssql", "oracle", "oci"):
            return "database", scheme, "connection string"
        if scheme in ("redis", "rediss", "amqp", "amqps", "kafka", "memcached", "doctrine", "sync", "nats"):
            return "queue", scheme, "connection string"
        if scheme in ("smtp", "smtps", "imap", "imaps", "sendmail", "sendgrid", "mailgun", "postmark", "ses", "mailjet", "brevo", "resend"):
            return "mail", scheme, "mailer DSN"
        cls, svc = classify_host(m.group("host"))
        if cls not in ("other", "noise", "internal"):
            return cls, svc, "URL"
    for rx, cls, svc in KEY_CLASSES:
        if rx.search(key or ""):
            if cls == "auth" and re.search(r"licen[cs]e|session|cookie|salt|csrf|oauth|signing|hmac", key or "", re.I) and not re.fullmatch(r"[A-Za-z0-9+/=_.-]{16,}", v):
                return "other", "", ""          # a license *text*, a session name, a cookie name: not a credential
            if cls == "endpoint" and v:
                hc, hs = classify_host(_host_of(v))
                if hc not in ("other", "noise", "internal", "ip"):
                    return hc, hs, "host"
            return cls, svc, ""
    hc, hs = classify_host(_host_of(v)) if ("://" in v or DOMAIN_RE.fullmatch(v)) else ("other", "")
    if hc not in ("other",):
        return hc, hs, "host"
    return "other", "", ""


def _host_of(v: str) -> str:
    v = (v or "").strip()
    if "://" in v:
        try:
            return (urlsplit(v).hostname or "").lower()
        except ValueError:
            return ""
    m = DOMAIN_RE.search(v)
    return m.group(1).lower() if m else (v.lower() if IPV4_RE.fullmatch(v) else "")


def mask(v: str) -> str:
    v = v or ""
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "…" + v[-4:] + f" ({len(v)} chars)"


# ------------------------------------------------------------------------------------------------ configuration
_KV_RE = re.compile(r"^\s*(?:-\s+)?(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]{0,80})\s*[=:]\s*(.*?)\s*$")
_PHP_DEFINE_RE = re.compile(r"define\(\s*['\"]([A-Za-z0-9_]+)['\"]\s*,\s*(['\"])(.*?)\2\s*\)", re.S)
_PHP_ARROW_RE = re.compile(r"['\"]([A-Za-z0-9_.-]{2,60})['\"]\s*=>\s*(['\"])(.*?)\2", re.S)
_PHP_VAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]{1,60})\s*=\s*(['\"])(.*?)\2\s*;", re.S)
_PHP_ENV_RE = re.compile(r"\benv\(\s*['\"]([A-Za-z0-9_]+)['\"]\s*,\s*(['\"])(.*?)\2\s*\)", re.S)
_JSON_RE = re.compile(r"\"([A-Za-z0-9_.:-]{1,80})\"\s*:\s*\"((?:[^\"\\]|\\.)*)\"")
_PY_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]{1,60})\s*=\s*(['\"])(.*?)\2\s*(?:#.*)?$", re.M)
_PY_DICT_RE = re.compile(r"['\"]([A-Za-z0-9_]{2,40})['\"]\s*:\s*(['\"])(.*?)\2")


def _strip_value(v: str) -> str:
    v = v.strip()
    if v and v[0] in "\"'`":
        q = v[0]
        j = 1
        while j < len(v):
            if v[j] == "\\" and q != "'":
                j += 2
                continue
            if v[j] == q:
                return v[1:j]
            j += 1
        return v[1:]
    if " #" in v:
        v = v.split(" #", 1)[0].rstrip()
    if "\t#" in v:
        v = v.split("\t#", 1)[0].rstrip()
    if v.endswith(","):
        v = v[:-1].strip().strip("\"'")
    return v


_PARENT_PHP_RE = re.compile(r"['\"]([A-Za-z0-9_.-]{2,60})['\"]\s*=>\s*(?:\[|array\s*\()")
_PARENT_JSON_RE = re.compile(r"\"([A-Za-z0-9_.-]{1,60})\"\s*:\s*\{")


def _parent_before(text: str, pos: int, rx: re.Pattern, back: int = 1500) -> str:
    """The nearest enclosing array/object name before pos (a heuristic: the last `'name' => [` whose bracket is still
    open in the window), for config written as nested arrays."""
    window = text[max(0, pos - back):pos]
    best = ""
    for m in rx.finditer(window):
        after = window[m.end():]
        depth = 0
        closed = False
        for ch in after:
            if ch in "[{(":
                depth += 1
            elif ch in "]})":
                if depth == 0:
                    closed = True
                    break
                depth -= 1
        if not closed:
            best = m.group(1)
    return best


def harvest_text(name: str, text: str) -> list[dict[str, Any]]:
    """(key, value, line) pairs worth recording from one configuration-like file (any of the formats). Nested keys
    carry their parent (`aftership.key`, `telegram.token`) so the service is recognised from the context."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    low = name.lower()
    lines = text.splitlines()

    def put(key: str, value: str, line: int, how: str, parent: str = ""):
        key = key.strip()
        value = (value or "").strip()
        full = f"{parent}.{key}" if parent and parent.lower() != key.lower() else key
        if not key or len(value) > 2000 or (full, value) in seen:
            return
        flat = full.replace(".", "_")
        interesting = bool(SECRET_KEY_RE.search(flat)) or any(rx.search(value) for rx, *_ in VALUE_SHAPES) or "://" in value or bool(PRIVATE_KEY_RE.search(value)) \
            or bool(IPV4_RE.fullmatch(value)) or bool(DOMAIN_RE.fullmatch(value)) or "@" in value and "." in value
        if not interesting:
            return
        seen.add((full, value))
        cls, svc, note = classify_key_value(flat, value)
        rows.append({"key": full, "value": value, "line": line, "how": how, "class": cls, "service": svc, "note": note,
                     "placeholder": bool(PLACEHOLDER_RE.match(value)) or value == ""})

    pk = PRIVATE_KEY_RE.search(text)
    if pk:
        rows.append({"key": pk.group(0), "value": "(private key material, not copied)", "line": text.count("\n", 0, pk.start()) + 1, "how": "pem",
                     "class": "auth", "service": "private key", "note": "private key material", "placeholder": False})
    if low.endswith((".php", ".inc")):
        for m in _PHP_DEFINE_RE.finditer(text):
            put(m.group(1), m.group(3), text.count("\n", 0, m.start()) + 1, "define")
        for rx, how in ((_PHP_ARROW_RE, "array"), (_PHP_VAR_RE, "variable"), (_PHP_ENV_RE, "env() default")):
            for m in rx.finditer(text):
                put(m.group(1), m.group(3), text.count("\n", 0, m.start()) + 1, how, _parent_before(text, m.start(), _PARENT_PHP_RE) if rx is _PHP_ARROW_RE else "")
        return rows
    if low.endswith(".json") or low.endswith(".ipynb"):
        for m in _JSON_RE.finditer(text):
            try:
                val = m.group(2).encode("utf-8").decode("unicode_escape", errors="replace")
            except Exception:  # noqa: BLE001
                val = m.group(2)
            put(m.group(1), val, text.count("\n", 0, m.start()) + 1, "json", _parent_before(text, m.start(), _PARENT_JSON_RE))
        return rows
    if low.endswith(".py"):
        for m in _PY_RE.finditer(text):
            put(m.group(1), m.group(3), text.count("\n", 0, m.start()) + 1, "python")
        for m in _PY_DICT_RE.finditer(text):
            put(m.group(1), m.group(3), text.count("\n", 0, m.start()) + 1, "python dict", _parent_before(text, m.start(), _PARENT_JSON_RE) or _parent_before(text, m.start(), _PARENT_PHP_RE))
        return rows
    if low.endswith((".js", ".ts", ".mjs", ".cjs")):
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]{1,60})\s*[:=]\s*(['\"`])(.*?)\2", text):
            put(m.group(1), m.group(3), text.count("\n", 0, m.start()) + 1, "js", _parent_before(text, m.start(), _PARENT_JSON_RE))
        for m in _PY_DICT_RE.finditer(text):
            put(m.group(1), m.group(3), text.count("\n", 0, m.start()) + 1, "js object", _parent_before(text, m.start(), _PARENT_JSON_RE))
        return rows
    # key = value / key: value lines (.env, ini, yaml, properties, toml, docker-compose); yaml/toml parents by indentation / section
    yaml_like = low.endswith((".yml", ".yaml"))
    parents: list[tuple[int, str]] = []
    section = ""
    for i, raw in enumerate(lines[:20000], 1):
        s = raw.strip()
        if not s or s.startswith(("#", ";", "//", "/*", "*", "<!--")):
            continue
        if s.startswith("[") and s.endswith("]") and not yaml_like:
            section = s.strip("[]").strip().strip("\"'")
            continue
        m = _KV_RE.match(raw)
        if not m:
            continue
        indent = len(raw) - len(raw.lstrip(" \t"))
        key, val = m.group(1), _strip_value(m.group(2))
        if yaml_like:
            while parents and parents[-1][0] >= indent:
                parents.pop()
            if val in ("", "|", ">", "{", "[", "|-", ">-"):
                parents.append((indent, key))
                continue
            parent = ".".join(k for _, k in parents[-2:])
        else:
            parent = section
            if val in ("", "|", ">", "{", "[") and not low.startswith(".env") and not low.endswith(".env"):
                continue
        put(key, val, i, "key=value", parent)
    return rows


def _skip_dir(path: Path, root: Path) -> bool:
    """A system path of a mounted rootfs (never the target application's code), by its path relative to the root."""
    try:
        rel = str(path.resolve().relative_to(root.resolve())).replace("\\", "/").lower()
    except ValueError:
        return False
    return rel in SYS_REL or any(rel == s or rel.startswith(s + "/") for s in SYS_REL)


def _config_candidates(root: Path, log: Log) -> Iterator[Path]:
    n = 0
    dirs = 0
    stack = [root]
    while stack and dirs < MAX_WALK_DIRS and n < MAX_CONFIG_FILES:
        d = stack.pop()
        dirs += 1
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        rel_dir = _rel(d, root)
        in_conf_dir = bool(CONFIG_DIR_RE.search(rel_dir + "/"))
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    if e.name in SKIP_DIRS or e.name in ("node_modules", "vendor") or e.name == ".git" or _skip_dir(Path(e.path), root):
                        continue
                    stack.append(Path(e.path))
                elif e.is_file(follow_symlinks=False):
                    if e.stat(follow_symlinks=False).st_size > MAX_FILE_BYTES:
                        continue
                    nm = e.name
                    if CONFIG_NAME_RE.search(nm) or (in_conf_dir and nm.lower().endswith((".php", ".yml", ".yaml", ".json", ".ini", ".toml", ".neon", ".env", ".cfg", ".conf", ".properties", ".xml", ".py", ".js"))):
                        n += 1
                        yield Path(e.path)
            except OSError:
                continue


def harvest_config(root: Path, log: Log) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Configuration values across the tree -> (values rows, database rows)."""
    values: list[dict[str, Any]] = []
    dbs: list[dict[str, Any]] = []
    files = 0
    for p in _config_candidates(root, log):
        text = _read_text(p)
        if not text:
            continue
        files += 1
        rel = _rel(p, root)
        example = bool(re.search(r"\.(example|sample|dist|template|tpl)(\.|$)|example|sample", p.name, re.I))
        for r in harvest_text(p.name, text):
            r.update({"file": rel, "example": example})
            values.append(r)
            m = DSN_RE.match(r["value"]) if "://" in r["value"] else None
            if m and r["class"] == "database":
                dbs.append({"file": rel, "key": r["key"], "scheme": m.group("scheme").lower(), "host": (m.group("host") or "").strip("[]"), "port": m.group("port") or "",
                            "user": m.group("user") or "", "password_present": bool(m.group("pw")), "database": (m.group("db") or "").split("?")[0].strip("/"), "example": example})
    # database names given piecewise (DB_HOST / DB_DATABASE / DB_NAME / MYSQL_DATABASE ...)
    by_file: dict[str, dict[str, str]] = defaultdict(dict)
    for r in values:
        k = r["key"].lower().replace(".", "_")
        if re.search(r"(^|_)(db|database|mysql|maria|postgres|pg|dbal)_?(name|database|dbname|db)$|^(database|dbname|db_name|mysql_database|postgres_db|pgdatabase)$", k):
            by_file[r["file"]]["database"] = r["value"]
        elif re.search(r"(^|_)(db|database|mysql|maria|postgres|pg)_?(host|hostname|server)$|^(dbhost|mysql_host)$", k):
            by_file[r["file"]]["host"] = r["value"]
        elif re.search(r"(^|_)(db|database|mysql|maria|postgres|pg)_?(user|username|login)$|^(dbuser|mysql_user)$", k):
            by_file[r["file"]]["user"] = r["value"]
        elif re.search(r"(^|_)(db|database|mysql|maria|postgres|pg)_?(pass|password|passwd|pwd)$|^(dbpass|mysql_password|mysql_root_password)$", k):
            by_file[r["file"]]["password"] = r["value"]
        elif re.search(r"(^|_)(db|database|mysql|maria|postgres|pg)_?port$", k):
            by_file[r["file"]]["port"] = r["value"]
    for f, d in by_file.items():
        if d.get("database"):
            dbs.append({"file": f, "key": "DB_* keys", "scheme": "", "host": d.get("host", ""), "port": d.get("port", ""), "user": d.get("user", ""),
                        "password_present": bool(d.get("password")), "database": d["database"], "example": bool(re.search(r"example|sample|dist|template", f, re.I))})
    log(f"[code] configuration: {files} files read, {len(values)} values kept, {len(dbs)} database connections")
    return values, dbs


# ------------------------------------------------------------------------------------------------ endpoints and identifiers
def _code_files(root: Path) -> Iterator[Path]:
    n = 0
    total = 0
    dirs = 0
    stack = [root]
    while stack and dirs < MAX_WALK_DIRS and n < MAX_CODE_FILES and total < MAX_CODE_BYTES:
        d = stack.pop()
        dirs += 1
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    if e.name in SKIP_DIRS or e.name in ("node_modules", "vendor", ".git") or _skip_dir(Path(e.path), root):
                        continue
                    stack.append(Path(e.path))
                elif e.is_file(follow_symlinks=False):
                    nm = e.name.lower()
                    size = e.stat(follow_symlinks=False).st_size
                    if size > MAX_FILE_BYTES or size == 0 or nm.endswith((".min.js", ".min.css", ".map", ".lock")):
                        continue
                    ext = os.path.splitext(nm)[1]
                    if ext in CODE_EXT or nm.startswith(".env") or nm in ("dockerfile", "makefile", "procfile", "crontab") or CONFIG_NAME_RE.search(e.name):
                        n += 1
                        total += size
                        yield Path(e.path)
            except OSError:
                continue


def scan_endpoints(root: Path, log: Log) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """-> (endpoints by host, hits, identifiers) over the code and configuration files of the tree."""
    hosts: dict[str, dict[str, Any]] = {}
    hits: list[dict[str, Any]] = []
    idents: dict[tuple[str, str], dict[str, Any]] = {}
    files = 0
    t0 = time.time()

    def add_host(host: str, url: str, rel: str, line: int, excerpt: str, how: str):
        host = host.lower().strip(".")
        if not host:
            return
        cls, svc = classify_host(host.split(":")[0] if re.match(r"^[\d.]+:\d+$", host) else host)
        h = hosts.get(host)
        if h is None:
            h = hosts[host] = {"host": host, "class": cls, "service": svc, "hits": 0, "files": set(), "first_file": rel, "first_line": line, "example": url[:300], "schemes": set()}
        h["hits"] += 1
        h["files"].add(rel)
        h["schemes"].add(how)
        if len(hits) < 200_000:
            hits.append({"host": host, "class": cls, "service": svc, "url": url[:500], "file": rel, "line": line, "excerpt": excerpt[:200], "how": how})

    def add_ident(t: str, v: str, n: str, rel: str, line):
        k = (t, n)
        e = idents.get(k)
        if e is None:
            e = idents[k] = {"type": t, "value": v, "norm": n, "count": 0, "files": [], "first_file": rel, "first_line": line() if callable(line) else line}
        e["count"] += 1
        if rel not in e["files"] and len(e["files"]) < 8:
            e["files"].append(rel)

    for p in _code_files(root):
        text = _read_text(p)
        if not text:
            continue
        files += 1
        rel = _rel(p, root)
        is_code = os.path.splitext(p.name.lower())[1] in (".php", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".vue", ".py", ".rb", ".go", ".java", ".kt", ".cs", ".rs", ".sh")
        for i, line in enumerate(text.splitlines()[:50000], 1):
            if len(line) > 4000:
                line = line[:4000]
            for m in URL_ANY_RE.finditer(line):
                url = m.group(1).rstrip(".,;:'\")]}")
                try:
                    sp = urlsplit(url)
                    host = sp.hostname or ""
                except ValueError:
                    continue
                if not host and sp.scheme.lower() in ("tg",):
                    add_host("t.me", url, rel, i, line.strip(), "tg://")
                    continue
                if not host:
                    continue
                add_host(host, url, rel, i, line.strip(), sp.scheme.lower())
                tm = TG_TOKEN_RE.search(url)
                if tm and "api.telegram.org" in host:
                    add_ident("telegram_token", tm.group(1), tm.group(1), rel, i)
            for m in TME_RE.finditer(line):
                add_host("t.me", m.group(0), rel, i, line.strip(), "t.me")
                add_ident("telegram_link", "t.me/" + m.group(1), m.group(1).lower(), rel, i)
            for m in HOSTY_RE.finditer(line):
                add_host(m.group(1), m.group(1), rel, i, line.strip(), "quoted host")
            for m in IP_PORT_RE.finditer(line):
                ip = m.group(1)
                if ip.startswith(("0.", "255.")) or ip in ("127.0.0.1", "0.0.0.0") or VERSION_LIKE_RE.match(ip) and (("version" in line.lower()) or ("v" + ip in line)):
                    continue
                if PRIVATE_NET_RE.match(ip) or DOC_NET_RE.match(ip):
                    continue
                add_host(ip + (f":{m.group(2)}" if m.group(2) else ""), ip + (f":{m.group(2)}" if m.group(2) else ""), rel, i, line.strip(), "ip")
                add_ident("ipv4", ip, ip, rel, i)
            for m in TG_TOKEN_RE.finditer(line):
                add_ident("telegram_token", m.group(1), m.group(1), rel, i)
        ctx = "code" if is_code else p.name
        for t, v, n in scan_text(text[:400_000], ctx):
            if t in ("email", "wallet", "iban", "handle", "sshkey") or (t == "phone" and not is_code):
                if t == "handle" and (is_code or "/" in v or v.lower() in ("@param", "@return", "@var", "@throws", "@type", "@author", "@license", "@package", "@since", "@todo")):
                    continue
                add_ident(t, v, n, rel, lambda v=v: (text.count("\n", 0, text.find(v)) + 1) if text.find(v) >= 0 else 0)
    out_hosts = []
    for h in hosts.values():
        h["files_n"] = len(h["files"])
        h["files"] = sorted(h["files"])[:6]
        h["schemes"] = ",".join(sorted(h["schemes"]))
        out_hosts.append(h)
    out_hosts.sort(key=lambda h: (0 if h["class"] in LEAD_CLASSES else 1 if h["class"] in ("ip", "other", "endpoint") else 2, -h["hits"]))
    log(f"[code] endpoints: {files} code/config files read, {len(out_hosts)} hosts, {len(hits)} references, {len(idents)} identifiers, {time.time() - t0:.0f} s")
    return out_hosts, hits, sorted(idents.values(), key=lambda e: (e["type"], -e["count"]))




# ------------------------------------------------------------------------------------------------ calls, webhooks and provider pivots
PROVIDER_HOLDS: dict[str, str] = {
    # messaging
    "telegram": "Bot creator/owner user ID & phone (via numeric bot_id prefix before ':'), webhook target URL & delivery IP logs (getWebhookInfo), subscriber/admin chat_id list, channel/group metadata, and message/command history",
    "discord": "Webhook creator user ID, guild (server) & channel IDs, account registration e-mail/phone/IP logs, and message delivery logs",
    "slack": "Workspace ID, app/token creator account & e-mail, channel message history, and API caller IP logs",
    "whatsapp": "Meta Business Account ID, registered sender phone number, WABA admin/billing accounts, and message delivery logs",
    "meta": "Meta App/Business ID, developer account e-mail/phone, webhook callback URLs, and Graph API caller IP logs",
    "xmpp": "Jabber server account registration, roster/contact list, offline message queue, and client connection IP/timestamp logs",
    "viber": "Bot/public account owner phone & registration, webhook target URL, and message delivery logs",
    "signal": "Registered account phone number and device link timestamps",
    "matrix": "Homeserver account registration, room membership/events, device IDs, and access IP logs",
    "line": "LINE Official Account / channel owner, webhook endpoint URL, and message delivery logs",
    "max": "Bot/account owner registration phone/e-mail, webhook endpoint, and API caller IP logs",
    # sms (virtual / activation vs transactional)
    "sms-activate": "Account registration e-mail / Telegram handle, balance top-up payment history (crypto txids, cards, e-wallets), rented virtual phone numbers, activation timestamps, received SMS texts, and API caller IP logs",
    "5sim": "Account registration e-mail / OAuth identity, balance deposit records (crypto/cards/wallets), leased virtual numbers, received OTP/SMS contents, and API access IPs",
    "onlinesim": "Account registration e-mail/Telegram, payment top-up history, rented virtual numbers, received SMS messages, and API caller IPs",
    "smshub": "Account registration e-mail, balance top-up records, activation number history, SMS contents, and API caller IPs",
    "textverified": "Account e-mail & billing/crypto payment history, verification phone numbers rented, SMS texts received, and client IP logs",
    "smspva": "Account registration e-mail, deposit payment history, rented numbers, SMS activation logs, and API caller IPs",
    "grizzlysms": "Account registration e-mail/Telegram, balance top-up records, virtual number activations, and API caller IPs",
    "daisysms": "Account registration e-mail, crypto/card deposit records, rented US numbers, SMS texts received, and API caller IPs",
    "tigersms": "Account registration e-mail, balance top-up history, virtual number activations, and API caller IPs",
    "herosms": "Account registration e-mail, balance top-up history, virtual number activations, and API caller IPs",
    "getsmscode": "Account e-mail, balance top-up records, rented numbers, SMS logs, and API caller IPs",
    "sms-man": "Account registration e-mail/Telegram, payment deposits, rented phone numbers, SMS texts, and API caller IPs",
    "vak-sms": "Account registration e-mail/Telegram, balance top-up records, rented numbers, SMS logs, and API caller IPs",
    "smsbower": "Account registration e-mail, balance top-up history, rented numbers, and API caller IPs",
    "twilio": "Account holder KYC & billing method, subaccounts, leased sender phone numbers, CDRs (recipient numbers, timestamps, message bodies, status), webhook URLs, and API access IPs",
    "vonage": "Account holder KYC & billing details, sender numbers/IDs, SMS/voice CDRs, webhook callback URLs, and API access IPs",
    "plivo": "Account holder KYC & billing details, leased numbers, SMS/voice CDRs, webhook URLs, and API caller IPs",
    "smsaero": "Account holder e-mail/phone & billing records, sender names, recipient SMS logs, and API caller IPs",
    "smsc": "Account holder login/KYC & billing history, sender IDs, outbound SMS CDRs, and API client IPs",
    "sms.ru": "Account holder phone/KYC & billing history, outbound SMS logs (recipients, text, timestamps), and API caller IPs",
    "messagebird": "Account holder KYC & billing records, sender numbers, message logs, webhook URLs, and API caller IPs",
    "telnyx": "Account holder KYC & billing method, messaging profiles, leased numbers, CDRs, webhook URLs, and API caller IPs",
    # shipping
    "aftership": "Account holder e-mail & billing records, submitted tracking numbers, carrier slugs, order/customer metadata attached to trackings, webhook callback URLs, and API caller IP logs",
    "17track": "Account holder e-mail & billing tier, registered tracking numbers, carrier codes, webhook push URLs, and API caller IPs",
    "trackingmore": "Account holder e-mail & billing records, submitted tracking numbers, webhook URLs, and API caller IPs",
    "parcelsapp": "Account/API subscriber e-mail & billing, queried tracking numbers, and caller IP logs",
    "parcelmonitor": "Account/API subscriber details, queried tracking numbers, webhook URLs, and caller IP logs",
    "shippo": "Account holder KYC & payment method, shipping label purchases, sender & recipient street addresses/names/phones, tracking numbers, carrier accounts, and API/login IPs",
    "easypost": "Account holder KYC & billing method, created shipments/labels, origin & destination addresses, customs forms, carrier accounts, webhook URLs, and API caller IPs",
    "shipstation": "Account holder billing & connected store integrations, order & shipment history, recipient addresses, tracking numbers, and login/API IPs",
    "stamps": "Account holder KYC & USPS postage purchase records, sender/recipient addresses, tracking numbers, and login/API IPs",
    "pirateship": "Account holder e-mail & payment method, label purchase history, sender/recipient addresses, and login IPs",
    "ups": "Shipper account number KYC & billing, label generation & pickup records, origin/destination addresses, and API caller IPs",
    "usps": "WebTools/API user ID registration, mailer ID, address validation & tracking query logs, and caller IPs",
    "fedex": "FedEx developer/shipper account KYC, meter number, shipment/tracking logs, and API caller IPs",
    "dhl": "DHL shipper account KYC & billing, waybill/label creation logs, origin/destination addresses, and API caller IPs",
    # payments & e-money
    "stripe": "Merchant KYC identity, bank payout accounts & debit cards, full charge/payout/dispute ledger, customer billing & IP/fingerprint records, webhook endpoints, and dashboard/API IPs",
    "paypal": "Merchant account KYC, linked bank accounts/cards, transaction & IPN history, counterparty e-mails, and login/API IPs",
    "square": "Merchant KYC & linked bank accounts, location IDs, payment/payout ledger, and API/dashboard login IPs",
    "braintree": "Merchant KYC & payout bank details, transaction vault/ledger, webhook endpoints, and API caller IPs",
    "adyen": "Merchant company KYC, settlement bank accounts, payment/modification logs, webhook URLs, and API caller IPs",
    "perfect money": "Account holder registration e-mail/phone/KYC, member ID & U/E/G purse numbers, internal transfer counterparties, voucher/exchanger deposit & withdrawal history, SCI/IPN status URLs, and login/API IPs",
    "webmoney": "WMID passport/attestation KYC, Z/R/E purse history, transfer counterparties, merchant X-interface/LMI callback settings, and login/API IPs",
    "qiwi": "Wallet phone number & passport KYC, P2P/merchant transfer history, linked cards, webhook URLs, and API caller IPs",
    "yoomoney": "Wallet account KYC & phone/e-mail, incoming/outgoing transfer ledger, linked cards, HTTP notification URLs, and login/API IPs",
    "payeer": "Account registration e-mail/phone/KYC, merchant shop ID, fiat/crypto exchange & transfer ledger, IPN status URLs, and login/API IPs",
    "advcash": "Account holder KYC & e-mail, wallet transfer & card payout history, SCI callback URLs, and login/API IPs",
    "volet": "Account holder KYC & e-mail, wallet transfer & payout history, SCI callback URLs, and login/API IPs",
    "skrill": "Account holder KYC & bank/card links, merchant status_url callbacks, transfer ledger, and login IPs",
    "payoneer": "Account holder KYC, receiving accounts, payer counterparties, withdrawal bank accounts, and login IPs",
    "wise": "Account holder KYC, multi-currency borderless account IBANs, transfer counterparties, and API/login IPs",
    "revolut": "Merchant/business account KYC, IBANs, counterparty transfers, webhook URLs, and API/login IPs",
    # crypto
    "nowpayments": "Merchant account e-mail/Telegram, created invoice logs, deposit addresses & on-chain txids, custody/payout withdrawal wallet addresses, IPN callback URLs, and API access IPs",
    "cryptomus": "Merchant account e-mail/Telegram/KYC, merchant UUID, invoice & static wallet logs, withdrawal addresses & txids, webhook URLs, and API/login IPs",
    "coinpayments": "Merchant account e-mail/KYC, merchant ID, IPN secret & callback URLs, deposit addresses, auto-sweep/withdrawal addresses, and login/API IPs",
    "plisio": "Merchant account e-mail, shop configuration, invoice & txid history, payout wallet addresses, callback URLs, and API caller IPs",
    "coingate": "Merchant account KYC, order/invoice ledger, settlement crypto/bank destinations, callback URLs, and API caller IPs",
    "btcpay": "Store configuration, xpub / derivation scheme or hot wallet keys, invoice & payment logs, webhook endpoints",
    "bitpay": "Merchant KYC, settlement wallet/bank details, invoice ledger, IPN callbacks, and API caller IPs",
    "binance": "Account KYC identity, registration e-mail/phone, deposit & withdrawal addresses and txids, spot/P2P/Pay ledger, API key permissions, and login/API IPs",
    "coinbase": "Account/Commerce KYC identity, e-mail/phone, deposit/withdrawal addresses, webhook endpoints, and API/login IPs",
    "kraken": "Account KYC identity, deposit/withdrawal addresses & bank wires, trade ledger, and API/login IPs",
    "kucoin": "Account registration e-mail/phone/KYC, deposit/withdrawal txids, trade ledger, and API/login IPs",
    "bybit": "Account registration e-mail/phone/KYC, deposit/withdrawal txids, P2P counterparties, and API/login IPs",
    "okx": "Account KYC, deposit/withdrawal addresses & txids, subaccounts, and API/login IPs",
    "garantex": "Account registration phone/e-mail/KYC, ruble/USDT deposit & withdrawal codes, P2P/OTC counterparties, and login/API IPs",
    "grinex": "Account registration details, deposit/withdrawal codes & txids, OTC counterparties, and login/API IPs",
    "trongrid": "API key owner e-mail, queried TRON/TRC20 addresses & contract events, broadcast raw transactions, and caller IP logs",
    "tron": "API key owner e-mail, queried TRON/TRC20 addresses & contract events, broadcast raw transactions, and caller IP logs",
    "etherscan": "API key registration e-mail, queried Ethereum addresses/txns, and caller IP addresses",
    "bscscan": "API key registration e-mail, queried BNB Chain addresses/txns, and caller IP addresses",
    "infura": "Developer account e-mail & billing, project ID usage, RPC calls & broadcast transaction hashes, and caller IPs",
    "alchemy": "Developer account e-mail & billing, app API key logs, webhook targets, broadcast txns, and caller IPs",
    # mail
    "sendgrid": "Account owner e-mail & billing, verified sender domains/identities, outbound email activity logs (recipients, subjects, timestamps), event webhooks, and SMTP/API client IPs",
    "mailgun": "Account owner e-mail & billing, verified sending domains, message logs (recipients, subjects, delivery/bounce events), webhook URLs, and API/SMTP client IPs",
    "postmark": "Account owner & server token configuration, verified signatures, full outbound/inbound message activity logs, and caller IPs",
    "amazon ses": "AWS account ID & IAM principal, verified identities/domains, sending statistics, and CloudTrail/SES API caller IPs",
    "brevo": "Account owner e-mail & billing, sender domains, transactional email/SMS logs, and API/SMTP client IPs",
    "resend": "Account owner e-mail & billing, verified domains, outbound email logs (recipients, subjects, timestamps), and API caller IPs",
    "gmail": "Google Account recovery phone/e-mail, OAuth/App-Password audit logs, Sent folder & SMTP message headers, and login IP history",
    "office365": "Microsoft 365 tenant & mailbox owner, message trace logs, sign-in audit logs, and client IPs",
    "yandex": "Yandex account phone/recovery e-mail, mailbox messages, app password creation, and SMTP/IMAP access IPs",
    "mail.ru": "Mail.ru account phone/recovery e-mail, mailbox messages, and SMTP/IMAP access IPs",
    "proton": "Account recovery e-mail/payment details, Proton Bridge/SMTP token usage, and authentication logs",
    # cloud
    "aws": "AWS Account ID, root/IAM user identity & billing, S3 bucket contents, CloudTrail API audit logs (access key ID, caller IPs, timestamps)",
    "cloudflare r2": "Cloudflare account owner e-mail & billing, bucket objects, API token audit logs, and caller IPs",
    "digitalocean spaces": "DigitalOcean account e-mail & billing method, Spaces bucket contents, access key logs, and login IPs",
    "backblaze": "Backblaze account e-mail & billing, B2 bucket files, application key audit logs, and caller IPs",
    "cloudinary": "Account owner e-mail & billing, cloud_name media assets, upload IP logs, and API key settings",
    "dropbox": "Account owner e-mail & billing, stored files/shared links, app token audit logs, and device/IP logs",
    "mega": "Account registration e-mail, stored encrypted blobs/links, payment records, and session IP history",
    # proxy & anti-detect
    "bright data": "Customer account KYC & billing method, zone configuration, proxy usage bandwidth/target logs, and client source IPs",
    "oxylabs": "Customer account e-mail & billing, sub-user credentials, traffic usage logs, and client connection IPs",
    "smartproxy": "Customer account e-mail & payment records, proxy sub-users, and client connection IPs",
    "iproyal": "Customer account e-mail & crypto/card payments, proxy orders, and client connection IPs",
    "soax": "Customer account e-mail & billing, whitelist IPs, proxy package usage, and client source IPs",
    "proxy6": "Account registration e-mail, balance top-up records (wallets/cards), leased proxy IP:port list, and client IPs",
    "proxy-seller": "Account e-mail, payment records, leased proxy IPs, and client connection logs",
    "webshare": "Account e-mail & billing, proxy list assignments, and access IP logs",
    "multilogin (anti-detect browser)": "Account e-mail & subscription payment records, synced browser profiles (cookies, fingerprints, proxy configs), team seats, and login IPs",
    "gologin (anti-detect browser)": "Account e-mail & payment history, cloud browser profiles (cookies, saved logins, proxies), shared profile members, and API/login IPs",
    "dolphin anty (anti-detect browser)": "Account e-mail/Telegram & subscription payment records, stored browser profiles, proxy list, team permissions, and login IPs",
    "adspower (anti-detect browser)": "Account e-mail/phone & payment records, cloud-synced browser profiles, proxy configs, and login IPs",
    "incogniton (anti-detect browser)": "Account e-mail & billing, stored browser profiles, and login IPs",
    "octo browser (anti-detect)": "Account e-mail/Telegram & crypto/card payment records, browser profiles, tags, and login IPs",
    # code-hosting & hosting
    "github": "Account/organization owner e-mail, verified SSH keys, personal access token & deploy key usage logs, git push/fetch IP audit logs, private repositories, and Actions secrets",
    "gitlab": "Account/group owner e-mail, SSH keys, PAT/deploy token logs, repository push/pull IP audit logs, and CI/CD variables",
    "bitbucket": "Atlassian account e-mail, SSH keys, app passwords, repository access logs, and Pipelines secrets",
    "cloudflare": "Account owner e-mail & billing, DNS zone records (true origin server IPs behind proxy), API token audit logs, Workers scripts, and login IPs",
    "hetzner": "Customer KYC & billing/payment records, provisioned servers/IPs, reverse DNS, and Robot/Cloud console login IPs",
    "digitalocean": "Account e-mail & billing, droplets/volumes/snapshots, SSH keys, and API/console login IPs",
    "njalla": "Account registration e-mail/XMPP, crypto/PayPal top-up txids, domain DNS records & VPS origin IPs, and login logs",
    "namecheap": "Account holder e-mail/phone & payment records (cards/BTC), domain registration/DNS history, and login IPs",
    "aeza": "Account e-mail/Telegram, crypto/card deposit records, rented VPS IPs, and panel login IPs",
    "reg.ru": "Account holder passport/phone/e-mail, payment history, domains & VPS services, and login IPs",
    "timeweb": "Account holder e-mail/phone & payment methods, hosted sites/VPS instances, and control-panel login IPs",
    # captcha, geo, ai
    "2captcha": "Account registration e-mail, balance top-up records, solved captcha task logs (target site URLs/sitekeys, timestamps), and API caller IPs",
    "rucaptcha": "Account registration e-mail, balance top-up records, solved captcha task logs, and API caller IPs",
    "anti-captcha": "Account registration e-mail, funding payment records, captcha task domain logs, and API caller IPs",
    "capmonster": "Account registration e-mail, balance top-ups, solved captcha domain/sitekey logs, and API caller IPs",
    "capsolver": "Account registration e-mail, crypto/card top-ups, captcha task logs, and API caller IPs",
    "ipinfo": "Account e-mail & billing tier, API token usage, queried IP addresses, and caller IPs",
    "ip-api": "Pro subscriber e-mail & billing, queried IP logs, and caller IPs",
    "maxmind": "Account holder e-mail & billing, GeoIP license key download/query logs, and caller IPs",
    "ipqualityscore": "Account e-mail & billing, proxy/fraud lookup logs (queried IPs/emails/phones), and caller IPs",
    "dadata": "Account e-mail/phone & billing, address/company lookup logs, and API caller IPs",
    "openai": "Organization/account owner e-mail & billing card, API key creation/usage timestamps, caller IP logs, and retained request logs",
    "anthropic": "Organization/account owner e-mail & billing card, API key usage logs, caller IPs, and workspace members",
    "openrouter": "Account e-mail/OAuth identity, crypto/card credit top-ups, model generation logs, and caller IPs",
    "deepseek": "Account e-mail/phone, balance top-up records, API key usage logs, and caller IPs",
    "google gemini": "Google Cloud project owner & billing account, API key usage metrics, and caller IPs",
}

CLASS_HOLDS: dict[str, str] = {
    "messaging": "Bot/webhook creator account, channel/chat IDs, message delivery history, and API caller IP logs",
    "sms": "Account registration e-mail & balance top-up/billing records, sender/rented phone numbers, SMS CDRs/contents, and API caller IPs",
    "shipping": "Account holder e-mail & billing records, submitted tracking numbers / shipping labels, sender & recipient addresses, webhook URLs, and API caller IPs",
    "payments": "Merchant KYC & payout bank/wallet accounts, transaction ledger, IPN/webhook settings, and login/API IPs",
    "crypto": "Account/merchant registration e-mail, deposit & withdrawal wallet addresses and on-chain txids, invoice logs, and API/login IPs",
    "mail": "Account owner & billing details, verified sender domains, outbound message logs (recipients, timestamps), and SMTP/API client IPs",
    "cloud": "Account holder billing & IAM identity, stored bucket/container objects, and access audit logs (caller IPs, keys)",
    "proxy": "Customer account e-mail & payment records, leased proxy credentials/exit IPs, or synced anti-detect browser profiles, and client source IPs",
    "code-hosting": "Account/organization owner e-mail, SSH keys, token audit logs, git push/clone IP logs, and private repositories",
    "hosting": "Customer account e-mail & payment records, DNS zone records (origin IPs), VPS provisioning history, and login IPs",
    "captcha": "Account registration e-mail, balance top-up records, target site URLs/sitekeys solved, and API caller IPs",
    "geo": "Account owner e-mail & billing, API query volume, queried IPs/addresses, and caller IPs",
    "ai": "Account/organization owner e-mail & billing method, API key usage timestamps, and caller IP logs",
    "database": "Database server user accounts, table contents, query/connection logs, and client host IPs",
    "queue": "Broker connection logs, queue/channel payloads, and client host IPs",
    "ip": "Hosting/ASN subscriber & billing records for this IP, web/API server access logs (caller IP, timestamps, URI, User-Agent), and upstream application state",
    "endpoint": "Domain registrar & DNS hosting records, web/API server access logs (caller IP, timestamps, URI, payload), TLS certificate history, and upstream database",
    "other": "Domain registrar & hosting subscriber records, server access logs (caller IP, timestamps, request URI/body), and upstream application data",
}


def provider_holds(cls: str, service: str) -> str:
    s = (service or "").lower().strip()
    if s in PROVIDER_HOLDS:
        return PROVIDER_HOLDS[s]
    for k, v in PROVIDER_HOLDS.items():
        if k in s or s in k and len(s) >= 4:
            return v
    return CLASS_HOLDS.get(cls or "other", CLASS_HOLDS["other"])


_ENV_LOOKUP_RE = re.compile(
    r"""(?:\bgetenv\s*\(\s*['"]([A-Za-z0-9_.-]+)['"]\s*\)|"""
    r"""\$_(?:ENV|SERVER)\s*\[\s*['"]([A-Za-z0-9_.-]+)['"]\s*\]|"""
    r"""\benv\s*\(\s*['"]([A-Za-z0-9_.-]+)['"](?:\s*,\s*['"]([^'"]*)['"])?\s*\)|"""
    r"""\b(?:config|Config::get|\$this->getParameter|constant)\s*\(\s*['"]([A-Za-z0-9_.-]+)['"]\s*\)|"""
    r"""\$(?:config|cfg|settings|env)\s*\[\s*['"]([A-Za-z0-9_.-]+)['"]\s*\]|"""
    r"""\bos\.getenv\s*\(\s*['"]([A-Za-z0-9_.-]+)['"](?:\s*,\s*['"]([^'"]*)['"])?\s*\)|"""
    r"""\bos\.environ\.get\s*\(\s*['"]([A-Za-z0-9_.-]+)['"](?:\s*,\s*['"]([^'"]*)['"])?\s*\)|"""
    r"""\bos\.environ\s*\[\s*['"]([A-Za-z0-9_.-]+)['"]\s*\]|"""
    r"""\b(?:settings|config)\.([A-Z][A-Z0-9_]{2,})\b|"""
    r"""\b(?:settings|config)\s*\[\s*['"]([A-Za-z0-9_.-]+)['"]\s*\]|"""
    r"""\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)|"""
    r"""\bprocess\.env\s*\[\s*['"]([A-Za-z0-9_.-]+)['"]\s*\]|"""
    r"""\bimport\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*))"""
)


def _call_args(text: str, open_paren_pos: int, limit: int = 800) -> tuple[list[str], int]:
    """Parse balanced-parenthesis arguments starting at open_paren_pos ('(') -> (args_list, end_pos).
    Handles nested function calls, arrays/dicts, multiline calls, and quoted strings without splitting on inner commas."""
    n = min(len(text), open_paren_pos + limit)
    i = open_paren_pos + 1
    depth = 1
    quote = ""
    args: list[str] = []
    cur: list[str] = []
    while i < n and depth > 0:
        ch = text[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and i + 1 < n:
                cur.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            cur.append(ch)
        elif ch in ("(", "[", "{"):
            depth += 1
            cur.append(ch)
        elif ch in (")", "]", "}"):
            depth -= 1
            if depth == 0:
                break
            cur.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    last = "".join(cur).strip()
    if last or args:
        args.append(last)
    return args, i


def _build_config_index(values: list[dict[str, Any]], history_secrets: list[dict[str, Any]]) -> dict[str, Any]:
    """Index live and historical config values by exact key, flat underscore key, and suffix so variable hosts and
    credentials in code resolve back to the file and key that defines them."""
    by_key: dict[str, dict[str, Any]] = {}
    all_items: list[dict[str, Any]] = []
    for r in values:
        if r.get("placeholder") or not r.get("value"):
            continue
        entry = {
            "key": r["key"], "value": r["value"], "file": r.get("file", ""), "line": r.get("line", 0),
            "class": r.get("class", "other"), "service": r.get("service", ""), "example": bool(r.get("example")),
            "from_history": False, "commit": "",
        }
        all_items.append(entry)
        for k in {r["key"].lower(), r["key"].lower().replace(".", "_").replace("-", "_"), r["key"].split(".")[-1].lower()}:
            if not k:
                continue
            prev = by_key.get(k)
            if prev is None or (prev["example"] and not entry["example"]):
                by_key[k] = entry
    for h in history_secrets:
        if not h.get("value"):
            continue
        entry = {
            "key": h["key"], "value": h["value"], "file": f"{h.get('repo', '')}/{h.get('path', '')}".replace("//", "/"),
            "line": 0, "class": h.get("class", "other"), "service": h.get("service", ""), "example": False,
            "from_history": not bool(h.get("value_still_in_file")), "commit": (h.get("introduced_by_commit") or "")[:10],
        }
        all_items.append(entry)
        for k in {h["key"].lower(), h["key"].lower().replace(".", "_").replace("-", "_")}:
            if k and k not in by_key:
                by_key[k] = entry
    return {"by_key": by_key, "items": all_items}


def _lookup_cfg(key: str, cfg_idx: dict[str, Any]) -> Optional[dict[str, Any]]:
    by_key = cfg_idx.get("by_key") or {}
    kl = (key or "").strip().lower()
    if kl in by_key:
        return by_key[kl]
    flat = kl.replace(".", "_").replace("-", "_")
    if flat in by_key:
        return by_key[flat]
    leaf = kl.split(".")[-1]
    if leaf in by_key and len(leaf) >= 4:
        return by_key[leaf]
    return None


def _resolve_expr(expr: str, file_vars: dict[str, tuple[str, str, str, int]], cfg_idx: dict[str, Any]) -> tuple[str, str, str, bool, list[int]]:
    """Resolve an expression (URL argument, host argument, concatenated string, f-string, template literal) against
    config keys and in-file variables -> (resolved_text, resolved_from, credential_key, used_variable_or_config, def_lines_used)."""
    raw = (expr or "").strip()
    if not raw:
        return "", "", "", False, []
    # Strip leading Python string prefixes (f"...", r"...", fr"...")
    s = re.sub(r"^[frbuFRBU]{1,2}(?=['\"])", "", raw)
    sources: list[str] = []
    creds: list[str] = []
    def_lines: list[int] = []
    used_var = False

    def repl_env(m: re.Match) -> str:
        nonlocal used_var
        used_var = True
        groups = m.groups()
        key = next((g for idx, g in enumerate(groups) if g is not None and idx not in (3, 7, 9)), "")
        default = groups[3] or groups[7] or groups[9] or ""
        hit = _lookup_cfg(key, cfg_idx)
        if hit:
            tag = f"config:{hit['key']} ({hit['file']})" + (f" [history {hit['commit']}]" if hit.get("from_history") else "")
            if tag not in sources:
                sources.append(tag)
            if SECRET_KEY_RE.search(hit["key"]) and hit["key"] not in creds:
                creds.append(hit["key"])
            return hit["value"]
        if default:
            sources.append(f"config:{key} (default)")
            return default
        sources.append(f"config:{key} (unconfigured)")
        if SECRET_KEY_RE.search(key) and key not in creds:
            creds.append(key)
        return f"__CFG_{key}__"

    s = _ENV_LOOKUP_RE.sub(repl_env, s)

    # shell / PHP / JS template / Python f-string variable references: ${VAR}, $var, {var}
    def repl_var(m: re.Match) -> str:
        nonlocal used_var
        vname = m.group(1) or m.group(2) or m.group(3) or ""
        if not vname or vname.startswith("_"):
            return m.group(0)
        if vname in file_vars:
            used_var = True
            val, src, ckey, dln = file_vars[vname]
            if dln and dln not in def_lines:
                def_lines.append(dln)
            lbl = f"var:${vname}" + (f" <- {src}" if src else "")
            if lbl not in sources:
                sources.append(lbl)
            if ckey and ckey not in creds:
                creds.append(ckey)
            return val
        hit = _lookup_cfg(vname, cfg_idx)
        if hit:
            used_var = True
            lbl = f"config:{hit['key']} ({hit['file']})"
            if lbl not in sources:
                sources.append(lbl)
            if SECRET_KEY_RE.search(hit["key"]) and hit["key"] not in creds:
                creds.append(hit["key"])
            return hit["value"]
        return m.group(0)

    s = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_.]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\}", repl_var, s)
    # Unwrap any remaining ${...} or {...} around already-resolved values in f-strings / template literals
    s = re.sub(r"\$\{([^{}\s]+)\}|\{([^{}:,\s]+)\}", lambda m: m.group(1) or m.group(2), s)

    # If the expression is a single bare identifier (Python/JS variable name without $), check file_vars / cfg_idx
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s):
        if s in file_vars:
            used_var = True
            val, src, ckey, dln = file_vars[s]
            if dln and dln not in def_lines:
                def_lines.append(dln)
            lbl = f"var:{s}" + (f" <- {src}" if src else "")
            if lbl not in sources:
                sources.append(lbl)
            if ckey and ckey not in creds:
                creds.append(ckey)
            s = val
        else:
            hit = _lookup_cfg(s, cfg_idx)
            if hit:
                used_var = True
                lbl = f"config:{hit['key']} ({hit['file']})"
                if lbl not in sources:
                    sources.append(lbl)
                if SECRET_KEY_RE.search(hit["key"]) and hit["key"] not in creds:
                    creds.append(hit["key"])
                s = hit["value"]

    # Collapse string concatenation operators (PHP ` . ` and Python/JS ` + `) without touching dots inside hosts/IPs
    s = re.sub(r"""['"`]\s*(?:\.|\+)\s*['"`]""", "", s)
    s = re.sub(r"""['"`]\s*(?:\.|\+)\s*""", "", s)
    s = re.sub(r"""\s*(?:\.|\+)\s*['"`]""", "", s)
    joined = re.sub(r"^[frbuFRBU]{1,2}(?=['\"])", "", s.strip()).strip("\"'`")
    return joined, "; ".join(sources[:3]), ", ".join(creds[:3]), used_var, def_lines


_ASSIGN_RE = re.compile(
    r"""(?m)^\s*(?:(?:const|let|var|export\s+const|private|public|protected|readonly)\s+)?"""
    r"""(?:\$([A-Za-z_][A-Za-z0-9_]{0,60})|(?:self|this)\.([A-Za-z_][A-Za-z0-9_]{0,60})|([A-Za-z_][A-Za-z0-9_]{1,60}))"""
    r"""(?<![=!<>])\s*=\s*(?![=>])([^\n;]{2,400})"""
)
_DEFINE_ASSIGN_RE = re.compile(r"""\bdefine\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*([^)]+)\)""")


def _extract_file_vars(text: str, cfg_idx: dict[str, Any]) -> dict[str, tuple[str, str, str, int]]:
    """Collect local variable and constant assignments in a code file so call sites referencing $u, $host, base_url,
    etc. resolve to the literal or config-backed URL/host."""
    fvars: dict[str, tuple[str, str, str, int]] = {}
    for m in _DEFINE_ASSIGN_RE.finditer(text):
        k, rhs = m.group(1), m.group(2).strip()
        ln = text.count("\n", 0, m.start()) + 1
        val, src, ckey, _, _ = _resolve_expr(rhs, fvars, cfg_idx)
        if val:
            fvars[k] = (val, src, ckey, ln)
    for m in _ASSIGN_RE.finditer(text):
        vname = m.group(1) or m.group(2) or m.group(3) or ""
        rhs = m.group(4).strip().rstrip(";").strip()
        if not vname or vname in ("if", "for", "while", "return", "switch", "catch", "elif", "else", "case"):
            continue
        if re.match(r"^(?:curl_init|file_get_contents|fopen|fsockopen|pfsockopen|stream_socket_client|requests\.|httpx\.|fetch\(|axios\.)", rhs):
            continue
        ln = text.count("\n", 0, m.start()) + 1
        val, src, ckey, used, _ = _resolve_expr(rhs, fvars, cfg_idx)
        if val and ("://" in val or used or DOMAIN_RE.search(val) or IPV4_RE.search(val) or TG_TOKEN_RE.search(val) or val.startswith("/")):
            fvars[vname] = (val, src, ckey, ln)
    return fvars


_LICENSE_BEACON_RE = re.compile(
    r"(licen[cs]e|check_?licen[cs]e|verify_?licen[cs]e|activate_?licen[cs]e|heartbeat|beacon|phone_?home|"
    r"kill_?switch|version_?check|update_?check|/gate\b|panel_?sync|register_?node|report_?status|hwid|machine_?id)",
    re.I,
)
_PAYLOAD_KEY_RE = re.compile(r"""['"]([A-Za-z_][A-Za-z0-9_.-]{1,40})['"]\s*(?:=>|:\s*(?!//))""")
_PAYLOAD_VAR_RE = re.compile(r"""(\$_(?:POST|GET|REQUEST|SERVER|COOKIE)\s*\[\s*['"][^'"]+['"]\s*\]|\$[A-Za-z_][A-Za-z0-9_]{1,32})""")
_HEADER_NAME_RE = re.compile(r"""['"]([A-Za-z][A-Za-z0-9-]{2,40})\s*:\s*(?!//)[^'"]*['"]""")
_QUERY_KEY_RE = re.compile(r"""[?&]([A-Za-z0-9_.-]{2,32})=""")


def _extract_payload_and_creds(window: str, url: str, cfg_idx: dict[str, Any]) -> tuple[str, str]:
    """Summarize payload keys, variables, query parameters and headers sent in a call window, and identify any
    referenced credential keys."""
    keys: list[str] = []
    vars_: list[str] = []
    hdrs: list[str] = []
    creds: list[str] = []

    for m in _QUERY_KEY_RE.finditer(url or ""):
        k = m.group(1)
        if k not in keys:
            keys.append(k)
    for m in _HEADER_NAME_RE.finditer(window):
        h = m.group(1)
        if h.lower() not in ("content-type", "accept", "user-agent", "cache-control", "connection", "content-length", "http", "https") and h not in hdrs:
            hdrs.append(h)
    for m in _PAYLOAD_KEY_RE.finditer(window):
        k = m.group(1)
        if k.lower() in ("http", "https", "method", "header", "headers", "content", "body", "json", "data", "form_params", "timeout", "verify", "url", "uri") or k in hdrs:
            continue
        if k not in keys:
            keys.append(k)
    for m in _PAYLOAD_VAR_RE.finditer(window):
        v = re.sub(r"\s+", "", m.group(1))
        if v.lower() in ("$ch", "$curl", "$hb", "$res", "$resp", "$response", "$err", "$errno", "$status", "$http", "$client", "$this", "$u", "$url", "$uri", "$sock"):
            continue
        if v not in vars_:
            vars_.append(v)
    for m in _ENV_LOOKUP_RE.finditer(window):
        groups = m.groups()
        k = next((g for idx, g in enumerate(groups) if g is not None and idx not in (3, 7, 9)), "")
        if k and (SECRET_KEY_RE.search(k) or _lookup_cfg(k, cfg_idx)) and k not in creds:
            creds.append(k)
    tm = TG_TOKEN_RE.search(url or "") or TG_TOKEN_RE.search(window)
    if tm:
        tok = tm.group(1)
        matched_k = ""
        for it in cfg_idx.get("items") or []:
            if it["value"] == tok:
                matched_k = it["key"]
                break
        lbl = matched_k or f"bot{tok[:10]}…"
        if lbl not in creds:
            creds.append(lbl)

    parts: list[str] = []
    if keys:
        parts.append("keys: " + ", ".join(keys[:8]))
    if vars_:
        parts.append("vars: " + ", ".join(vars_[:6]))
    if hdrs:
        parts.append("headers: " + ", ".join(hdrs[:4]))
    return "; ".join(parts), ", ".join(creds[:4])


def _host_and_url_from_resolved(resolved: str, raw_expr: str) -> tuple[str, str]:
    """Extract (host, clean_url_or_target) from a resolved target string."""
    s = (resolved or "").strip().strip("\"'`")
    # Check unconfigured config placeholder FIRST so __CFG_X__ is never parsed as a literal hostname
    m_cfg = re.search(r"__CFG_([A-Za-z0-9_.-]+)__", s)
    if m_cfg:
        clean_u = re.sub(r"__CFG_([A-Za-z0-9_.-]+)__", r"(config:\1)", s)
        return f"(config:{m_cfg.group(1)})", clean_u[:300]
    m = URL_ANY_RE.search(s)
    if m:
        u = m.group(1).rstrip(".,;:'\")]}")
        try:
            sp = urlsplit(u)
            h = (sp.hostname or "").lower().strip(".")
            if sp.port and IPV4_RE.fullmatch(h):
                h = f"{h}:{sp.port}"
            return h, u
        except ValueError:
            pass
    m_ip = IP_PORT_RE.search(s)
    if m_ip:
        ip = m_ip.group(1)
        port = m_ip.group(2)
        hp = f"{ip}:{port}" if port else ip
        return hp, s[:300]
    m_dom = DOMAIN_RE.search(s)
    if m_dom and "." in m_dom.group(1):
        cand = m_dom.group(1).lower()
        tld = cand.rsplit(".", 1)[-1]
        if tld not in ("py", "php", "js", "ts", "sh", "json", "env", "get", "post", "request", "body", "headers", "format", "join"):
            return cand, s[:300]
    raw_clean = re.sub(r"\s+", " ", raw_expr.strip())[:120]
    return f"(expr:{raw_clean[:60]})" if raw_clean else "", raw_clean


# Call patterns across languages (open-paren anchored for balanced argument extraction)
_PHP_CURL_INIT_OPEN_RE = re.compile(r"\bcurl_init\s*\(")
_PHP_CURLOPT_URL_RE = re.compile(r"\bCURLOPT_URL\s*(?:,|=?>)\s*([^\n,);\]]+)")
_PHP_FGC_OPEN_RE = re.compile(r"\b(file_get_contents|fopen)\s*\(")
_PHP_HTTP_CLIENT_OPEN_RE = re.compile(
    r"(?:\bHttp\s*::\s*(?:withToken\([^)]*\)\s*->\s*|withHeaders\([^)]*\)\s*->\s*|asForm\(\)\s*->\s*|timeout\([^)]*\)\s*->\s*)*"
    r"|\$(?:client|http|guzzle|api)\w*\s*->\s*|\bwp_remote_)"
    r"(get|post|put|delete|patch|head|request|send)\s*\(",
    re.I,
)
_PY_HTTP_OPEN_RE = re.compile(
    r"\b(requests|httpx|urllib\.request|aiohttp|\w*session|\w*client)\s*\.\s*(get|post|put|delete|patch|head|request|urlopen|Request)\s*\("
)
_JS_HTTP_OPEN_RE = re.compile(
    r"(?:\b(fetch|axios|got)\s*\(|\b(axios|got|http|https|superagent)\s*\.\s*(get|post|put|delete|patch|request)\s*\(|\bnew\s+(WebSocket)\s*\()"
)
_GO_RB_HTTP_OPEN_RE = re.compile(
    r"\b(?:(http)\.(Get|Post|PostForm|NewRequest|NewRequestWithContext)|(Net::HTTP|Faraday|RestClient|HttpClient)\.(get|post|put|delete|get_response|PostAsync|GetAsync))\s*\("
)
_SOCKET_OPEN_RE = re.compile(
    r"\b(p?fsockopen|stream_socket_client|socket_connect|socket\.create_connection|\w*sock\w*\.connect|(?:net|tls)\.(?:connect|createConnection))\s*\("
)
_MAIL_CALL_OPEN_RE = re.compile(
    r"(?:\b(mail|wp_mail)\s*\(|(?:\$\w*mail\w*|\bMail|\bMailer)\s*(?:->|::)\s*(send|to|raw|queue)\s*\("
    r"|\bsmtplib\.(SMTP(?:_SSL)?)\s*\(|\b(nodemailer\.createTransport)\s*\(|\.?(sendMail|sendmail|send_message)\s*\()"
)
_TG_DISCORD_SDK_OPEN_RE = re.compile(
    r"(?:(?:\$(?:bot|tg|telegram)\w*|\b(?:bot|telegram|tg|dispatcher|Telegram))\s*(?:->|::|\.)\s*"
    r"(send_?message|send_?document|send_?photo|send_?video|send_?audio|send_?media_?group|forward_?message|set_?webhook|get_?updates|"
    r"sendMessage|sendDocument|sendPhoto|sendVideo|sendAudio|sendMediaGroup|forwardMessage|setWebhook|getUpdates)\s*\("
    r"|\bnew\s+(DiscordWebhook|WebhookClient)\s*\()"
)
_SHELL_CURL_WGET_RE = re.compile(r"(?<![\w/.-])(curl|wget)\b\s+([^\n`]{3,400})")
_SHELL_PIPE_EXEC_RE = re.compile(
    r"(?:\|\s*(?:sudo\s+)?(?:/usr/bin/|/bin/)?(?:ba|z|da|k|a)?sh\b|\|\s*(?:sudo\s+)?(?:python3?|php|perl|ruby|node)\b|"
    r"(?:ba|z)?sh\s+-c\s+['\"]?\$\((?:curl|wget)\b|eval\s+['\"]?\$\((?:curl|wget)\b|&&\s*chmod\s+\+x\b)"
)
_CRON_LINE_RE = re.compile(r"^\s*((?:@[a-zA-Z]+|(?:[\d*,/-]+\s+){5}))(?:([a-zA-Z0-9_-]+)\s+)?(.+)$")
_SCHED_METHOD_RE = re.compile(r"->\s*(?:command|exec|call)\s*\(\s*([^)]+)\).*?->\s*(cron\s*\([^)]+\)|every[A-Za-z]+\s*\([^)]*\)|hourly\s*\(|daily\s*\(|weekly\s*\()", re.S)

# Inbound webhook / IPN patterns
_WEBHOOK_ROUTE_RE = re.compile(
    r"""(?:\bRoute\s*::\s*(post|get|any|match)\s*\(\s*['"]([^'"]*(?:webhook|ipn|callback|notify|hook|bot)[^'"]*)['"]|"""
    r"""#\[Route\s*\(\s*['"]([^'"]*(?:webhook|ipn|callback|notify|hook|bot)[^'"]*)['"]|"""
    r"""@Route\s*\(\s*['"]([^'"]*(?:webhook|ipn|callback|notify|hook|bot)[^'"]*)['"]|"""
    r"""@(?:app|router|bp)\.(post|get|route|all)\s*\(\s*['"]([^'"]*(?:webhook|ipn|callback|notify|hook|bot)[^'"]*)['"]|"""
    r"""\b(?:app|router)\.(post|get|all|use)\s*\(\s*['"]([^'"]*(?:webhook|ipn|callback|notify|hook|bot)[^'"]*)['"]|"""
    r"""\bpath\s*\(\s*['"]([^'"]*(?:webhook|ipn|callback|notify|hook|bot)[^'"]*)['"])""",
    re.I,
)
_WEBHOOK_SIG_PATTERNS: list[tuple[re.Pattern, str, str, str, str]] = [
    (re.compile(r"HTTP_STRIPE_SIGNATURE|Stripe-Signature|Webhook::constructEvent|stripe\.Webhook\.construct_event", re.I), "webhook", "payments", "stripe", "Stripe-Signature"),
    (re.compile(r"_notify-validate|HTTP_PAYPAL_TRANSMISSION_SIG", re.I), "ipn", "payments", "paypal", "PayPal IPN verify"),
    (re.compile(r"PAYMENT_BATCH_NUM|V2_HASH|PAYEE_ACCOUNT", re.I), "ipn", "payments", "perfect money", "V2_HASH (MD5)"),
    (re.compile(r"x-nowpayments-sig|HTTP_X_NOWPAYMENTS_SIG", re.I), "ipn", "crypto", "nowpayments", "x-nowpayments-sig (HMAC)"),
    (re.compile(r"HTTP_HMAC.*ipn_mode|ipn_mode.*HTTP_HMAC", re.I | re.S), "ipn", "crypto", "coinpayments", "HTTP_HMAC"),
    (re.compile(r"BTCPay-Sig|HTTP_BTCPAY_SIG", re.I), "webhook", "crypto", "btcpay", "BTCPay-Sig"),
    (re.compile(r"X-Telegram-Bot-Api-Secret-Token|HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN", re.I), "bot-webhook", "messaging", "telegram", "X-Telegram-Bot-Api-Secret-Token"),
    (re.compile(r"['\"]update_id['\"].*['\"](?:message|callback_query)['\"]|['\"]callback_query['\"].*['\"]chat['\"]", re.I | re.S), "bot-webhook", "messaging", "telegram", "Telegram Update JSON"),
    (re.compile(r"aftership-hmac-sha256|HTTP_AFTERSHIP_HMAC_SHA256", re.I), "webhook", "shipping", "aftership", "aftership-hmac-sha256"),
    (re.compile(r"X-Twilio-Signature|HTTP_X_TWILIO_SIGNATURE", re.I), "webhook", "sms", "twilio", "X-Twilio-Signature"),
    (re.compile(r"X-Hub-Signature-256|HTTP_X_HUB_SIGNATURE_256", re.I), "webhook", "code-hosting", "github", "X-Hub-Signature-256"),
    (re.compile(r"m_operation_id.*m_sign|m_sign.*m_operation_id", re.I | re.S), "ipn", "payments", "payeer", "m_sign (SHA256)"),
    (re.compile(r"notification_type.*sha1_hash|sha1_hash.*notification_type", re.I | re.S), "ipn", "payments", "yoomoney", "sha1_hash"),
]
_WEBHOOK_FILENAME_RE = re.compile(r"(webhook|ipn|callback|notify|bot_?hook|payment_?status)", re.I)
_INPUT_FIELD_RE = re.compile(
    r"""(?:\$_(?:POST|GET|REQUEST)\s*\[\s*['"]([A-Za-z0-9_.-]{2,40})['"]\s*\]|"""
    r"""\$(?:data|payload|input|update|body|event|req|request)\s*\[\s*['"]([A-Za-z0-9_.-]{2,40})['"]\s*\]|"""
    r"""\b(?:data|payload|body|req\.body|request\.json)\.(?:get\s*\(\s*['"]([A-Za-z0-9_.-]{2,40})['"]\)|([A-Za-z0-9_]{2,40})))"""
)


def scan_calls(
    root: Path,
    values: list[dict[str, Any]],
    history_secrets: list[dict[str, Any]],
    hosts: list[dict[str, Any]],
    hits: list[dict[str, Any]],
    idents: list[dict[str, Any]],
    log: Log,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Scan code, config and cron files for outbound network/service calls (including variable hosts resolved from
    configuration) and inbound webhook/IPN handlers -> (calls, webhooks)."""
    t0 = time.time()
    cfg_idx = _build_config_index(values, history_secrets)
    calls: list[dict[str, Any]] = []
    webhooks: list[dict[str, Any]] = []
    host_map: dict[str, dict[str, Any]] = {h["host"]: h for h in hosts}
    hit_keys: set[tuple[str, str]] = {(x["host"], x["file"]) for x in hits}

    default_mail_host = ""
    default_tg_key = ""
    for it in cfg_idx.get("items") or []:
        if it["class"] == "mail" and not default_mail_host:
            h = _host_of(it["value"])
            if h:
                default_mail_host = h
        if it["service"] == "telegram" and not default_tg_key and TG_TOKEN_RE.search(it["value"]):
            default_tg_key = it["key"]

    def ensure_host_in_endpoints(host: str, url: str, rel: str, line: int, excerpt: str, how: str) -> tuple[str, str]:
        hclean = (host or "").lower().strip(".")
        if not hclean or hclean.startswith("("):
            return "endpoint", ""
        base_h = hclean.split(":")[0] if re.match(r"^[\d.]+:\d+$", hclean) else hclean
        cls, svc = classify_host(base_h)
        if cls in ("noise", "internal"):
            return cls, svc
        existing = host_map.get(hclean)
        if existing is None:
            rec = {
                "host": hclean, "class": cls, "service": svc, "hits": 1, "files_n": 1, "files": [rel],
                "first_file": rel, "first_line": line, "example": (url or hclean)[:300], "schemes": how,
            }
            hosts.append(rec)
            host_map[hclean] = rec
            hit_keys.add((hclean, rel))
            if len(hits) < 200_000:
                hits.append({"host": hclean, "class": cls, "service": svc, "url": (url or hclean)[:500], "file": rel, "line": line, "excerpt": excerpt[:200], "how": how})
        elif (hclean, rel) not in hit_keys:
            existing["hits"] += 1
            existing["files_n"] = existing.get("files_n", len(existing["files"])) + 1
            if rel not in existing["files"] and len(existing["files"]) < 6:
                existing["files"].append(rel)
            hit_keys.add((hclean, rel))
            if len(hits) < 200_000:
                hits.append({"host": hclean, "class": cls, "service": svc, "url": (url or hclean)[:500], "file": rel, "line": line, "excerpt": excerpt[:200], "how": how})
        return cls, svc

    def add_call(
        rel: str, line: int, kind: str, mechanism: str, method: str, raw_target: str, window: str, excerpt: str,
        file_vars: dict[str, tuple[str, str, str, int]], consumed_lines: set[int], extra_flags: Optional[list[str]] = None,
        forced_host: str = "", forced_cls: str = "", forced_svc: str = "", schedule: str = "",
    ):
        resolved, res_from, ckey_from_target, used_var, def_lns = _resolve_expr(raw_target, file_vars, cfg_idx)
        for dln in def_lns:
            consumed_lines.add(dln)
        host, clean_url = _host_and_url_from_resolved(resolved, raw_target)
        if forced_host and (not host or host.startswith("(")):
            host = forced_host
        base_h = host.split(":")[0] if re.match(r"^[\d.]+:\d+$", host) else host
        cls, svc = classify_host(base_h) if host and not host.startswith("(") else (forced_cls or "endpoint", forced_svc or "")
        if forced_cls and cls in ("other", "endpoint"):
            cls = forced_cls
        if forced_svc and not svc:
            svc = forced_svc
        if cls == "noise":
            return
        if used_var and host and not host.startswith("("):
            ensure_host_in_endpoints(host, clean_url, rel, line, excerpt, "call (config)" if "config:" in res_from else "call (var)")
        payload, ckey_win = _extract_payload_and_creds(window, clean_url, cfg_idx)
        if schedule:
            payload = f"schedule: {schedule}" + (f"; {payload}" if payload else "")
        cred_key = ", ".join(dict.fromkeys([c for c in (ckey_from_target, ckey_win) if c]))
        flags: list[str] = list(extra_flags or [])
        if used_var and "variable-host" not in flags:
            flags.append("variable-host")
        if svc == "telegram" or "api.telegram.org" in host or kind == "telegram":
            kind = "telegram"
            cls, svc = "messaging", "telegram"
            if "telegram-notify" not in flags:
                flags.append("telegram-notify")
            m_act = re.search(r"/bot[^/]+/([A-Za-z]+)", clean_url)
            if m_act and m_act.group(1) not in payload:
                payload = f"action: {m_act.group(1)}" + (f"; {payload}" if payload else "")
            if not cred_key and default_tg_key:
                cred_key = default_tg_key
        elif svc == "discord" or "discord.com/api/webhooks" in clean_url or "discordapp.com/api/webhooks" in clean_url or kind == "discord":
            kind = "discord"
            cls, svc = "messaging", "discord"
            if "discord-webhook" not in flags:
                flags.append("discord-webhook")
        if _LICENSE_BEACON_RE.search(clean_url) or _LICENSE_BEACON_RE.search(window) or _LICENSE_BEACON_RE.search(rel):
            if "license-check" not in flags and "heartbeat" not in flags:
                flags.append("license-check" if re.search(r"licen[cs]e|activate|hwid", clean_url + " " + window, re.I) else "heartbeat")
            if kind == "http":
                kind = "license/heartbeat"
        calls.append({
            "file": rel, "line": line, "kind": kind, "mechanism": mechanism, "method": method.upper(),
            "host": host or "(dynamic)", "url_or_target": (clean_url or raw_target.strip())[:400],
            "class": cls, "service": svc, "resolved_from": res_from, "payload": payload[:300],
            "credential_key": cred_key[:160], "flags": ", ".join(flags), "excerpt": excerpt.strip()[:240],
        })

    for p in _code_files(root):
        text = _read_text(p)
        if not text:
            continue
        rel = _rel(p, root)
        nm = p.name.lower()
        ext = os.path.splitext(nm)[1]
        is_cron_file = nm in ("crontab",) or "cron" in rel.lower()
        is_shell_file = ext in (".sh", ".bash", ".bat", ".cmd", ".ps1") or nm in ("dockerfile", "makefile", "procfile", "crontab")
        is_code = ext in (".php", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".vue", ".py", ".rb", ".go", ".java", ".kt", ".cs", ".rs", ".sh", ".bash")
        if not is_code and not is_cron_file and not is_shell_file:
            continue

        lines = text.splitlines()[:50000]
        file_vars = _extract_file_vars(text[:300_000], cfg_idx)
        consumed_lines: set[int] = set()

        def get_curl_window(ln: int, max_span: int = 16) -> tuple[str, int]:
            out_l: list[str] = []
            end_ln = ln
            for k in range(ln - 1, min(len(lines), ln - 1 + max_span)):
                if k > ln - 1 and re.search(r"\bcurl_init\s*\(", lines[k]):
                    break
                out_l.append(lines[k])
                end_ln = k + 1
                if re.search(r"\b(?:curl_exec|curl_close|curl_multi_add_handle)\s*\(", lines[k]):
                    break
            return "\n".join(out_l), end_ln

        def mark_span(start_pos: int, end_pos: int) -> tuple[int, str]:
            ln1 = text.count("\n", 0, start_pos) + 1
            ln2 = text.count("\n", 0, max(start_pos, end_pos)) + 1
            for k in range(ln1, ln2 + 1):
                consumed_lines.add(k)
            win = "\n".join(lines[max(0, ln1 - 1):min(len(lines), ln2 + 1)])
            return ln1, win

        # 1. PHP cURL blocks & HTTP calls
        if ext in (".php", ".inc", ".tpl"):
            for m in _PHP_CURL_INIT_OPEN_RE.finditer(text):
                args, end_p = _call_args(text, m.end() - 1)
                ln = text.count("\n", 0, m.start()) + 1
                win, end_ln = get_curl_window(ln, 16)
                arg = args[0] if args and args[0] else ""
                if not arg:
                    mu = _PHP_CURLOPT_URL_RE.search(win)
                    arg = mu.group(1).strip() if mu else ""
                method = "GET"
                if re.search(r"CURLOPT_POST\b\s*(?:,|=?>)\s*(?:true|1)|CURLOPT_POSTFIELDS", win, re.I):
                    method = "POST"
                mc = re.search(r"CURLOPT_CUSTOMREQUEST\s*(?:,|=?>)\s*['\"]([A-Z]+)['\"]", win)
                if mc:
                    method = mc.group(1)
                for k in range(ln, end_ln + 1):
                    consumed_lines.add(k)
                add_call(rel, ln, "http", "php:curl", method, arg, win, lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines,
                         extra_flags=["cron"] if is_cron_file else None)

            for m in _PHP_CURLOPT_URL_RE.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                if ln in consumed_lines:
                    continue
                win, end_ln = get_curl_window(max(1, ln - 2), 12)
                method = "POST" if re.search(r"CURLOPT_POST|CURLOPT_POSTFIELDS", win) else "GET"
                for k in range(ln, end_ln + 1):
                    consumed_lines.add(k)
                add_call(rel, ln, "http", "php:curl", method, m.group(1).strip(), win, lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines,
                         extra_flags=["cron"] if is_cron_file else None)

            for m in _PHP_FGC_OPEN_RE.finditer(text):
                fn = m.group(1)
                args, end_p = _call_args(text, m.end() - 1)
                if not args or not args[0]:
                    continue
                arg = args[0]
                ctx_arg = args[2] if len(args) >= 3 else ""
                if arg in ("'php://input'", '"php://input"', "STDIN"):
                    continue
                resolved, _, _, used, _ = _resolve_expr(arg, file_vars, cfg_idx)
                ln, win = mark_span(m.start(), end_p)
                if "://" in resolved and re.match(r"^(https?|ftp|sftp|ssh|tcp|tls|ssl)://", resolved, re.I) or used and ("http" in resolved.lower() or _host_and_url_from_resolved(resolved, arg)[0] and not _host_and_url_from_resolved(resolved, arg)[0].startswith("(")) or ctx_arg and "http" in win.lower():
                    method = "POST" if re.search(r"['\"]method['\"]\s*=>\s*['\"]POST['\"]", win, re.I) else "GET"
                    add_call(rel, ln, "http", f"php:{fn}", method, arg, win, lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines,
                             extra_flags=["cron"] if is_cron_file else None)

            for m in _PHP_HTTP_CLIENT_OPEN_RE.finditer(text):
                verb = m.group(1).upper()
                args, end_p = _call_args(text, m.end() - 1)
                if not args:
                    continue
                if verb in ("REQUEST", "SEND") and len(args) >= 2 and re.fullmatch(r"['\"][A-Za-z]+['\"]", args[0]):
                    verb = args[0].strip("\"'").upper()
                    target_arg = args[1]
                else:
                    target_arg = args[0]
                ln, win = mark_span(m.start(), end_p)
                add_call(rel, ln, "http", "php:http-client", verb if verb not in ("REQUEST", "SEND") else "POST", target_arg, win,
                         lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines, extra_flags=["cron"] if is_cron_file else None)

        # 2. Python HTTP calls
        if ext == ".py":
            for m in _PY_HTTP_OPEN_RE.finditer(text):
                lib, verb = m.group(1), m.group(2)
                args, end_p = _call_args(text, m.end() - 1)
                if not args:
                    continue
                if verb.lower() == "request" and len(args) >= 2:
                    method = args[0].strip("\"'").upper()
                    target_arg = args[1]
                else:
                    method = "GET" if verb.lower() in ("get", "urlopen", "head") else ("POST" if verb.lower() in ("post", "request") else verb.upper())
                    target_arg = args[0]
                ln, win = mark_span(m.start(), end_p)
                add_call(rel, ln, "http", f"py:{lib}.{verb}", method, target_arg, win, lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines,
                         extra_flags=["cron"] if is_cron_file else None)

        # 3. JS / TS HTTP & WebSocket calls
        if ext in (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".vue"):
            for m in _JS_HTTP_OPEN_RE.finditer(text):
                args, end_p = _call_args(text, m.end() - 1)
                if not args:
                    continue
                ln, win = mark_span(m.start(), end_p)
                target_arg = args[0]
                if m.group(1):
                    lib = m.group(1)
                    mm = re.search(r"method\s*:\s*['\"]([A-Za-z]+)['\"]", win, re.I)
                    method = mm.group(1).upper() if mm else "GET"
                    mech = f"js:{lib}"
                elif m.group(2):
                    lib, verb = m.group(2), m.group(3)
                    method = verb.upper() if verb.lower() != "request" else "POST"
                    mech = f"js:{lib}.{verb}"
                else:
                    method = "WS"
                    mech = "js:WebSocket"
                add_call(rel, ln, "http", mech, method, target_arg, win, lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines)

        # 4. Go / Ruby / Java / C# HTTP calls
        if ext in (".go", ".rb", ".java", ".kt", ".cs"):
            for m in _GO_RB_HTTP_OPEN_RE.finditer(text):
                verb = (m.group(2) or m.group(4) or "GET").upper()
                args, end_p = _call_args(text, m.end() - 1)
                if not args:
                    continue
                if "NEWREQUEST" in verb and len(args) >= 2:
                    method = args[0].strip("\"'").upper()
                    target_arg = args[1]
                else:
                    method = "POST" if "POST" in verb else "GET"
                    target_arg = args[0]
                ln, win = mark_span(m.start(), end_p)
                add_call(rel, ln, "http", f"{ext.lstrip('.')}:http", method, target_arg, win, lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines)

        # 5. Telegram / Discord SDK calls
        for m in _TG_DISCORD_SDK_OPEN_RE.finditer(text):
            ln_check = text.count("\n", 0, m.start()) + 1
            if ln_check in consumed_lines:
                continue
            args, end_p = _call_args(text, m.end() - 1)
            ln, win = mark_span(m.start(), end_p)
            if m.group(1):
                act = m.group(1)
                add_call(rel, ln, "telegram", f"sdk:{act}", "POST", f"https://api.telegram.org/{act}", win + " " + ", ".join(args),
                         lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines, extra_flags=["telegram-notify"],
                         forced_host="api.telegram.org", forced_cls="messaging", forced_svc="telegram")
            else:
                cls_nm = m.group(2)
                add_call(rel, ln, "discord", f"sdk:{cls_nm}", "POST", args[0] if args else "", win,
                         lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines, extra_flags=["discord-webhook"],
                         forced_host="discord.com", forced_cls="messaging", forced_svc="discord")

        # 6. Sockets
        for m in _SOCKET_OPEN_RE.finditer(text):
            fn = m.group(1)
            args, end_p = _call_args(text, m.end() - 1)
            if not args:
                continue
            ln, win = mark_span(m.start(), end_p)
            target_arg = args[0]
            if len(args) >= 2 and re.fullmatch(r"\d{2,5}", args[1]):
                h_clean = args[0].strip('"').strip("'")
                target_arg = f"{h_clean}:{args[1]}"
            add_call(rel, ln, "socket", f"socket:{fn}", "TCP", target_arg, win, lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines)

        # 7. Mail calls
        for m in _MAIL_CALL_OPEN_RE.finditer(text):
            fn = m.group(1) or m.group(2) or m.group(3) or m.group(4) or m.group(5) or "mail"
            args, end_p = _call_args(text, m.end() - 1)
            ln, win = mark_span(m.start(), end_p)
            first_arg = args[0] if args else ""
            target_arg = first_arg if fn.startswith("SMTP") else (default_mail_host or first_arg or "smtp")
            add_call(rel, ln, "mail", f"mail:{fn}", "SMTP", target_arg, win, lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines,
                     forced_host=default_mail_host, forced_cls="mail", forced_svc="mail")

        # 8. Shell / Cron / Subprocess curl & wget (including curl|sh)
        for i, line in enumerate(lines, 1):
            if i in consumed_lines:
                continue
            sched = ""
            cm = _CRON_LINE_RE.match(line) if is_cron_file else None
            if cm and not line.lstrip().startswith("#"):
                sched = cm.group(1).strip()
            for m in _SHELL_CURL_WGET_RE.finditer(line):
                tool, rest = m.group(1), m.group(2)
                url_m = URL_ANY_RE.search(rest) or re.search(r"(['\"]?https?://[^\s\"'|;&]+|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?[^\s\"'|;&]*)", rest)
                if not url_m:
                    continue
                target_arg = url_m.group(0).strip("\"'")
                pipe_exec = bool(_SHELL_PIPE_EXEC_RE.search(line))
                method = "POST" if re.search(r"(?:^|\s)(?:-X\s*POST|--data|--data-raw|--data-binary|-d\s|-F\s|--post-data)", rest) else "GET"
                flags = []
                if pipe_exec:
                    flags.append("shell-pipe-exec")
                if is_cron_file or sched:
                    flags.append("cron")
                kind = "shell-exec" if pipe_exec else ("cron" if (is_cron_file or sched) else "http")
                mech = f"sh:{tool}|sh" if pipe_exec else (f"cron:{tool}" if (is_cron_file or sched) else f"sh:{tool}")
                consumed_lines.add(i)
                add_call(rel, i, kind, mech, method, target_arg, line, line, file_vars, consumed_lines, extra_flags=flags, schedule=sched)

        # Framework scheduler definitions (e.g. $schedule->exec('curl ...')->everyFiveMinutes())
        for m in _SCHED_METHOD_RE.finditer(text):
            ln = text.count("\n", 0, m.start()) + 1
            if ln in consumed_lines:
                continue
            cmd_arg, freq = m.group(1).strip(), m.group(2).strip()
            add_call(rel, ln, "cron", "scheduler", "CRON", cmd_arg, m.group(0), lines[ln - 1] if ln <= len(lines) else "", file_vars, consumed_lines,
                     extra_flags=["cron"], schedule=freq)

        # 9. Variable-assigned API action URLs (Telegram /bot.../sendMessage, SMS handler_api.php, AfterShip /v4/trackings, /gate)
        # when assigned in a code stub or helper whose call happens in another file (and not already consumed above)
        if is_code:
            for i, line in enumerate(lines, 1):
                if i in consumed_lines:
                    continue
                for m in URL_ANY_RE.finditer(line):
                    u = m.group(1).rstrip(".,;:'\")]}")
                    try:
                        sp = urlsplit(u)
                        h = (sp.hostname or "").lower()
                        pth = sp.path or ""
                    except ValueError:
                        continue
                    if not h or sp.scheme.lower() not in ("http", "https", "wss", "ws", "socks5", "socks4", "socks"):
                        continue
                    cls, svc = classify_host(h)
                    if cls in ("noise", "internal"):
                        continue
                    if pth and pth != "/" and (cls in LEAD_CLASSES or cls == "ip" or _LICENSE_BEACON_RE.search(u)):
                        method = "POST" if re.search(r"sendMessage|sendDocument|sendPhoto|webhook|trackings|/gate|pay|order", u, re.I) else "GET"
                        kind = "telegram" if svc == "telegram" else ("license/heartbeat" if _LICENSE_BEACON_RE.search(u) else "http")
                        add_call(rel, i, kind, "url-endpoint", method, u, line, line, file_vars, consumed_lines,
                                 extra_flags=["cron"] if is_cron_file else None)

        # 10. Inbound webhooks & IPN handlers
        if is_code:
            file_routes: list[tuple[int, str, str]] = []
            for m in _WEBHOOK_ROUTE_RE.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                method = (m.group(1) or m.group(5) or m.group(7) or "POST").upper()
                route = m.group(2) or m.group(3) or m.group(4) or m.group(6) or m.group(8) or m.group(9) or rel
                file_routes.append((ln, method, route))

            wh_hits: list[tuple[int, str, str, str, str, str]] = []
            seen_wh: set[tuple[str, str]] = set()
            reads_input = bool(re.search(r"php://input|\$_POST|\$_REQUEST|\$_GET|request\.json|req\.body|->getContent\(|get_json\(|request\.form|request\.POST|request\.body|->request->|->query->|\$request->", text))
            for rx, kind, cls, svc, ver in (_WEBHOOK_SIG_PATTERNS if reads_input else ()):
                for m in rx.finditer(text):
                    ln = text.count("\n", 0, m.start()) + 1
                    preceding = [(rln, r) for rln, _, r in file_routes if rln <= ln and ln - rln <= 60]
                    if preceding:
                        route = max(preceding, key=lambda x: x[0])[1]
                    else:
                        nearby = [(abs(rln - ln), r) for rln, _, r in file_routes if abs(rln - ln) <= 30]
                        route = min(nearby, key=lambda x: x[0])[1] if nearby else rel
                    if (svc, route) in seen_wh:
                        continue
                    seen_wh.add((svc, route))
                    wh_hits.append((ln, kind, cls, svc, ver, route))

            for rln, rmethod, route in file_routes:
                if not any(r == route for _, _, _, _, _, r in wh_hits):
                    cls, svc = "endpoint", "webhook"
                    for rx, kc, ks in KEY_CLASSES:
                        if rx.search(route):
                            cls, svc = kc, ks
                            break
                    wh_hits.append((rln, "webhook", cls, svc, "route handler", route))

            if not wh_hits and _WEBHOOK_FILENAME_RE.search(p.name) and re.search(r"php://input|\$_POST|\$_REQUEST|request\.json|req\.body", text):
                cls, svc = "endpoint", "webhook"
                for rx, kc, ks in KEY_CLASSES:
                    if rx.search(p.name) or rx.search(text[:2000]):
                        cls, svc = kc, ks
                        break
                wh_hits.append((1, "ipn" if "ipn" in p.name.lower() else "webhook", cls, svc, "none seen", rel))

            for ln, kind, cls, svc, ver, route in wh_hits:
                win = "\n".join(lines[max(0, ln - 5):min(len(lines), ln + 30)])
                fields: list[str] = []
                for fm in _INPUT_FIELD_RE.finditer(win):
                    fld = fm.group(1) or fm.group(2) or fm.group(3) or fm.group(4) or ""
                    if fld and fld not in fields:
                        fields.append(fld)
                ckey = ""
                for it in cfg_idx.get("items") or []:
                    if it["service"] == svc and svc not in ("", "webhook"):
                        ckey = it["key"]
                        break
                webhooks.append({
                    "file": rel, "line": ln, "kind": kind, "route_or_script": route, "method": "POST",
                    "class": cls, "service": svc, "verification": ver,
                    "payload_fields": ", ".join(fields[:10]), "credential_key": ckey,
                    "excerpt": (lines[ln - 1] if ln <= len(lines) else lines[0]).strip()[:240],
                })

    hosts.sort(key=lambda h: (0 if h["class"] in LEAD_CLASSES else 1 if h["class"] in ("ip", "other", "endpoint") else 2, -h["hits"]))
    log(f"[code] calls: {len(calls)} outbound call(s), {len(webhooks)} inbound webhook/IPN handler(s), {time.time() - t0:.1f} s")
    return calls, webhooks


def build_pivots(
    repos: list[dict[str, Any]],
    values: list[dict[str, Any]],
    history_secrets: list[dict[str, Any]],
    hosts: list[dict[str, Any]],
    hits: list[dict[str, Any]],
    idents: list[dict[str, Any]],
    calls: list[dict[str, Any]],
    webhooks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the per-provider forensic pivot sheet: one row per external provider / contact joining outbound calls,
    inbound webhooks, endpoint references, live & historical credentials, account/bot IDs, what's sent, and what
    records that provider holds."""
    groups: dict[str, dict[str, Any]] = {}

    def norm_provider(cls: str, svc: str, host: str = "") -> tuple[str, str]:
        s = (svc or "").strip().lower()
        c = (cls or "other").strip().lower()
        generic = {"", "host/url", "webhook", "login", "application secret", "public address", "private address", "local", "service name", "other", "endpoint", "carrier", "shipping", "sms", "payments", "crypto", "mail", "proxy", "cloud storage", "code hosting", "ai api", "geo", "captcha"}
        if s and s not in generic:
            return s, (c if c not in ("other", "endpoint") else cls)
        h = (host or "").strip().lower()
        if h and not h.startswith("("):
            base_h = h.split(":")[0] if re.match(r"^[\d.]+:\d+$", h) else h
            hc, hs = classify_host(base_h)
            if hs and hs not in generic:
                return hs, hc
            return h, (hc if hc != "other" else c)
        if s:
            return s, c
        return h or c or "unknown", c

    def get_group(prov: str, cls: str) -> dict[str, Any]:
        g = groups.get(prov)
        if g is None:
            g = groups[prov] = {
                "provider": prov, "class": cls or "other", "hosts": set(), "calls": [], "webhooks": [],
                "hits_n": 0, "methods": set(), "what_sent": [], "cred_keys": [], "creds_masked": [],
                "accounts": [], "live_creds": 0, "hist_creds": 0, "call_sites": [], "webhook_sites": [],
            }
        elif g["class"] in ("other", "endpoint", "info") and cls not in ("other", "endpoint", "info", ""):
            g["class"] = cls
        return g

    def add_unique(lst: list[str], item: str, limit: int = 12):
        if item and item not in lst and len(lst) < limit:
            lst.append(item)

    # 1. Endpoint hosts
    for h in hosts:
        if h["class"] in ("noise", "internal"):
            continue
        prov, cls = norm_provider(h["class"], h["service"], h["host"])
        g = get_group(prov, cls)
        g["hosts"].add(h["host"])
        g["hits_n"] += int(h.get("hits") or 0)
        if h.get("example") and "://" in h["example"]:
            try:
                sp = urlsplit(h["example"])
                if sp.path and sp.path != "/":
                    add_unique(g["what_sent"], f"{sp.scheme.upper()} {sp.path[:80]}")
            except ValueError:
                pass

    # 2. Outbound calls
    for c in calls:
        if c["class"] in ("noise", "internal"):
            continue
        if (not c["host"] or c["host"].startswith("(")) and c["class"] in ("", "endpoint", "other"):
            continue                      # an unresolved variable host is a call site to read in calls.csv, not a provider
        prov, cls = norm_provider(c["class"], c["service"], c["host"])
        g = get_group(prov, cls)
        if c["host"] and not c["host"].startswith("("):
            g["hosts"].add(c["host"])
        g["calls"].append(c)
        g["methods"].add(c["method"])
        add_unique(g["call_sites"], f"{c['file']}:{c['line']}")
        desc = f"{c['method']} {c['url_or_target'][:80]}"
        if c.get("payload"):
            desc += f" ({c['payload'][:100]})"
        if c.get("resolved_from"):
            desc += f" [{c['resolved_from'][:60]}]"
        add_unique(g["what_sent"], desc, 8)
        tm = re.search(r"(\d{8,12}):[A-Za-z0-9_-]{20,}", c.get("url_or_target") or "")
        if tm:
            add_unique(g["accounts"], f"bot_id:{tm.group(1)} ({c['file']}:{c['line']})")

    # 3. Inbound webhooks / IPNs
    for w in webhooks:
        prov, cls = norm_provider(w["class"], w["service"], "")
        g = get_group(prov, cls)
        g["webhooks"].append(w)
        g["methods"].add(f"webhook {w['method']}")
        add_unique(g["webhook_sites"], f"{w['file']}:{w['line']}")
        wdesc = f"inbound {w['kind']} {w['route_or_script']}"
        if w.get("payload_fields"):
            wdesc += f" (fields: {w['payload_fields'][:80]})"
        if w.get("verification") and w["verification"] != "none seen":
            wdesc += f" [verify: {w['verification']}]"
        add_unique(g["what_sent"], wdesc, 8)

    # 4. Live configuration credentials & values
    for v in values:
        if v.get("placeholder") or v.get("example") or v["class"] in ("other", "noise", "internal", "database", "auth", "endpoint"):
            continue
        host_v = _host_of(v["value"])
        prov, cls = norm_provider(v["class"], v["service"], host_v)
        if host_v and (IPV4_RE.fullmatch(host_v) or host_v == "localhost") and classify_host(host_v)[0] == "internal" and prov in (host_v, v["service"], v["class"]):
            continue                      # a local address in config (127.0.0.1:11434) is not a provider to pivot to
        g = get_group(prov, cls)
        if host_v and not IPV4_RE.fullmatch(host_v) or (host_v and not PRIVATE_NET_RE.match(host_v)):
            if host_v:
                g["hosts"].add(host_v)
        g["live_creds"] += 1
        add_unique(g["cred_keys"], f"{v['file']}: {v['key']}")
        add_unique(g["creds_masked"], f"{v['key']}={mask(v['value'])}")
        tm = re.search(r"(\d{8,12}):[A-Za-z0-9_-]{20,}", v["value"])
        if tm:
            add_unique(g["accounts"], f"bot_id:{tm.group(1)} ({v['key']})")
        elif re.search(r"account|merchant|shop_id|client_id|user|login|chat_id|channel|wallet|address|from|perfect_?money", v["key"], re.I) and len(v["value"]) <= 64:
            add_unique(g["accounts"], f"{v['key']}={v['value']}")
        elif "://" in v["value"]:
            dm = DSN_RE.match(v["value"])
            if dm and dm.group("user"):
                add_unique(g["accounts"], f"user:{dm.group('user')}@{dm.group('host') or ''}")

    # 5. Historical secrets (removed from working tree or in git history)
    for h in history_secrets:
        if h["class"] in ("other", "noise", "internal", "database", "auth", "endpoint"):
            continue
        host_v = _host_of(h["value"])
        prov, cls = norm_provider(h["class"], h["service"], host_v)
        g = get_group(prov, cls)
        if host_v and not PRIVATE_NET_RE.match(host_v):
            g["hosts"].add(host_v)
        loc = f"{h.get('repo', '')}/{h.get('path', '')}".replace("//", "/")
        if not h.get("value_still_in_file"):
            g["hist_creds"] += 1
            commit_short = (h.get("introduced_by_commit") or "")[:8]
            add_unique(g["cred_keys"], f"{loc}: {h['key']} [history {commit_short}]")
            add_unique(g["creds_masked"], f"{h['key']}={mask(h['value'])} [history {commit_short}]")
        tm = re.search(r"(\d{8,12}):[A-Za-z0-9_-]{20,}", h["value"])
        if tm:
            add_unique(g["accounts"], f"bot_id:{tm.group(1)} (history:{h['key']})")

    # 6. Identifiers (inline Telegram tokens & t.me links in code)
    for i in idents:
        if i["type"] == "telegram_token":
            g = get_group("telegram", "messaging")
            g["hosts"].add("api.telegram.org")
            bot_id = i["value"].split(":", 1)[0]
            add_unique(g["accounts"], f"bot_id:{bot_id} ({i['first_file']}:{i['first_line']})")
            add_unique(g["creds_masked"], f"token={mask(i['value'])} ({i['first_file']}:{i['first_line']})")
        elif i["type"] == "telegram_link":
            g = get_group("telegram", "messaging")
            g["hosts"].add("t.me")
            add_unique(g["accounts"], i["value"])

    # 7. Git remotes (GitHub / GitLab / Bitbucket / Gitea accounts & tokens in remote URLs)
    for r in repos:
        for rem in r.get("remotes") or []:
            u = rem.get("url") or ""
            h = _host_of(u)
            if not h and "@" in u and ":" in u:
                h = u.split("@", 1)[1].split(":", 1)[0].lower()
            if not h:
                continue
            hc, hs = classify_host(h)
            if hc in ("noise", "internal"):
                continue
            prov, cls = norm_provider(hc, hs, h)
            g = get_group(prov, cls)
            g["hosts"].add(h)
            g["methods"].add("git remote")
            m_slug = re.search(r"[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$", u)
            if m_slug:
                add_unique(g["accounts"], f"repo:{m_slug.group(1)}")
            add_unique(g["what_sent"], f"git remote {rem.get('name', 'origin')} ({r['repo']})")
            for rx, _, _, note in VALUE_SHAPES_LOOSE:
                mt = rx.search(u)
                if mt:
                    g["live_creds"] += 1
                    add_unique(g["cred_keys"], f"{r['repo']}/.git/config: remote.{rem.get('name', 'origin')}.url")
                    add_unique(g["creds_masked"], f"{note}={mask(mt.group(0))}")

    out: list[dict[str, Any]] = []
    for prov, g in groups.items():
        has_out = len(g["calls"]) > 0 or g["hits_n"] > 0 or "git remote" in g["methods"]
        has_in = len(g["webhooks"]) > 0
        if has_out and has_in:
            direction = "both"
        elif has_in:
            direction = "inbound"
        elif has_out:
            direction = "outbound"
        elif g["live_creds"] > 0:
            direction = "dormant (config only)"
        else:
            direction = "dormant (history only)"
        history_only = bool(g["hist_creds"] > 0 and g["live_creds"] == 0)
        out.append({
            "provider": prov,
            "class": g["class"],
            "direction": direction,
            "hosts": "; ".join(sorted(g["hosts"])[:10]),
            "calls_n": len(g["calls"]),
            "webhooks_n": len(g["webhooks"]),
            "hits_n": g["hits_n"],
            "methods": ", ".join(sorted(g["methods"])) or ("CONFIG" if not has_out else "REF"),
            "what_sent": "; ".join(g["what_sent"][:6]) or ("configured credential (no call site in tree)" if not has_out else "endpoint reference"),
            "credential_keys": "; ".join(g["cred_keys"][:8]) or ("(none in config - inline or unauthenticated)" if (has_out or has_in) else ""),
            "credentials_masked": "; ".join(g["creds_masked"][:8]),
            "accounts_or_ids": "; ".join(g["accounts"][:10]),
            "history_only": history_only,
            "call_sites": "; ".join(g["call_sites"][:8]),
            "webhook_sites": "; ".join(g["webhook_sites"][:8]),
            "provider_holds": provider_holds(g["class"], prov),
        })
    out = [r for r in out if not ((IPV4_RE.fullmatch(r["provider"]) or r["provider"] == "localhost") and classify_host(r["provider"])[0] == "internal")]
    out.sort(key=lambda r: (
        0 if r["class"] in LEAD_CLASSES else (1 if r["class"] in ("ip", "endpoint") else 2),
        -(r["calls_n"] + r["webhooks_n"] + (2 if r["credential_keys"] and not r["credential_keys"].startswith("(") else 0)),
        -r["hits_n"],
        r["provider"],
    ))
    return out


# ------------------------------------------------------------------------------------------------ repositories
def find_repos(root: Path, log: Log) -> list[Path]:
    """Every .git directory (or gitdir file) under the root, bounded."""
    out: list[Path] = []
    dirs = 0
    stack = [root]
    while stack and dirs < MAX_WALK_DIRS and len(out) < MAX_REPOS:
        d = stack.pop()
        dirs += 1
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in sorted(entries, key=lambda e: e.name):
            try:
                if e.name == ".git":
                    out.append(Path(e.path))
                    continue
                if e.is_dir(follow_symlinks=False) and e.name not in ("node_modules", "__pycache__", "cache", "caches", "tmp", "temp", "venv", ".venv", "site-packages", "bower_components") \
                        and not _skip_dir(Path(e.path), root):
                    stack.append(Path(e.path))
            except OSError:
                continue
    return out


def _resolve_gitdir(dotgit: Path, root: Path) -> Optional[Path]:
    if dotgit.is_dir():
        return dotgit if (dotgit / "HEAD").is_file() else None
    if dotgit.is_file():
        t = _read_text(dotgit, 4096)
        m = re.match(r"\s*gitdir:\s*(.+)", t)
        if m:
            target = m.group(1).strip()
            cand = (dotgit.parent / target) if not target.startswith("/") else (root / target.lstrip("/"))
            try:
                cand = cand.resolve()
                if str(cand).startswith(str(root.resolve())) and (cand / "HEAD").is_file():
                    return cand
            except OSError:
                return None
    return None


def _copy_small_tree(src: Path, dst: Path, max_files: int = 20000, max_bytes: int = 64 * 2**20) -> int:
    """refs/ and logs/ of the seized repository into the shadow: files copied by content (no symlinks followed)."""
    n = 0
    total = 0
    if not src.is_dir():
        return 0
    for dp, dns, fns in os.walk(src, followlinks=False):
        rel = Path(dp).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        dns[:] = [d for d in dns if not os.path.islink(os.path.join(dp, d))]
        for fn in fns:
            sp = Path(dp) / fn
            if sp.is_symlink() or not sp.is_file():
                continue
            try:
                size = sp.stat().st_size
                if size > 8 * 2**20 or total + size > max_bytes:
                    continue
                shutil.copyfile(sp, dst / rel / fn)
                n += 1
                total += size
                if n >= max_files:
                    return n
            except OSError:
                continue
    return n


def _shadow(gitdir: Path, tmp: Path) -> Path:
    """A git directory of our own that reads the seized objects through objects/info/alternates and carries a clean
    config: nothing of the seized config is ever loaded, nothing is written into the evidence."""
    sh = tmp / ("shadow-" + hashlib.sha1(str(gitdir).encode()).hexdigest()[:10])
    sh.mkdir(parents=True, exist_ok=True)
    (sh / "objects" / "info").mkdir(parents=True, exist_ok=True)
    (sh / "objects" / "pack").mkdir(parents=True, exist_ok=True)
    (sh / "refs" / "heads").mkdir(parents=True, exist_ok=True)
    (sh / "refs" / "tags").mkdir(parents=True, exist_ok=True)
    (sh / "objects" / "info" / "alternates").write_text(str(gitdir.resolve() / "objects") + "\n", "utf-8")
    head = _read_text(gitdir / "HEAD", 1024).strip() if (gitdir / "HEAD").is_file() else ""
    if not (head.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head)):
        head = "ref: refs/heads/main"
    (sh / "HEAD").write_text(head + "\n", "utf-8")
    objfmt = ""
    if (gitdir / "config").is_file():
        cfg = parse_git_config(_read_text(gitdir / "config", 262144))
        objfmt = (cfg.get("extensions") or {}).get("objectformat", "")
    conf = "[core]\n\trepositoryformatversion = " + ("1" if objfmt else "0") + "\n\tbare = true\n\tfilemode = false\n\tlogallrefupdates = false\n"
    if objfmt:
        conf += f"[extensions]\n\tobjectformat = {objfmt}\n"
    (sh / "config").write_text(conf, "utf-8")
    _copy_small_tree(gitdir / "refs", sh / "refs")
    _copy_small_tree(gitdir / "logs", sh / "logs")
    for fn in ("packed-refs", "shallow"):
        if (gitdir / fn).is_file() and not (gitdir / fn).is_symlink():
            try:
                if (gitdir / fn).stat().st_size <= 64 * 2**20:
                    shutil.copyfile(gitdir / fn, sh / fn)
            except OSError:
                pass
    return sh


class _Git:
    def __init__(self, shadow: Path, tmp: Path):
        self.shadow = shadow
        self.env = {"GIT_DIR": str(shadow), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": str(tmp), "XDG_CONFIG_HOME": str(tmp),
                    "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/true", "SSH_ASKPASS": "/bin/true", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "GIT_PAGER": "cat", "PAGER": "cat",
                    "GIT_OPTIONAL_LOCKS": "0", "GIT_CEILING_DIRECTORIES": "/", "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_ATTR_NOSYSTEM": "1", "GIT_SSH_COMMAND": "/bin/false"}
        self.base = ["git", "--no-pager", "-c", "safe.directory=*", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.sshCommand=/bin/false",
                     "-c", "protocol.allow=never", "-c", "core.askPass=/bin/true", "-c", "gc.auto=0", "-c", "core.commitGraph=false", "-c", "fetch.writeCommitGraph=false",
                     "-c", "core.quotePath=false", "-c", "log.showSignature=false", "-c", "core.alternateRefsCommand=", "-c", "diff.renames=false"]

    def run(self, args: list[str], timeout: int = GIT_TIMEOUT, inp: Optional[bytes] = None, max_out: int = 2**31) -> tuple[int, bytes, str]:
        try:
            p = subprocess.run(self.base + args, env=self.env, cwd=str(self.shadow), input=inp, capture_output=True, timeout=timeout)
            return p.returncode, p.stdout[:max_out], p.stderr.decode("utf-8", errors="replace")[:2000]
        except subprocess.TimeoutExpired:
            return 124, b"", f"timed out after {timeout} s"
        except OSError as e:
            return 127, b"", str(e)


_REFLOG_RE = re.compile(r"^([0-9a-f]{40,64}) ([0-9a-f]{40,64}) (.*?) <([^>]*)> (\d+) ([+-]\d{4})\t?(.*)$")
_RAW_RE = re.compile(rb":(\d+) (\d+) ([0-9a-f]+) ([0-9a-f]+) ([A-Z])\x00([^\x00]*)\x00")


def _iso(ts: str, tz: str) -> str:
    try:
        t = int(ts)
    except ValueError:
        return ""
    sign = 1 if tz.startswith("+") else -1
    off = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
    lt = time.gmtime(t + off)
    return time.strftime("%Y-%m-%dT%H:%M:%S", lt) + f"{tz[:3]}:{tz[3:5]}"


def read_repo(root: Path, dotgit: Path, tmp: Path, log: Log, acc: "Acc") -> dict[str, Any]:
    """One repository -> its summary; rows go into the accumulator."""
    gitdir = _resolve_gitdir(dotgit, root)
    repo_root = dotgit.parent
    rel = _rel(repo_root, root)
    name = repo_root.name or "repo"
    info: dict[str, Any] = {"repo": rel, "name": name, "gitdir": _rel(gitdir, root) if gitdir else "", "remotes": [], "branch": "", "shallow": False, "user": None, "command_keys": [],
                            "hooks": [], "refs": 0, "branches": [], "tags": [], "commits": 0, "reflog_only": 0, "authors": 0, "first_commit": "", "last_commit": "", "deleted": 0,
                            "unreachable_commits": 0, "unreachable_blobs": 0, "history_secrets": 0, "reflog_entries": 0, "errors": [], "agent_files": [], "description": ""}
    if gitdir is None:
        info["errors"].append("no readable git directory (HEAD missing or gitdir outside the evidence)")
        return info
    from .fingerprint import repo_facts
    facts = repo_facts(repo_root)
    for k in ("remotes", "branch", "shallow", "user", "command_keys", "hooks"):
        if k in facts:
            info[k] = facts[k]
    info["agent_files"] = [f for f in AGENT_FILES if (repo_root / f).exists()]
    if (gitdir / "description").is_file():
        d = _read_text(gitdir / "description", 2048).strip()
        if d and "Unnamed repository" not in d:
            info["description"] = d[:200]
    # the reflog: parsed as text from the seized logs/ (whoever worked in this clone, and what they did)
    logs = gitdir / "logs"
    if logs.is_dir():
        for dp, dns, fns in os.walk(logs, followlinks=False):
            for fn in fns:
                lp = Path(dp) / fn
                refname = str(lp.relative_to(logs)).replace("\\", "/")
                for line in _read_text(lp, 32 * 2**20).splitlines()[:100000]:
                    m = _REFLOG_RE.match(line)
                    if not m:
                        continue
                    info["reflog_entries"] += 1
                    acc.reflog.append({"repo": rel, "ref": refname, "old": m.group(1), "new": m.group(2), "name": m.group(3), "email": m.group(4), "date": _iso(m.group(5), m.group(6)),
                                       "tz": m.group(6), "action": m.group(7).split(":", 1)[0].strip(), "message": m.group(7)[:500]})
    if not shutil.which("git"):
        info["errors"].append("git is not installed in the distro: remotes, reflog and config read as text only; no commit history")
        return info
    sh = _shadow(gitdir, tmp)
    g = _Git(sh, tmp)
    rc, out, err = g.run(["for-each-ref", "--format=%(refname)%00%(objectname)%00%(objecttype)"], timeout=120)
    if rc != 0:
        info["errors"].append(f"git for-each-ref: {err.strip()[:300]}")
    refs = [l.split("\x00") for l in out.decode("utf-8", errors="replace").splitlines() if l]
    info["refs"] = len(refs)
    info["branches"] = [r[0].replace("refs/heads/", "").replace("refs/remotes/", "remote:") for r in refs if r[0].startswith(("refs/heads/", "refs/remotes/"))][:200]
    info["tags"] = [r[0].replace("refs/tags/", "") for r in refs if r[0].startswith("refs/tags/")][:200]
    rc, out, err = g.run(["rev-list", "--all", f"--max-count={MAX_COMMITS}"], timeout=600)
    ref_reachable = set(out.decode("ascii", errors="replace").split())
    fmt = "%x1e%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%s%x1f%b%x1f"
    rc, out, err = g.run(["log", "--all", "--reflog", "--date-order", f"--max-count={MAX_COMMITS}", f"--format={fmt}", "--raw", "--no-abbrev", "--no-renames", "-z",
                          "--diff-merges=first-parent"], timeout=GIT_TIMEOUT)
    if rc != 0 and not out:
        info["errors"].append(f"git log: {err.strip()[:300]}")
        rc, out, err = g.run(["log", "--all", "--reflog", "--date-order", f"--max-count={MAX_COMMITS}", f"--format={fmt}", "-z"], timeout=GIT_TIMEOUT)
    blob_intro: dict[str, tuple[str, str, str, str]] = {}     # blob -> (date, commit, author_email, path)
    deleted: list[dict[str, Any]] = []
    authors: dict[str, dict[str, Any]] = acc.authors
    first, last = "", ""
    ncommits = 0
    for rec in out.split(b"\x1e"):
        if not rec.strip(b"\x00\n"):
            continue
        parts = rec.split(b"\x1f")
        if len(parts) < 11:
            continue
        h, parents, an, ae, ad, cn, ce, cd, subj, body = [x.decode("utf-8", errors="replace") for x in parts[:10]]
        h = h.strip("\x00\n")
        raw = parts[10]
        ncommits += 1
        reach = "refs" if h in ref_reachable else "reflog-only"
        if reach == "reflog-only":
            info["reflog_only"] += 1
        changes = _RAW_RE.findall(raw)
        n_a = n_m = n_d = 0
        for oldmode, newmode, oldsha, newsha, status, path in changes:
            st = status.decode()
            pth = path.decode("utf-8", errors="replace")
            if st == "D":
                n_d += 1
                if len(deleted) < 200_000:
                    deleted.append({"repo": rel, "path": pth, "commit": h, "author_email": ae, "date": ad, "present_in_tree": (repo_root / pth).exists()})
            elif st in ("A", "M", "T", "C", "R"):
                n_a += st == "A"
                n_m += st != "A"
                ns = newsha.decode()
                if set(ns) != {"0"} and SECRET_PATH_RE.search(pth):
                    prev = blob_intro.get(ns)
                    if prev is None or ad < prev[0]:
                        blob_intro[ns] = (ad, h, ae, pth)
        acc.commits.append({"repo": rel, "hash": h, "parents": parents.strip(), "author_name": an, "author_email": ae, "author_date": ad, "author_tz": ad[-6:] if len(ad) >= 6 and ad[-6] in "+-" else "",
                            "committer_name": cn, "committer_email": ce, "committer_date": cd, "subject": subj[:500], "body": body.strip()[:4000], "reachable_from": reach,
                            "files_added": n_a, "files_modified": n_m, "files_deleted": n_d})
        if ad:
            first = ad if not first or ad < first else first
            last = ad if not last or ad > last else last
        for role, nm, em, dt in (("author", an, ae, ad), ("committer", cn, ce, cd)):
            key = (em or nm).lower()
            a = authors.get(key)
            if a is None:
                a = authors[key] = {"email": em, "names": Counter(), "author_commits": 0, "committer_commits": 0, "first": "", "last": "", "tz": Counter(), "repos": set()}
            a["names"][nm] += 1
            a[f"{role}_commits"] += 1
            a["repos"].add(rel)
            if dt:
                a["first"] = dt if not a["first"] or dt < a["first"] else a["first"]
                a["last"] = dt if not a["last"] or dt > a["last"] else a["last"]
                if len(dt) >= 6 and dt[-6] in "+-":
                    a["tz"][dt[-6:]] += 1
    info["commits"] = ncommits
    info["first_commit"], info["last_commit"] = first, last
    info["deleted"] = len(deleted)
    acc.deleted.extend(deleted)
    if ncommits >= MAX_COMMITS:
        info["errors"].append(f"history capped at {MAX_COMMITS} commits")
    # historical configuration blobs: secrets and identifiers with the commit that introduced them
    if blob_intro:
        shas = list(blob_intro)[:MAX_HISTORY_BLOBS * 2]
        rc, out, err = g.run(["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], inp=("\n".join(shas) + "\n").encode(), timeout=600)
        picked: list[str] = []
        total = 0
        for l in out.decode("ascii", errors="replace").splitlines():
            p = l.split()
            if len(p) == 3 and p[1] == "blob" and p[2].isdigit() and int(p[2]) <= MAX_BLOB_BYTES:
                if total + int(p[2]) > MAX_HISTORY_BYTES or len(picked) >= MAX_HISTORY_BLOBS:
                    break
                picked.append(p[0])
                total += int(p[2])
        if picked:
            rc, out, err = g.run(["cat-file", "--batch"], inp=("\n".join(picked) + "\n").encode(), timeout=GIT_TIMEOUT)
            pos = 0
            n_secrets = 0
            while pos < len(out):
                nl = out.find(b"\n", pos)
                if nl < 0:
                    break
                hdr = out[pos:nl].decode("ascii", errors="replace").split()
                pos = nl + 1
                if len(hdr) != 3 or hdr[1] == "missing":
                    continue
                size = int(hdr[2])
                content = out[pos:pos + size]
                pos += size + 1
                sha = hdr[0]
                date, commit, email, path = blob_intro.get(sha, ("", "", "", ""))
                text = content.decode("utf-8", errors="replace") if b"\x00" not in content[:4096] else ""
                if not text:
                    continue
                present = (repo_root / path).exists()
                current = _read_text(repo_root / path) if present else ""
                for r in harvest_text(Path(path).name, text):
                    if r["placeholder"]:
                        continue
                    still = bool(current) and bool(re.search(r"(?<![A-Za-z0-9_])" + re.escape(r["value"]) + r"(?![A-Za-z0-9_])", current))
                    acc.history_secrets.append({"repo": rel, "path": path, "blob": sha, "introduced_by_commit": commit, "introduced_by": email, "introduced_at": date, "key": r["key"],
                                                "value": r["value"][:2000], "class": r["class"], "service": r["service"], "note": r["note"], "file_still_present": present,
                                                "value_still_in_file": still})
                    n_secrets += 1
                for t, v, n in scan_text(text[:400_000], path):
                    if t in ("email", "wallet", "iban", "handle", "phone", "ipv4"):
                        acc.history_idents.append({"repo": rel, "path": path, "blob": sha, "introduced_by_commit": commit, "introduced_by": email, "introduced_at": date, "type": t,
                                                   "value": v, "norm": n})
            # one row per distinct (path, key, value): the same setting lives in every historical version of the file
            best: dict[tuple[str, str, str], dict[str, Any]] = {}
            keep: list[dict[str, Any]] = []
            for r in acc.history_secrets:
                if r["repo"] != rel:
                    keep.append(r)
                    continue
                k = (r["path"], r["key"], r["value"])
                b = best.get(k)
                if b is None or (r["introduced_at"] and r["introduced_at"] < b["introduced_at"]):
                    best[k] = r
            acc.history_secrets = keep + list(best.values())
            info["history_secrets"] = len(best)
    # unreachable objects (git fsck): commits amended/reset away and never expired, blobs of deleted files
    rc, out, err = g.run(["fsck", "--no-progress", "--unreachable", "--no-dangling"], timeout=600)
    if rc == 124:
        info["errors"].append("git fsck timed out: unreachable objects not listed")
    ucommits, ublobs = [], []
    for l in out.decode("utf-8", errors="replace").splitlines():
        p = l.split()
        if len(p) >= 3 and p[0] in ("unreachable", "dangling"):
            if p[1] == "commit":
                ucommits.append(p[2])
            elif p[1] == "blob":
                ublobs.append(p[2])
    info["unreachable_commits"], info["unreachable_blobs"] = len(ucommits), len(ublobs)
    if ucommits:
        rc, out, err = g.run(["cat-file", "--batch"], inp=("\n".join(ucommits[:MAX_UNREACHABLE]) + "\n").encode(), timeout=600)
        pos = 0
        while pos < len(out):
            nl = out.find(b"\n", pos)
            if nl < 0:
                break
            hdr = out[pos:nl].decode("ascii", errors="replace").split()
            pos = nl + 1
            if len(hdr) != 3 or hdr[1] != "commit":
                continue
            size = int(hdr[2])
            body = out[pos:pos + size].decode("utf-8", errors="replace")
            pos += size + 1
            am = re.search(r"^author (.*?) <([^>]*)> (\d+) ([+-]\d{4})$", body, re.M)
            msg = body.split("\n\n", 1)[1].strip() if "\n\n" in body else ""
            acc.unreachable.append({"repo": rel, "object": "commit", "hash": hdr[0], "author_name": am.group(1) if am else "", "author_email": am.group(2) if am else "",
                                    "date": _iso(am.group(3), am.group(4)) if am else "", "subject": msg.split("\n", 1)[0][:300], "text": ""})
    if ublobs:
        rc, out, err = g.run(["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], inp=("\n".join(ublobs[:MAX_UNREACHABLE]) + "\n").encode(), timeout=600)
        small = [l.split()[0] for l in out.decode("ascii", errors="replace").splitlines() if len(l.split()) == 3 and l.split()[2].isdigit() and int(l.split()[2]) <= MAX_BLOB_BYTES][:MAX_UNREACHABLE]
        if small:
            rc, out, err = g.run(["cat-file", "--batch"], inp=("\n".join(small) + "\n").encode(), timeout=600)
            pos = 0
            while pos < len(out):
                nl = out.find(b"\n", pos)
                if nl < 0:
                    break
                hdr = out[pos:nl].decode("ascii", errors="replace").split()
                pos = nl + 1
                if len(hdr) != 3 or hdr[1] != "blob":
                    continue
                size = int(hdr[2])
                content = out[pos:pos + size]
                pos += size + 1
                if b"\x00" in content[:4096]:
                    continue
                text = content.decode("utf-8", errors="replace")
                found = scan_blob_strict(text)
                idents = [(t, v) for t, v, n in scan_text(text[:200_000], "blob") if t in ("email", "wallet", "iban", "phone")]
                if found or idents:
                    acc.unreachable.append({"repo": rel, "object": "blob", "hash": hdr[0], "author_name": "", "author_email": "", "date": "",
                                            "subject": "; ".join(f"{r['key']}={r['value'][:60]}" for r in found[:6]) + ("; " if found and idents else "") + "; ".join(f"{t}:{v}" for t, v in idents[:6]),
                                            "text": text[:2000]})
                    for r in found:
                        acc.history_secrets.append({"repo": rel, "path": "(unreachable blob)", "blob": hdr[0], "introduced_by_commit": "", "introduced_by": "", "introduced_at": "", "key": r["key"],
                                                    "value": r["value"][:2000], "class": r["class"], "service": r["service"], "note": r["note"], "file_still_present": False, "value_still_in_file": False})
    info["authors"] = len({(c["author_email"] or c["author_name"]).lower() for c in acc.commits if c["repo"] == rel})
    return info


class Acc:
    def __init__(self):
        self.commits: list[dict[str, Any]] = []
        self.authors: dict[str, dict[str, Any]] = {}
        self.reflog: list[dict[str, Any]] = []
        self.deleted: list[dict[str, Any]] = []
        self.unreachable: list[dict[str, Any]] = []
        self.history_secrets: list[dict[str, Any]] = []
        self.history_idents: list[dict[str, Any]] = []


# ------------------------------------------------------------------------------------------------ the stage
def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(columns)
        for r in rows:
            w.writerow(["; ".join(r.get(c)) if isinstance(r.get(c), (list, set, tuple)) else ("" if r.get(c) is None else r.get(c)) for c in columns])
    return len(rows)


def export_slug(root: Path) -> str:
    from .dbexport import slug
    return "code-" + slug(root.name or "tree", 40) + "-" + hashlib.sha1(str(root).encode("utf-8", "replace")).hexdigest()[:6]


def run(case, log: Log = print, root: Optional[Path] = None, out_root: Optional[Path] = None) -> dict[str, Any]:
    """The whole stage for a case: repositories + configuration + endpoints + identifiers -> tables, findings, custody."""
    from .dbexport import export_root, slug as _slug
    t0 = time.time()
    root = Path(root) if root else Path(case.mount_root)
    if not root.is_dir():
        raise SystemExit(f"[code] not a directory: {root}")
    tmp = Path(tempfile.mkdtemp(prefix="gumshoe-code-"))
    acc = Acc()
    repos: list[dict[str, Any]] = []
    try:
        found = find_repos(root, log)
        log(f"[code] {len(found)} repositor{'y' if len(found) == 1 else 'ies'} under {root}" + (f" (git {_git_version()})" if shutil.which("git") else " (git not installed: text-only read)"))
        for dg in found:
            t1 = time.time()
            info = read_repo(root, dg, tmp, log, acc)
            repos.append(info)
            log(f"[code]   {info['repo']}: {info['commits']} commits ({info['reflog_only']} reflog-only), {info['authors']} authors, {info['first_commit'][:10]}..{info['last_commit'][:10]}, "
                f"{len(info['remotes'])} remote(s), {info['deleted']} deletions, {info['unreachable_commits']} unreachable commits, {info['history_secrets']} values in historical config, "
                f"{time.time() - t1:.0f} s" + (f"; {'; '.join(info['errors'])}" if info["errors"] else ""))
        values, dbs = harvest_config(root, log)
        hosts, hits, idents = scan_endpoints(root, log)
        calls, webhooks = scan_calls(root, values, acc.history_secrets, hosts, hits, idents, log)
        pivots = build_pivots(repos, values, acc.history_secrets, hosts, hits, idents, calls, webhooks)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # which dump belongs to which application: database names in the configuration vs the case's exports
    links = []
    try:
        from .dbexport import list_exports
        export_dbs: dict[str, list[str]] = defaultdict(list)
        for e in list_exports(case):
            for t in e.get("tables") or []:
                if t.get("database"):
                    export_dbs[t["database"].lower()].append(e["name"])
        for d in dbs:
            if d["database"] and d["database"].lower() in export_dbs:
                links.append({"file": d["file"], "key": d["key"], "database": d["database"], "export": ", ".join(sorted(set(export_dbs[d["database"].lower()]))), "host": d["host"], "user": d["user"]})
    except Exception as e:  # noqa: BLE001
        log(f"[code] export matching skipped: {e}")
    # authors table
    authors = []
    for key, a in acc.authors.items():
        authors.append({"email": a["email"], "name": a["names"].most_common(1)[0][0], "other_names": "; ".join(n for n, _ in a["names"].most_common()[1:5]), "author_commits": a["author_commits"],
                        "committer_commits": a["committer_commits"], "first": a["first"], "last": a["last"], "tz_offsets": "; ".join(f"{tz} ({n})" for tz, n in a["tz"].most_common(4)),
                        "repos": "; ".join(sorted(a["repos"]))})
    authors.sort(key=lambda a: -a["author_commits"])
    # tables: a "code" export the Databases tab and Players read like any other
    name = export_slug(root)
    out = (Path(out_root) if out_root else export_root(case)) / name
    idx = case.dir / "db" / name
    if out.exists():
        shutil.rmtree(out, ignore_errors=True)
    idx.mkdir(parents=True, exist_ok=True)
    tables: list[dict[str, Any]] = []

    def table(db: str, tbl: str, rows: list[dict[str, Any]], cols: list[str]):
        p = out / _slug(db) / f"{tbl}.csv"
        n = _write_csv(p, rows, cols)
        tables.append({"database": db, "table": tbl, "rows": n, "columns": len(cols), "files": [p.name], "bytes": p.stat().st_size, "blobs": 0, "rejected": 0, "error": ""})

    table("git", "repositories", [{**r, "remotes": "; ".join(f"{x['name']}={x['url']}" for x in r["remotes"]), "user": f"{r['user']['name']} <{r['user']['email']}>" if r.get("user") else "",
                                   "branches": "; ".join(r["branches"][:30]), "tags": "; ".join(r["tags"][:30]), "errors": "; ".join(r["errors"]), "command_keys": "; ".join(r["command_keys"]),
                                   "hooks": "; ".join(r["hooks"]), "agent_files": "; ".join(r["agent_files"])} for r in repos],
          ["repo", "name", "remotes", "branch", "shallow", "user", "commits", "reflog_only", "authors", "first_commit", "last_commit", "deleted", "unreachable_commits", "unreachable_blobs",
           "history_secrets", "reflog_entries", "refs", "branches", "tags", "command_keys", "hooks", "agent_files", "description", "errors"])
    table("git", "commits", acc.commits, ["repo", "hash", "parents", "author_name", "author_email", "author_date", "author_tz", "committer_name", "committer_email", "committer_date", "subject", "body",
                                          "reachable_from", "files_added", "files_modified", "files_deleted"])
    table("git", "authors", authors, ["email", "name", "other_names", "author_commits", "committer_commits", "first", "last", "tz_offsets", "repos"])
    table("git", "reflog", acc.reflog, ["repo", "ref", "date", "tz", "name", "email", "action", "message", "old", "new"])
    table("git", "deleted", acc.deleted, ["repo", "path", "commit", "author_email", "date", "present_in_tree"])
    table("git", "unreachable", acc.unreachable, ["repo", "object", "hash", "author_name", "author_email", "date", "subject", "text"])
    table("git", "history_secrets", acc.history_secrets, ["repo", "path", "key", "value", "class", "service", "note", "introduced_at", "introduced_by", "introduced_by_commit", "file_still_present",
                                                          "value_still_in_file", "blob"])
    table("git", "history_identifiers", acc.history_idents, ["repo", "path", "type", "value", "norm", "introduced_at", "introduced_by", "introduced_by_commit", "blob"])
    table("config", "values", values, ["file", "line", "key", "value", "class", "service", "note", "placeholder", "example", "how"])
    table("config", "databases", dbs, ["file", "key", "scheme", "host", "port", "user", "password_present", "database", "example"])
    table("config", "export_links", links, ["file", "key", "database", "export", "host", "user"])
    table("code", "endpoints", hosts, ["host", "class", "service", "hits", "files_n", "files", "first_file", "first_line", "example", "schemes"])
    table("code", "endpoint_hits", hits, ["host", "class", "service", "url", "file", "line", "excerpt", "how"])
    table("code", "calls", calls, ["file", "line", "kind", "mechanism", "method", "host", "url_or_target", "class", "service", "resolved_from", "payload", "credential_key", "flags", "excerpt"])
    table("code", "webhooks", webhooks, ["file", "line", "kind", "route_or_script", "method", "class", "service", "verification", "payload_fields", "credential_key", "excerpt"])
    table("code", "pivots", pivots, ["provider", "class", "direction", "hosts", "calls_n", "webhooks_n", "hits_n", "methods", "what_sent", "credential_keys", "credentials_masked", "accounts_or_ids", "history_only", "call_sites", "webhook_sites", "provider_holds"])
    table("code", "identifiers", idents, ["type", "value", "norm", "count", "first_file", "first_line", "files"])
    summary = {"kind": "code", "source": str(root), "rel": root.name, "out": str(out), "name": name, "generated": utc_now(), "tables": tables, "tables_total": len(tables),
               "rows_total": sum(t["rows"] for t in tables), "repos": repos, "seconds": round(time.time() - t0, 1), "custody_head": list(case.custody.head())}
    (idx / "source.json").write_text(json.dumps(summary, indent=2, default=str), "utf-8")
    with open(idx / "tables.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["database", "table", "rows", "columns", "files", "bytes", "blobs", "rejected", "error"])
        for t in tables:
            w.writerow([t["database"], t["table"], t["rows"], t["columns"], "; ".join(t["files"]), t["bytes"], 0, 0, ""])
    (out / "README.txt").write_text(_readme(summary), "utf-8")
    # findings
    findings = [f for f in case.read_findings() if not str(f.get("rule", "")).startswith("code.")]
    new = _findings(root, repos, values, dbs, links, hosts, idents, acc, calls=calls, webhooks=webhooks, pivots=pivots)
    findings.extend(f.to_dict() for f in new)
    case.write_findings(findings)
    try:
        from .collect import write_summary
        write_summary(case, findings)
    except Exception:  # noqa: BLE001
        pass
    code = {"generated": utc_now(), "root": str(root), "export": name, "out": str(out), "repos": repos, "config_values": len(values), "databases": len(dbs), "export_links": links,
            "endpoints": len(hosts), "lead_hosts": [h for h in hosts if h["class"] in LEAD_CLASSES][:200], "public_ips": [h for h in hosts if h["class"] == "ip"][:100],
            "calls": len(calls), "webhooks": len(webhooks), "pivots": len(pivots), "call_rows": calls[:200], "webhook_rows": webhooks[:100], "pivot_rows": pivots[:200],
            "identifiers": len(idents), "history_secrets": len(acc.history_secrets), "findings": len(new), "seconds": round(time.time() - t0, 1)}
    code["report"] = explain(code, values, authors)
    case.write_json("code.json", code)
    case.custody.append("code_read", {"root": str(root), "repos": len(repos), "commits": len(acc.commits), "config_values": len(values), "endpoints": len(hosts),
                                      "calls": len(calls), "webhooks": len(webhooks), "pivots": len(pivots), "findings": len(new), "export": name})
    log(f"[code] done in {code['seconds']} s: {len(repos)} repositories, {len(acc.commits)} commits, {len(values)} configuration values, {len(hosts)} hosts, "
        f"{len(calls)} calls, {len(webhooks)} webhooks, {len(pivots)} pivots, {len(new)} findings -> {out}")
    return code


def _git_version() -> str:
    try:
        return subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10).stdout.strip().replace("git version ", "")
    except Exception:  # noqa: BLE001
        return "?"


def _readme(summary: dict[str, Any]) -> str:
    return ("Gumshoe - source code read as tables (deterministic, no model).\n"
            f"Root: {summary['source']}\nGenerated: {summary['generated']}\n\n"
            "git/repositories.csv     one row per repository: remotes, branch, counts, config keys that would run commands\n"
            "git/commits.csv          every commit reachable from the refs or the reflog (reachable_from = refs | reflog-only), author date with the author's UTC offset\n"
            "git/authors.csv          one row per e-mail: commits, first/last, the UTC offsets seen (the developer's time zone)\n"
            "git/reflog.csv           the clone's reflog: who did what in that working copy, when\n"
            "git/deleted.csv          files deleted from history and whether the path is present in the working tree now\n"
            "git/unreachable.csv      commits and blobs that no ref or reflog reaches (amended / reset away) - git fsck\n"
            "git/history_secrets.csv  credentials, tokens and DSNs in historical configuration blobs, with the commit that introduced them and whether the value is still in the file\n"
            "git/history_identifiers.csv  e-mails, wallets, phones in those blobs\n"
            "config/values.csv        configuration values in the working tree (class/service say what each is for; placeholder/example are flagged)\n"
            "config/databases.csv     database connections (DSNs and DB_* keys)\n"
            "config/export_links.csv  configuration database names that match an extracted database of this case\n"
            "code/endpoints.csv       every host the code refers to, classified (noise = documentation/CDN/schema links)\n"
            "code/endpoint_hits.csv   each reference with file and line\n"
            "code/calls.csv           outbound call sites (curl/fetch/requests, sockets, mail, curl|sh, Telegram/Discord, license/heartbeat, cron), with variable hosts resolved from config\n"
            "code/webhooks.csv        inbound webhook / IPN / callback handlers with route, signature verification and payload fields\n"
            "code/pivots.csv          per-provider pivot sheet: hosts, direction, what is sent, which credential/account it uses (live and historical), and what that provider holds\n"
            "code/identifiers.csv     e-mails, wallets, handles, Telegram links/tokens, public IPs in code and configuration\n\n"
            "The repositories were read with git against a shadow directory: the seized .git/config was never loaded and nothing was written into the evidence.\n")


def _findings(root: Path, repos, values, dbs, links, hosts, idents, acc: Acc, calls=None, webhooks=None, pivots=None) -> list[Finding]:
    out: list[Finding] = []
    for r in repos:
        rem = ", ".join(f"{x['name']}={x['url']}" for x in r["remotes"][:3]) or "no remote configured"
        out.append(Finding(source="code", severity="info", rule="code.repo", title=f"Repository {r['repo']}: {r['commits']} commits by {r['authors']} author(s), {r['first_commit'][:10]}..{r['last_commit'][:10]}, {rem}",
                           description=(f"Branch {r['branch'] or '?'}; {r['refs']} refs; {r['reflog_entries']} reflog entries; {r['deleted']} file deletions in history; {r['reflog_only']} commits reachable only "
                                        f"from the reflog; {r['unreachable_commits']} unreachable commits; {r['history_secrets']} configuration values in historical blobs."
                                        + (f" Shallow clone." if r["shallow"] else "") + (f" Local git user: {r['user']['name']} <{r['user']['email']}>." if r.get("user") else "")
                                        + (f" Errors: {'; '.join(r['errors'])}." if r["errors"] else "")),
                           path=r["repo"], tags=["code", "git"], extra={"remotes": r["remotes"], "commits": r["commits"], "authors": r["authors"]}))
        if r["command_keys"]:
            out.append(Finding(source="code", severity="medium", rule="code.git_config_command", title=f"{r['repo']}/.git/config would run a command when git opens the repository: {r['command_keys'][0][:120]}",
                               description="Keys such as core.fsmonitor, core.sshCommand, core.hooksPath, diff.external or filter.*.clean execute what they name whenever git - or an IDE with git "
                                           "integration - runs in this working copy. Gumshoe never loaded this config (shadow git directory). Do not open the folder in an IDE on a machine that matters. "
                                           "Keys: " + "; ".join(r["command_keys"][:8]), path=r["repo"] + "/.git/config", tags=["code", "git", "booby-trap"], extra={"keys": r["command_keys"]}))
        if r["hooks"]:
            out.append(Finding(source="code", severity="low", rule="code.git_hooks", title=f"{r['repo']} has custom git hooks: {', '.join(r['hooks'][:6])}",
                               description="Hooks run when git commits, merges, checks out or pushes in this working copy. Read them before anyone uses git there.", path=r["repo"] + "/.git/hooks",
                               tags=["code", "git"]))
        if r["agent_files"]:
            out.append(Finding(source="code", severity="info", rule="code.ai_agent_instructions", title=f"{r['repo']} carries instructions for an AI coding agent: {', '.join(r['agent_files'])}",
                               description="The file(s) instruct a coding agent (Codex/Claude Code/Cursor-style). The code was written at least partly with one; the file often describes the "
                                           "product in the developer's own words.", path=r["repo"] + "/" + r["agent_files"][0], tags=["code", "ai-agent"]))
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for u in acc.unreachable:
        if u["object"] == "commit":
            by_repo[u["repo"]].append(u)
    for repo, us in by_repo.items():
        us.sort(key=lambda u: u["date"], reverse=True)
        out.append(Finding(source="code", severity="low", rule="code.unreachable_commits", title=f"{len(us)} unreachable commit(s) in {repo} (amended, rebased or reset away)",
                           description="No branch, tag or reflog entry reaches these commits; their trees may hold what was removed on purpose. Newest first: "
                                       + "; ".join(f"{u['date'][:10]} {u['author_email']} {u['hash'][:10]} - {u['subject'][:60]}" for u in us[:8]) + ("; …" if len(us) > 8 else "")
                                       + ". All of them in git/unreachable.csv.", path=repo, tags=["code", "git", "unreachable"], extra={"count": len(us), "hashes": [u["hash"] for u in us[:50]]}))
    for s in [x for x in acc.history_secrets if not x["value_still_in_file"] and x["class"] in LEAD_CLASSES + ("database", "auth")][:60]:
        out.append(Finding(source="code", severity=CLASS_SEVERITY.get(s["class"], "low"), rule="code.history_secret",
                           title=f"Removed from the code but kept by history: {s['key']} ({s['service'] or s['class']}) in {s['repo']}{('/' + s['path']) if s['path'] else ''}",
                           description=f"Value {mask(s['value'])}, introduced {s['introduced_at'][:19]} by {s['introduced_by']} in commit {s['introduced_by_commit'][:12]}; the file "
                                       f"{'is still in the working tree without this value' if s['file_still_present'] else 'is no longer in the working tree'}. Full value in git/history_secrets.csv.",
                           path=s["repo"] + "/" + s["path"], tags=["code", "git", "secret", s["class"]], extra={"key": s["key"], "class": s["class"], "service": s["service"]}))
    live = [v for v in values if not v["placeholder"] and not v["example"] and v["class"] in LEAD_CLASSES + ("database", "auth")]
    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for v in live:
        by_file[v["file"]].append(v)
    for f, vs in list(by_file.items())[:80]:
        classes = Counter(v["class"] for v in vs)
        top = max((v for v in vs), key=lambda v: {"medium": 2, "low": 1}.get(CLASS_SEVERITY.get(v["class"], "info"), 0))
        services = sorted({v["service"] or v["class"] for v in vs})
        out.append(Finding(source="code", severity=CLASS_SEVERITY.get(top["class"], "low"), rule="code.config_secrets",
                           title=f"{f}: {len(vs)} credential/service value(s) - {', '.join(services[:8])}",
                           description="; ".join(f"{v['key']} = {mask(v['value'])} [{v['service'] or v['class']}{(' - ' + v['note']) if v['note'] else ''}]" for v in vs[:25])
                                       + ("; …" if len(vs) > 25 else "") + ". Full values in config/values.csv.",
                           path=f, tags=["code", "config"] + sorted(classes), extra={"services": services, "count": len(vs)}))
    for l in links[:40]:
        out.append(Finding(source="code", severity="info", rule="code.database_link", title=f"{l['file']} names database `{l['database']}` - the extracted export {l['export']} holds it",
                           description=f"Key {l['key']}" + (f", host {l['host']}" if l["host"] else "") + (f", user {l['user']}" if l["user"] else "") + ": this configuration and that dump belong together.",
                           path=l["file"], tags=["code", "database-link"], extra=l))
    for h in [x for x in hosts if x["class"] in LEAD_CLASSES][:80]:
        out.append(Finding(source="code", severity="low", rule="code.endpoint_service", title=f"The code talks to {h['host']} ({h['service'] or h['class']}): {h['hits']} reference(s) in {h['files_n']} file(s)",
                           description=f"First seen {h['first_file']}:{h['first_line']} - {h['example'][:200]}. A third-party service with records of its own.",
                           path=h["first_file"], line=h["first_line"], tags=["code", "endpoint", h["class"]], extra={"host": h["host"], "class": h["class"], "service": h["service"]}))
    for h in [x for x in hosts if x["class"] == "ip"][:40]:
        out.append(Finding(source="code", severity="low", rule="code.endpoint_ip", title=f"Public IP address in the code: {h['host']} ({h['hits']} reference(s))",
                           description=f"First seen {h['first_file']}:{h['first_line']} - {h['example'][:200]}.", path=h["first_file"], line=h["first_line"], tags=["code", "endpoint", "ip"]))
    for i in [x for x in idents if x["type"] in ("telegram_token", "telegram_link")][:40]:
        out.append(Finding(source="code", severity="medium" if i["type"] == "telegram_token" else "low", rule="code.telegram",
                           title=("Telegram bot token in the code: " + mask(i["value"])) if i["type"] == "telegram_token" else f"Telegram link in the code: {i['value']}",
                           description=f"{i['count']} occurrence(s), first {i['first_file']}:{i['first_line']}. Full value in code/identifiers.csv.", path=i["first_file"], line=i["first_line"],
                           tags=["code", "telegram"]))
    pk = [v for v in values if v["service"] == "private key"]
    for v in pk[:20]:
        out.append(Finding(source="code", severity="medium", rule="code.private_key", title=f"Private key material in {v['file']}", description=v["key"], path=v["file"], line=v["line"],
                           tags=["code", "key"]))
    for c in (calls or []):
        fl = c.get("flags") or ""
        if "shell-pipe-exec" in fl:
            out.append(Finding(source="code", severity="high", rule="code.shell_fetch_exec",
                               title=f"Remote script fetched and piped to an interpreter in {c['file']}:{c['line']} ({c['mechanism']} -> {c['host']})",
                               description=f"Target {c['url_or_target']}" + (f" (resolved from {c['resolved_from']})" if c.get("resolved_from") else "")
                                           + f"; excerpt: {c['excerpt']}. Full row in code/calls.csv.",
                               path=c["file"], line=c["line"], tags=["code", "call", "shell-exec"]))
        elif "license-check" in fl or "heartbeat" in fl:
            out.append(Finding(source="code", severity="medium", rule="code.license_or_beacon",
                               title=f"License / heartbeat / beacon call in {c['file']}:{c['line']}: {c['method']} {c['host']} ({c['mechanism']})",
                               description=f"Target {c['url_or_target']}" + (f" [resolved from {c['resolved_from']}]" if c.get("resolved_from") else "")
                                           + (f"; sends {c['payload']}" if c.get("payload") else "") + f". Excerpt: {c['excerpt']}",
                               path=c["file"], line=c["line"], tags=["code", "call", "beacon"]))
    var_calls = [c for c in (calls or []) if "variable-host" in (c.get("flags") or "") and not c["host"].startswith("(")]
    for c in var_calls[:40]:
        out.append(Finding(source="code", severity="low", rule="code.variable_host_call",
                           title=f"Call to variable-configured host {c['host']} ({c['service'] or c['class']}) in {c['file']}:{c['line']}",
                           description=f"{c['mechanism']} {c['method']} {c['url_or_target']} — resolved via {c['resolved_from']}"
                                       + (f"; payload: {c['payload']}" if c.get("payload") else "")
                                       + (f"; credential: {c['credential_key']}" if c.get("credential_key") else "") + ".",
                           path=c["file"], line=c["line"], tags=["code", "call", "variable-host", c["class"]]))
    for w in (webhooks or [])[:40]:
        out.append(Finding(source="code", severity="low", rule="code.webhook_handler",
                           title=f"Inbound {w['kind']} handler {w['route_or_script']} ({w['service'] or w['class']}) at {w['file']}:{w['line']}",
                           description=f"Verification: {w['verification']}" + (f"; payload fields: {w['payload_fields']}" if w.get("payload_fields") else "")
                                       + (f"; config secret: {w['credential_key']}" if w.get("credential_key") else "") + ". All handlers in code/webhooks.csv.",
                           path=w["file"], line=w["line"], tags=["code", "webhook", w["class"]]))
    for pv in [p for p in (pivots or []) if p["class"] in LEAD_CLASSES or p["calls_n"] > 0 or p["webhooks_n"] > 0][:50]:
        first_loc = (pv["call_sites"] or pv["webhook_sites"] or "").split(";")[0].strip()
        f_path = first_loc.rsplit(":", 1)[0] if ":" in first_loc else ""
        f_line = int(first_loc.rsplit(":", 1)[1]) if ":" in first_loc and first_loc.rsplit(":", 1)[1].isdigit() else None
        out.append(Finding(source="code", severity="low" if pv["class"] in LEAD_CLASSES else "info", rule="code.pivot",
                           title=f"Provider pivot [{pv['provider']}] ({pv['class']}, {pv['direction']}): {pv['calls_n']} call(s), {pv['webhooks_n']} webhook(s)",
                           description=f"Hosts: {pv['hosts'] or '-'}. What is sent/received: {pv['what_sent']}. "
                                       f"Credentials: {pv['credentials_masked'] or pv['credential_keys'] or 'none'}. "
                                       + (f"Accounts/IDs: {pv['accounts_or_ids']}. " if pv.get("accounts_or_ids") else "")
                                       + f"What the provider holds: {pv['provider_holds']}. Full sheet in code/pivots.csv.",
                           path=f_path or None, line=f_line, tags=["code", "pivot", pv["class"]], extra=pv))
    return out


def explain(code: dict[str, Any], values: Optional[list[dict[str, Any]]] = None, authors: Optional[list[dict[str, Any]]] = None) -> str:
    L = [f"SOURCE CODE under {code['root']} ({code['seconds']} s): {len(code['repos'])} repositories, {code['config_values']} configuration values, {code['endpoints']} hosts, "
         f"{code.get('calls', 0)} calls, {code.get('webhooks', 0)} webhooks, {code.get('pivots', 0)} provider pivots, {code['identifiers']} identifiers -> export {code['export']}"]
    for r in code["repos"]:
        L.append(f"  {r['repo']}: {r['commits']} commits ({r['reflog_only']} reflog-only), {r['authors']} authors, {r['first_commit'][:10]} .. {r['last_commit'][:10]}; branch {r['branch'] or '?'}"
                 + (f"; remotes {', '.join(x['url'] for x in r['remotes'][:3])}" if r["remotes"] else "; no remote") + (f"; {r['deleted']} deletions" if r["deleted"] else "")
                 + (f"; {r['unreachable_commits']} unreachable commits" if r["unreachable_commits"] else "") + (f"; {r['history_secrets']} values in historical config" if r["history_secrets"] else "")
                 + (f"; AI-agent files {', '.join(r['agent_files'])}" if r["agent_files"] else "") + (f"; CONFIG RUNS COMMANDS: {'; '.join(r['command_keys'][:3])}" if r["command_keys"] else "")
                 + (f"; errors: {'; '.join(r['errors'])}" if r["errors"] else ""))
    if authors:
        L.append("  authors: " + "; ".join(f"{a['name']} <{a['email']}> {a['author_commits']} commits {a['first'][:10]}..{a['last'][:10]} tz {a['tz_offsets'] or '?'}" for a in authors[:12]))
    if code.get("export_links"):
        L.append("  configuration <-> extracted databases: " + "; ".join(f"{l['file']} -> {l['database']} = {l['export']}" for l in code["export_links"][:10]))
    if values:
        live = [v for v in values if not v["placeholder"] and not v["example"] and v["class"] in LEAD_CLASSES + ("database",)]
        svc = Counter(v["service"] or v["class"] for v in live)
        if svc:
            L.append("  live credentials/services in configuration: " + ", ".join(f"{s} ({n})" for s, n in svc.most_common(20)))
    if code.get("lead_hosts"):
        L.append("  services the code talks to: " + "; ".join(f"{h['host']} [{h['service'] or h['class']}] x{h['hits']}" for h in code["lead_hosts"][:25]))
    if code.get("public_ips"):
        L.append("  public IPs in the code: " + ", ".join(h["host"] for h in code["public_ips"][:20]))
    if code.get("call_rows"):
        L.append(f"  outbound calls ({code.get('calls', len(code['call_rows']))}): " + "; ".join(
            f"{c['file']}:{c['line']} {c['mechanism']} {c['method']} {c['host']}"
            + (f" [{c['resolved_from']}]" if c.get("resolved_from") else "")
            + (f" ({c['payload']})" if c.get("payload") else "")
            + (f" <{c['flags']}>" if c.get("flags") else "")
            for c in code["call_rows"][:18]
        ))
    if code.get("webhook_rows"):
        L.append(f"  inbound webhooks / IPN handlers ({code.get('webhooks', len(code['webhook_rows']))}): " + "; ".join(
            f"{w['file']}:{w['line']} {w['route_or_script']} [{w['service'] or w['class']}] verify={w['verification']} fields={w['payload_fields'] or '-'}"
            for w in code["webhook_rows"][:15]
        ))
    if code.get("pivot_rows"):
        L.append(f"  per-provider pivot sheet ({code.get('pivots', len(code['pivot_rows']))}):")
        for pv in code["pivot_rows"][:25]:
            L.append(f"    - {pv['provider']} [{pv['class']}, {pv['direction']}] hosts={pv['hosts'] or '-'} | sent={pv['what_sent'][:120]} | "
                     f"creds={pv['credentials_masked'] or pv['credential_keys'] or 'none'}"
                     + (f" | ids={pv['accounts_or_ids']}" if pv.get("accounts_or_ids") else "")
                     + f" | holds: {pv['provider_holds']}")
    return "\n".join(L)


def load(case) -> Optional[dict[str, Any]]:
    return case.read_json("code.json", None)
