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
  * IDENTIFIERS - e-mails, wallets, handles, IPs in code and configuration.

Everything is written as CSV tables under a "code" export of the case (<case>/db/code-<name>/ -> git.commits,
git.authors, git.reflog, git.deleted, git.unreachable, git.history_secrets, config.values, config.databases,
code.endpoints, code.endpoint_hits, code.identifiers), so the Databases tab searches them with the extracted
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
                           r"|smtp|imap|mail|(^|_)bot|telegram|tg_|twilio|nexmo|vonage|plivo|sms|aftership|shippo|easypost|stripe|paypal|coinbase|binance|aws|s3_|bucket|cloudflare|captcha"
                           r"|proxy|socks|webhook|private|credential|login|(^|_)user(name)?$|host(name)?$|_host|endpoint|url$|_url|uri$|_uri|domain$|wallet|address|licen[cs]e|jwt|session"
                           r"|salt|seed|mnemonic|cookie|openai|anthropic|gemini|deepseek|client_id|client_secret|app_id|account_sid|merchant|shop_id|api_id|api_hash|phone|port$)", re.I)
PLACEHOLDER_RE = re.compile(r"^(|\s*|xxx+|yyy+|zzz+|\*+|\.\.\.|null|none|nil|undefined|false|true|0|1|change[_-]?me|changeit|your[_-].*|<.*>|\[.*\]|\$\{.*\}|%.*%|example.*|sample.*|dummy.*|placeholder.*|secret|password|passw0rd|root|admin|test|localhost|127\.0\.0\.1|todo|tbd|fixme|~|-)$", re.I)
DSN_RE = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.-]{1,24})://(?:(?P<user>[^:@/\s]*)(?::(?P<pw>[^@/\s]*))?@)?(?P<host>\[[0-9a-fA-F:.]+\]|[^:/?#\s]+)?(?::(?P<port>\d{1,5}))?(?:/(?P<db>[^?#\s]*))?(?:\?(?P<q>[^#\s]*))?", re.I)
TG_TOKEN_RE = re.compile(r"(?<![\w:])(\d{8,10}:[A-Za-z0-9_-]{35})(?![\w-])")
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
    (r"\d{8,10}:[A-Za-z0-9_-]{35}", "messaging", "telegram", "Telegram bot token"),
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
                    still = bool(current) and r["value"] in current
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
    new = _findings(root, repos, values, dbs, links, hosts, idents, acc)
    findings.extend(f.to_dict() for f in new)
    case.write_findings(findings)
    try:
        from .collect import write_summary
        write_summary(case, findings)
    except Exception:  # noqa: BLE001
        pass
    code = {"generated": utc_now(), "root": str(root), "export": name, "out": str(out), "repos": repos, "config_values": len(values), "databases": len(dbs), "export_links": links,
            "endpoints": len(hosts), "lead_hosts": [h for h in hosts if h["class"] in LEAD_CLASSES][:200], "public_ips": [h for h in hosts if h["class"] == "ip"][:100],
            "identifiers": len(idents), "history_secrets": len(acc.history_secrets), "findings": len(new), "seconds": round(time.time() - t0, 1)}
    code["report"] = explain(code, values, authors)
    case.write_json("code.json", code)
    case.custody.append("code_read", {"root": str(root), "repos": len(repos), "commits": len(acc.commits), "config_values": len(values), "endpoints": len(hosts), "findings": len(new),
                                      "export": name})
    log(f"[code] done in {code['seconds']} s: {len(repos)} repositories, {len(acc.commits)} commits, {len(values)} configuration values, {len(hosts)} hosts, {len(new)} findings -> {out}")
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
            "code/identifiers.csv     e-mails, wallets, handles, Telegram links/tokens, public IPs in code and configuration\n\n"
            "The repositories were read with git against a shadow directory: the seized .git/config was never loaded and nothing was written into the evidence.\n")


def _findings(root: Path, repos, values, dbs, links, hosts, idents, acc: Acc) -> list[Finding]:
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
    return out


def explain(code: dict[str, Any], values: Optional[list[dict[str, Any]]] = None, authors: Optional[list[dict[str, Any]]] = None) -> str:
    L = [f"SOURCE CODE under {code['root']} ({code['seconds']} s): {len(code['repos'])} repositories, {code['config_values']} configuration values, {code['endpoints']} hosts, "
         f"{code['identifiers']} identifiers -> export {code['export']}"]
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
    return "\n".join(L)


def load(case) -> Optional[dict[str, Any]]:
    return case.read_json("code.json", None)
