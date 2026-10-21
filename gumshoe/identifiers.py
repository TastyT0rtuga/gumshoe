"""Identifiers worth linking people by, found and *validated* in text and table cells.

Types: email, phone, ipv4, ipv6, domain, url, handle (@name), wallet (with the network: btc, ltc, doge,
eth/evm, tron, xrp, xmr, bch), txid (64-hex in a transaction context), iban, card (Luhn-valid PAN with a
known issuer range), pwhash (bcrypt / phpass / md5-ish from password columns), sshkey (fingerprint),
username and name (from columns only - too ambiguous in free text).

Every wallet format that carries a checksum is checked (base58check for BTC/LTC/DOGE/TRON, the XRP
alphabet, bech32/bech32m for bc1/ltc1, EIP-55 when the EVM address is mixed case), so a random
34-character token is not reported as a Bitcoin address. Normalisation (`norm`) is what two mentions
are compared on: lower-cased e-mail, digits-only phone, lower-cased EVM address, bech32 lower-cased.
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterator, Optional

# --------------------------------------------------------------------------- checksums
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_XRP = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_B58_IDX = {c: i for i, c in enumerate(_B58)}
_B58_XRP_IDX = {c: i for i, c in enumerate(_B58_XRP)}


def _b58decode(s: str, alphabet_idx: dict[str, int]) -> Optional[bytes]:
    n = 0
    for ch in s:
        v = alphabet_idx.get(ch)
        if v is None:
            return None
        n = n * 58 + v
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    first = _B58[0] if alphabet_idx is _B58_IDX else _B58_XRP[0]
    for ch in s:
        if ch == first:
            pad += 1
        else:
            break
    return b"\x00" * pad + full


def base58check(s: str, versions: tuple[int, ...] = (), xrp: bool = False, length: int = 25) -> bool:
    raw = _b58decode(s, _B58_XRP_IDX if xrp else _B58_IDX)
    if raw is None or len(raw) != length:
        return False
    payload, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != check:
        return False
    return (not versions) or payload[0] in versions


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32_ok(addr: str) -> bool:
    """bech32 (segwit v0) or bech32m (v1+) checksum; hrp bc/ltc/tb."""
    a = addr.lower()
    if addr != a and addr != addr.upper():
        return False
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False
    hrp, data = a[:pos], a[pos + 1:]
    if any(ch not in _BECH32_CHARSET for ch in data):
        return False
    vals = [_BECH32_CHARSET.index(ch) for ch in data]
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _bech32_polymod(hrp_exp + vals)
    return pm in (1, 0x2bc830a3)


def eip55_ok(addr: str) -> bool:
    """An EVM address: all one case is accepted; mixed case must match the EIP-55 checksum."""
    hexpart = addr[2:]
    if hexpart == hexpart.lower() or hexpart == hexpart.upper():
        return True
    try:
        from hashlib import sha3_256  # not keccak; fall back below
    except ImportError:
        return True
    try:
        import sha3  # type: ignore  # pysha3 (keccak) if present
        digest = sha3.keccak_256(hexpart.lower().encode()).hexdigest()
    except Exception:  # noqa: BLE001 - without keccak we accept mixed case (cannot verify)
        return True
    for i, ch in enumerate(hexpart):
        if ch.isalpha() and ((int(digest[i], 16) >= 8) != ch.isupper()):
            return False
    return True


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not (15 <= len(s) <= 34) or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    t = s[4:] + s[:4]
    n = "".join(str(int(c, 36)) for c in t)
    return int(n) % 97 == 1


# --------------------------------------------------------------------------- patterns
EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)(?![\w-])")
IPV4_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
_H = r"[0-9A-Fa-f]{1,4}"
IPV6_RE = re.compile(r"(?<![:\w])(" + "|".join([
    rf"(?:{_H}:){{7}}{_H}", rf"(?:{_H}:){{1,7}}:", rf"(?:{_H}:){{1,6}}:{_H}", rf"(?:{_H}:){{1,5}}(?::{_H}){{1,2}}",
    rf"(?:{_H}:){{1,4}}(?::{_H}){{1,3}}", rf"(?:{_H}:){{1,3}}(?::{_H}){{1,4}}", rf"(?:{_H}:){{1,2}}(?::{_H}){{1,5}}",
    rf"{_H}:(?::{_H}){{1,6}}", rf":(?::{_H}){{1,7}}"]) + r")(?![:\w])")
PHONE_TEXT_RE = re.compile(r"(?<![\w.])(\+?\d{1,3}[\s().-]{0,3}\(?\d{2,4}\)?[\s.-]{0,2}\d{2,4}[\s.-]{0,2}\d{2,4}(?:[\s.-]{0,2}\d{2,4})?)(?![\w])")
URL_RE = re.compile(r"\b((?:https?|ftp)://[^\s\"'<>)\]]{4,300})", re.I)
DOMAIN_RE = re.compile(r"(?<![\w@/.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|io|co|ru|su|ua|by|kz|cn|in|de|fr|uk|us|eu|me|tv|xyz|top|site|online|club|shop|store|pro|vip|app|dev|cc|to|ws|pw|cloud|host|link|live|news|tech|space|fun|icu|lol|monster|run|work|one|zone|agency|money|cash|finance|market|exchange|trade|bet|casino|vegas|pl|cz|sk|hu|ro|bg|rs|hr|si|lt|lv|ee|fi|se|no|dk|nl|be|ch|at|it|es|pt|gr|tr|il|ae|sa|ir|pk|bd|lk|np|th|vn|id|my|sg|ph|kr|jp|tw|hk|au|nz|za|ng|ke|eg|ma|br|ar|mx|cl|co|pe|ve|ca|am|ge|az|uz|kg|tj|tm|md|cy|mt|lu|ie|is|li|mc|sm|va|ad|al|mk|ba|me|xn--[a-z0-9]+))(?![\w-])", re.I)
HANDLE_RE = re.compile(r"(?<![\w@.])@([A-Za-z][A-Za-z0-9_]{4,31})(?![\w@])")
HEX64_RE = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?([0-9A-Fa-f]{64})(?![0-9A-Fa-f])")
EVM_RE = re.compile(r"(?<![0-9A-Za-z])(0x[0-9A-Fa-f]{40})(?![0-9A-Za-z])")
B58_RE = re.compile(r"(?<![0-9A-Za-z])([13LMDT][1-9A-HJ-NP-Za-km-z]{25,34})(?![0-9A-Za-z])")
BECH32_RE = re.compile(r"(?<![0-9A-Za-z])((?:bc1|ltc1|tb1)[02-9ac-hj-np-z]{6,87})(?![0-9A-Za-z])", re.I)
XRP_RE = re.compile(r"(?<![0-9A-Za-z])(r[1-9A-HJ-NP-Za-km-z]{24,34})(?![0-9A-Za-z])")
XMR_RE = re.compile(r"(?<![0-9A-Za-z])([48][0-9AB][1-9A-HJ-NP-Za-km-z]{93})(?![0-9A-Za-z])")
BCH_RE = re.compile(r"(?<![0-9A-Za-z])((?:bitcoincash:)?[qp][a-z0-9]{41})(?![0-9A-Za-z])")
IBAN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?)(?![A-Za-z0-9])")
CARD_RE = re.compile(r"(?<![\d-])((?:\d[ -]?){12,18}\d)(?![\d-])")
SSHFP_RE = re.compile(r"\b(SHA256:[A-Za-z0-9+/]{43}=?|(?:[0-9a-f]{2}:){15}[0-9a-f]{2})\b")
PWHASH_RE = re.compile(r"^(\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}|\$P\$[./A-Za-z0-9]{31}|\$H\$[./A-Za-z0-9]{31}|\$argon2[id]+\$[^\s]{20,}|\$[156]\$[^\s]{10,}|\*[0-9A-F]{40}|[0-9a-f]{32}|[0-9a-f]{40})$")
_PHONE_BAD = re.compile(r"^(\d)\1+$")


def _phone_norm(s: str) -> Optional[str]:
    d = re.sub(r"\D", "", s)
    if not (7 <= len(d) <= 15) or _PHONE_BAD.match(d):
        return None
    if s.strip().startswith("+") or s.strip().startswith("00"):
        d = d.lstrip("0") if s.strip().startswith("00") else d
        return "+" + d
    if len(d) == 11 and d[0] in "78":           # Russian/Kazakh national format 8 (xxx) ...
        return "+7" + d[1:]
    if len(d) == 10:
        return d                                 # national number, country unknown
    return d


def wallet_network(s: str) -> Optional[str]:
    """Which network a candidate address belongs to, or None when its checksum/format fails."""
    if s.startswith("0x") and len(s) == 42:
        return "evm" if eip55_ok(s) else None
    low = s.lower()
    if low.startswith(("bc1", "tb1")) and bech32_ok(s):
        return "btc"
    if low.startswith("ltc1") and bech32_ok(s):
        return "ltc"
    if s[0] in "13" and base58check(s, (0x00, 0x05)):
        return "btc"
    if s[0] in "LM" and base58check(s, (0x30, 0x32, 0x05)):
        return "ltc"
    if s[0] == "D" and base58check(s, (0x1e, 0x16)):
        return "doge"
    if s[0] == "T" and len(s) == 34 and base58check(s, (0x41,)):
        return "tron"
    if s[0] == "r" and 25 <= len(s) <= 35 and base58check(s, (0x00,), xrp=True):
        return "xrp"
    if s[0] in "48" and len(s) == 95:
        return "xmr"
    if low.startswith("bitcoincash:") or (len(s) == 42 and s[0] in "qp" and s == low):
        return "bch" if _cashaddr_ok(low.replace("bitcoincash:", "")) else None
    return None


def _cashaddr_ok(payload: str) -> bool:
    # cashaddr polymod over "bitcoincash" prefix
    gen = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
    chk = 1
    prefix = [ord(c) & 0x1f for c in "bitcoincash"] + [0]
    try:
        data = [_BECH32_CHARSET.index(c) for c in payload]
    except ValueError:
        return False
    for v in prefix + data:
        c0 = chk >> 35
        chk = ((chk & 0x07ffffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((c0 >> i) & 1) else 0
    return chk == 1


_CARD_PREFIX = re.compile(r"^(4\d{12}(?:\d{3})?(?:\d{3})?|5[1-5]\d{14}|2(?:2[2-9]\d|[3-6]\d\d|7[01]\d|720)\d{12}|3[47]\d{13}|6(?:011|5\d\d)\d{12}|35\d{14}|2[0-9]{15}|220[0-4]\d{12})$")


def card_ok(digits: str) -> bool:
    return 13 <= len(digits) <= 19 and luhn_ok(digits) and bool(_CARD_PREFIX.match(digits)) and not _PHONE_BAD.match(digits)


# --------------------------------------------------------------------------- extraction
def scan_text(text: str, context: str = "") -> Iterator[tuple[str, str, str]]:
    """(type, value, norm) for every validated identifier in a piece of free text.
    `context` (a column name or file name) decides whether 64-hex is a tx id and whether bare numbers are phones."""
    if not text:
        return
    ctx = context.lower()
    seen: set[tuple[str, str]] = set()

    def emit(t: str, v: str, n: str):
        if (t, n) not in seen:
            seen.add((t, n))
            yield (t, v, n)

    for m in EMAIL_RE.finditer(text):
        v = m.group(1)
        yield from emit("email", v, v.lower())
    for m in URL_RE.finditer(text):
        v = m.group(1).rstrip(".,;:")
        yield from emit("url", v, v.lower())
        host = re.sub(r"^[a-z]+://", "", v.lower()).split("/")[0].split(":")[0].split("@")[-1]
        if host and not IPV4_RE.fullmatch(host):
            yield from emit("domain", host, host)
    for m in IPV4_RE.finditer(text):
        v = m.group(1)
        if not v.startswith(("0.", "127.", "255.")):
            yield from emit("ipv4", v, v)
    if ":" in text:
        for m in IPV6_RE.finditer(text):
            v = m.group(1)
            if v.count(":") >= 2 and len(v) >= 7 and not v.startswith(("fe80", "::1")) and not re.fullmatch(r"[\d:]+", v):
                yield from emit("ipv6", v, v.lower())
    for m in DOMAIN_RE.finditer(text):
        v = m.group(1).lower()
        if "@" not in text[max(0, m.start() - 1):m.start() + 1]:
            yield from emit("domain", v, v)
    for m in HANDLE_RE.finditer(text):
        yield from emit("handle", "@" + m.group(1), m.group(1).lower())
    for m in EVM_RE.finditer(text):
        v = m.group(1)
        net = wallet_network(v)
        if net:
            yield from emit("wallet", v, "evm:" + v.lower())
    for m in BECH32_RE.finditer(text):
        v = m.group(1)
        net = wallet_network(v)
        if net:
            yield from emit("wallet", v, f"{net}:{v.lower()}")
    for m in B58_RE.finditer(text):
        v = m.group(1)
        net = wallet_network(v)
        if net:
            yield from emit("wallet", v, f"{net}:{v}")
    for m in XRP_RE.finditer(text):
        v = m.group(1)
        if wallet_network(v) == "xrp":
            yield from emit("wallet", v, "xrp:" + v)
    for m in XMR_RE.finditer(text):
        v = m.group(1)
        yield from emit("wallet", v, "xmr:" + v)
    for m in BCH_RE.finditer(text):
        v = m.group(1)
        if wallet_network(v) == "bch":
            yield from emit("wallet", v, "bch:" + v.lower().replace("bitcoincash:", ""))
    if any(k in ctx for k in ("tx", "hash", "txid", "transaction", "payment", "deposit", "withdraw")) or "0x" in text \
            or re.search(r"\b(tx|txid|hash|transaction|txn)\b", text, re.I):
        for m in HEX64_RE.finditer(text):
            v = m.group(1).lower()
            yield from emit("txid", v, v)
    masked = text
    for m in IBAN_RE.finditer(text):
        v = m.group(1).replace(" ", "").upper()
        if iban_ok(v):
            yield from emit("iban", v, v)
            masked = masked[:m.start()] + " " * (m.end() - m.start()) + masked[m.end():]
    for m in CARD_RE.finditer(masked):
        d = re.sub(r"\D", "", m.group(1))
        if card_ok(d):
            yield from emit("card", d, d)
            masked = masked[:m.start()] + " " * (m.end() - m.start()) + masked[m.end():]
    for m in SSHFP_RE.finditer(text):
        yield from emit("sshkey", m.group(1), m.group(1))
    if any(k in ctx for k in ("phone", "tel", "mobile", "cell", "whatsapp", "contact", "msg", "message", "note", "comment", "text", "body", "description", "address")):
        for m in PHONE_TEXT_RE.finditer(masked):
            raw = m.group(1)
            if not re.search(r"[\s().+-]", raw) and not raw.startswith("+"):
                continue                  # a bare run of digits in text is an id, not a phone
            n = _phone_norm(raw)
            if n and len(re.sub(r"\D", "", raw)) >= 9:
                yield from emit("phone", raw.strip(), n)


def cell_value(t: str, v: str) -> Optional[tuple[str, str, str]]:
    """A whole cell from a column known to hold identifiers of type `t`: validated and normalised, or None."""
    v = (v or "").strip()
    if not v or v.lower() in ("null", "none", "n/a", "-", "0", "unknown", "undefined"):
        return None
    if t == "email":
        return ("email", v, v.lower()) if EMAIL_RE.fullmatch(v) else None
    if t == "phone":
        n = _phone_norm(v)
        return ("phone", v, n) if n else None
    if t == "ip":
        if IPV4_RE.fullmatch(v):
            return ("ipv4", v, v)
        if IPV6_RE.fullmatch(v):
            return ("ipv6", v, v.lower())
        return None
    if t == "wallet":
        net = wallet_network(v)
        if net:
            return ("wallet", v, f"{net}:{v.lower() if net in ('evm', 'btc', 'ltc', 'bch') and (v.startswith('0x') or v.lower().startswith(('bc1', 'ltc1', 'tb1', 'q', 'p', 'bitcoincash')) ) else v}")
        if HEX64_RE.fullmatch(v):
            return ("txid", v.lower().replace("0x", ""), v.lower().replace("0x", ""))
        return None
    if t == "txid":
        m = HEX64_RE.fullmatch(v)
        return ("txid", m.group(1).lower(), m.group(1).lower()) if m else None
    if t == "username":
        if 2 <= len(v) <= 64 and not v.isdigit() and " " not in v.strip():
            return ("username", v, v.lower())
        return ("username", v, v.lower()) if 2 <= len(v) <= 64 else None
    if t == "name":
        s = re.sub(r"\s+", " ", v)
        if 2 <= len(s) <= 120 and not s.isdigit() and not EMAIL_RE.fullmatch(s):
            return ("name", s, name_key(s))
        return None
    if t == "pwhash":
        return ("pwhash", v, v) if PWHASH_RE.fullmatch(v) else None
    if t == "domain":
        s = v.lower().strip(".")
        return ("domain", s, s) if DOMAIN_RE.fullmatch(s) else None
    if t == "iban":
        s = v.replace(" ", "").upper()
        return ("iban", s, s) if iban_ok(s) else None
    if t == "card":
        d = re.sub(r"\D", "", v)
        return ("card", d, d) if card_ok(d) else None
    if t == "handle":
        s = v.lstrip("@")
        return ("handle", "@" + s, s.lower()) if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", s) else None
    return None


# --------------------------------------------------------------------------- names
_TRANSLIT = {"а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh", "з": "z", "и": "i", "й": "i", "к": "k", "л": "l",
             "м": "m", "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh",
             "щ": "shch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya", "і": "i", "ї": "i", "є": "e", "ґ": "g"}


def name_key(s: str) -> str:
    """A comparison key for a person name: lower-case, Cyrillic transliterated, punctuation dropped, tokens sorted
    (so 'Petrov Ivan' and 'Ivan Petrov' meet)."""
    t = s.lower()
    t = "".join(_TRANSLIT.get(ch, ch) for ch in t)
    t = re.sub(r"[^a-z0-9\s]", " ", t)
    toks = sorted(x for x in t.split() if len(x) > 1)
    return " ".join(toks)


# --------------------------------------------------------------------------- column typing
_COL_HINTS: list[tuple[str, re.Pattern]] = [
    ("email", re.compile(r"(^|_)(e?mail|email_?address|user_?email|contact_?email)($|_)", re.I)),
    ("phone", re.compile(r"(^|_)(phone|tel|telephone|mobile|cell|msisdn|whatsapp|contact_?no|phone_?number)($|_|\d)", re.I)),
    ("ip", re.compile(r"(^|_)(ip|ipaddr|ip_?address|remote_?addr|client_?ip|login_?ip|last_?ip|reg_?ip|user_?ip|c-ip|host_?ip|src_?ip|dst_?ip|ip4|ip6)($|_)", re.I)),
    ("wallet", re.compile(r"(wallet|address_?(btc|eth|trc|erc|usdt|crypto)|(btc|eth|trx|tron|usdt|ltc|doge|xmr|crypto)_?(addr|address|wallet)|payout_?address|deposit_?address|withdraw_?address|to_?address|from_?address)", re.I)),
    ("txid", re.compile(r"(^|_)(txid|tx_?hash|tx_?id|transaction_?(id|hash)|hash_?tx|txn)($|_)", re.I)),
    ("pwhash", re.compile(r"(^|_)(pass|passwd|password|user_?pass|pwd|hash|password_?hash)($|_)", re.I)),
    ("username", re.compile(r"(^|_)(user_?name|username|user_?login|login|nick|nickname|handle|account|acct|screen_?name|uname|user)($)", re.I)),
    ("name", re.compile(r"(^|_)(name|full_?name|first_?name|last_?name|surname|fio|customer_?name|owner|contact_?name|display_?name|real_?name|holder|beneficiary|sender|receiver|recipient|payee|payer)($|_)", re.I)),
    ("domain", re.compile(r"(^|_)(domain|host|hostname|site|website|url|homepage|referer|referrer)($|_)", re.I)),
    ("amount", re.compile(r"(^|_)(amount|amt|total|sum|price|fee|balance|paid|cost|value|credit|debit|qty_?usd|usd|btc_?amount|net|gross|subtotal|payout|deposit|withdraw(al)?)($|_)", re.I)),
    ("currency", re.compile(r"(^|_)(currency|cur|ccy|coin|asset|symbol|token)($|_)", re.I)),
    ("date", re.compile(r"(^|_)(date|time|ts|timestamp|created|updated|modified|registered|login_?time|addtime|at|when|dt|datetime|expires?|last_?seen|first_?seen|last_?login|birth)($|_)", re.I)),
    ("iban", re.compile(r"(^|_)(iban|account_?number|acct_?no|bank_?account)($|_)", re.I)),
    ("card", re.compile(r"(^|_)(card|pan|card_?number|cc_?number|credit_?card)($|_)", re.I)),
    ("handle", re.compile(r"(^|_)(telegram|tg|twitter|instagram|discord|skype|signal|handle)($|_)", re.I)),
    ("text", re.compile(r"(^|_)(note|notes|comment|comments|message|msg|body|text|description|desc|content|memo|remark|details|info|data|json|meta|value|log|subject|title|address|street)($|_)", re.I)),
]


def guess_column_type(name: str, samples: list[str]) -> str:
    """'email' | 'phone' | 'ip' | 'wallet' | 'txid' | 'pwhash' | 'username' | 'name' | 'domain' | 'amount' | 'currency' | 'date' |
    'iban' | 'card' | 'handle' | 'text' | 'id' | 'skip'. Header hints first, confirmed or overruled by the sampled values."""
    hint = ""
    for t, rx in _COL_HINTS:
        if rx.search(name):
            hint = t
            break
    vals = [v for v in samples if v and v.strip() and v.strip().lower() not in ("null", "none", "0", "-")][:500]
    if not vals:
        return hint or "skip"
    frac = lambda f: sum(1 for v in vals if f(v.strip())) / len(vals)  # noqa: E731
    if frac(lambda v: bool(EMAIL_RE.fullmatch(v))) >= 0.6:
        return "email"
    if frac(lambda v: bool(IPV4_RE.fullmatch(v)) or bool(IPV6_RE.fullmatch(v))) >= 0.6:
        return "ip"
    if frac(lambda v: wallet_network(v) is not None) >= 0.5:
        return "wallet"
    if frac(lambda v: bool(HEX64_RE.fullmatch(v))) >= 0.6:
        return "txid" if hint in ("txid", "wallet", "") else hint
    if frac(lambda v: bool(PWHASH_RE.fullmatch(v))) >= 0.6:
        return "pwhash"
    if hint == "phone" and frac(lambda v: _phone_norm(v) is not None) >= 0.5:
        return "phone"
    if hint == "card" and frac(lambda v: card_ok(re.sub(r"\D", "", v))) >= 0.5:
        return "card"
    if hint == "iban" and frac(lambda v: iban_ok(v)) >= 0.5:
        return "iban"
    if hint in ("date",) or frac(lambda v: bool(_DATE_LIKE.match(v))) >= 0.7:
        return "date" if hint == "date" or frac(lambda v: bool(_DATE_LIKE.match(v))) >= 0.7 else hint
    numeric = frac(lambda v: bool(re.fullmatch(r"-?\d+(\.\d+)?", v)))
    if hint == "amount" and numeric >= 0.8:
        return "amount"
    if hint in ("username", "name", "domain", "handle", "currency", "text"):
        if hint == "domain" and frac(lambda v: bool(DOMAIN_RE.fullmatch(v.lower().strip(".")))) < 0.3 and not frac(lambda v: "/" in v) > 0.3:
            return "text"
        return hint
    if numeric >= 0.9:
        return "id"
    avg = sum(len(v) for v in vals) / len(vals)
    if avg >= 12 or frac(lambda v: " " in v.strip()) >= 0.3:
        return "text"
    return "skip" if avg < 4 else "text"


_DATE_LIKE = re.compile(r"^(\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?|\d{2}/\d{2}/\d{4}( \d{2}:\d{2}(:\d{2})?)?|1[5-9]\d{8}|20\d{8}|1[5-9]\d{11})$")
