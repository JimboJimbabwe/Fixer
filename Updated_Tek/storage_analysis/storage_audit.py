#!/usr/bin/env python3
"""
Browser Storage Security Analyzer  v2.1
=======================================
Scans text dumps (localStorage / sessionStorage / cookies / IndexedDB exports,
HAR files, logs, config files ...) for secrets and personal data.

Highlights
  * 70+ detection rules: auth tokens, cloud/SaaS keys, private keys, DB strings,
    PII, payment data, crypto wallets, risky cookies, client-side authz flags
  * Validation to cut false positives (Luhn, IBAN mod-97, SSN rules, JWT decoding,
    entropy checks, placeholder filtering)
  * Secrets are MASKED in all output unless --show-secrets is given
  * Understands reports from storage_capture.js: reads the section headers and
    reports hits as "localStorage > authToken", adds key-name detection (token /
    password / session ... keys, also inside JSON values) and Cache-Control checks
  * Scans files, directories (recursive) or stdin
  * Reports as colour terminal output, JSON or Markdown
  * CI friendly: --fail-on <severity> sets a non-zero exit code

Usage
  python storage_analyzer.py dump.txt
  python storage_analyzer.py ./exports/ --min-severity medium
  python storage_analyzer.py dump.txt --ask-password -u user@example.com
  python storage_analyzer.py dump.txt -o report.json      # or report.md
  cat dump.txt | python storage_analyzer.py - --fail-on high
"""

from __future__ import annotations

import argparse
import base64
import binascii
import bisect
import getpass
import json
import math
import os
import re
import shutil
import sys
import urllib.parse
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from types import SimpleNamespace
from pathlib import Path
from typing import Callable, Iterable, Optional

__version__ = "2.1.0"


# ════════════════════════════════════════════════════════════════════════════
#  Severity & terminal styling
# ════════════════════════════════════════════════════════════════════════════
class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        return cls[name.strip().upper()]


UNICODE = (getattr(sys.stdout, "encoding", "") or "").lower().startswith("utf")
SEV_COLOR = {
    Severity.CRITICAL: "1;97;41",
    Severity.HIGH: "1;31",
    Severity.MEDIUM: "1;33",
    Severity.LOW: "1;36",
    Severity.INFO: "90",
}


class Style:
    """Tiny ANSI helper that can be switched off."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t): return self(t, "1")
    def dim(self, t): return self(t, "90")
    def cyan(self, t): return self(t, "36")
    def green(self, t): return self(t, "1;32")
    def red(self, t): return self(t, "1;31")

    def badge(self, sev: Severity) -> str:
        return self(f" {sev.name:<8} ", SEV_COLOR[sev])


# ════════════════════════════════════════════════════════════════════════════
#  Validators & helpers
# ════════════════════════════════════════════════════════════════════════════
_PLACEHOLDER_EXACT = {
    "true", "false", "null", "none", "undefined", "nil", "empty", "string",
    "password", "secret", "token", "value", "test", "todo", "n/a",
}
_PLACEHOLDER_PARTS = (
    "example", "your_", "your-", "yourkey", "changeme", "change_me", "placeholder",
    "dummy", "sample", "xxxx", "****", "<", ">", "{{", "${", "redacted", "insert",
)


def not_placeholder(value: str) -> bool:
    low = value.lower().strip()
    if low in _PLACEHOLDER_EXACT or len(set(low)) <= 2:
        return False
    return not any(p in low for p in _PLACEHOLDER_PARTS)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def looks_random(v: str) -> bool:
    return not_placeholder(v) and shannon_entropy(v) >= 3.0


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return total % 10 == 0


def card_brand(number: str) -> Optional[str]:
    d = re.sub(r"\D", "", number)
    n2, n4 = int(d[:2]), int(d[:4])
    if d[0] == "4" and len(d) in (13, 16, 19):
        return "Visa"
    if (51 <= n2 <= 55 or 2221 <= n4 <= 2720) and len(d) == 16:
        return "Mastercard"
    if n2 in (34, 37) and len(d) == 15:
        return "American Express"
    if (d.startswith("6011") or d.startswith("65") or 644 <= int(d[:3]) <= 649) and len(d) in (16, 19):
        return "Discover"
    if (300 <= int(d[:3]) <= 305 or n2 in (36, 38, 39)) and len(d) in (14, 16, 19):
        return "Diners Club"
    if 3528 <= n4 <= 3589 and len(d) in (16, 19):
        return "JCB"
    if n2 in (62,) and 16 <= len(d) <= 19:
        return "UnionPay"
    return None


def card_ok(v: str) -> bool:
    return card_brand(v) is not None and luhn_ok(v)


def ssn_ok(v: str) -> bool:
    area, group, serial = v.split("-")
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


def iban_ok(v: str) -> bool:
    s = re.sub(r"\s", "", v).upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1
    except ValueError:
        return False


def phone_us_ok(v: str) -> bool:
    d = re.sub(r"\D", "", v)
    d = d[1:] if len(d) == 11 and d[0] == "1" else d
    return len(d) == 10 and d[0] in "23456789" and d[3] in "23456789"


def phone_intl_ok(v: str) -> bool:
    return 8 <= len(re.sub(r"\D", "", v)) <= 15


_IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js")


def email_ok(v: str) -> bool:
    return not v.lower().endswith(_IMAGE_EXT) and not v.split("@")[0].lower() in ("example", "test", "user")


def _ip_parts(v: str):
    return [int(p) for p in v.split(".")]


def ip_is_private(v: str) -> bool:
    a, b, *_ = _ip_parts(v)
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254)


def ip_is_public(v: str) -> bool:
    a, *_ = _ip_parts(v)
    return not ip_is_private(v) and a not in (0, 127, 255) and v != "1.0.0.0"


def _b64url_json(segment: str):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def jwt_ok(v: str) -> bool:
    try:
        header = _b64url_json(v.split(".")[0])
        return isinstance(header, dict) and ("alg" in header or "typ" in header)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False


def jwt_notes(v: str) -> str:
    notes = []
    try:
        header, payload = (_b64url_json(p) for p in v.split(".")[:2])
        alg = header.get("alg")
        notes.append(f"alg={alg}")
        if str(alg).lower() == "none":
            notes.append("UNSIGNED token (alg=none)")
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            when = datetime.fromtimestamp(exp, tz=timezone.utc)
            state = "EXPIRED" if when < datetime.now(timezone.utc) else "valid until"
            notes.append(f"{state} {when:%Y-%m-%d %H:%M} UTC")
        else:
            notes.append("no expiry (exp) claim")
        claims = [k for k in ("sub", "email", "name", "role", "roles", "scope", "uid", "user_id") if k in payload]
        if claims:
            notes.append("claims: " + ", ".join(claims))
    except Exception:  # noqa: BLE001 - best effort decoding only
        pass
    return "; ".join(notes)


def basic_auth_ok(v: str) -> bool:
    try:
        return b":" in base64.b64decode(v + "=" * (-len(v) % 4), validate=True)
    except (ValueError, binascii.Error):
        return False


def cookie_flags_weak(full: str) -> bool:
    low = full.lower()
    return "httponly" not in low or "secure" not in low


def cookie_notes(full: str) -> str:
    low = full.lower()
    missing = [f for f in ("HttpOnly", "Secure", "SameSite") if f.lower() not in low]
    return "missing: " + ", ".join(missing) if missing else ""


def mask_value(value: str, style: str = "default") -> str:
    """Hide most of a secret while keeping it recognisable."""
    if style == "last4":
        idx = [i for i, ch in enumerate(value) if ch.isalnum()]
        keep = set(idx[-4:])
        return "".join(ch if (not ch.isalnum() or i in keep) else "*" for i, ch in enumerate(value))
    n = len(value)
    if n <= 8:
        return value[:1] + "*" * (n - 1)
    if n <= 16:
        return value[:2] + "*" * (n - 4) + value[-2:]
    return value[:4] + "*" * min(n - 6, 24) + value[-2:]


# ════════════════════════════════════════════════════════════════════════════
#  Rule definitions
# ════════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: Severity
    regex: re.Pattern
    group: int = 0                                     # capture group holding the secret
    validate: Optional[Callable[[str], bool]] = None   # runs on the captured value
    validate_full: Optional[Callable[[str], bool]] = None  # runs on the whole match
    enrich: Optional[Callable[[str], str]] = None      # returns an extra note
    mask_style: str = "default"                        # default | last4 | none
    priority: int = 0                                  # lower wins overlap ties


C, H, M, L, I = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def rule(id_, title, category, severity, pattern, flags=0, **kw) -> Rule:
    return Rule(id_, title, category, severity, re.compile(pattern, flags), **kw)


def kv(keys: str, min_len: int = 16, chars: str = r"[A-Za-z0-9_\-\.\/+=~%]") -> str:
    """Regex for  key = value / "key": "value" / escaped-JSON  assignments."""
    return rf'(?i)(?:{keys})[\w.-]*\\?["\']?\s*[:=]\s*\\?["\']?({chars}{{{min_len},}})'


_PW_VALUE = r"[^\s\"'\\,;&}{\]\[]"

RULES: list[Rule] = [
    # ── Authentication & sessions ───────────────────────────────────────────
    rule("jwt", "JSON Web Token (JWT)", "auth", C,
         r"\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*", validate=jwt_ok, enrich=jwt_notes),
    rule("bearer", "Bearer token", "auth", C,
         r"(?i)\bbearer\s+(?!eyJ)([A-Za-z0-9\-._~+/]{20,}=*)", group=1, validate=not_placeholder),
    rule("basic_auth", "HTTP Basic auth credentials", "auth", H,
         r"(?i)\bbasic\s+([A-Za-z0-9+/]{12,}={0,2})", group=1, validate=basic_auth_ok),
    rule("api_key", "Generic API key", "auth", C,
         kv(r"api[_-]?key|apikey|x-api-key"), group=1, validate=looks_random, priority=1),
    rule("access_token", "Access token", "auth", C,
         kv(r"access[_-]?token|accesstoken", 20, r"[A-Za-z0-9_\-\.~+/=]"), group=1, validate=looks_random, priority=1),
    rule("refresh_token", "Refresh token", "auth", C,
         kv(r"refresh[_-]?token|refreshtoken", 20, r"[A-Za-z0-9_\-\.~+/=]"), group=1, validate=looks_random, priority=1),
    rule("id_token", "OpenID/ID token", "auth", H,
         kv(r"id[_-]?token", 20, r"[A-Za-z0-9_\-\.~+/=]"), group=1, validate=looks_random, priority=1),
    rule("client_secret", "OAuth client secret", "auth", C,
         kv(r"client[_-]?secret", 12), group=1, validate=looks_random, priority=1),
    rule("session_id", "Session identifier", "auth", H,
         kv(r"session[_-]?id|sessionid|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|sess_token"),
         group=1, validate=looks_random, priority=1),
    rule("csrf_token", "CSRF / XSRF token", "auth", L,
         kv(r"csrf[_-]?token|xsrf[_-]?token|authenticity_token|_csrf"), group=1, validate=looks_random, priority=1),
    rule("password_kv", "Plaintext password", "auth", C,
         rf'(?i)(?:passw(?:or)?d|pwd|passphrase)[\w.-]*\\?["\']?\s*[:=]\s*\\?["\']?({_PW_VALUE}{{4,}})',
         group=1, validate=not_placeholder, priority=1),
    rule("secret_kv", "Generic secret / key material", "auth", H,
         kv(r"secret|private[_-]?key|auth[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key", 12),
         group=1, validate=looks_random, priority=2),
    rule("secret_in_url", "Secret in URL query string", "auth", H,
         r"(?i)[?&](?:access_token|token|api[_-]?key|apikey|auth|sig|signature|secret)=([A-Za-z0-9._~%+/=-]{16,})",
         group=1, validate=looks_random, priority=2),
    rule("password_in_url", "Password in URL parameter", "auth", H,
         r"(?i)[?&;](?:passw(?:or)?d|pwd|pass)=([^&\s\"'#\\]+)", group=1, validate=not_placeholder),
    rule("set_cookie_weak", "Cookie set without HttpOnly/Secure", "auth", M,
         r"(?i)\bSet-Cookie:\s*[^=;\s]+=([^;\r\n]*)([^\r\n]*)", group=1, validate_full=cookie_flags_weak, priority=3),
    rule("authz_flag", "Client-side authorization flag (tamperable)", "auth", L,
         r'(?i)\\?["\']?\b(?:is[_-]?admin|is[_-]?superuser|role|user[_-]?role)\\?["\']?\s*[:=]\s*\\?["\']?(?:true|admin|superuser|root|owner)\b',
         mask_style="none"),

    # ── Cloud providers ────────────────────────────────────────────────────
    rule("aws_access_key", "AWS access key ID", "cloud", C,
         r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b"),
    rule("aws_secret_key", "AWS secret access key", "cloud", C,
         r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\\?[\"']?\s*[:=]\s*\\?[\"']?([A-Za-z0-9/+=]{40})\b", group=1),
    rule("google_api_key", "Google API key", "cloud", C, r"\bAIza[\w-]{35}\b"),
    rule("google_oauth_token", "Google OAuth access token", "cloud", C, r"\bya29\.[\w-]{20,}"),
    rule("google_client_secret", "Google OAuth client secret", "cloud", C, r"\bGOCSPX-[\w-]{20,}"),
    rule("gcp_service_account", "GCP service-account key file", "cloud", H,
         r'\\?"type\\?"\s*:\s*\\?"service_account\\?"', mask_style="none"),
    rule("azure_storage_key", "Azure storage account key", "cloud", C,
         r"AccountKey=([A-Za-z0-9+/=]{40,})", group=1),
    rule("azure_sas", "Azure SAS token", "cloud", H,
         r"[?&]sv=\d{4}-\d{2}-\d{2}&[^\s\"']*?sig=([A-Za-z0-9%+/=]{20,})", group=1),
    rule("digitalocean_token", "DigitalOcean token", "cloud", C, r"\bdop_v1_[a-f0-9]{64}\b"),
    rule("firebase_url", "Firebase database URL", "cloud", I,
         r"https://[\w-]+(?:-default-rtdb)?\.firebaseio\.com", mask_style="none"),

    # ── SaaS & developer platforms ─────────────────────────────────────────
    rule("github_token", "GitHub token", "saas", C,
         r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    rule("gitlab_token", "GitLab personal access token", "saas", C, r"\bglpat-[\w-]{20}\b"),
    rule("slack_token", "Slack token", "saas", C, r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    rule("slack_webhook", "Slack webhook URL", "saas", H,
         r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    rule("discord_webhook", "Discord webhook URL", "saas", H,
         r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"),
    rule("discord_bot_token", "Discord bot token", "saas", C,
         r"\b[MNO][A-Za-z\d_-]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b"),
    rule("telegram_bot_token", "Telegram bot token", "saas", C, r"\b\d{8,10}:AA[\w-]{33}\b"),
    rule("stripe_live_secret", "Stripe live secret key", "saas", C, r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    rule("stripe_test_secret", "Stripe test secret key", "saas", L, r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}\b"),
    rule("stripe_publishable", "Stripe publishable key (public by design)", "saas", I, r"\bpk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    rule("twilio_api_key", "Twilio API key", "saas", H, r"\bSK[0-9a-f]{32}\b"),
    rule("twilio_account_sid", "Twilio account SID", "saas", M, r"\bAC[0-9a-f]{32}\b"),
    rule("sendgrid_key", "SendGrid API key", "saas", C, r"\bSG\.[\w-]{22}\.[\w-]{43}\b"),
    rule("mailgun_key", "Mailgun API key", "saas", C, r"\bkey-[0-9a-f]{32}\b"),
    rule("mailchimp_key", "Mailchimp API key", "saas", H, r"\b[0-9a-f]{32}-us\d{1,2}\b"),
    rule("npm_token", "npm access token", "saas", C, r"\bnpm_[A-Za-z0-9]{36}\b"),
    rule("pypi_token", "PyPI upload token", "saas", C, r"\bpypi-AgEIcHlwaS5vcmc[\w-]{50,}"),
    rule("shopify_token", "Shopify access token", "saas", C, r"\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b"),
    rule("square_token", "Square access token", "saas", C, r"\b(?:sq0atp-[\w-]{22}|EAAA[\w-]{60})\b"),
    rule("huggingface_token", "Hugging Face token", "saas", C, r"\bhf_[A-Za-z0-9]{34}\b"),
    rule("openai_key", "OpenAI API key", "saas", C, r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b"),
    rule("anthropic_key", "Anthropic API key", "saas", C, r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    rule("notion_token", "Notion integration token", "saas", C, r"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b"),
    rule("postman_key", "Postman API key", "saas", H, r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
    rule("sentry_dsn", "Sentry DSN", "saas", M, r"https://[0-9a-f]{32}@[\w.-]+/\d+"),

    # ── Cryptographic material ─────────────────────────────────────────────
    rule("private_key", "Private key", "crypto", C,
         r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----", mask_style="none"),

    # ── Connection strings & embedded credentials ─────────────────────────
    rule("db_conn_creds", "Database connection string with credentials", "database", C,
         r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|sqlserver|clickhouse|cockroachdb)"
         r"://[^\s:@/\"'\\]+:[^\s@/\"'\\]+@[^\s\"'<>\\]+"),
    rule("db_conn", "Database connection string", "database", H,
         r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|sqlserver|clickhouse|cockroachdb)"
         r"://[^\s\"'<>\\]+", priority=1),
    rule("url_credentials", "Credentials embedded in URL", "database", H,
         r"\b[a-z][a-z0-9+.-]{1,15}://[^\s:@/\"'\\]+:([^\s@/\"'\\]+)@[^\s\"'<>\\]+", group=1, validate=not_placeholder, priority=1),
    rule("azure_conn_string", "Azure connection string", "database", C,
         r"DefaultEndpointsProtocol=https?;[^\s\"']*AccountKey=[A-Za-z0-9+/=]{20,}"),

    # ── Personal data (PII) ────────────────────────────────────────────────
    rule("email", "Email address", "pii", M,
         r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b", validate=email_ok, priority=5),
    rule("phone_us", "US phone number", "pii", M,
         r"(?<![\w.])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?!\d)", validate=phone_us_ok, priority=5),
    rule("phone_intl", "International phone number", "pii", M,
         r"(?<![\w.])\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{2,4}[ .-]\d{2,4}(?:[ .-]\d{2,4})?(?!\d)",
         validate=phone_intl_ok, priority=6),
    rule("ssn", "US Social Security number", "pii", H, r"\b\d{3}-\d{2}-\d{4}\b", validate=ssn_ok, mask_style="last4"),
    rule("dob", "Date of birth", "pii", M,
         r"(?i)(?:dob|date[_-]?of[_-]?birth|birth[_-]?date|birthday)\\?[\"']?\s*[:=]\s*\\?[\"']?(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})",
         group=1),
    rule("geo_coordinate", "Geolocation coordinate", "pii", L,
         r"(?i)\b(?:lat(?:itude)?|lng|lon(?:gitude)?)\b\\?[\"']?\s*[:=]\s*(-?\d{1,3}\.\d{4,})", group=1),
    rule("ipv4_internal", "Internal IP address", "network", L,
         r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])",
         validate=ip_is_private, mask_style="none"),
    rule("ipv4_public", "Public IP address", "network", I,
         r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])",
         validate=ip_is_public, mask_style="none"),
    rule("mac_address", "MAC address", "network", I, r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),

    # ── Financial ──────────────────────────────────────────────────────────
    rule("credit_card", "Payment card number", "financial", C,
         r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])", validate=card_ok, mask_style="last4",
         enrich=lambda v: f"{card_brand(v)}, Luhn-valid"),
    rule("iban", "IBAN bank account", "financial", H,
         r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b", validate=iban_ok, mask_style="last4"),
    rule("eth_address", "Ethereum wallet address", "financial", L, r"\b0x[a-fA-F0-9]{40}\b", mask_style="none"),
    rule("btc_address", "Bitcoin (bech32) address", "financial", L, r"\bbc1[ac-hj-np-z02-9]{25,62}\b", mask_style="none"),
]

ADVICE = {
    "auth": "Don't keep credentials/tokens in web storage; use HttpOnly+Secure+SameSite cookies, short TTLs; rotate anything exposed.",
    "cloud": "Revoke and rotate the credential now, then audit provider logs for misuse. Keep secrets server-side.",
    "saas": "Revoke and regenerate the token in the provider dashboard; scope tokens to least privilege.",
    "crypto": "Treat the key as compromised: generate a new key pair and remove the old one everywhere.",
    "database": "Rotate the DB password, restrict network access, and never ship connection strings to clients.",
    "pii": "Minimise what is stored client-side; encrypt or drop personal data and honour retention rules (GDPR/CCPA).",
    "network": "Avoid leaking infrastructure details to the client; review whether this value must be exposed.",
    "financial": "Never store card/bank data in the browser (PCI DSS); tokenise via your payment provider.",
    "cache": "Send 'Cache-Control: no-store' (and avoid 'public') on pages that show authenticated or personal data.",
}


# ════════════════════════════════════════════════════════════════════════════
#  Result containers
# ════════════════════════════════════════════════════════════════════════════
@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: str
    count: int
    lines: list
    column: int
    match: str
    context: str
    notes: str
    remediation: str
    locations: list = field(default_factory=list)   # e.g. "localStorage > authToken"


@dataclass
class Exposure:
    kind: str
    line: int
    context: str


@dataclass
class FileResult:
    path: str
    size: int
    lines: int
    findings: list = field(default_factory=list)
    password_exposures: Optional[list] = None   # None = not tested
    credential_pair: Optional[dict] = None
    error: Optional[str] = None
    source_url: Optional[str] = None     # from a storage_capture.js report
    captured: Optional[str] = None
    parsed: Optional[dict] = None        # items parsed per storage type


# ════════════════════════════════════════════════════════════════════════════
#  Storage-report parsing (output of storage_capture.js)
# ════════════════════════════════════════════════════════════════════════════
SECTION_LABELS = {
    "LOCAL STORAGE": "localStorage", "SESSION STORAGE": "sessionStorage", "COOKIES": "cookie",
    "URL PARAMETERS": "URL parameter", "URL FRAGMENT": "URL fragment", "CACHE HEADERS": "response header",
    "CONSOLIDATED COOKIE LIST": "cookie list",
}
_SECTION_RE = re.compile(r"^---\s*([A-Z][A-Z ()/_-]*?)\s*---\s*$")
_MARKER_RE = re.compile(r"^⚠️? ?Potential sensitive data(?: \((?P<why>.*?)\))? - ")
_META_RE = re.compile(r"^(URL|Origin|Captured)\s*:\s*(.*)$")
_ITEM_RE = re.compile(r"^(?P<key>.+?)(?::[ \t]|:$)(?P<value>.*)$")

# Key-name heuristics (kept in sync with storage_capture.js). Keys are split into
# words so "authToken" matches but "keyboard", "author" and "tokenExpiry" do not.
SECRET_WORDS = {"password", "passwd", "pwd", "pass", "passphrase", "secret", "secrets", "credential",
                "credentials", "cvv", "cvc", "ssn", "pin", "apikey", "iban"}
TOKEN_WORDS = {"token", "tokens", "jwt", "auth", "authorization", "bearer", "session", "sessionid", "sid",
               "csrf", "xsrf", "otp", "sso", "jsessionid", "phpsessid"}
KEY_QUALIFIERS = {"api", "private", "secret", "access", "encryption", "signing", "client", "master", "auth"}
CARD_QUALIFIERS = {"number", "num", "no", "pan"}
BENIGN_WORDS = {"expiry", "expires", "expiration", "exp", "type", "name", "count", "length", "timeout", "ttl",
                "enabled", "disabled", "status", "url", "endpoint", "header", "prefix", "version", "timestamp",
                "time", "date", "format", "mode", "flag", "required", "valid", "expired", "start", "end",
                "last", "active", "show", "hide", "is", "has"}


def key_words(key: str) -> list:
    return [w for w in re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key).lower()) if w]


def key_class(key: str) -> Optional[str]:
    w = key_words(key)
    if not w or any(x in BENIGN_WORDS for x in w):
        return None
    if any(x in SECRET_WORDS for x in w) or ("key" in w and any(x in KEY_QUALIFIERS for x in w)) \
            or ("card" in w and any(x in CARD_QUALIFIERS for x in w)):
        return "secret"
    if any(x in TOKEN_WORDS for x in w):
        return "token"
    return None


def key_value_ok(cls: str, value: str) -> bool:
    v = value.strip()
    if not v or not not_placeholder(v):
        return False
    return len(v) >= 4 if cls == "secret" else (len(v) >= 12 and shannon_entropy(v) >= 3.0)


def _pseudo(id_, title, category, severity, priority, mask_style="default"):
    return SimpleNamespace(id=id_, title=title, category=category, severity=severity,
                           priority=priority, mask_style=mask_style, enrich=None)


KEY_SECRET_RULE = _pseudo("storage_secret_key", "Secret stored client-side (by key name)", "auth", Severity.CRITICAL, 3)
KEY_TOKEN_RULE = _pseudo("storage_token_key", "Token/session stored client-side (by key name)", "auth", Severity.HIGH, 3)
CAPTURE_FLAG_RULE = _pseudo("capture_flag", "Flagged by capture script (not confirmed)", "auth", Severity.INFO, 9)
CACHE_MISSING_RULE = _pseudo("cache_missing", "No Cache-Control header", "cache", Severity.MEDIUM, 0, "none")
CACHE_NO_STORE_RULE = _pseudo("cache_no_store", "Cache-Control lacks 'no-store'", "cache", Severity.MEDIUM, 0, "none")
CACHE_PUBLIC_RULE = _pseudo("cache_public", "Cache-Control allows shared caching ('public')", "cache", Severity.MEDIUM, 0, "none")


@dataclass
class StorageItem:
    section: str      # e.g. "LOCAL STORAGE"
    key: str
    value: str
    flagged: bool     # the capture script already marked it
    why: str
    line: int
    vstart: int       # absolute offsets of the value in the file
    vend: int
    lstart: int       # absolute offsets of the whole line
    lend: int

    @property
    def label(self) -> str:
        return SECTION_LABELS.get(self.section, self.section.lower())


@dataclass
class StorageDump:
    items: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    skip_ranges: list = field(default_factory=list)   # duplicated content that must not be scanned twice

    def __post_init__(self):
        self.by_line: dict = {}

    def counts(self) -> dict:
        return dict(Counter(i.label for i in self.items))


def parse_storage_report(content: str) -> Optional[StorageDump]:
    """Parse a storage_capture.js report; None if the text is not in that format."""
    lines = content.split("\n")
    if not any((m := _SECTION_RE.match(l.strip())) and m.group(1) in SECTION_LABELS for l in lines):
        return None
    dump, section, pos, skip_start = StorageDump(), None, 0, None
    for no, raw in enumerate(lines, 1):
        line = raw.rstrip("\r")
        start, pos = pos, pos + len(raw) + 1
        m = _SECTION_RE.match(line.strip())
        if m and m.group(1) in SECTION_LABELS:
            if skip_start is not None:
                dump.skip_ranges.append((skip_start, start))
                skip_start = None
            section = m.group(1)
            if section == "CONSOLIDATED COOKIE LIST":     # same cookies as COOKIES; don't double-report
                skip_start = min(pos, len(content))
            continue
        if section is None:
            mm = _META_RE.match(line.strip())
            if mm:
                dump.meta[mm.group(1)] = mm.group(2).strip()
            continue
        if section == "CONSOLIDATED COOKIE LIST" or not line.strip() or line.lstrip().startswith("#"):
            continue
        marker = _MARKER_RE.match(line)
        if not marker and line.lstrip().startswith("⚠"):
            continue                                       # free-text warning from the capture script
        off = marker.end() if marker else 0
        im = _ITEM_RE.match(line[off:])
        if not im:
            continue
        item = StorageItem(section=section, key=im.group("key").strip(), value=im.group("value"),
                           flagged=bool(marker), why=(marker.group("why") or "") if marker else "", line=no,
                           vstart=start + off + im.start("value"), vend=start + off + im.end("value"),
                           lstart=start, lend=start + len(line))
        dump.items.append(item)
        dump.by_line[no] = item
    if skip_start is not None:
        dump.skip_ranges.append((skip_start, len(content)))
    return dump


def blank_ranges(content: str, ranges: list) -> str:
    """Replace text with spaces (keeping newlines) so offsets and line numbers stay valid."""
    out, pos = [], 0
    for s, e in ranges:
        out += [content[pos:s], re.sub(r"[^\n]", " ", content[s:e])]
        pos = e
    out.append(content[pos:])
    return "".join(out)


# ════════════════════════════════════════════════════════════════════════════
#  Analyzer
# ════════════════════════════════════════════════════════════════════════════
class StorageAnalyzer:
    def __init__(self, min_severity: Severity = Severity.INFO, show_secrets: bool = False,
                 entropy_scan: bool = False, context_radius: int = 40, rules: Iterable[Rule] = RULES,
                 parse_reports: bool = True):
        self.rules = list(rules)
        self.min_severity = min_severity
        self.show_secrets = show_secrets
        self.entropy_scan = entropy_scan
        self.radius = context_radius
        self.parse_reports = parse_reports

    # ── helpers ──────────────────────────────────────────────────────────
    def _mask(self, value: str, style: str) -> str:
        if self.show_secrets or style == "none":
            return value
        return mask_value(value, style)

    @staticmethod
    def _line_starts(content: str) -> list:
        return [0] + [m.end() for m in re.finditer(r"\n", content)]

    def _context(self, content: str, spans: list, start: int, end: int) -> str:
        """Surrounding text with every detected secret in the window masked."""
        lo, hi = max(0, start - self.radius), min(len(content), end + self.radius)
        ends = [s[1] for s in spans]
        out, pos = [], lo
        for s, e, masked in spans[bisect.bisect_right(ends, lo):]:
            if s >= hi:
                break
            if s > pos:
                out.append(content[pos:s])
            out.append(masked)
            pos = max(pos, min(e, hi))
        if pos < hi:
            out.append(content[pos:hi])
        return " ".join("".join(out).split())

    # ── core scan ────────────────────────────────────────────────────────
    def scan_text(self, content: str, name: str = "<input>") -> FileResult:
        dump = parse_storage_report(content) if self.parse_reports else None
        if dump and dump.skip_ranges:
            content = blank_ranges(content, dump.skip_ranges)
        starts = self._line_starts(content)
        result = FileResult(path=name, size=len(content.encode("utf-8", "ignore")), lines=len(starts))
        if dump:
            result.source_url, result.captured = self._safe_url(dump.meta.get("URL")), dump.meta.get("Captured")
            result.parsed = dump.counts()

        candidates = []   # (rule, start, end, value, note)
        for r in self.rules:
            if r.severity < self.min_severity:
                continue
            for m in r.regex.finditer(content):
                value = m.group(r.group)
                if value is None:
                    continue
                if r.validate and not r.validate(value):
                    continue
                if r.validate_full and not r.validate_full(m.group(0)):
                    continue
                note = r.enrich(value) if r.enrich else ""
                if r.id == "set_cookie_weak":
                    note = cookie_notes(m.group(0))
                s, e = m.span(r.group)
                candidates.append((r, s, e, value, note))

        if self.entropy_scan and Severity.LOW >= self.min_severity:
            candidates += self._entropy_candidates(content)
        if dump:
            candidates += [c for c in self._storage_candidates(dump) if c[0].severity >= self.min_severity]

        # Resolve overlaps: highest severity, then most specific, then longest.
        candidates.sort(key=lambda c: (-c[0].severity, c[0].priority, -(c[2] - c[1]), c[1]))
        accepted, taken = [], []
        for cand in candidates:
            s, e = cand[1], cand[2]
            i = bisect.bisect_left(taken, (s, e))
            if (i < len(taken) and taken[i][0] < e) or (i and taken[i - 1][1] > s):
                continue
            taken.insert(i, (s, e))
            accepted.append(cand)
        accepted.sort(key=lambda c: c[1])

        spans = [(c[1], c[2], self._mask(c[3], c[0].mask_style)) for c in accepted]

        # Group identical secrets (same rule + same value) into one finding.
        grouped: dict = {}
        for (r, s, e, value, note), (_, _, masked) in zip(accepted, spans):
            line = bisect.bisect_right(starts, s)
            item = dump.by_line.get(line) if dump else None
            where = f"{item.label} > {item.key}" if item else None
            key = (r.id, value)
            if key in grouped:
                f = grouped[key]
                f.count += 1
                f.lines.append(line)
                if where and where not in f.locations:
                    f.locations.append(where)
                continue
            grouped[key] = Finding(
                rule_id=r.id, title=r.title, category=r.category, severity=r.severity.name,
                count=1, lines=[line], column=s - starts[line - 1] + 1, match=masked,
                context=self._context(content, spans, s, e), notes=note,
                remediation=ADVICE.get(r.category, ""), locations=[where] if where else [],
            )
        # The same value reported by a generic key-name rule AND a specific rule (e.g. the page URL
        # header echoing a query parameter): keep the specific one and merge the locations.
        generic = {"storage_token_key", "storage_secret_key", "capture_flag"}
        by_value: dict = {}
        for (rid, value), f in grouped.items():
            if rid not in generic:
                by_value.setdefault(value, f)
        for key in [k for k in grouped if k[0] in generic and k[1] in by_value]:
            f, target = grouped.pop(key), by_value[key[1]]
            target.count += f.count
            target.lines = sorted(set(target.lines) | set(f.lines))
            target.locations += [w for w in f.locations if w not in target.locations]
        result.findings = sorted(grouped.values(), key=lambda f: (-Severity[f.severity], f.lines[0]))
        return result

    def _safe_url(self, url: Optional[str]) -> Optional[str]:
        """Mask credentials and secret-looking parameter values in a URL before it is displayed."""
        if not url or self.show_secrets:
            return url
        url = re.sub(r"(//[^/:@\s]+:)([^@/\s]+)(@)", lambda m: m.group(1) + mask_value(m.group(2)) + m.group(3), url)

        def param(m):
            k, v = m.group(2), m.group(3)
            return m.group(1) + k + "=" + (mask_value(v) if len(v) >= 12 or key_class(k) else v)
        return re.sub(r"([?&#])([^=&#\s]+)=([^&#\s]*)", param, url)

    # ── storage-report aware detection ───────────────────────────────────
    def _storage_candidates(self, dump: StorageDump) -> list:
        out = []
        for it in dump.items:
            if it.section == "CACHE HEADERS":
                out += self._cache_candidates(it)
                continue
            cls = key_class(it.key)
            if cls and key_value_ok(cls, it.value):
                rule = KEY_SECRET_RULE if cls == "secret" else KEY_TOKEN_RULE
                out.append((rule, it.vstart, it.vend, it.value, f'key name "{it.key}"'))
            elif it.value.lstrip()[:1] in ("{", "["):
                out += self._json_candidates(it)
            if it.flagged and it.vend > it.vstart:
                out.append((CAPTURE_FLAG_RULE, it.vstart, it.vend, it.value,
                            f"capture script: {it.why}" if it.why else "flagged by capture script"))
        return out

    @staticmethod
    def _json_candidates(it: StorageItem) -> list:
        try:
            data = json.loads(it.value)
        except ValueError:
            return []
        hits = []

        def walk(node, path, depth):
            if depth > 6:
                return
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, path + [str(k)], depth + 1)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, path + [f"[{i}]"], depth + 1)
            elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
                leaf = next((p for p in reversed(path) if not p.startswith("[")), "")
                cls, sv = key_class(leaf), str(node)
                if cls and key_value_ok(cls, sv):
                    hits.append((cls, re.sub(r"\.\[", "[", ".".join(path)), sv))

        walk(data, [], 0)
        out = []
        for cls, path, sv in hits:
            idx = it.value.find(sv)
            if idx >= 0:
                rule = KEY_SECRET_RULE if cls == "secret" else KEY_TOKEN_RULE
                out.append((rule, it.vstart + idx, it.vstart + idx + len(sv), sv, f"nested key {path}"))
        return out

    @staticmethod
    def _cache_candidates(it: StorageItem) -> list:
        if it.key.lower() != "cache-control":
            return []
        v = it.value.strip().lower()
        text = f"{it.key}: {it.value}".strip()
        if v in ("", "null", "(none)", "none", "undefined"):
            return [(CACHE_MISSING_RULE, it.lstart, it.lend, text, "pages with personal data should send no-store")]
        if "public" in v:
            return [(CACHE_PUBLIC_RULE, it.lstart, it.lend, text, "")]
        if "no-store" not in v:
            return [(CACHE_NO_STORE_RULE, it.lstart, it.lend, text, "no-cache/max-age alone still lets the browser keep a copy")]
        return []

    def _entropy_candidates(self, content: str):
        from types import SimpleNamespace
        pseudo = SimpleNamespace(id="high_entropy", title="High-entropy string (possible secret)",
                                 category="auth", severity=Severity.LOW, priority=9, mask_style="default",
                                 enrich=None)
        out = []
        for m in re.finditer(r"[A-Za-z0-9+/_\-]{32,}={0,2}", content):
            v = m.group(0)
            if (re.search(r"\d", v) and re.search(r"[A-Za-z]", v) and shannon_entropy(v) >= 4.2
                    and not re.fullmatch(r"[0-9a-fA-F-]{32,40}", v)):
                out.append((pseudo, m.start(), m.end(), v, f"entropy={shannon_entropy(v):.2f} bits/char"))
        return out

    # ── known-password exposure test ────────────────────────────────────
    def check_password(self, content: str, result: FileResult, password: str, username: Optional[str] = None):
        variants = [("Plaintext (exact)", password, 0)]
        variants.append(("Plaintext (different case)", password, re.IGNORECASE))
        b64 = base64.b64encode(password.encode()).decode()
        variants += [
            ("Base64", b64, 0),
            ("Base64 (no padding)", b64.rstrip("="), 0),
            ("Base64 URL-safe", base64.urlsafe_b64encode(password.encode()).decode().rstrip("="), 0),
            ("URL-encoded", urllib.parse.quote(password, safe=""), 0),
            ("URL-encoded (form, '+')", urllib.parse.quote_plus(password), 0),
            ("Hex-encoded", password.encode().hex(), re.IGNORECASE),
            ("JSON-escaped", json.dumps(password)[1:-1], 0),
        ]
        starts = self._line_starts(content)
        found, seen = [], set()
        for label, needle, flags in variants:
            if len(needle) < 3:
                continue
            for m in re.finditer(re.escape(needle), content, flags):
                if label == "Plaintext (different case)" and m.group(0) == password:
                    continue
                if (m.start(), m.end()) in seen:
                    continue
                seen.add((m.start(), m.end()))
                found.append((label, m.start(), m.end()))
        found.sort(key=lambda x: x[1])

        # Drop overlapping duplicates, then mask all occurrences in the context.
        clean, last_end = [], -1
        for label, s, e in found:
            if s >= last_end:
                clean.append((label, s, e))
                last_end = e
        spans = [(s, e, "*" * min(e - s, 8)) for _, s, e in clean]
        result.password_exposures = [
            asdict(Exposure(label, bisect.bisect_right(starts, s), self._context(content, spans, s, e)))
            for label, s, e in clean
        ]

        if username:
            u, p = content.find(username), content.find(password)
            if u != -1 and p != -1 and abs(u - p) < 500:
                result.credential_pair = {"distance_chars": abs(u - p),
                                          "line": bisect.bisect_right(starts, min(u, p))}


# ════════════════════════════════════════════════════════════════════════════
#  Reporting
# ════════════════════════════════════════════════════════════════════════════
class Reporter:
    def __init__(self, style: Style, width: int):
        self.s, self.w = style, width
        self.hr = ("─" if UNICODE else "-") * width

    def _banner(self, text: str, sub: str = ""):
        tl, tr, bl, br, h, v = ("╭", "╮", "╰", "╯", "─", "│") if UNICODE else ("+", "+", "+", "+", "-", "|")
        inner = self.w - 2
        print(self.s.cyan(tl + h * inner + tr))
        print(self.s.cyan(v) + self.s.bold(f" {text}".ljust(inner)) + self.s.cyan(v))
        if sub:
            print(self.s.cyan(v) + self.s.dim(f" {sub}".ljust(inner)) + self.s.cyan(v))
        print(self.s.cyan(bl + h * inner + br))

    def _section(self, title: str):
        print(f"\n{self.s.bold(title)}\n{self.s.dim(self.hr)}")

    def print_file(self, r: FileResult, show_info: bool = True):
        s = self.s
        print()
        self._banner(f"SECURITY ANALYSIS  ·  {r.path}",
                     f"{r.size:,} bytes  ·  {r.lines:,} lines  ·  {datetime.now():%Y-%m-%d %H:%M:%S}")
        if r.error:
            print(s.red(f"\n  Could not scan: {r.error}"))
            return

        if r.source_url or r.parsed:
            self._section("CAPTURE")
            if r.source_url:
                print(f"  Page     : {r.source_url}")
            if r.captured:
                print(f"  Captured : {r.captured}")
            if r.parsed:
                print("  Parsed   : " + "  ·  ".join(f"{k} {v}" for k, v in r.parsed.items()))

        counts = Counter(f.severity for f in r.findings)
        total_hits = sum(f.count for f in r.findings)
        top = max((Severity[f.severity] for f in r.findings), default=None)

        self._section("SUMMARY")
        scale = max(counts.values(), default=1)
        for sev in sorted(Severity, reverse=True):
            n = counts.get(sev.name, 0)
            bar_len = round(24 * n / scale) if n else 0
            bar = ("█" if UNICODE else "#") * bar_len
            print(f"  {s.badge(sev)} {n:>4}  {s(bar, SEV_COLOR[sev].split(';')[-1] if n else '90')}")
        print(f"\n  {len(r.findings)} unique finding(s), {total_hits} occurrence(s)")
        verdict = ("CLEAN – nothing sensitive detected" if top is None else f"Highest severity: {top.name}")
        print("  " + (s.green(verdict) if top is None else s(verdict, SEV_COLOR[top])))

        if r.findings:
            cats = Counter(f.category for f in r.findings)
            print("  " + s.dim("By category: " + ", ".join(f"{k} {v}" for k, v in cats.most_common())))

        # Detailed findings
        n = 0
        for f in r.findings:
            sev = Severity[f.severity]
            if sev == Severity.INFO and not show_info:
                continue
            n += 1
            lines = ", ".join(map(str, f.lines[:8])) + (" …" if len(f.lines) > 8 else "")
            print(f"\n {s.dim(f'{n:>3}.')} {s.badge(sev)} {s.bold(f.title)}  {s.dim('[' + f.category + ']')}")
            print(f"      {s.dim('where  ')} line {lines} (col {f.column})" + (f"  ×{f.count}" if f.count > 1 else ""))
            if f.locations:
                more = f" (+{len(f.locations) - 3} more)" if len(f.locations) > 3 else ""
                print(f"      {s.dim('source ')} {', '.join(f.locations[:3])}{more}")
            print(f"      {s.dim('match  ')} {s.cyan(f.match)}")
            if f.notes:
                print(f"      {s.dim('notes  ')} {f.notes}")
            print(f"      {s.dim('context')} …{f.context}…")
            if sev >= Severity.MEDIUM and f.remediation:
                print(f"      {s.dim('fix    ')} {f.remediation}")

        # Password test
        if r.password_exposures is not None:
            self._section("PASSWORD EXPOSURE TEST")
            if r.password_exposures:
                print(s.red(f"  ✗ Password FOUND – {len(r.password_exposures)} instance(s)" if UNICODE
                            else f"  [!] Password FOUND - {len(r.password_exposures)} instance(s)"))
                for e in r.password_exposures:
                    print(f"    · {s.bold(e['kind'])} at line {e['line']}\n      …{e['context']}…")
            else:
                print(s.green("  ✓ Password not found in any tested encoding" if UNICODE
                              else "  [OK] Password not found in any tested encoding"))
            if r.credential_pair:
                print(s.red(f"  ✗ Username and password appear within {r.credential_pair['distance_chars']} "
                            f"characters (line {r.credential_pair['line']}) – credential pair exposed"))

    def print_totals(self, results: list):
        s = self.s
        print()
        self._banner("OVERALL RESULT", f"{len(results)} file(s) scanned")
        sev = Counter()
        for r in results:
            for f in r.findings:
                sev[f.severity] += f.count
        for level in sorted(Severity, reverse=True):
            print(f"  {s.badge(level)} {sev.get(level.name, 0):>5}")
        print()


def build_summary(results: list) -> dict:
    by_sev, by_cat, by_rule = Counter(), Counter(), Counter()
    for r in results:
        for f in r.findings:
            by_sev[f.severity] += f.count
            by_cat[f.category] += f.count
            by_rule[f.rule_id] += f.count
    return {
        "files_scanned": len(results),
        "unique_findings": sum(len(r.findings) for r in results),
        "total_occurrences": sum(by_sev.values()),
        "by_severity": {s.name: by_sev.get(s.name, 0) for s in sorted(Severity, reverse=True)},
        "by_category": dict(by_cat.most_common()),
        "by_rule": dict(by_rule.most_common()),
    }


def write_json(path: str, results: list, args) -> None:
    doc = {
        "tool": "storage_analyzer", "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(),
        "options": {"min_severity": args.min_severity, "secrets_masked": not args.show_secrets,
                    "entropy_scan": args.entropy},
        "summary": build_summary(results),
        "files": [asdict(r) for r in results],
    }
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")


def write_markdown(path: str, results: list, args) -> None:
    sm = build_summary(results)
    out = [f"# Storage Security Report", "",
           f"_Generated {datetime.now():%Y-%m-%d %H:%M} · storage_analyzer v{__version__}"
           f"{'' if args.show_secrets else ' · secrets masked'}_", "",
           "## Summary", "", "| Severity | Occurrences |", "|---|---:|"]
    out += [f"| {k} | {v} |" for k, v in sm["by_severity"].items()]
    for r in results:
        out += ["", f"## `{r.path}`", "", f"{r.size:,} bytes · {r.lines:,} lines", ""]
        if r.source_url:
            out += [f"Page: `{r.source_url}`" + (f" · captured {r.captured}" if r.captured else ""), ""]
        if not r.findings:
            out.append("No sensitive data detected.")
        else:
            out += ["| # | Severity | Finding | Source | Lines | Match | Notes |", "|--:|---|---|---|---|---|---|"]
            for i, f in enumerate(r.findings, 1):
                lines = ", ".join(map(str, f.lines[:6])) + (" …" if len(f.lines) > 6 else "")
                src = "; ".join(f.locations[:3]).replace("|", "\\|")
                out.append(f"| {i} | {f.severity} | {f.title} | {src} | {lines} | `{f.match.replace('|', chr(92) + '|')}` | {f.notes} |")
        if r.password_exposures is not None:
            out += ["", "**Password test:** " + (f"FOUND ({len(r.password_exposures)})" if r.password_exposures else "not found")]
    Path(path).write_text("\n".join(out) + "\n", encoding="utf-8")


# ════════════════════════════════════════════════════════════════════════════
#  File discovery & CLI
# ════════════════════════════════════════════════════════════════════════════
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".mypy_cache"}


def iter_files(paths: list) -> Iterable[str]:
    for p in paths:
        if p == "-" or os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for name in sorted(files):
                    yield os.path.join(root, name)
        else:
            yield p   # let the reader report the error


def read_text(path: str, max_bytes: int) -> str:
    if path == "-":
        return sys.stdin.read()
    size = os.path.getsize(path)
    if size > max_bytes:
        raise ValueError(f"file is {size:,} bytes (limit {max_bytes:,}; raise with --max-size)")
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"\x00" in raw[:8192]:
        raise ValueError("looks like a binary file")
    return raw.decode("utf-8", errors="ignore")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="storage_analyzer",
        description="Scan text dumps for secrets, tokens and personal data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  storage_analyzer.py dump.txt
  storage_analyzer.py ./exports/ --min-severity medium
  storage_analyzer.py dump.txt --ask-password -u user@example.com
  storage_analyzer.py dump.txt -o report.md          (.json, .md supported)
  cat dump.txt | storage_analyzer.py - --fail-on high
""")
    p.add_argument("paths", nargs="+", metavar="PATH", help="file(s), directory(ies) or '-' for stdin")
    p.add_argument("-p", "--password", help="test password to look for (visible in shell history; prefer --ask-password)")
    p.add_argument("--ask-password", action="store_true", help="prompt for the test password without echoing it")
    p.add_argument("-u", "--username", help="username/email to check for proximity to the password")
    p.add_argument("-o", "--output", help="write report to this file (.json or .md)")
    p.add_argument("-m", "--min-severity", default="info", choices=[s.name.lower() for s in Severity],
                   help="hide findings below this level (default: info)")
    p.add_argument("--fail-on", choices=[s.name.lower() for s in Severity],
                   help="exit with status 2 if any finding is at or above this level")
    p.add_argument("--entropy", action="store_true", help="also flag high-entropy strings (noisier)")
    p.add_argument("--show-secrets", action="store_true", help="print full secret values (careful!)")
    p.add_argument("--hide-info", action="store_true", help="omit INFO findings from the terminal report")
    p.add_argument("--max-size", type=int, default=25 * 1024 * 1024, help="skip files larger than N bytes")
    p.add_argument("--no-parse", action="store_true",
                   help="treat input as plain text even if it is a storage_capture.js report")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--list-rules", action="store_true", help="print all detection rules and exit")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def list_rules(style: Style):
    print(style.bold(f"{len(RULES)} detection rules\n"))
    cat = None
    for r in sorted(RULES, key=lambda r: (r.category, -r.severity, r.title)):
        if r.category != cat:
            cat = r.category
            print(style.cyan(f"\n[{cat}]"))
        print(f"  {style.badge(r.severity)} {r.title}")


def main(argv=None) -> int:
    # "list-rules" has no positional path, so handle it before argparse complains.
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--list-rules" in argv:
        list_rules(Style(sys.stdout.isatty() and "--no-color" not in argv and "NO_COLOR" not in os.environ))
        return 0
    args = parse_args(argv)

    style = Style(sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ)
    width = max(72, min(110, shutil.get_terminal_size((100, 20)).columns))
    reporter = Reporter(style, width)

    password = args.password
    if args.ask_password:
        password = getpass.getpass("Test password: ")

    analyzer = StorageAnalyzer(min_severity=Severity.parse(args.min_severity),
                               show_secrets=args.show_secrets, entropy_scan=args.entropy,
                               parse_reports=not args.no_parse)

    results = []
    for path in iter_files(args.paths):
        try:
            content = read_text(path, args.max_size)
        except (OSError, ValueError) as exc:
            if path in args.paths:   # explicitly requested -> report as an error
                results.append(FileResult(path, 0, 0, error=str(exc)))
                reporter.print_file(results[-1])
            else:                    # found while walking a directory -> skip quietly
                print(style.dim(f"  skipped {path}: {exc}"), file=sys.stderr)
            continue
        res = analyzer.scan_text(content, "<stdin>" if path == "-" else path)
        if password:
            analyzer.check_password(content, res, password, args.username)
        results.append(res)
        reporter.print_file(res, show_info=not args.hide_info)

    if not results:
        print(style.red("No readable files to analyze."), file=sys.stderr)
        return 1
    if any(r.error for r in results):
        return 1
    if len(results) > 1:
        reporter.print_totals(results)

    if args.output:
        ext = Path(args.output).suffix.lower()
        (write_markdown if ext in (".md", ".markdown") else write_json)(args.output, results, args)
        print(f"{style.green('✓' if UNICODE else '[+]')} Report saved to {args.output}")

    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(Severity[f.severity] >= threshold for r in results for f in r.findings):
            return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
