#!/usr/bin/env python3
"""
WSTG-CONF-12 — Content Security Policy (CSP) Scanner  (v2)
Path: utilities/CSP_Scanner.py

Reads a Burp Suite XML export and, for every HTML page in it:

  1. Collects ENFORCING policies from Content-Security-Policy headers and
     <meta http-equiv="Content-Security-Policy"> tags (both apply in a browser)
  2. Flags Report-Only (no enforcement) and absent CSP
  3. Analyses each policy *in context* (effective directive fallback, nonce /
     strict-dynamic mitigations, per-directive relevance)
  4. Tags endpoints as AUTH / INPUT
  5. Groups identical results so a policy shared by 200 pages is reported once

What changed vs v1 (noise reduction)
  DUPLICATES
    * Endpoints are grouped by identical policy + findings (one block, N endpoints)
    * Repeated captures of the same endpoint are merged; numeric/UUID path
      segments collapse to {id}; query strings are ignored
    * Per-response nonces / hashes are normalised so they don't split groups
    * Same finding on several directives is merged into one entry
  FALSE POSITIVES
    * Only HTML documents are evaluated (skips JS/CSS/images/JSON, redirects,
      204/304, downloads, HEAD/OPTIONS, items with no response, 4xx/5xx by default)
    * Report-Only is never analysed as if it were enforced
    * 'unsafe-inline' next to a nonce/hash and host/scheme sources next to
      'strict-dynamic' are treated as harmless legacy fallbacks
    * Directive-aware severity: unsafe-inline in style-src is LOW, data: in
      img-src / * in img-src are ignored, default-src only matters where it is
      the actual fallback
    * Multiple enforcing policies are intersected (a strict one covers a lax one)
    * Missing frame-ancestors is downgraded when X-Frame-Options exists and
      ignored for <meta> CSPs (cannot be set there)
    * Fixed: the <meta> regex truncated policies at the first quote; headers
      with several CSP lines/commas were truncated to the first one; AUTH/INPUT
      tagging matched substrings ("auth" matched "author")
  NEW (true positives)
    * Unknown / misspelled directives, static or reused nonces, short nonces,
      known script-host bypasses (JSONP / Angular / user-content hosts)

Usage:
  python3 utilities/CSP_Scanner.py \\
      --xml  inputs/XML/subfolder/export.xml \\
      --csp-strings inputs/Data/CSP_Strings.json \\
      -o outputs/test_output/test_findings.txt

Flags:
  -x / --xml            Burp XML export (required)
  -c / --csp-strings    CSP_Strings.json (built-in defaults used if missing)
  -o / --output         Output report (default: outputs/test_output/test_findings.txt)
  --auth-only           Only report endpoints tagged AUTH
  --input-only          Only report endpoints tagged INPUT
  -m / --min-severity   Hide findings below this level (default: low)
  --include-errors      Also evaluate 4xx/5xx HTML responses
  --max-endpoints N     Endpoints listed per group (default: 10)
  --show-all-endpoints  List every endpoint in every group
  --no-collapse-ids     Don't collapse numeric/UUID path segments
  --json FILE           Also write machine-readable JSON
"""

from __future__ import annotations

import argparse
import base64
import difflib
import json
import os
import re
import sys
import textwrap
import xml.etree.ElementTree as ET
import zlib
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urlparse

VERSION = "2.0"

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEV_NAMES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {n: i for i, n in enumerate(SEV_NAMES)}


def sev_rank(name: str) -> int:
    return SEV_RANK.get(str(name).upper(), 2)


def shift_down(rank: int, delta: int, floor: int = 0) -> int:
    """Lower a severity by `delta` levels. `floor` can never raise a severity."""
    return max(rank - delta, min(rank, floor))


# ---------------------------------------------------------------------------
# Built-in defaults (used for any key missing from CSP_Strings.json)
# ---------------------------------------------------------------------------

DEFAULT_STRINGS = {
    "high_risk_directives": [
        {"value": "'unsafe-inline'", "severity": "HIGH",
         "reasoning": "Allows inline <script>, inline event handlers and javascript: URLs, which "
                      "removes most of CSP's protection against reflected/stored XSS."},
        {"value": "'unsafe-eval'", "severity": "MEDIUM",
         "reasoning": "Allows eval(), new Function() and string timers, turning many DOM-based "
                      "injection primitives into code execution."},
        {"value": "'unsafe-hashes'", "severity": "MEDIUM",
         "reasoning": "Allows inline event-handler attributes whose hash is listed, weakening "
                      "the policy relative to nonces."},
        {"value": "data:", "severity": "HIGH",
         "reasoning": "data: URIs can carry attacker-controlled active content (e.g. "
                      "<script src=data:...>), bypassing source allow-lists."},
        {"value": "blob:", "severity": "MEDIUM",
         "reasoning": "blob: URLs can be created by any script that already runs, and may be used "
                      "to smuggle further code past the allow-list."},
        {"value": "filesystem:", "severity": "MEDIUM",
         "reasoning": "filesystem: URLs may host attacker-written content."},
    ],
    "wildcard_patterns": [
        {"value": "*", "severity": "HIGH",
         "reasoning": "A bare * allows loading from any origin, so the allow-list gives no protection."},
        {"value": "https:", "severity": "MEDIUM",
         "reasoning": "Scheme-only https: allows any HTTPS host, including attacker-controlled ones."},
        {"value": "http:", "severity": "HIGH",
         "reasoning": "Scheme-only http: allows any plaintext host (also enables MITM injection)."},
    ],
    "missing_directives": [
        {"directive": "default-src", "severity": "MEDIUM",
         "reasoning": "No default-src: every fetch directive that is not listed explicitly is unrestricted."},
        {"directive": "script-src", "severity": "HIGH",
         "reasoning": "No script-src (and no default-src fallback): script sources are unrestricted."},
        {"directive": "object-src", "severity": "HIGH",
         "reasoning": "No object-src (and no default-src fallback): <object>/<embed> content is "
                      "unrestricted. Recommended: object-src 'none'."},
        {"directive": "base-uri", "severity": "MEDIUM",
         "reasoning": "No base-uri: an injected <base> tag can redirect relative script URLs to an "
                      "attacker host. default-src does NOT cover this."},
        {"directive": "form-action", "severity": "MEDIUM",
         "reasoning": "No form-action: injected forms can post credentials to any origin. "
                      "default-src does NOT cover this."},
        {"directive": "frame-ancestors", "severity": "MEDIUM",
         "reasoning": "No frame-ancestors: the page can be framed by any site (clickjacking). "
                      "default-src does NOT cover this."},
    ],
    "nonce_and_hash_notes": [
        {"value": "nonce-", "severity": "INFO",
         "reasoning": "Nonce-based policy: verify the nonce is unpredictable and unique per response."},
        {"value": "sha256-", "severity": "INFO",
         "reasoning": "Hash-based policy: verify hashes cover only the intended static inline code."},
    ],
    "report_only_indicator": {
        "severity": "MEDIUM",
        "reasoning": "Content-Security-Policy-Report-Only only REPORTS violations; the browser "
                     "does not block anything, so the page has no CSP enforcement.",
    },
    "auth_path_keywords": [
        "login", "log-in", "signin", "sign-in", "logout", "register", "signup", "sign-up",
        "password", "forgot-password", "reset", "oauth", "sso", "auth", "authenticate",
        "account", "mfa", "2fa", "session", "token", "admin",
    ],
    "input_bearing_keywords": [
        "search", "query", "comment", "contact", "feedback", "profile", "upload", "edit",
        "post", "submit", "form", "message", "review", "checkout", "payment", "settings",
    ],
}

# ---------------------------------------------------------------------------
# CSP knowledge
# ---------------------------------------------------------------------------

KNOWN_DIRECTIVES = {
    "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src",
    "style-src-elem", "style-src-attr", "img-src", "font-src", "connect-src", "media-src",
    "object-src", "frame-src", "child-src", "worker-src", "manifest-src", "prefetch-src",
    "base-uri", "form-action", "frame-ancestors", "sandbox", "report-uri", "report-to",
    "plugin-types", "upgrade-insecure-requests", "block-all-mixed-content",
    "require-trusted-types-for", "trusted-types", "navigate-to", "referrer",
    "require-sri-for", "fenced-frame-src",
}
SCRIPT_DIRS = ("script-src", "script-src-elem", "script-src-attr")
STYLE_DIRS = ("style-src", "style-src-elem", "style-src-attr")
FETCH_DIRS_COVERED_BY_DEFAULT = {
    "script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem",
    "style-src-attr", "img-src", "font-src", "connect-src", "media-src", "object-src",
    "frame-src", "child-src", "worker-src", "manifest-src", "prefetch-src",
}
NEVER_COVERED_BY_DEFAULT = {"base-uri", "form-action", "frame-ancestors", "sandbox", "report-uri"}
META_UNSUPPORTED = {"frame-ancestors", "report-uri", "sandbox"}

# Hosts that commonly serve JSONP / Angular gadgets / user-controlled scripts.
BYPASS_HOSTS_EXACT = {
    "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "raw.githubusercontent.com", "accounts.google.com", "www.google.com", "www.googleapis.com",
}
BYPASS_PROVIDER_SUFFIXES = {
    "cloudfront.net", "amazonaws.com", "appspot.com", "herokuapp.com", "github.io",
    "firebaseapp.com", "azurewebsites.net", "blogspot.com", "googleapis.com",
}

_NONCE_RE = re.compile(r"'nonce-([^']+)'", re.I)
_HASH_RE = re.compile(r"'(sha(?:256|384|512))-[^']+'", re.I)

FINDING_TYPE_LABEL = {
    "CSP_ABSENT": "CSP Absent",
    "REPORT_ONLY": "Report-Only Mode (No Enforcement)",
    "HIGH_RISK_DIRECTIVE": "High-Risk Directive",
    "WILDCARD_SOURCE": "Wildcard Source",
    "MISSING_DIRECTIVE": "Missing Directive",
    "NONCE_HASH_NOTE": "Nonce/Hash Note",
    "UNKNOWN_DIRECTIVE": "Unknown / Misspelled Directive",
    "WEAK_NONCE": "Weak Nonce",
    "NONCE_REUSE": "Static / Reused Nonce",
    "BYPASSABLE_HOST": "Potential Script-Src Bypass Host",
}
ALWAYS_KEEP = {"WEAK_NONCE", "UNKNOWN_DIRECTIVE", "BYPASSABLE_HOST"}  # exempt from policy intersection


def bare(token: str) -> str:
    return token.strip().strip("'\"").lower()


# ---------------------------------------------------------------------------
# HTTP / Burp XML helpers
# ---------------------------------------------------------------------------

def decode_bytes(elem) -> bytes:
    """Raw bytes of a Burp element (handles base64='true')."""
    if elem is None or elem.text is None:
        return b""
    if elem.attrib.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(elem.text)
        except Exception:
            return b""
    return elem.text.encode("utf-8", errors="replace")


def split_http(raw: bytes) -> tuple:
    m = re.search(rb"\r?\n\r?\n", raw)
    if not m:
        return raw.decode("iso-8859-1", errors="replace"), b""
    return raw[:m.start()].decode("iso-8859-1", errors="replace"), raw[m.end():]


def parse_response_head(head: str) -> tuple:
    """-> (status_code | None, {lower-name: [values...]}) keeping ALL occurrences."""
    lines = head.replace("\r\n", "\n").split("\n")
    status = None
    m = re.match(r"HTTP/\S+\s+(\d{3})", lines[0].strip()) if lines else None
    if m:
        status = int(m.group(1))
    headers: dict = defaultdict(list)
    last = None
    for line in lines[1:]:
        if line[:1] in (" ", "\t") and last:          # obs-fold continuation
            headers[last][-1] += " " + line.strip()
        elif ":" in line:
            name, _, value = line.partition(":")
            last = name.strip().lower()
            headers[last].append(value.strip())
    return status, headers


def dechunk(body: bytes) -> bytes:
    out, i = bytearray(), 0
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            return bytes(out) if out else body
        try:
            size = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            return body if not out else bytes(out)
        if size == 0:
            return bytes(out)
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2


def decode_body(body: bytes, headers: dict, limit: int = 8 * 1024 * 1024) -> bytes:
    """De-chunk and gunzip/inflate so <meta> tags are visible."""
    if any("chunked" in v.lower() for v in headers.get("transfer-encoding", [])):
        body = dechunk(body)
    enc = (headers.get("content-encoding") or [""])[0].lower()
    try:
        if "gzip" in enc:
            return zlib.decompressobj(31).decompress(body, limit)
        if "deflate" in enc:
            try:
                return zlib.decompressobj(15).decompress(body, limit)
            except zlib.error:
                return zlib.decompressobj(-15).decompress(body, limit)
        if "br" in enc:
            try:
                import brotli  # type: ignore
                return brotli.decompress(body)
            except Exception:
                return b""
    except zlib.error:
        return b""
    return body


def is_html_document(headers: dict, body: bytes) -> bool:
    ctype = (headers.get("content-type") or [""])[0].lower()
    if ctype:
        return "text/html" in ctype or "application/xhtml+xml" in ctype
    sniff = body[:512].lstrip().lower()
    return sniff.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def body_text(body: bytes, headers: dict) -> str:
    ctype = (headers.get("content-type") or [""])[0]
    m = re.search(r"charset=([\w-]+)", ctype, re.I)
    try:
        return body.decode(m.group(1) if m else "utf-8", errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


class _MetaCSPParser(HTMLParser):
    """Proper HTML parsing: policies contain quotes, so regexes are unreliable."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.policies: list = []

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        if a.get("http-equiv", "").strip().lower() == "content-security-policy" and a.get("content", "").strip():
            self.policies.append(a["content"].strip())


def extract_meta_policies(html: str) -> list:
    parser = _MetaCSPParser()
    try:
        parser.feed(html[:400_000])
    except Exception:
        pass
    return parser.policies


# ---------------------------------------------------------------------------
# Path classification & normalisation
# ---------------------------------------------------------------------------

def _tokens(s: str) -> list:
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)          # camelCase -> words
    return [t for t in re.split(r"[^A-Za-z0-9]+", s.lower()) if t]


class PathClassifier:
    """Whole-token matching ('auth' no longer matches '/author')."""

    def __init__(self, auth_keywords: list, input_keywords: list):
        self.auth = [k for k in (_tokens(x) for x in auth_keywords) if k]
        self.inp = [k for k in (_tokens(x) for x in input_keywords) if k]

    @staticmethod
    def _hit(tokens: list, kws: list) -> bool:
        for kw in kws:
            n = len(kw)
            if "".join(kw) in tokens:                      # e.g. forgotpassword
                return True
            if any(tokens[i:i + n] == kw for i in range(len(tokens) - n + 1)):
                return True
        return False

    def tags(self, path: str, body: bytes) -> set:
        toks = _tokens(path)
        tags = set()
        if self._hit(toks, self.auth) or re.search(rb"<input[^>]+type\s*=\s*[\"']?password", body[:1_000_000], re.I):
            tags.add("AUTH")
        if self._hit(toks, self.inp):
            tags.add("INPUT")
        return tags


_ID_SEG = re.compile(
    r"^(?:\d+(?:\.\w{1,5})?|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}"
    r"|(?=.*\d)[A-Za-z0-9_-]{24,}={0,2})$", re.I)


def normalize_path(path: str, collapse: bool) -> str:
    path = path.split("?", 1)[0].split("#", 1)[0] or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    if not collapse:
        return path
    return "/".join("{id}" if _ID_SEG.match(s) else s for s in path.split("/"))


# ---------------------------------------------------------------------------
# CSP parsing & analysis
# ---------------------------------------------------------------------------

def parse_csp_directives(policy: str) -> dict:
    """{directive: [sources]} — first occurrence of a directive wins (per spec)."""
    directives: dict = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens and tokens[0].lower() not in directives:
            directives[tokens[0].lower()] = tokens[1:]
    return directives


def split_header_policies(values: list) -> list:
    """Several header lines and/or comma-joined policies -> list of policy strings."""
    out = []
    for v in values:
        out.extend(p.strip() for p in v.split(",") if p.strip())
    return out


def normalise_for_display(raw: str) -> str:
    raw = _NONCE_RE.sub("'nonce-<…>'", raw)
    return _HASH_RE.sub(lambda m: f"'{m.group(1).lower()}-<…>'", raw)


def policy_signature(directives: dict) -> str:
    parts = []
    for d in sorted(directives):
        srcs = []
        for s in directives[d]:
            s = _NONCE_RE.sub("'nonce-<>'", s)
            s = _HASH_RE.sub(lambda m: f"'{m.group(1).lower()}-<>'", s)
            srcs.append(s.lower())
        parts.append(d + " " + " ".join(sorted(srcs)))
    return "; ".join(parts)


def extract_nonces(directives: dict) -> list:
    return [m.group(1) for srcs in directives.values() for s in srcs for m in [_NONCE_RE.fullmatch(s)] if m]


def _value_kind(val: str, wildcard: bool) -> str:
    if val == "unsafe-inline":
        return "inline"
    if val in ("unsafe-eval", "wasm-unsafe-eval"):
        return "eval"
    if val == "unsafe-hashes":
        return "hashes"
    return "wildcard" if wildcard else "scheme"


def _token_matches(val: str, token: str, kind: str) -> bool:
    b = bare(token)
    if kind in ("inline", "eval", "hashes") or val.endswith(":") or val == "*":
        return b == val
    return val in b                                          # host-like entries


def _relevance(kind: str, d: str, directives: dict):
    """(severity_delta, floor, note) or None when the token is harmless in `d`."""
    script_explicit = any(x in directives for x in SCRIPT_DIRS)
    if d in SCRIPT_DIRS:
        return 0, 0, ""
    if d == "default-src":
        if not script_explicit:
            return 0, 0, "default-src is the effective script policy (no script-src present)"
        if kind in ("eval", "hashes"):
            return None
        return 1, 1, "script-src is explicit, so default-src only governs non-script fetches"
    if kind in ("eval", "hashes"):
        return None
    if kind == "inline":
        return (2, 1, "applies to styles only (style-src), not script execution") if d in STYLE_DIRS else None
    if d in ("object-src", "base-uri", "frame-ancestors"):
        return 0, 0, ""
    if d in ("frame-src", "child-src", "worker-src", "form-action", "connect-src", "manifest-src"):
        return 1, 1, ""
    if kind == "wildcard" and d in STYLE_DIRS:
        return 2, 1, "applies to styles only"
    return None                                              # img/font/media etc.: not worth reporting


def _host_of(token: str) -> str:
    return re.sub(r"^[a-z-]+://", "", bare(token)).split("/")[0].split(":")[0]


def _is_bypass_host(token: str) -> bool:
    h = _host_of(token)
    if not h or h.startswith(("'", "nonce", "sha")) or h.endswith(":"):
        return False
    if h in BYPASS_HOSTS_EXACT:
        return True
    if h.startswith("*."):
        sfx = h[2:]
        return sfx in BYPASS_PROVIDER_SUFFIXES or any(x == sfx or x.endswith("." + sfx) for x in BYPASS_HOSTS_EXACT)
    return False


def analyse_policy(directives: dict, cfg: dict, source: str = "header", has_xfo: bool = False) -> list:
    """Context-aware analysis of ONE policy -> list of finding dicts."""
    out: list = []

    def add(rank, ftype, directive, matched, reasoning, note=""):
        out.append({"severity": SEV_NAMES[rank], "finding_type": ftype, "directive": directive,
                    "matched_value": matched, "reasoning": reasoning, "note": note})

    script_names = [d for d in SCRIPT_DIRS if d in directives] or (["default-src"] if "default-src" in directives else [])
    script_modern = any(
        bare(s).startswith("nonce-") or re.match(r"sha(256|384|512)-", bare(s))
        for d in script_names for s in directives[d])

    # 1 + 2. High-risk values and wildcards, judged per directive -------------
    for group, wildcard in (("high_risk_directives", False), ("wildcard_patterns", True)):
        ftype = "WILDCARD_SOURCE" if wildcard else "HIGH_RISK_DIRECTIVE"
        for entry in cfg[group]:
            val = bare(entry["value"])
            kind = _value_kind(val, wildcard)
            base = sev_rank(entry["severity"])
            for d, sources in directives.items():
                if not any(_token_matches(val, s, kind) for s in sources):
                    continue
                rel = _relevance(kind, d, directives)
                if rel is None:
                    continue
                delta, floor, note = rel
                rank = shift_down(base, delta, floor)
                if delta == 0 and d in (*SCRIPT_DIRS, "default-src"):
                    srcs = [bare(s) for s in sources]
                    modern = any(s.startswith("nonce-") or re.match(r"sha(256|384|512)-", s) for s in srcs)
                    if kind == "inline" and modern:
                        rank, note = 0, "ignored by CSP2+ browsers because a nonce/hash is present (legacy fallback only)"
                    elif kind in ("scheme", "wildcard") and modern and "strict-dynamic" in srcs:
                        rank, note = 0, "ignored by CSP3 browsers under 'strict-dynamic' (legacy fallback only)"
                add(rank, ftype, d, entry["value"], entry.get("reasoning", ""), note)

    # 3. Known script-host bypasses ------------------------------------------
    for d in script_names:
        srcs = [bare(s) for s in directives[d]]
        if "strict-dynamic" in srcs and script_modern:
            continue
        for s in directives[d]:
            if _is_bypass_host(s):
                add(2, "BYPASSABLE_HOST", d, s,
                    "This host serves JSONP endpoints, Angular/legacy libraries or user-controlled "
                    "files that can be abused to execute script despite the allow-list. Prefer "
                    "nonces + 'strict-dynamic' instead of host allow-lists.",
                    "heuristic — confirm a usable gadget exists")

    # 4. Missing directives -----------------------------------------------------
    explicit_core = "script-src" in directives and "object-src" in directives
    for entry in cfg["missing_directives"]:
        d = entry["directive"].lower()
        if d in directives:
            continue
        if d in FETCH_DIRS_COVERED_BY_DEFAULT and "default-src" in directives:
            continue                                         # fallback covers it
        rank, note = sev_rank(entry["severity"]), ""
        if d in META_UNSUPPORTED and source == "meta":
            continue                                         # cannot be set via <meta>
        if d == "frame-ancestors" and has_xfo:
            rank, note = 0, "X-Frame-Options header present (legacy clickjacking protection)"
        elif d == "base-uri" and not (script_modern or any("strict-dynamic" in map(bare, directives[x]) for x in script_names)):
            rank, note = shift_down(rank, 1, 1), "no nonce/strict-dynamic in use, so impact is lower"
        elif d == "default-src" and explicit_core:
            rank, note = shift_down(rank, 1, 1), "script-src and object-src are set explicitly"
        add(rank, "MISSING_DIRECTIVE", d, "(absent)", entry["reasoning"], note)

    # 5. Misspelled / unknown directives -------------------------------------
    for d in directives:
        if d not in KNOWN_DIRECTIVES:
            hint = difflib.get_close_matches(d, KNOWN_DIRECTIVES, n=1, cutoff=0.75)
            add(1, "UNKNOWN_DIRECTIVE", d, "(unrecognised)",
                "Browsers silently ignore unknown directives, so whatever this was meant to "
                "restrict stays unrestricted.", f"did you mean '{hint[0]}'?" if hint else "")

    # 6. Nonce quality + informational notes -----------------------------------
    for n in extract_nonces(directives):
        if len(n) < 16:
            add(2, "WEAK_NONCE", next(d for d, s in directives.items() if f"'nonce-{n}'" in s),
                "(nonce < 16 chars)", "Nonces should carry at least 128 bits of entropy "
                "(≈22 base64 characters); short nonces can be guessed.")
    for entry in cfg["nonce_and_hash_notes"]:
        val = bare(entry["value"])
        hits = [d for d, srcs in directives.items() if any(val in bare(s) for s in srcs)]
        for d in hits[:1]:
            add(sev_rank(entry["severity"]), "NONCE_HASH_NOTE", d, entry["value"], entry["reasoning"])

    return out


def combine_policies(per_policy: list) -> list:
    """Several enforcing policies apply as an INTERSECTION: a weakness only exists
    if every policy allows it."""
    if len(per_policy) <= 1:
        return per_policy[0] if per_policy else []
    key = lambda f: (f["finding_type"], f["directive"], f["matched_value"])  # noqa: E731
    common = set.intersection(*({key(f) for f in fl} for fl in per_policy))
    out, seen = [], set()
    for fl in per_policy:
        for f in fl:
            if (key(f) in common or f["finding_type"] in ALWAYS_KEEP) and key(f) not in seen:
                seen.add(key(f))
                out.append(f)
    return out


def merge_findings(findings: list) -> list:
    """Same issue on several directives -> one entry listing them."""
    merged: "OrderedDict[tuple, dict]" = OrderedDict()
    for f in findings:
        k = (f["finding_type"], f["matched_value"], f["severity"], f["reasoning"], f.get("note", ""))
        if k in merged:
            ds = merged[k]["directive"].split(", ")
            if f["directive"] not in ds:
                merged[k]["directive"] = ", ".join(ds + [f["directive"]])
        else:
            merged[k] = dict(f)
    return sorted(merged.values(), key=lambda x: (-sev_rank(x["severity"]), x["finding_type"], x["directive"]))


# ---------------------------------------------------------------------------
# Per-item processing
# ---------------------------------------------------------------------------

def _text(item, tag: str) -> str:
    e = item.find(f"./{tag}")
    return e.text.strip() if e is not None and e.text else ""


def evaluate_item(index: int, item, cfg: dict, classifier: PathClassifier, opts) -> tuple:
    """-> (record | None, skip_reason | None)"""
    raw = decode_bytes(item.find("./response"))
    if not raw.strip():
        return None, "no response"

    request = decode_bytes(item.find("./request")).decode("iso-8859-1", errors="replace")
    first = request.split("\n", 1)[0].strip().split(" ")
    method = (_text(item, "method") or (first[0] if first and first[0] else "UNKNOWN")).upper()
    req_path = first[1] if len(first) >= 2 else "/"

    url = _text(item, "url")
    if not url:
        url = f"{_text(item, 'protocol') or 'https'}://{_text(item, 'host') or 'unknown'}{req_path}"
    parsed = urlparse(url)
    host, path = parsed.netloc.lower(), parsed.path or "/"

    head, body = split_http(raw)
    status, headers = parse_response_head(head)
    if status is None and _text(item, "status").isdigit():
        status = int(_text(item, "status"))

    if method in ("HEAD", "OPTIONS"):
        return None, "HEAD/OPTIONS"
    if status is not None:
        if 300 <= status < 400:
            return None, "redirect (3xx)"
        if status in (204, 205) or status < 200:
            return None, "no content"
        if status >= 400 and not opts.include_errors:
            return None, "error response (4xx/5xx)"
    if any("attachment" in v.lower() for v in headers.get("content-disposition", [])):
        return None, "download"

    body = decode_body(body, headers)
    if not is_html_document(headers, body):
        return None, "non-HTML content"

    # ---- collect policies ---------------------------------------------------
    header_policies = split_header_policies(headers.get("content-security-policy", []))
    ro_policies = split_header_policies(headers.get("content-security-policy-report-only", []))
    meta_policies = extract_meta_policies(body_text(body, headers)) if body else []
    enforcing = [("header", p) for p in header_policies] + [("meta", p) for p in meta_policies]
    has_xfo = bool(headers.get("x-frame-options"))

    tags = classifier.tags(path, body)
    findings: list = []
    parsed_policies = [(src, raw_p, parse_csp_directives(raw_p)) for src, raw_p in enforcing]

    ro_entry = cfg["report_only_indicator"]
    if enforcing:
        per_policy = [analyse_policy(d, cfg, src, has_xfo) for src, _, d in parsed_policies if d]
        findings = combine_policies(per_policy)
        if ro_policies:                                      # report-only next to enforcing = testing a stricter policy
            findings.append({"severity": "INFO", "finding_type": "REPORT_ONLY",
                             "directive": "Content-Security-Policy-Report-Only",
                             "matched_value": "(also present)",
                             "reasoning": "A Report-Only policy is deployed alongside the enforcing one "
                                          "(usually a stricter policy under test). No action needed.",
                             "note": ""})
    elif ro_policies:
        findings.append({"severity": ro_entry.get("severity", "MEDIUM"), "finding_type": "REPORT_ONLY",
                         "directive": "Content-Security-Policy-Report-Only",
                         "matched_value": "(no enforcing CSP)", "reasoning": ro_entry.get("reasoning", ""),
                         "note": "policy is not analysed because it is not enforced"})
    else:
        sev = "HIGH" if tags else "MEDIUM"
        findings.append({"severity": sev, "finding_type": "CSP_ABSENT", "directive": "Content-Security-Policy",
                         "matched_value": "(header and meta tag both absent)",
                         "reasoning": "No Content-Security-Policy header or <meta> tag was found on this HTML "
                                      "page. Without a CSP the browser applies no restriction on script "
                                      "sources, so any XSS is fully exploitable.",
                         "note": "AUTH/INPUT endpoint" if tags else ""})

    if enforcing:
        source = "header" if header_policies and not meta_policies else ("meta" if meta_policies and not header_policies else "header+meta")
    else:
        source = "report-only" if ro_policies else "absent"

    sig_policies = tuple(sorted(policy_signature(d) for _, _, d in parsed_policies))
    return {
        "index": index, "method": method, "url": url, "host": host, "path": path,
        "status": status, "tags": tags, "source": source,
        "policies": [normalise_for_display(r) for _, r, _ in parsed_policies] or [normalise_for_display(p) for p in ro_policies],
        "sig_policies": sig_policies,
        "nonces": [n for _, _, d in parsed_policies for n in extract_nonces(d)],
        "findings": findings,
    }, None


# ---------------------------------------------------------------------------
# Cross-item analysis, filtering, grouping
# ---------------------------------------------------------------------------

def add_nonce_reuse(records: list) -> None:
    """A nonce must be fresh per response; the same value on several responses defeats CSP."""
    where: dict = defaultdict(list)
    for r in records:
        for n in set(r["nonces"]):
            where[n].append(r)
    for n, rs in where.items():
        if len(rs) < 2:
            continue
        distinct_pages = {(r["host"], r["path"]) for r in rs}
        sev = "HIGH" if len(distinct_pages) > 1 else "MEDIUM"
        for r in rs:
            r["findings"].append({
                "severity": sev, "finding_type": "NONCE_REUSE", "directive": "script-src",
                "matched_value": "(same nonce seen in multiple responses)",
                "reasoning": "The identical nonce value was served in more than one response"
                             + (" for different pages" if len(distinct_pages) > 1 else "")
                             + ". An attacker who has seen it can inject <script nonce=…> and bypass CSP. "
                               "Nonces must be random per response (check for page caching too).",
                "note": "" if len(distinct_pages) > 1 else "same URL only — could also be a duplicated capture"})


def build_groups(records: list, collapse_ids: bool) -> list:
    """Merge repeated endpoints, then group by identical policy + findings."""
    # a) merge repeated captures of the same endpoint with identical results
    endpoints: "OrderedDict[tuple, dict]" = OrderedDict()
    for r in records:
        fkey = tuple(sorted((f["severity"], f["finding_type"], f["directive"], f["matched_value"]) for f in r["findings"]))
        k = (r["method"], r["host"], normalize_path(r["path"], collapse_ids), r["sig_policies"], fkey)
        if k in endpoints:
            endpoints[k]["hits"] += 1
            endpoints[k]["tags"] |= r["tags"]
            continue
        endpoints[k] = {**r, "norm_path": normalize_path(r["path"], collapse_ids), "hits": 1,
                        "gkey": (r["source"], r["sig_policies"], fkey)}

    # b) group endpoints that share the same policy and findings
    groups: "OrderedDict[tuple, dict]" = OrderedDict()
    for e in endpoints.values():
        g = groups.setdefault(e["gkey"], {"findings": merge_findings(e["findings"]), "source": e["source"],
                                          "policies": e["policies"], "endpoints": []})
        g["endpoints"].append(e)
    out = list(groups.values())
    for g in out:
        g["top"] = max((sev_rank(f["severity"]) for f in g["findings"]), default=0)
        g["hosts"] = sorted({e["host"] for e in g["endpoints"]})
    out.sort(key=lambda g: (-g["top"], -len(g["endpoints"])))
    return out


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

SEVERITY_BADGE = {n: f"[{n}]".ljust(10) for n in SEV_NAMES}
SOURCE_LABEL = {
    "header": "Response Header (Enforcing)",
    "meta": "<meta> Tag",
    "header+meta": "Response Header + <meta> Tag (both enforced)",
    "report-only": "Response Header (Report-Only — NOT enforced)",
    "absent": "ABSENT",
}
W = 76


def _wrap(prefix: str, text: str, indent: str) -> list:
    return textwrap.wrap(text, width=W, initial_indent=prefix, subsequent_indent=indent) or [prefix.rstrip()]


def write_report(output_path: str, groups: list, stats: dict, meta: dict, opts) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    L: list = []
    L += ["=" * W, f"WSTG-CONF-12 — Content Security Policy (CSP) Scanner  v{VERSION}",
          "WSTG-CONF-12 | Test for Content Security Policy", "=" * W,
          f"Generated   : {meta['generated']}",
          f"XML File    : {meta['xml']}",
          f"CSP Strings : {meta['csp_strings_path']}",
          f"Min severity: {opts.min_severity.upper()}  (lower-severity findings hidden)", ""]

    n_endpoints = sum(len(g["endpoints"]) for g in groups)
    L += ["SCOPE",
          f"  Items in export                : {stats['items']}",
          f"  HTML pages evaluated           : {stats['evaluated']}  → {stats['unique_endpoints']} unique endpoints",
          f"  Skipped (not a browsable page) : {sum(stats['skipped'].values())}"]
    for reason, n in stats["skipped"].most_common():
        L.append(f"      {reason:<28} {n}")
    L += ["", "RESULT",
          f"  Endpoints with a clean policy  : {stats['clean_endpoints']}",
          f"  Endpoints with findings        : {n_endpoints}   (AUTH {sum('AUTH' in e['tags'] for g in groups for e in g['endpoints'])}, "
          f"INPUT {sum('INPUT' in e['tags'] for g in groups for e in g['endpoints'])})",
          f"  Distinct policy/finding groups : {len(groups)}   ← each is reported once below", ""]
    L.append("  Worst severity per endpoint    :")
    by_ep = Counter(SEV_NAMES[g["top"]] for g in groups for _ in g["endpoints"])
    for s in reversed(SEV_NAMES):
        if by_ep[s]:
            L.append(f"      {s:<10} {by_ep[s]:>5} endpoint(s)")
    L += ["", "=" * W, ""]

    if not groups:
        L.append("No CSP issues found at or above the minimum severity on the evaluated pages.")
    for gi, g in enumerate(groups, 1):
        eps = g["endpoints"]
        tag_c = Counter(t for e in eps for t in e["tags"])
        tag_s = (" — " + ", ".join(f"{t} {c}" for t, c in sorted(tag_c.items()))) if tag_c else ""
        L += ["-" * W,
              f"[G{gi}] {SEV_NAMES[g['top']]}  ·  {len(eps)} endpoint(s) on {len(g['hosts'])} host(s){tag_s}",
              "-" * W,
              f"  CSP Source : {SOURCE_LABEL.get(g['source'], g['source'])}"]
        if g["policies"]:
            for i, p in enumerate(g["policies"], 1):
                L += _wrap("  CSP Value  : " if i == 1 else f"  CSP Value {i}: ", p, " " * 15)
            L.append("               (per-response nonces/hashes shown as <…>)")
        if len(g["hosts"]) <= 6:
            L.append(f"  Hosts      : {', '.join(g['hosts'])}")
        L += ["", f"  Findings ({len(g['findings'])}):"]
        for f in g["findings"]:
            ftype = FINDING_TYPE_LABEL.get(f["finding_type"], f["finding_type"])
            L.append(f"    {SEVERITY_BADGE[f['severity']]} {ftype}")
            if f["directive"] and f["matched_value"]:
                L.append(f"        Directive : {f['directive']}")
                L.append(f"        Match     : {f['matched_value']}")
            if f.get("note"):
                L += _wrap("        Note      : ", f["note"], " " * 20)
            if f["reasoning"]:
                L += _wrap("        Reasoning : ", f["reasoning"], " " * 20)
            L.append("")
        limit = None if opts.show_all_endpoints else opts.max_endpoints
        shown = eps if limit is None else eps[:limit]
        L.append(f"  Endpoints ({len(shown)} of {len(eps)} shown):")
        for e in shown:
            t = f"  [{'|'.join(sorted(e['tags']))}]" if e["tags"] else ""
            hits = f"  ×{e['hits']}" if e["hits"] > 1 else ""
            L.append(f"    {e['method']:<6} {e['host']}{e['norm_path']}  ({e['status'] or 'n/a'}){t}{hits}")
        if limit is not None and len(eps) > limit:
            L.append(f"    … +{len(eps) - limit} more (use --show-all-endpoints or --json for the full list)")
        L.append("")

    if groups:
        L += ["", "=" * W, "REMEDIATION GUIDANCE", "=" * W, "",
              "Minimal recommended CSP for a standard web application:", "",
              "  Content-Security-Policy:",
              "    default-src 'self';",
              "    script-src 'nonce-{RANDOM}' 'strict-dynamic';",
              "    object-src 'none';",
              "    base-uri 'none';",
              "    form-action 'self';",
              "    frame-ancestors 'none';",
              "    upgrade-insecure-requests;", "",
              "  - Generate a fresh, unguessable nonce (≥128 bits) for EVERY response.",
              "  - Prefer nonces + 'strict-dynamic' over host allow-lists; hashes for static inline code.",
              "  - Roll out with Report-Only first, then switch to enforcing.", "",
              "References:",
              "  https://content-security-policy.com/",
              "  https://csp-evaluator.withgoogle.com/",
              "  https://owasp.org/www-project-secure-headers/", ""]
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))


def write_json(path: str, groups: list, stats: dict, meta: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    doc = {
        "tool": "CSP_Scanner", "version": VERSION, **meta,
        "stats": {**stats, "skipped": dict(stats["skipped"])},
        "groups": [{
            "id": f"G{i}", "top_severity": SEV_NAMES[g["top"]], "source": g["source"], "policies": g["policies"],
            "findings": g["findings"],
            "endpoints": [{k: (sorted(v) if isinstance(v, set) else v) for k, v in
                           {"method": e["method"], "host": e["host"], "path": e["norm_path"], "url": e["url"],
                            "status": e["status"], "tags": e["tags"], "hits": e["hits"]}.items()}
                          for e in g["endpoints"]],
        } for i, g in enumerate(groups, 1)],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="CONF-12: Scan a Burp XML export for CSP presence and policy weaknesses",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-x", "--xml", required=True, help="Burp Suite XML export file")
    p.add_argument("-c", "--csp-strings", default="inputs/Data/CSP_Strings.json",
                   help="CSP strings JSON (built-in defaults fill any missing key)")
    p.add_argument("-o", "--output", default="outputs/test_output/test_findings.txt", help="Output report")
    p.add_argument("--auth-only", action="store_true", help="Only report AUTH endpoints")
    p.add_argument("--input-only", action="store_true", help="Only report INPUT-bearing endpoints")
    p.add_argument("-m", "--min-severity", default="low", choices=[s.lower() for s in SEV_NAMES],
                   help="Hide findings below this severity (default: low)")
    p.add_argument("--include-errors", action="store_true", help="Also evaluate 4xx/5xx HTML responses")
    p.add_argument("--max-endpoints", type=int, default=10, help="Endpoints listed per group (default 10)")
    p.add_argument("--show-all-endpoints", action="store_true", help="List every endpoint in every group")
    p.add_argument("--no-collapse-ids", action="store_true", help="Do not collapse numeric/UUID path segments")
    p.add_argument("--json", metavar="FILE", help="Also write JSON results")
    return p.parse_args()


def load_strings(path: str) -> tuple:
    cfg = json.loads(json.dumps(DEFAULT_STRINGS))
    label = "built-in defaults"
    try:
        with open(path, encoding="utf-8") as fh:
            user = json.load(fh)
        cfg.update({k: v for k, v in user.items() if v})
        label = path
    except FileNotFoundError:
        print(f"[!] CSP strings file not found: {path} — using built-in defaults")
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in {path}: {e}")
        sys.exit(1)
    for key in ("high_risk_directives", "wildcard_patterns", "missing_directives", "nonce_and_hash_notes"):
        for entry in cfg[key]:
            entry["severity"] = str(entry.get("severity", "MEDIUM")).upper()
            entry.setdefault("reasoning", "")
    cfg["report_only_indicator"]["severity"] = str(cfg["report_only_indicator"].get("severity", "MEDIUM")).upper()
    return cfg, label


def main():
    opts = parse_args()
    print("=" * 60)
    print(f"CONF-12 — CSP Scanner v{VERSION}")
    print("=" * 60)

    cfg, cfg_label = load_strings(opts.csp_strings)
    classifier = PathClassifier(cfg["auth_path_keywords"], cfg["input_bearing_keywords"])
    print(f"[*] CSP strings: {cfg_label}")

    try:
        items = ET.parse(opts.xml).getroot().findall(".//item")
    except FileNotFoundError:
        print(f"[!] XML not found: {opts.xml}")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}")
        sys.exit(1)
    if not items:
        print("[!] No <item> elements found in XML.")
        sys.exit(1)
    xml_name = os.path.basename(opts.xml)
    print(f"[*] XML: {xml_name} — {len(items)} items")

    skipped: Counter = Counter()
    records: list = []
    for i, item in enumerate(items, 1):
        rec, why = evaluate_item(i, item, cfg, classifier, opts)
        if rec is None:
            skipped[why] += 1
        else:
            records.append(rec)

    add_nonce_reuse(records)
    min_rank = sev_rank(opts.min_severity)
    unique_eps = {(r["method"], r["host"], normalize_path(r["path"], not opts.no_collapse_ids)) for r in records}

    flagged = []
    for r in records:
        r["findings"] = [f for f in r["findings"] if sev_rank(f["severity"]) >= min_rank]
        if not r["findings"]:
            continue
        if opts.auth_only and "AUTH" not in r["tags"]:
            continue
        if opts.input_only and "INPUT" not in r["tags"]:
            continue
        flagged.append(r)

    groups = build_groups(flagged, not opts.no_collapse_ids)
    flagged_eps = sum(len(g["endpoints"]) for g in groups)
    stats = {"items": len(items), "evaluated": len(records), "unique_endpoints": len(unique_eps),
             "skipped": skipped, "clean_endpoints": max(0, len(unique_eps) - flagged_eps),
             "groups": len(groups), "flagged_endpoints": flagged_eps}
    meta = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "xml": xml_name, "csp_strings_path": cfg_label}

    write_report(opts.output, groups, stats, meta, opts)
    if opts.json:
        write_json(opts.json, groups, stats, meta)

    print(f"[*] Evaluated {len(records)} HTML responses ({len(unique_eps)} unique endpoints); "
          f"skipped {sum(skipped.values())} non-page items")
    print(f"[*] {flagged_eps} endpoints with findings → {len(groups)} distinct group(s)")
    for g in groups[:8]:
        print(f"    {SEV_NAMES[g['top']]:<8} {len(g['endpoints']):>4} endpoint(s)  "
              f"{', '.join(FINDING_TYPE_LABEL.get(f['finding_type'], f['finding_type']) for f in g['findings'][:2])}")
    print(f"\n[+] Report written → {opts.output}" + (f"\n[+] JSON written   → {opts.json}" if opts.json else ""))
    if not (opts.auth_only or opts.input_only):
        print("\n  Tip: rerun with --auth-only or --input-only to focus on sensitive endpoints.")


if __name__ == "__main__":
    main()
