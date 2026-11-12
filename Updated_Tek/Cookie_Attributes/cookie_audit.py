#!/usr/bin/env python3
"""
burp_cookie_audit.py — Audit Burp Suite proxy XML exports for insecure cookie attributes.

Usage:
    python burp_cookie_audit.py -f export.xml
    python burp_cookie_audit.py -f export.xml --verbose
    python burp_cookie_audit.py -f export.xml --json
"""

import argparse
import base64
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CookieFinding:
    host: str
    protocol: str
    cookie_name: str
    missing_attributes: tuple[str, ...]
    insecure_attributes: tuple[str, ...]


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def decode_burp_field(element) -> Optional[str]:
    """Decode a Burp XML field — may be raw text or base64."""
    if element is None:
        return None
    text = element.text or ""
    if element.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return None
    return text


def parse_response_headers(raw: str) -> dict[str, list[str]]:
    """Extract headers from a raw HTTP response string into a dict of lowercase name → [values]."""
    headers: dict[str, list[str]] = {}
    lines = raw.splitlines()
    for line in lines[1:]:          # skip status line
        if not line.strip():
            break                   # end of header section
        if ":" in line:
            name, _, value = line.partition(":")
            key = name.strip().lower()
            headers.setdefault(key, []).append(value.strip())
    return headers


def parse_set_cookie(header_value: str) -> dict:
    """Parse a single Set-Cookie header value into name and attribute dict."""
    parts = [p.strip() for p in header_value.split(";")]
    name, _, _ = parts[0].partition("=")
    attributes: dict[str, str | bool] = {}
    for part in parts[1:]:
        if "=" in part:
            k, _, v = part.partition("=")
            attributes[k.strip().lower()] = v.strip()
        else:
            attributes[part.strip().lower()] = True
    return {"name": name.strip(), "attributes": attributes}


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------

def check_cookie(cookie: dict, protocol: str) -> tuple[list[str], list[str]]:
    """
    Returns (missing_attrs, insecure_attrs) for a parsed cookie dict.

    Checks:
      - Secure flag present
      - HttpOnly flag present
      - SameSite attribute present
      - SameSite=None must be paired with Secure
      - Secure flag on a plain HTTP response (will be ignored by browser)
    """
    attrs = cookie["attributes"]
    missing: list[str] = []
    insecure: list[str] = []

    if "secure" not in attrs:
        missing.append("Secure")

    if "httponly" not in attrs:
        missing.append("HttpOnly")

    if "samesite" not in attrs:
        missing.append("SameSite")
    else:
        samesite_val = attrs["samesite"]
        if isinstance(samesite_val, str) and samesite_val.lower() == "none":
            if "secure" not in attrs:
                insecure.append("SameSite=None without Secure (cookie rejected by modern browsers)")

    if protocol.lower() == "http" and "secure" in attrs:
        insecure.append("Secure flag set on HTTP response (flag is ineffective; cookie is exposed)")

    return missing, insecure


# ---------------------------------------------------------------------------
# Core audit
# ---------------------------------------------------------------------------

def audit(filepath: str, verbose: bool = False) -> list[CookieFinding]:
    """Parse a Burp XML export and return deduplicated CookieFinding objects."""
    # Strip DOCTYPE declaration — ElementTree chokes on internal subsets
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            raw_xml = fh.read()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    # Remove DOCTYPE block so ET can parse without an external resolver.
    # Burp's internal subset contains its own > characters so a [^>]* regex
    # stops too early.  Scan manually for ]> instead.
    import re
    def _strip_doctype(s):
        start = s.find("<!DOCTYPE")
        if start == -1:
            return s
        bracket = s.find("[", start)
        gt      = s.find(">", start)
        if bracket != -1 and bracket < gt:
            end = s.find("]>", bracket)
            if end != -1:
                return s[:start] + s[end + 2:]
        if gt != -1:
            return s[:start] + s[gt + 1:]
        return s
    raw_xml = _strip_doctype(raw_xml)

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        print(f"[ERROR] XML parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    items = root.findall("item")
    if not items:
        print("[INFO] No <item> elements found — is this a Burp proxy XML export?")
        return []

    seen: set[CookieFinding] = set()
    total_responses = 0

    for item in items:
        host_el    = item.find("host")
        protocol_el = item.find("protocol")
        response_el = item.find("response")

        host     = (host_el.text or "unknown").strip() if host_el is not None else "unknown"
        protocol = (protocol_el.text or "https").strip().lower() if protocol_el is not None else "https"

        raw_response = decode_burp_field(response_el)
        if not raw_response:
            continue
        total_responses += 1

        headers = parse_response_headers(raw_response)
        set_cookie_values = headers.get("set-cookie", [])

        for sc in set_cookie_values:
            cookie = parse_set_cookie(sc)
            name = cookie["name"]
            if not name:
                continue

            missing, insecure = check_cookie(cookie, protocol)

            if verbose and not (missing or insecure):
                # Print clean cookies only in verbose mode; don't add to findings
                print(f"  [OK]  {host}  →  {name}")
                continue

            if missing or insecure:
                finding = CookieFinding(
                    host=host,
                    protocol=protocol.upper(),
                    cookie_name=name,
                    missing_attributes=tuple(sorted(missing)),
                    insecure_attributes=tuple(sorted(insecure)),
                )
                seen.add(finding)   # set deduplicates identical findings

    if verbose:
        print(f"\n[INFO] Scanned {total_responses} responses.\n")

    return sorted(seen, key=lambda f: (f.host, f.cookie_name))


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"


def print_text(findings: list[CookieFinding]) -> None:
    if not findings:
        print("\n[✓] No insecure cookie configurations found.\n")
        return

    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}  INSECURE COOKIE FINDINGS  —  {len(findings)} unique{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}\n")

    for f in findings:
        print(f"  {CYAN}Host   :{RESET}  {f.host}  ({f.protocol})")
        print(f"  {CYAN}Cookie :{RESET}  {f.cookie_name}")
        if f.missing_attributes:
            print(f"  {YELLOW}Missing:{RESET}  {', '.join(f.missing_attributes)}")
        if f.insecure_attributes:
            print(f"  {RED}Insecure:{RESET} {chr(10) + ' ' * 12}".join(f.insecure_attributes))
        print()

    print(f"{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}  Total unique findings: {len(findings)}{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}\n")


def print_json(findings: list[CookieFinding]) -> None:
    out = [
        {
            "host": f.host,
            "protocol": f.protocol,
            "cookie_name": f.cookie_name,
            "missing_attributes": list(f.missing_attributes),
            "insecure_attributes": list(f.insecure_attributes),
        }
        for f in findings
    ]
    print(json.dumps(out, indent=2))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="burp_cookie_audit",
        description="Audit Burp Suite proxy XML exports for insecure cookie attributes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Checks performed
────────────────
  Missing Secure flag
  Missing HttpOnly flag
  Missing SameSite attribute
  SameSite=None without Secure (rejected by modern browsers)
  Secure flag on HTTP response (flag is ineffective)

Deduplication
─────────────
  Findings are keyed on (host, cookie_name, missing_attrs, insecure_attrs).
  Identical issues seen across multiple requests are reported only once.

Examples
────────
  python burp_cookie_audit.py -f export.xml
  python burp_cookie_audit.py -f export.xml --verbose
  python burp_cookie_audit.py -f export.xml --json
""",
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        metavar="FILE",
        help="Path to Burp Suite proxy XML export",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Also print cookies that passed all checks",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON (useful for piping to other tools)",
    )

    args = parser.parse_args()
    findings = audit(args.file, verbose=args.verbose)

    if args.json:
        print_json(findings)
    else:
        print_text(findings)


if __name__ == "__main__":
    main()
