#!/usr/bin/env python3
"""
cors_tester.py — Run CORS misconfiguration probes using cookies extracted
from the browser via extract_storage.js.

Usage:
    python cors_tester.py --url https://example.com/api/ --storage browser_storage.json
    python cors_tester.py --url https://example.com/api/ --storage browser_storage.json --format color
    python cors_tester.py --url https://example.com/api/ --storage browser_storage.json --format table
    python cors_tester.py --url https://example.com/api/ --storage browser_storage.json --format json
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
RESET     = "\033[0m"
BOLD      = "\033[1m"
RED       = "\033[91m"
GREEN     = "\033[92m"
YELLOW    = "\033[93m"
CYAN      = "\033[96m"
GREY      = "\033[90m"
WHITE     = "\033[97m"
BG_RED    = "\033[41m"
BG_YELLOW = "\033[43m"
BG_GREEN  = "\033[42m"
BG_CYAN   = "\033[46m"

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   YELLOW,
    "INFO":     CYAN,
    "PASS":     GREEN,
}
SEV_BADGE = {
    "CRITICAL": f"{BG_RED}{BOLD} CRITICAL {RESET}",
    "HIGH":     f"{BG_YELLOW}{BOLD}   HIGH   {RESET}",
    "MEDIUM":   f"{BG_YELLOW}{BOLD}  MEDIUM  {RESET}",
    "INFO":     f"{BG_CYAN}{BOLD}   INFO   {RESET}",
    "PASS":     f"{BG_GREEN}{BOLD}   PASS   {RESET}",
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TestCase:
    name:        str
    description: str
    origin:      str
    category:    str


@dataclass
class TestResult:
    test:        TestCase
    command:     list[str]
    acao:        Optional[str]
    acac:        Optional[str]
    status_code: Optional[str]
    outcome:     str
    severity:    str          # CRITICAL | HIGH | MEDIUM | INFO | PASS


# ---------------------------------------------------------------------------
# Test suite builder
# ---------------------------------------------------------------------------

def build_test_cases(url: str) -> list[TestCase]:
    parsed   = urlparse(url)
    hostname = parsed.hostname or parsed.netloc   # example.com (no port)
    scheme   = parsed.scheme or "https"

    return [
        # ── Validation bypass ────────────────────────────────────────────
        TestCase(
            name="Prefix bypass",
            description=f"Does server do startsWith('{hostname}')?",
            origin=f"{scheme}://{hostname}.evil.com",
            category="Validation Bypass",
        ),
        TestCase(
            name="Suffix bypass",
            description=f"Does server do endsWith('{hostname}')?",
            origin=f"{scheme}://evil{hostname}",
            category="Validation Bypass",
        ),
        TestCase(
            name="Subdomain wildcard",
            description="Does any subdomain of the target get trusted?",
            origin=f"{scheme}://anything.{hostname}",
            category="Validation Bypass",
        ),
        TestCase(
            name="Scheme downgrade",
            description="Does server validate https vs http?",
            origin=f"http://{hostname}",
            category="Validation Bypass",
        ),
        TestCase(
            name="Case sensitivity",
            description="Does server normalize origin casing?",
            origin=f"{scheme}://{hostname.upper()}",
            category="Validation Bypass",
        ),
        # ── Special / edge-case origins ──────────────────────────────────
        TestCase(
            name="Null origin",
            description="Null accepted? (sandboxed iframe vector)",
            origin="null",
            category="Special Origin",
        ),
        TestCase(
            name="Localhost",
            description="Is localhost whitelisted?",
            origin="http://localhost",
            category="Special Origin",
        ),
        TestCase(
            name="Localhost:3000",
            description="Is localhost:3000 whitelisted? (common dev port)",
            origin="http://localhost:3000",
            category="Special Origin",
        ),
        TestCase(
            name="Loopback IP",
            description="Is 127.0.0.1 whitelisted?",
            origin="http://127.0.0.1",
            category="Special Origin",
        ),
        TestCase(
            name="Internal 192.168.x.x",
            description="Are RFC1918 addresses trusted?",
            origin="http://192.168.1.1",
            category="Internal Network",
        ),
        TestCase(
            name="Internal 10.x.x.x",
            description="Are RFC1918 addresses trusted?",
            origin="http://10.0.0.1",
            category="Internal Network",
        ),
    ]


# ---------------------------------------------------------------------------
# curl helpers
# ---------------------------------------------------------------------------

def build_curl_command(test: TestCase, url: str, cookie_header: Optional[str]) -> list[str]:
    """Build a curl command list for subprocess, using GET + header dump."""
    cmd = [
        "curl",
        "-s",              # silent — no progress meter
        "-D", "-",         # dump response headers to stdout
        "-o", "/dev/null", # discard response body
        "-H", f"Origin: {test.origin}",
        "-H", f"User-Agent: {USER_AGENT}",
    ]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]
    cmd.append(url)
    return cmd


def run_curl(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except FileNotFoundError:
        print("[ERROR] curl not found — please install curl.", file=sys.stderr)
        sys.exit(1)


def parse_response_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw.splitlines():
        if line.upper().startswith("HTTP/") or not line.strip():
            continue
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return headers


def extract_status_code(raw: str) -> Optional[str]:
    for line in raw.splitlines():
        m = re.match(r"HTTP/[\d.]+ (\d+)", line)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Outcome evaluation
# ---------------------------------------------------------------------------

def evaluate_outcome(test: TestCase, acao: Optional[str], acac: Optional[str]) -> tuple[str, str]:
    """Returns (human-readable outcome, severity string)."""
    if not acao:
        return "No CORS headers returned — not vulnerable to this probe", "PASS"

    acac_true        = acac and acac.lower() == "true"
    origin_reflected = acao.lower() == test.origin.lower()
    is_wildcard      = acao.strip() == "*"

    if is_wildcard and acac_true:
        return (
            "Wildcard + credentials — misconfigured but modern browsers block this combination",
            "MEDIUM",
        )
    if origin_reflected and acac_true:
        return (
            f"EXPLOITABLE — origin reflected ({acao}) with credentials enabled (ACAC: true)",
            "CRITICAL",
        )
    if origin_reflected and not acac_true:
        return (
            f"Origin reflected ({acao}) but no credentials — exposes unauthenticated responses only",
            "HIGH",
        )
    if is_wildcard:
        return "Wildcard ACAO without credentials — open to all origins, public data only", "INFO"

    return f"ACAO set to '{acao}' — does not reflect tested origin, likely safe for this probe", "PASS"


# ---------------------------------------------------------------------------
# Cookie loader
# ---------------------------------------------------------------------------

def load_cookie_header(storage_path: str) -> Optional[str]:
    try:
        with open(storage_path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Storage file not found: {storage_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Invalid JSON in storage file: {exc}", file=sys.stderr)
        sys.exit(1)

    cookies = data.get("cookiesParsed", {})
    if not cookies:
        return None
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _cmd_str(cmd: list[str]) -> str:
    """Redact the Cookie header value for safe printing."""
    out = []
    skip_next = False
    for token in cmd:
        if skip_next:
            # Redact long cookie strings
            if token.startswith("Cookie:") and len(token) > 60:
                out.append("Cookie: [redacted]")
            else:
                out.append(token)
            skip_next = False
        else:
            out.append(token)
            if token == "-H":
                skip_next = True
    return " ".join(out)


def format_plain(results: list[TestResult]) -> None:
    for i, r in enumerate(results, 1):
        print(f"\n[{i:02d}] {r.test.name}  |  {r.test.category}")
        print(f"  Doing   : {_cmd_str(r.command)}")
        print(f"  Response: ACAO={r.acao or 'not set'}  ACAC={r.acac or 'not set'}  HTTP={r.status_code or '?'}")
        print(f"  Outcome : {r.outcome}")
        print(f"  Severity: {r.severity}")


def format_color(results: list[TestResult]) -> None:
    print(f"\n{BOLD}{'═' * 72}{RESET}")
    print(f"{BOLD}  CORS MISCONFIGURATION TEST RESULTS{RESET}")
    print(f"{BOLD}{'═' * 72}{RESET}")

    for i, r in enumerate(results, 1):
        col   = SEV_COLOR.get(r.severity, WHITE)
        badge = SEV_BADGE.get(r.severity, r.severity)

        print(f"\n  {BOLD}{CYAN}[{i:02d}]{RESET}  {BOLD}{r.test.name}{RESET}  {badge}")
        print(f"  {GREY}Category :{RESET}  {r.test.category}")
        print(f"  {GREY}Origin   :{RESET}  {WHITE}{r.test.origin}{RESET}")
        print()
        print(f"  {GREY}Doing    :{RESET}  {GREY}{_cmd_str(r.command)}{RESET}")
        print()
        print(f"  {GREY}Response :{RESET}  ACAO={col}{r.acao or 'not set'}{RESET}"
              f"   ACAC={col}{r.acac or 'not set'}{RESET}"
              f"   HTTP={r.status_code or '?'}")
        print(f"  {GREY}Outcome  :{RESET}  {col}{r.outcome}{RESET}")
        print(f"  {'─' * 70}")

    # Summary table
    counts: dict[str, int] = {}
    for r in results:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    print(f"\n{BOLD}  SUMMARY{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO", "PASS"]:
        if sev in counts:
            col = SEV_COLOR.get(sev, WHITE)
            bar = "█" * counts[sev]
            print(f"  {col}{sev:<10}{RESET}  {bar}  {counts[sev]}")
    print(f"\n{BOLD}{'═' * 72}{RESET}\n")


def format_table(results: list[TestResult]) -> None:
    headers = ["#", "Test Name", "Category", "Origin Sent", "ACAO", "ACAC", "HTTP", "Severity"]
    rows = []
    for i, r in enumerate(results, 1):
        rows.append([
            str(i),
            r.test.name,
            r.test.category,
            r.test.origin,
            r.acao or "—",
            r.acac or "—",
            r.status_code or "?",
            r.severity,
        ])

    widths = [
        max(len(str(cell)) for cell in [headers[col]] + [row[col] for row in rows])
        for col in range(len(headers))
    ]
    sep     = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    sep_hdr = "+" + "+".join("=" * (w + 2) for w in widths) + "+"

    def render_row(row):
        return "|" + "|".join(f" {str(cell):<{widths[i]}} " for i, cell in enumerate(row)) + "|"

    print(sep)
    print(render_row(headers))
    print(sep_hdr)
    for row in rows:
        print(render_row(row))
    print(sep)

    # Outcome column separately since it's too wide for the table
    print()
    for i, r in enumerate(results, 1):
        print(f"  [{i:02d}]  {r.outcome}")


def format_json_out(results: list[TestResult]) -> None:
    out = [
        {
            "test_name":    r.test.name,
            "category":     r.test.category,
            "description":  r.test.description,
            "origin_sent":  r.test.origin,
            "command":      _cmd_str(r.command),
            "acao":         r.acao,
            "acac":         r.acac,
            "http_status":  r.status_code,
            "outcome":      r.outcome,
            "severity":     r.severity,
        }
        for r in results
    ]
    print(json.dumps(out, indent=2))


FORMATTERS = {
    "plain": format_plain,
    "color": format_color,
    "table": format_table,
    "json":  format_json_out,
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cors_tester",
        description="Run CORS misconfiguration probes using cookies from extract_storage.js output.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output formats
──────────────
  color   ANSI-colored with severity badges and summary chart (default)
  plain   Simple labeled text — good for logging / CI output
  table   ASCII table — good for copy/paste into reports
  json    Machine-readable — pipe to jq or save for later

Examples
────────
  python cors_tester.py --url https://example.com/api/users --storage browser_storage.json
  python cors_tester.py --url https://example.com/api/users --storage browser_storage.json --format table
  python cors_tester.py --url https://example.com/api/users --storage browser_storage.json --format json | jq '.[] | select(.severity=="CRITICAL")'
""",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL to probe (e.g. https://example.com/api/profile)",
    )
    parser.add_argument(
        "--storage",
        required=True,
        metavar="FILE",
        help="Path to browser_storage.json produced by extract_storage.js",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "color", "table", "json"],
        default="color",
        help="Output format (default: color)",
    )
    args = parser.parse_args()

    cookie_header = load_cookie_header(args.storage)
    test_cases    = build_test_cases(args.url)
    results: list[TestResult] = []

    if args.format != "json":
        print(f"\n  Target  : {args.url}")
        print(f"  Cookies : {'loaded (' + args.storage + ')' if cookie_header else 'none found in storage file'}")
        print(f"  Tests   : {len(test_cases)}\n")

    for test in test_cases:
        cmd = build_curl_command(test, args.url, cookie_header)

        if args.format != "json":
            print(f"  → {test.name:<22}", end=" ", flush=True)

        raw            = run_curl(cmd)
        headers        = parse_response_headers(raw)
        acao           = headers.get("access-control-allow-origin")
        acac           = headers.get("access-control-allow-credentials")
        status         = extract_status_code(raw)
        outcome, sev   = evaluate_outcome(test, acao, acac)

        if args.format != "json":
            col   = SEV_COLOR.get(sev, WHITE) if args.format == "color" else ""
            reset = RESET if args.format == "color" else ""
            print(f"{col}{sev}{reset}")

        results.append(TestResult(
            test=test,
            command=cmd,
            acao=acao,
            acac=acac,
            status_code=status,
            outcome=outcome,
            severity=sev,
        ))

    print()
    FORMATTERS[args.format](results)


if __name__ == "__main__":
    main()
