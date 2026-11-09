#!/usr/bin/env python3
"""
WSTG-CONF-07 — HSTS XML Scanner

Scans a Burp proxy history XML export for the Strict-Transport-Security
header, per endpoint, instead of HSTS_test.py's live curl approach. Useful
when Burp already captured a response that shows the header and you want
to confirm/cross-check against the whole recorded dataset rather than
re-requesting every endpoint live (see: curl vs Burp mismatches - a
redirect hop, a cached edge response, or a WAF-served page can all cause
curl to miss a header Burp actually recorded, and vice versa).

For every <item> in the XML:
  - decodes the (optionally base64) <response> block
  - looks for a Strict-Transport-Security header, case-insensitively
  - if present, parses max-age / includeSubDomains / preload the same way
    HSTS_test.py does, and flags the same issues (missing max-age, too
    short a max-age, preload without includeSubDomains)
  - if absent, flags it as missing

Does not touch wstg_io.json, the project's folder layout, or the GUI in
any way yet - standalone test script. Point it at one Burp XML export.

Usage:
  python3 hsts_xml_scan.py path/to/burp_export.xml
  python3 hsts_xml_scan.py path/to/burp_export.xml --missing-only
  python3 hsts_xml_scan.py path/to/burp_export.xml -o report.txt
"""
import argparse
import base64
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# Burp XML decode helpers (same convention used elsewhere in this toolset,
# e.g. info10_collect.py's decode_element)
# ---------------------------------------------------------------------------

def decode_element(elem) -> str:
    if elem is None:
        return ""
    raw = elem.text or ""
    if elem.attrib.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return raw
    return raw


def parse_request_line(request_text: str) -> tuple:
    first = request_text.split("\n", 1)[0].strip() if request_text else ""
    parts = first.split(" ")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "UNKNOWN", "/"


def parse_response_headers(response_text: str) -> dict:
    """{header_name_lower: value} from the raw response's header block."""
    if not response_text:
        return {}
    head = response_text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    headers = {}
    for line in head.splitlines()[1:]:   # [0] is the status line
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return headers


def response_status(response_text: str) -> str:
    first = response_text.split("\n", 1)[0].strip() if response_text else ""
    m = re.search(r"\s(\d{3})\s", first)
    return m.group(1) if m else (first or "?")


# ---------------------------------------------------------------------------
# Same HSTS directive parsing / issue rules as HSTS_test.py
# ---------------------------------------------------------------------------

def parse_hsts_header(value: str) -> dict:
    result = {
        "raw": value,
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
        "valid": False,
        "issues": [],
    }
    if not value:
        result["issues"].append("Header absent")
        return result

    m = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if m:
        result["max_age"] = int(m.group(1))
    else:
        result["issues"].append("max-age directive missing")

    result["include_subdomains"] = bool(re.search(r"includeSubDomains", value, re.IGNORECASE))
    result["preload"] = bool(re.search(r"\bpreload\b", value, re.IGNORECASE))

    if result["max_age"] is not None:
        if result["max_age"] < 10886400:   # 18 weeks - preload minimum
            result["issues"].append(f"max-age={result['max_age']} is below the 18-week (10886400s) preload minimum")
        if result["max_age"] < 31536000:   # 1 year - recommended
            result["issues"].append(f"max-age={result['max_age']} is below the recommended 1-year (31536000s) value")

    if result["preload"] and not result["include_subdomains"]:
        result["issues"].append("preload directive present but includeSubDomains is missing - preload requires includeSubDomains")

    if not result["issues"] and result["max_age"] is not None:
        result["valid"] = True

    return result


# ---------------------------------------------------------------------------
# Load every item from the Burp XML
# ---------------------------------------------------------------------------

def load_items(xml_path: str) -> list[dict]:
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"[!] File not found: {xml_path}", file=sys.stderr)
        sys.exit(1)

    items = []
    for idx, item in enumerate(tree.getroot().findall(".//item")):
        url_elem = item.find("./url")
        url = (url_elem.text or "").strip() if url_elem is not None else ""

        request_text = decode_element(item.find("./request"))
        response_text = decode_element(item.find("./response"))

        method, path_str = parse_request_line(request_text)
        if not url:
            # Fall back to Host header + path if <url> wasn't recorded
            host_m = re.search(r"^Host:\s*(.+)$", request_text, re.IGNORECASE | re.MULTILINE)
            host = host_m.group(1).strip() if host_m else "UNKNOWN-HOST"
            url = f"https://{host}{path_str}"

        status_elem = item.find("./status")
        status = (status_elem.text or "").strip() if status_elem is not None and status_elem.text else response_status(response_text)

        resp_headers = parse_response_headers(response_text)
        hsts_value = resp_headers.get("strict-transport-security", "")
        parsed = parse_hsts_header(hsts_value)

        parts = urlsplit(url)
        items.append({
            "index": idx,
            "method": method,
            "path": (parts.path or path_str or "/"),
            "host": parts.netloc or "",
            "url": url,
            "status": status,
            "hsts": parsed,
        })
    return items


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def format_report(items: list[dict], missing_only: bool) -> str:
    lines = []
    lines.append("# HSTS XML Scan Report")
    lines.append(f"Endpoints scanned: {len(items)}")
    present = sum(1 for i in items if i["hsts"]["raw"])
    lines.append(f"Endpoints with Strict-Transport-Security header: {present}")
    lines.append(f"Endpoints without it: {len(items) - present}")
    lines.append("")
    lines.append("=" * 70)
    lines.append("")

    for i in items:
        hsts = i["hsts"]
        has_header = bool(hsts["raw"])
        if missing_only and has_header:
            continue

        lines.append(f"[{i['index']}] {i['method']} {i['path']}  (status {i['status']})")
        lines.append(f"    Host: {i['host']}")
        lines.append(f"    URL:  {i['url']}")
        if has_header:
            lines.append(f"    HSTS: PRESENT  -> Strict-Transport-Security: {hsts['raw']}")
            lines.append(f"          max-age={hsts['max_age']}  includeSubDomains={hsts['include_subdomains']}  preload={hsts['preload']}")
        else:
            lines.append("    HSTS: ABSENT")
        for issue in hsts["issues"]:
            lines.append(f"    ISSUE: {issue}")
        lines.append("")

    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("xml", help="Path to a Burp proxy history XML export.")
    p.add_argument("-o", "--output", default=None, help="Write the report to this file (default: print to stdout only).")
    p.add_argument("--missing-only", action="store_true", help="Only list endpoints where the header is absent.")
    args = p.parse_args()

    items = load_items(args.xml)
    if not items:
        print("[!] No <item> entries found in this XML - is it a Burp proxy history export?", file=sys.stderr)
        sys.exit(1)

    report = format_report(items, args.missing_only)
    print(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n[+] Report written -> {args.output}")


if __name__ == "__main__":
    main()
