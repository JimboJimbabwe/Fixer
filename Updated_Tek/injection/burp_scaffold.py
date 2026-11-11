#!/usr/bin/env python3
"""
burp_scaffold.py — Generate a URL wordlist from a Burp Suite proxy XML export.

Usage:
  python burp_scaffold.py --input-xml requests.xml --payloads payloads.txt \\
                          --output-wordlist urls.txt (--all | --select)

Notes:
  - Parses GET query params and POST application/x-www-form-urlencoded body params.
  - JSON / multipart POST bodies are not auto-parsed; extract params by hand and
    add them to the URL query string in Burp before exporting if needed.
  - POST body params are appended to the query string in generated URLs because
    EyeWitness only supports GET-style requests (screenshots, not form submissions).
"""

import argparse
import base64
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_burp_xml(xml_path: str) -> list[dict]:
    """Parse a Burp Suite 'Save items' XML export into structured request dicts."""
    try:
        tree = ET.parse(xml_path)
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {xml_path}")
    except ET.ParseError as exc:
        sys.exit(f"[!] Failed to parse XML: {exc}")

    root = tree.getroot()
    items: list[dict] = []

    for item in root.findall("item"):
        url    = item.findtext("url",    "").strip()
        method = item.findtext("method", "").strip().upper()

        if not url:
            continue

        # Decode raw request (Burp exports it base64-encoded by default)
        raw_request = ""
        req_elem = item.find("request")
        if req_elem is not None:
            text = req_elem.text or ""
            try:
                raw_request = (
                    base64.b64decode(text).decode("utf-8", errors="replace")
                    if req_elem.get("base64") == "true"
                    else text
                )
            except Exception:
                raw_request = ""

        # --- URL query params ---
        parsed_url = urlparse(url)
        url_params = {
            k: v[0]
            for k, v in parse_qs(parsed_url.query, keep_blank_values=True).items()
        }

        # --- Body params (form-urlencoded only) ---
        body_params: dict[str, str] = {}
        if method in ("POST", "PUT", "PATCH") and raw_request:
            sep = "\r\n\r\n" if "\r\n\r\n" in raw_request else "\n\n"
            parts = raw_request.split(sep, 1)
            if len(parts) == 2:
                headers_block, body = parts
                if "application/x-www-form-urlencoded" in headers_block.lower():
                    body_params = {
                        k: v[0]
                        for k, v in parse_qs(body.strip(), keep_blank_values=True).items()
                    }

        # Merge, tagging each param with its source
        params: dict[str, dict] = {}
        for k, v in url_params.items():
            params[k] = {"value": v, "source": "url"}
        for k, v in body_params.items():
            params[k] = {"value": v, "source": "body"}

        if not params:
            continue  # nothing to inject into — skip

        items.append(
            {
                "url":        url,
                "method":     method,
                "parsed_url": parsed_url,
                "params":     params,
            }
        )

    return items


# ---------------------------------------------------------------------------
# URL building
# ---------------------------------------------------------------------------

def build_url(item: dict, target_param: str, payload: str) -> str:
    """
    Return a full URL with *target_param* replaced by *payload*.

    All other URL-query params are preserved at their original values.
    Body params are promoted to the query string so EyeWitness can render them.
    """
    parsed = item["parsed_url"]

    # Start from all URL-query params, keeping original values
    qs: dict[str, str] = {
        k: v["value"]
        for k, v in item["params"].items()
        if v["source"] == "url"
    }
    # Swap (or inject) the target param
    qs[target_param] = payload

    new_parsed = parsed._replace(query=urlencode(qs))
    return urlunparse(new_parsed)


# ---------------------------------------------------------------------------
# Selection modes
# ---------------------------------------------------------------------------

def select_all(items: list[dict]) -> list[tuple[dict, str]]:
    """Return every (item, param_name) combination."""
    return [(item, name) for item in items for name in item["params"]]


def select_interactive(items: list[dict]) -> list[tuple[dict, str]]:
    """Walk through each endpoint and let the user pick which params to target."""
    selections: list[tuple[dict, str]] = []

    for idx, item in enumerate(items, 1):
        param_names = list(item["params"].keys())

        print(f"\n{'─' * 64}")
        print(f"  [{idx}/{len(items)}]  {item['method']}  {item['url']}")
        print("  Parameters:")
        for i, name in enumerate(param_names, 1):
            src = item["params"][name]["source"]
            tag = f"  [{src}]" if src != "url" else ""
            print(f"    {i}. {name}{tag}")

        while True:
            raw = input("  Select (all / 1,2,… / skip): ").strip().lower()

            if raw == "skip":
                chosen: list[str] = []
                break

            if raw == "all":
                chosen = param_names
                break

            try:
                indices = [int(x.strip()) for x in raw.split(",") if x.strip()]
                if indices and all(1 <= i <= len(param_names) for i in indices):
                    # Deduplicate while preserving order
                    seen: set[int] = set()
                    chosen = []
                    for i in indices:
                        if i not in seen:
                            seen.add(i)
                            chosen.append(param_names[i - 1])
                    break
                print(f"  [!] Enter numbers 1–{len(param_names)}, 'all', or 'skip'.")
            except ValueError:
                print("  [!] Invalid input.  Examples:  all  /  1  /  1,3  /  skip")

        for name in chosen:
            selections.append((item, name))

    return selections


# ---------------------------------------------------------------------------
# Payload loading
# ---------------------------------------------------------------------------

def load_payloads(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        sys.exit(f"[!] Payloads file not found: {path}")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    payloads = [ln for ln in lines if ln]  # drop blank lines
    if not payloads:
        sys.exit("[!] Payloads file is empty.")
    return payloads


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input-xml", required=True,
        metavar="FILE",
        help="Burp Suite 'Save items' XML export",
    )
    parser.add_argument(
        "--payloads", required=True,
        metavar="FILE",
        help="Payload wordlist (one entry per line)",
    )
    parser.add_argument(
        "--output-wordlist", required=True,
        metavar="FILE",
        help="Output URL list for EyeWitness (e.g. urls.txt)",
    )

    mode_grp = parser.add_mutually_exclusive_group(required=True)
    mode_grp.add_argument(
        "--all",    action="store_true",
        help="Include every parameter from every endpoint automatically",
    )
    mode_grp.add_argument(
        "--select", action="store_true",
        help="Interactively choose parameters endpoint by endpoint",
    )

    args = parser.parse_args()

    # 1. Parse XML
    print(f"\n[*] Parsing {args.input_xml} ...")
    items = parse_burp_xml(args.input_xml)
    if not items:
        sys.exit("[!] No parameterized requests found in the XML.")
    print(f"[+] Found {len(items)} request(s) with injectable parameters.")

    # 2. Load payloads
    payloads = load_payloads(args.payloads)
    print(f"[+] Loaded {len(payloads)} payload(s) from {args.payloads}.")

    # 3. Choose (endpoint, param) pairs
    if args.all:
        selections = select_all(items)
        print(f"[+] --all selected: {len(selections)} (endpoint × param) pair(s).")
    else:
        print("\n[*] Entering interactive selection mode ...\n")
        selections = select_interactive(items)

    if not selections:
        sys.exit("\n[!] No parameters selected. Nothing to write. Exiting.")

    # 4. Generate URLs
    urls: list[str] = []
    for item, param in selections:
        for payload in payloads:
            urls.append(build_url(item, param, payload))

    # 5. Write output
    out_path = Path(args.output_wordlist)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(urls) + "\n", encoding="utf-8")

    # 6. Summary
    has_body_params = any(
        item["params"][p]["source"] == "body" for item, p in selections
    )

    print(f"\n{'=' * 64}")
    print(f"[+] Done.  Wrote {len(urls)} URL(s) to {out_path}")
    print(f"    {len(selections)} (endpoint × param) pair(s)  ×  {len(payloads)} payload(s)")
    if has_body_params:
        print()
        print("    [~] One or more selected params came from a POST body.")
        print("        They have been appended to the query string so EyeWitness")
        print("        can render them (it only supports GET-style URLs).")
    print(f"{'=' * 64}\n")


if __name__ == "__main__":
    main()
