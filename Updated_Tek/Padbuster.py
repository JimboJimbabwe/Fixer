#!/usr/bin/env python3
"""
padbuster_builder.py — Interactive PadBuster command generator from Burp Suite proxy XML.

Pane 1 : Parse XML → display categorized endpoints → select which to test
Pane 2 : Preview generated commands per endpoint/cookie/blocksize/encoding
Pane 3 : Save command_history.json → optionally execute

Usage:
    python padbuster_builder.py -f export.xml
    python padbuster_builder.py -f export.xml --history ./output/commands.json
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
RESET    = "\033[0m"
BOLD     = "\033[1m"
DIM      = "\033[2m"
RED      = "\033[91m"
GREEN    = "\033[92m"
YELLOW   = "\033[93m"
CYAN     = "\033[96m"
WHITE    = "\033[97m"
GREY     = "\033[90m"
BG_BLUE  = "\033[44m"
BG_GREEN = "\033[42m"
BG_RED   = "\033[41m"

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")

def banner(pane_title: str, subtitle: str = "") -> None:
    W = 72
    print(f"\n{BOLD}╔{'═' * (W - 2)}╗{RESET}")
    left  = f"  PADBUSTER BUILDER  —  {pane_title}"
    right = f"  v1.0"
    pad   = W - 2 - len(left) - len(right)
    print(f"{BOLD}║{BG_BLUE}{left}{' ' * max(pad,1)}{right} {RESET}{BOLD}║{RESET}")
    if subtitle:
        sub = f"  {subtitle}"
        print(f"{BOLD}║{GREY}{sub:<{W-2}}{RESET}{BOLD}║{RESET}")
    print(f"{BOLD}╚{'═' * (W - 2)}╝{RESET}\n")

def divider(char: str = "─") -> None:
    print(f"{GREY}{char * 72}{RESET}")

def section(title: str) -> None:
    print(f"\n  {BOLD}{CYAN}{title}{RESET}")
    divider("·")


# ---------------------------------------------------------------------------
# PadBuster constants
# ---------------------------------------------------------------------------

ENCODINGS: dict[int, str] = {
    0: "Base64",
    1: "Lowercase HEX",
    2: "Uppercase HEX",
    3: ".NET UrlToken",
    4: "WebSafe Base64",
}

BLOCK_SIZES = [8, 16]       # DES/3DES = 8,  AES = 16
MAX_COOKIES = 4             # test at most 4 cookies per endpoint


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    idx:          int
    url:          str
    method:       str
    host:         str
    protocol:     str
    path:         str
    query_string: str
    cookies:      dict[str, str]
    body:         Optional[str]
    category:     str           # GET_PARAMS | POST_NO_BODY | POST_BODY | OTHER


@dataclass
class PadBusterCommand:
    endpoint_idx:  int
    url:           str
    method:        str
    cookie_name:   str
    cookie_value:  str
    all_cookies:   str
    block_size:    int
    encoding:      int
    encoding_name: str
    body:          Optional[str]
    command:       str
    executed:      bool          = False
    exit_code:     Optional[int] = None


# ---------------------------------------------------------------------------
# Burp XML parser
# ---------------------------------------------------------------------------

def _decode_burp_field(el) -> Optional[str]:
    if el is None:
        return None
    text = el.text or ""
    if el.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return None
    return text


def _extract_request_header(raw: str, name: str) -> Optional[str]:
    needle = name.lower() + ":"
    for line in raw.splitlines()[1:]:
        stripped = line.strip()
        if not stripped:
            break
        if stripped.lower().startswith(needle):
            return stripped[len(needle):].strip()
    return None


def _extract_body(raw: str) -> Optional[str]:
    for sep in ("\r\n\r\n", "\n\n"):
        parts = raw.split(sep, 1)
        if len(parts) == 2 and parts[1].strip():
            return parts[1].strip()
    return None


def _parse_cookie_header(header_val: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for pair in header_val.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, _, v = pair.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


def parse_burp_xml(filepath: str) -> list[Endpoint]:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            raw_xml = fh.read()
    except FileNotFoundError:
        print(f"{RED}[ERROR]{RESET} File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    # Strip DOCTYPE so ElementTree can parse without an external resolver
    raw_xml = re.sub(r"<!DOCTYPE[^>]*(?:\[.*?\])?>", "", raw_xml, flags=re.DOTALL)

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        print(f"{RED}[ERROR]{RESET} XML parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    items = root.findall("item")
    if not items:
        print(f"{YELLOW}[WARN]{RESET} No <item> elements found — is this a Burp proxy XML export?")
        return []

    endpoints: list[Endpoint] = []

    for item in items:
        host_el      = item.find("host")
        protocol_el  = item.find("protocol")
        method_el    = item.find("method")
        path_el      = item.find("path")
        request_el   = item.find("request")

        host     = (host_el.text     or "").strip()      if host_el     else ""
        protocol = (protocol_el.text or "https").strip() if protocol_el else "https"
        method   = (method_el.text   or "GET").strip().upper() if method_el else "GET"
        path_raw = (path_el.text     or "/").strip()     if path_el     else "/"

        raw_req = _decode_burp_field(request_el)
        if not raw_req:
            continue

        cookie_hdr = _extract_request_header(raw_req, "Cookie")
        if not cookie_hdr:
            continue        # skip requests without cookies

        cookies = _parse_cookie_header(cookie_hdr)
        if not cookies:
            continue

        path, query_string = (path_raw.split("?", 1) + [""])[:2]
        body = _extract_body(raw_req) if method in ("POST", "PUT", "PATCH") else None

        url = f"{protocol}://{host}{path}"
        if query_string:
            url += f"?{query_string}"

        if method == "GET":
            category = "GET_PARAMS" if query_string else "GET_PLAIN"
        elif method == "POST":
            category = "POST_BODY" if body else "POST_NO_BODY"
        else:
            category = "OTHER"

        endpoints.append(Endpoint(
            idx=len(endpoints) + 1,
            url=url,
            method=method,
            host=host,
            protocol=protocol,
            path=path,
            query_string=query_string,
            cookies=cookies,
            body=body,
            category=category,
        ))

    # Deduplicate: same method + url + cookie names
    seen:   set  = set()
    unique: list[Endpoint] = []
    for ep in endpoints:
        key = (ep.method, ep.url, frozenset(ep.cookies.keys()))
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    for i, ep in enumerate(unique, 1):
        ep.idx = i

    return unique


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------

def build_commands_for_endpoint(ep: Endpoint) -> list[PadBusterCommand]:
    cmds: list[PadBusterCommand] = []
    cookie_items  = list(ep.cookies.items())[:MAX_COOKIES]
    all_cookies   = "; ".join(f"{k}={v}" for k, v in ep.cookies.items())

    for cookie_name, cookie_value in cookie_items:
        for block_size in BLOCK_SIZES:
            for enc_id, enc_name in ENCODINGS.items():
                parts = [
                    "padbuster",
                    f'"{ep.url}"',
                    f'"{cookie_value}"',
                    str(block_size),
                    f'-cookies "{all_cookies}"',
                    f"-encoding {enc_id}",
                ]
                if ep.body:
                    safe_body = ep.body.replace('"', '\\"')
                    parts.append(f'-post "{safe_body}"')

                # Placeholder — user fills after identifying error pattern
                parts.append('# TODO: add -error "<error_string>"')

                cmds.append(PadBusterCommand(
                    endpoint_idx=ep.idx,
                    url=ep.url,
                    method=ep.method,
                    cookie_name=cookie_name,
                    cookie_value=cookie_value,
                    all_cookies=all_cookies,
                    block_size=block_size,
                    encoding=enc_id,
                    encoding_name=enc_name,
                    body=ep.body,
                    command=" ".join(parts),
                ))
    return cmds


# ---------------------------------------------------------------------------
# History writer
# ---------------------------------------------------------------------------

def write_history(
    commands:     list[PadBusterCommand],
    history_path: str,
    source_file:  str,
) -> None:
    out_dir = os.path.dirname(history_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    payload = {
        "generated_at": datetime.now().isoformat(),
        "source_file":  source_file,
        "total":        len(commands),
        "block_sizes":  BLOCK_SIZES,
        "encodings":    ENCODINGS,
        "commands": [
            {
                "endpoint_idx":  c.endpoint_idx,
                "method":        c.method,
                "url":           c.url,
                "cookie_name":   c.cookie_name,
                "cookie_value":  c.cookie_value,
                "all_cookies":   c.all_cookies,
                "block_size":    c.block_size,
                "encoding":      c.encoding,
                "encoding_name": c.encoding_name,
                "body":          c.body,
                "command":       c.command,
                "executed":      c.executed,
                "exit_code":     c.exit_code,
            }
            for c in commands
        ],
    }

    with open(history_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


# ---------------------------------------------------------------------------
# Pane 1 — Endpoint selection
# ---------------------------------------------------------------------------

CAT_LABEL: dict[str, str] = {
    "GET_PARAMS":    f"{GREEN}GET{RESET}   + URL params + cookies",
    "GET_PLAIN":     f"{GREEN}GET{RESET}   + cookies (no params)",
    "POST_NO_BODY":  f"{CYAN}POST{RESET}  + cookies  (no body)",
    "POST_BODY":     f"{CYAN}POST{RESET}  + cookies  + body",
    "OTHER":         f"{YELLOW}PUT / DELETE / PATCH{RESET}",
}


def pane_1_select(endpoints: list[Endpoint]) -> list[Endpoint]:
    clear_screen()

    main_eps  = [e for e in endpoints if e.category != "OTHER"]
    other_eps = [e for e in endpoints if e.category == "OTHER"]

    banner(
        "Pane 1 — Endpoint Select",
        f"{len(main_eps)} testable  |  {len(other_eps)} PUT/DELETE/PATCH  |  total {len(endpoints)}",
    )

    if not endpoints:
        print(f"  {RED}No endpoints with cookies found.{RESET}\n")
        sys.exit(0)

    # ── Main endpoints ───────────────────────────────────────────────────
    section("Testable Endpoints  (GET / POST with cookies)")
    print()

    for ep in main_eps:
        label        = CAT_LABEL.get(ep.category, ep.category)
        cookie_names = ", ".join(ep.cookies.keys())
        cookie_count = min(len(ep.cookies), MAX_COOKIES)
        cmd_count    = cookie_count * len(BLOCK_SIZES) * len(ENCODINGS)
        print(f"  {BOLD}[{ep.idx:02d}]{RESET}  {label}")
        print(f"        {WHITE}{ep.method:<6}{RESET}  {ep.url}")
        print(f"        {GREY}Cookies ({cookie_count}): {cookie_names}"
              f"  →  {cmd_count} commands{RESET}")
        print()

    # ── Other methods ────────────────────────────────────────────────────
    if other_eps:
        section("PUT / DELETE / PATCH  (selectable too)")
        print()
        for ep in other_eps:
            cookie_names = ", ".join(ep.cookies.keys())
            print(f"  {BOLD}[{ep.idx:02d}]{RESET}  {YELLOW}{ep.method:<8}{RESET}  {ep.url}")
            print(f"        {GREY}Cookies: {cookie_names}{RESET}")
            print()

    divider()
    print(f"\n  {BOLD}Selection:{RESET}  number  |  comma-separated (1,3,5)  |  all")
    print(f"  {DIM}Type 'done' once you have everything you want.{RESET}\n")

    selected_ids: set[int] = set()
    valid_ids    = {ep.idx for ep in endpoints}

    while True:
        try:
            raw = input(f"  {CYAN}>{RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting.")
            sys.exit(0)

        if raw == "done":
            if not selected_ids:
                print(f"  {YELLOW}  Nothing selected — pick at least one endpoint or Ctrl-C to quit.{RESET}")
                continue
            break

        if raw == "all":
            selected_ids = set(valid_ids)
            print(f"  {GREEN}✓ All {len(selected_ids)} endpoints selected.{RESET}")
            print(f"  {DIM}  Type 'done' to continue.{RESET}")
            continue

        tokens  = [t.strip() for t in raw.split(",") if t.strip()]
        added   = []
        unknown = []
        for tok in tokens:
            try:
                n = int(tok)
                if n in valid_ids:
                    selected_ids.add(n)
                    added.append(n)
                else:
                    unknown.append(tok)
            except ValueError:
                unknown.append(tok)

        if added:
            print(f"  {GREEN}✓ Added:{RESET} {', '.join(str(x) for x in sorted(added))}")
        if unknown:
            print(f"  {YELLOW}? Not found:{RESET} {', '.join(unknown)}")
        if selected_ids:
            print(f"  {GREY}  Selected so far: {', '.join(str(x) for x in sorted(selected_ids))}"
                  f"  — type 'done' to continue{RESET}")

    return [ep for ep in endpoints if ep.idx in selected_ids]


# ---------------------------------------------------------------------------
# Pane 2 — Command generation preview
# ---------------------------------------------------------------------------

def pane_2_generate(selected: list[Endpoint]) -> list[PadBusterCommand]:
    clear_screen()
    banner(
        "Pane 2 — Command Preview",
        f"{len(selected)} endpoint(s) selected  |  "
        f"block sizes: {BLOCK_SIZES}  |  encodings: {len(ENCODINGS)}",
    )

    all_commands: list[PadBusterCommand] = []

    for ep in selected:
        cookie_items = list(ep.cookies.items())[:MAX_COOKIES]
        ep_cmds      = build_commands_for_endpoint(ep)
        all_commands.extend(ep_cmds)

        print(f"  {BOLD}[{ep.idx:02d}]{RESET}  {WHITE}{ep.method}{RESET}  {ep.url}")
        print(f"        {GREY}Category: {ep.category}{RESET}")
        if ep.body:
            body_preview = ep.body[:60] + ("…" if len(ep.body) > 60 else "")
            print(f"        {GREY}Body    : {body_preview}{RESET}")

        print(f"\n        {BOLD}Cookies loaded ({len(cookie_items)}):{RESET}")
        for name, val in cookie_items:
            preview = val[:48] + ("…" if len(val) > 48 else "")
            print(f"        {CYAN}  {name}{RESET} = {GREY}{preview}{RESET}")

        print(f"\n        {GREEN}→ {len(ep_cmds)} commands generated{RESET}")
        print(f"        {DIM}  ({len(cookie_items)} cookies × {len(BLOCK_SIZES)} block sizes × {len(ENCODINGS)} encodings){RESET}\n")

        # Show one sample command per block size
        shown: set[int] = set()
        for cmd in ep_cmds:
            if cmd.block_size not in shown:
                shown.add(cmd.block_size)
                bs_label = "DES/3DES" if cmd.block_size == 8 else "AES"
                print(f"        {GREY}Sample (block={cmd.block_size} / {bs_label}, enc=0 Base64):{RESET}")
                print(f"        {DIM}{cmd.command}{RESET}")
                print()

        divider()
        print()

    # Grand total
    total_per_ep     = len(BLOCK_SIZES) * len(ENCODINGS)
    print(f"  {BOLD}Grand total: {len(all_commands)} commands{RESET}")
    print(f"  {GREY}  Breakdown per endpoint: up to {MAX_COOKIES} cookies × {len(BLOCK_SIZES)} block sizes × "
          f"{len(ENCODINGS)} encodings = up to {MAX_COOKIES * total_per_ep} cmds each{RESET}\n")

    return all_commands


# ---------------------------------------------------------------------------
# Pane 3 — Save + execute?
# ---------------------------------------------------------------------------

def pane_3_execute(
    commands:     list[PadBusterCommand],
    history_path: str,
    source_file:  str,
) -> None:
    clear_screen()
    banner("Pane 3 — Save & Execute", f"{len(commands)} total commands")

    # Always save first
    write_history(commands, history_path, source_file)
    print(f"  {GREEN}✓ Command history saved:{RESET}  {history_path}\n")

    # Print full command list
    section("All Generated Commands")
    print()

    prev_ep = None
    for i, c in enumerate(commands, 1):
        if c.endpoint_idx != prev_ep:
            prev_ep = c.endpoint_idx
            print(f"  {BOLD}{CYAN}── Endpoint {c.endpoint_idx}: {c.method} {c.url}{RESET}")
            print()

        bs_label  = "DES/3DES" if c.block_size == 8 else "AES    "
        enc_label = c.encoding_name
        print(f"  {GREY}[{i:03d}] block={c.block_size}B ({bs_label})  enc={c.encoding} ({enc_label:<18})  cookie={c.cookie_name}{RESET}")
        print(f"  {WHITE}{c.command}{RESET}")
        print()

    divider()
    print(f"\n  {BOLD}Run all {len(commands)} commands now?{RESET}")
    print(f"  {DIM}  Requires padbuster to be installed and in PATH.{RESET}")
    print(f"  {DIM}  You can also run them later:{RESET}")
    print(f"  {WHITE}    jq -r '.commands[].command' {history_path} | bash{RESET}")
    print(f"\n  {YELLOW}y{RESET} = run now    {YELLOW}n{RESET} = save only and exit\n")

    try:
        choice = input(f"  {CYAN}>{RESET} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        choice = "n"

    if choice != "y":
        print(f"\n  {GREEN}Done.{RESET}  Commands saved to: {history_path}\n")
        return

    # ── Execute ───────────────────────────────────────────────────────────
    print(f"\n  {BOLD}Running...{RESET}\n")

    for i, c in enumerate(commands, 1):
        bs_label  = "DES" if c.block_size == 8 else "AES"
        enc_label = c.encoding_name
        print(f"  {GREY}[{i:03d}/{len(commands)}]{RESET}  "
              f"ep={c.endpoint_idx}  cookie={c.cookie_name}  "
              f"block={c.block_size}({bs_label})  enc={c.encoding}({enc_label})")

        # Strip the trailing TODO comment before passing to shell
        exec_cmd = c.command.split("# TODO:")[0].strip()
        print(f"  {DIM}  {exec_cmd}{RESET}")

        try:
            result = subprocess.run(exec_cmd, shell=True, timeout=120)
            c.executed  = True
            c.exit_code = result.returncode
            col = GREEN if result.returncode == 0 else RED
            print(f"  {col}  exit={result.returncode}{RESET}\n")
        except subprocess.TimeoutExpired:
            print(f"  {YELLOW}  TIMEOUT (120s){RESET}\n")
        except Exception as exc:
            print(f"  {RED}  ERROR: {exc}{RESET}\n")

    # Re-save with execution results
    write_history(commands, history_path, source_file)
    print(f"  {GREEN}✓ Execution results written back to:{RESET}  {history_path}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="padbuster_builder",
        description="Interactive PadBuster command generator from Burp Suite proxy XML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
What it generates
─────────────────
  For each selected endpoint × cookie (max 4) × block size × encoding:

    padbuster "URL" "COOKIE_VALUE" BLOCKSIZE -cookies "k=v; k2=v2" -encoding N
              [-post "body"]   # TODO: add -error "<error_string>"

  Block sizes    8   DES / 3DES
                16   AES-128 / AES-192 / AES-256

  Encodings      0   Base64
                 1   Lowercase HEX
                 2   Uppercase HEX
                 3   .NET UrlToken
                 4   WebSafe Base64

Endpoints pulled from Burp XML
───────────────────────────────
  GET  + URL params + cookies
  POST + cookies (no body)
  POST + cookies + body
  PUT / DELETE / PATCH  (displayed, selectable)
  Requests without cookies are skipped.

Output JSON
───────────
  jq -r '.commands[].command' command_history.json
  jq '.commands[] | select(.block_size==16)' command_history.json
  jq '.commands[] | select(.executed==true and .exit_code!=0)' command_history.json

Examples
────────
  python padbuster_builder.py -f export.xml
  python padbuster_builder.py -f export.xml --history ./results/commands.json
""",
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        metavar="FILE",
        help="Burp Suite proxy XML export",
    )
    parser.add_argument(
        "--history",
        default="command_history.json",
        metavar="PATH",
        help="Output path for command_history.json  (default: ./command_history.json)",
    )
    args = parser.parse_args()

    print(f"\n  {GREY}Parsing {args.file}...{RESET}")
    endpoints = parse_burp_xml(args.file)

    if not endpoints:
        print(f"\n  {YELLOW}No endpoints with cookies found in {args.file}.{RESET}\n")
        sys.exit(0)

    print(f"  {GREEN}✓{RESET} Found {len(endpoints)} unique endpoints with cookies.\n")

    selected = pane_1_select(endpoints)
    commands = pane_2_generate(selected)

    if not commands:
        print(f"  {YELLOW}No commands generated.{RESET}\n")
        sys.exit(0)

    pane_3_execute(commands, args.history, args.file)


if __name__ == "__main__":
    main()
