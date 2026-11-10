#!/usr/bin/env python3
"""
WSTG-INJT-22 (Prototype Pollution) - wordlist + target-URL prep.

Two things, one run:

  1. Reads proto_pollution_probes.json (looked for in this item's own
     Utilities/python/, then Inputs/JSON/, then --probes-file) and writes
     three plain wordlists to this item's Inputs/Wordlists/:
       Body_Data.txt   - one compact JSON object per line (request bodies)
       URL_Hash.txt    - one #__proto__[...] fragment string per line
       URL_Seg.txt     - one ?__proto__[...] query string per line
     Dropping them in Inputs/Wordlists/ (rather than Outputs/test_outputs,
     where every other generated wordlist in this project lands) is
     deliberate: that's the one folder the GUI's own "Wordlists" panel
     reads from, so all three show up there with a Copy button for free,
     tagged the same way any other wordlist_in/wordlist_out entry would be.

  2. Reads every Burp Proxy XML file this item has in Inputs/XML/ and picks
     up to --max-urls (default 5) candidate target URLs for the hash
     fragment opener (hash_fragment_opener.py, run separately and only
     when the operator wants it):
       - First choice: pages whose response body shows real evidence of
         client-side hash routing - an anchor with a non-empty #fragment
         href, or a reference to location.hash / window.location.hash in
         a script. These are the pages most likely to actually read
         location.hash on load, which is what a #__proto__[...] payload
         needs to land anywhere.
       - Fallback: if nothing matches that, --max-urls random URLs from
         everything seen in the XML (no hash-awareness signal available,
         so there's nothing smarter to rank by).
     Written to this item's Outputs/test_outputs/urls.txt, one URL per
     line. If there's no XML yet, or no URLs in it, this step is skipped
     and said so - the wordlists above are still written either way.

Usage
-----
    python3 protopoll_wordlists.py --project-root /path/to/Projects/MyProject
    python3 protopoll_wordlists.py --project-root ... --max-urls 3
    python3 protopoll_wordlists.py --project-root ... --probes-file /path/to/custom_probes.json
"""
import argparse
import base64
import binascii
import glob
import json
import os
import random
import re
import sys
import xml.etree.ElementTree as ET

SELF_ID = "WSTG-INJT-22"
PROBES_FILENAME = "proto_pollution_probes.json"
DEFAULT_MAX_URLS = 5

HASH_HREF_RE = re.compile(r"""href\s*=\s*['"]#[^'"]+['"]""", re.IGNORECASE)
HASH_JS_RE = re.compile(r"""(?:window\s*\.\s*)?location\s*\.\s*hash\b""", re.IGNORECASE)


def find_item_folder(project_root, wstg_id):
    """Scan the project tree for the one folder named after wstg_id - never a
    hardcoded category path, since category folder names/numbers do drift
    (and have, elsewhere in this project) while the WSTG ID itself doesn't."""
    wstg_id = wstg_id.strip().upper()
    for root, dirs, _files in os.walk(project_root):
        for d in dirs:
            if d.strip().upper() == wstg_id:
                return os.path.join(root, d)
    return None


def atomic_write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def find_probes_file(self_dir, override):
    if override:
        if os.path.isfile(override):
            return override
        print(f"[error] --probes-file not found: {override}", file=sys.stderr)
        sys.exit(1)
    for segs in (("Utilities", "python"), ("Inputs", "JSON")):
        candidate = os.path.join(self_dir, *segs, PROBES_FILENAME)
        if os.path.isfile(candidate):
            return candidate
    return None


def load_probes(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    body = data.get("Body_Data")
    url_hash = data.get("URL_Hash")
    url_seg = data.get("URL_Seg")
    if not isinstance(body, list) or not isinstance(url_hash, list) or not isinstance(url_seg, list):
        print(f"[error] {path} is missing one of Body_Data / URL_Hash / URL_Seg as a list.", file=sys.stderr)
        sys.exit(1)
    return body, url_hash, url_seg


def write_wordlists(self_dir, body, url_hash, url_seg):
    wl_dir = os.path.join(self_dir, "Inputs", "Wordlists")
    body_out = os.path.join(wl_dir, "Body_Data.txt")
    hash_out = os.path.join(wl_dir, "URL_Hash.txt")
    seg_out = os.path.join(wl_dir, "URL_Seg.txt")

    atomic_write_text(body_out, "\n".join(json.dumps(obj, separators=(",", ":")) for obj in body) + "\n")
    atomic_write_text(hash_out, "\n".join(str(s) for s in url_hash) + "\n")
    atomic_write_text(seg_out, "\n".join(str(s) for s in url_seg) + "\n")

    print(f"[+] {body_out} <- {len(body)} entries", flush=True)
    print(f"[+] {hash_out} <- {len(url_hash)} entries", flush=True)
    print(f"[+] {seg_out} <- {len(url_seg)} entries", flush=True)


# ------------------------------- XML scanning -------------------------------

def split_http_message(raw_bytes):
    """Raw HTTP response bytes -> (headers_text, body_bytes). Tries CRLF then LF
    for the header/body blank-line separator; if neither is found, treats the
    whole thing as headers with no body."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw_bytes.find(sep)
        if idx != -1:
            return raw_bytes[:idx].decode("latin-1", errors="replace"), raw_bytes[idx + len(sep):]
    return raw_bytes.decode("latin-1", errors="replace"), b""


def decode_response_body(item_el):
    resp_el = item_el.find("response")
    if resp_el is None or not resp_el.text:
        return None
    is_b64 = (resp_el.get("base64") or "").strip().lower() == "true"
    raw_text = resp_el.text
    if is_b64:
        try:
            raw_bytes = base64.b64decode(raw_text, validate=False)
        except (binascii.Error, ValueError):
            return None
    else:
        raw_bytes = raw_text.encode("utf-8", errors="replace")
    _headers, body = split_http_message(raw_bytes)
    return body.decode("utf-8", errors="replace")


def iter_burp_items(xml_path):
    """Yield (url, body_text_or_None) for each <item> in one Burp Proxy XML
    export. Files that are not this schema (wrong root element, not XML at
    all, parse errors) are skipped quietly - this item's Inputs/XML/ can
    hold more than one dataset and not all of them have to be Burp XML."""
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        return
    root = tree.getroot()
    if root.tag != "items":
        return
    for item_el in root.findall("item"):
        url_el = item_el.find("url")
        url = (url_el.text or "").strip() if url_el is not None else ""
        if not url:
            continue
        body = decode_response_body(item_el)
        yield url, body


def looks_hash_aware(body_text):
    if not body_text:
        return False
    return bool(HASH_HREF_RE.search(body_text) or HASH_JS_RE.search(body_text))


def collect_candidate_urls(self_dir, max_urls, rng):
    """Returns (selected_urls, item_count, method) where method is
    'hash-aware pages' or 'random (no hash-aware pages found)'."""
    xml_dir = os.path.join(self_dir, "Inputs", "XML")
    xml_files = sorted(glob.glob(os.path.join(xml_dir, "*.xml")))
    if not xml_files:
        return [], 0, None

    all_urls = []
    seen_all = set()
    hash_urls = []
    seen_hash = set()
    item_count = 0

    for xf in xml_files:
        for url, body in iter_burp_items(xf):
            item_count += 1
            if url not in seen_all:
                seen_all.add(url)
                all_urls.append(url)
            if looks_hash_aware(body) and url not in seen_hash:
                seen_hash.add(url)
                hash_urls.append(url)

    if hash_urls:
        return hash_urls[:max_urls], item_count, "hash-aware pages"
    if all_urls:
        k = min(max_urls, len(all_urls))
        return rng.sample(all_urls, k), item_count, "random (no hash-aware pages found)"
    return [], item_count, None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-root", required=True, help="Project directory.")
    ap.add_argument("--probes-file", default=None, help="Override: explicit path to proto_pollution_probes.json.")
    ap.add_argument("--max-urls", type=int, default=DEFAULT_MAX_URLS, help=f"Target URLs to pick for urls.txt (default {DEFAULT_MAX_URLS}).")
    ap.add_argument("--seed", type=int, default=None, help="Random seed for the URL fallback pick, for a reproducible run (testing only).")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project_root)
    if not os.path.isdir(project_root):
        print(f"[error] --project-root is not a directory: {project_root}", file=sys.stderr)
        sys.exit(1)

    self_dir = find_item_folder(project_root, SELF_ID)
    if not self_dir:
        print(f"[error] no folder found for {SELF_ID} under {project_root}", file=sys.stderr)
        sys.exit(1)

    probes_file = find_probes_file(self_dir, args.probes_file)
    if not probes_file:
        print(
            f"[error] {PROBES_FILENAME} not found in {SELF_ID}'s Utilities/python or Inputs/JSON, "
            f"and no --probes-file given.",
            file=sys.stderr,
        )
        sys.exit(1)
    body, url_hash, url_seg = load_probes(probes_file)
    print(f"[info] probes: {probes_file}", flush=True)
    write_wordlists(self_dir, body, url_hash, url_seg)

    rng = random.Random(args.seed)
    selected, item_count, method = collect_candidate_urls(self_dir, args.max_urls, rng)
    if item_count == 0:
        print("[info] no Burp Proxy XML found in Inputs/XML/ yet - skipping urls.txt.", flush=True)
    elif not selected:
        print(f"[info] {item_count} XML item(s) read, but none had a usable URL - skipping urls.txt.", flush=True)
    else:
        urls_out = os.path.join(self_dir, "Outputs", "test_outputs", "urls.txt")
        atomic_write_text(urls_out, "\n".join(selected) + "\n")
        print(f"[+] {urls_out} <- {len(selected)} URL(s), picked by: {method} (from {item_count} XML item(s) read)", flush=True)


if __name__ == "__main__":
    main()
