#!/usr/bin/env python3
"""
WSTG-INJT-22 (Prototype Pollution) - hash fragment opener.

The "second script" - separate from protopoll_wordlists.py and run on its own,
only when the operator wants to watch client-side behavior live. Reads the
files protopoll_wordlists.py prepared:

    Outputs/test_outputs/urls.txt        - candidate target pages (up to 5)
    Inputs/Wordlists/URL_Hash.txt        - #__proto__[...] payload strings

...and opens each target URL in Firefox with one payload appended as the URL
fragment (#...), to see whether the page's own client-side code (often a
hash-based router) does anything unsafe with it - prototype pollution via
location.hash has no server-side trace, so this has to be watched live in a
real browser.

Rules this follows (my own interpretation of "never more than 3x payloads to
one url, many urls can be opened same time, with different hash frags" - see
the README's note on this if you want something different):

  - Every URL in urls.txt gets used.
  - No single URL gets more than --payloads-per-url (default 3) different
    payloads in one run - the fragment is the whole point of the test, so
    piling on more than a few per page just adds noise, not coverage.
  - Payloads are handed out across URLs from one shared, continuously
    advancing cycle through URL_Hash.txt, so consecutive URLs in the job
    list get different payloads rather than every URL repeating the same
    first three - the 14 shipped payloads spread across up to 5 URLs x 3
    slots (15) cover nearly all of them in one run.
  - Opens happen one at a time, in order, waiting --delay seconds (default
    10) between each - not literally all at once. "Many URLs" in one run
    just means the job list isn't limited to one URL, not that windows pop
    up simultaneously; that would make them harder to watch than useful.

Usage
-----
    python3 hash_fragment_opener.py --project-root /path/to/Projects/MyProject
    python3 hash_fragment_opener.py --project-root ... --new-window --delay 15
    python3 hash_fragment_opener.py --project-root ... --dry-run   # preview the job list, open nothing
"""
import argparse
import itertools
import os
import subprocess
import sys
import time

SELF_ID = "WSTG-INJT-22"
DEFAULT_PAYLOADS_PER_URL = 3
DEFAULT_DELAY = 10.0


def find_item_folder(project_root, wstg_id):
    """Scan the project tree for the one folder named after wstg_id - never a
    hardcoded category path (see protopoll_wordlists.py / the rest of this
    project for why)."""
    wstg_id = wstg_id.strip().upper()
    for root, dirs, _files in os.walk(project_root):
        for d in dirs:
            if d.strip().upper() == wstg_id:
                return os.path.join(root, d)
    return None


def read_lines(path):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip() != ""]


def build_jobs(urls, payloads, payloads_per_url):
    """[(url, payload), ...] - every url gets up to payloads_per_url entries,
    pulled in order from one shared cycle through payloads so consecutive
    urls get different ones (see the module docstring)."""
    jobs = []
    cycle = itertools.cycle(payloads)
    per_url = min(payloads_per_url, len(payloads))
    for url in urls:
        for _ in range(per_url):
            jobs.append((url, next(cycle)))
    return jobs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-root", required=True, help="Project directory.")
    ap.add_argument("--payloads-per-url", type=int, default=DEFAULT_PAYLOADS_PER_URL, help=f"Max payloads tried against one URL (default {DEFAULT_PAYLOADS_PER_URL}).")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help=f"Seconds to wait between opens (default {DEFAULT_DELAY}).")
    ap.add_argument("--new-window", action="store_true", help="Open each in a new window instead of a new tab in the same window.")
    ap.add_argument("--firefox-bin", default="firefox", help='Firefox command to run (default "firefox").')
    ap.add_argument("--urls-file", default=None, help="Override: explicit path to urls.txt.")
    ap.add_argument("--hash-file", default=None, help="Override: explicit path to URL_Hash.txt.")
    ap.add_argument("--dry-run", action="store_true", help="Print the job list and exit - opens nothing.")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project_root)
    if not os.path.isdir(project_root):
        print(f"[error] --project-root is not a directory: {project_root}", file=sys.stderr)
        sys.exit(1)

    self_dir = find_item_folder(project_root, SELF_ID)
    if not self_dir:
        print(f"[error] no folder found for {SELF_ID} under {project_root}", file=sys.stderr)
        sys.exit(1)

    urls_path = args.urls_file or os.path.join(self_dir, "Outputs", "test_outputs", "urls.txt")
    hash_path = args.hash_file or os.path.join(self_dir, "Inputs", "Wordlists", "URL_Hash.txt")

    urls = read_lines(urls_path)
    if urls is None:
        print(f"[error] {urls_path} not found - run protopoll_wordlists.py first (it needs Burp Proxy XML in Inputs/XML/ to produce it).", file=sys.stderr)
        sys.exit(1)
    if not urls:
        print(f"[error] {urls_path} is empty.", file=sys.stderr)
        sys.exit(1)

    payloads = read_lines(hash_path)
    if payloads is None:
        print(f"[error] {hash_path} not found - run protopoll_wordlists.py first.", file=sys.stderr)
        sys.exit(1)
    if not payloads:
        print(f"[error] {hash_path} is empty.", file=sys.stderr)
        sys.exit(1)

    jobs = build_jobs(urls, payloads, args.payloads_per_url)
    print(f"[info] {len(urls)} URL(s), {len(payloads)} payload(s), up to {args.payloads_per_url} per URL -> {len(jobs)} open(s), {args.delay}s apart.", flush=True)

    if args.dry_run:
        for i, (url, payload) in enumerate(jobs, 1):
            print(f"[dry-run] {i}/{len(jobs)}: {url}{payload}", flush=True)
        return

    flag = "--new-window" if args.new_window else "--new-tab"
    for i, (url, payload) in enumerate(jobs, 1):
        full_url = f"{url}{payload}"
        try:
            subprocess.Popen([args.firefox_bin, flag, full_url])
            print(f"[+] {i}/{len(jobs)}: opened {full_url}", flush=True)
        except FileNotFoundError:
            print(f"[error] {args.firefox_bin!r} is not on PATH. Install Firefox or pass --firefox-bin /path/to/firefox.", file=sys.stderr)
            sys.exit(1)
        if i < len(jobs):
            time.sleep(args.delay)

    print(f"[info] done - {len(jobs)} open(s) issued.", flush=True)


if __name__ == "__main__":
    main()
