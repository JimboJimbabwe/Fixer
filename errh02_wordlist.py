#!/usr/bin/env python3
"""
WSTG-ERRH-02 (Stack Traces) - unicode wordlist generator.

Builds a plain, one-value-per-line wordlist of unusual Unicode characters
(control chars, invisible/bidi-override chars, homoglyphs, astral-plane
oddities, ...) from unicode.json, meant to be thrown at inputs to see
whether the application leaks a stack trace instead of handling them
cleanly.

This script and its sibling, errh01_wordlist.py (WSTG-ERRH-01 - Improper
Error Handling), are meant to be run as a *pair* and deliberately
coordinate so the two resulting wordlists don't just duplicate each other:

  - If this item (ERRH-02) already has a wordlist, nothing is done (it's
    already made its contribution) - pass --force to rebuild it anyway.
  - Otherwise, this checks whether the sibling (ERRH-01) already has a
    wordlist. If it does, this reads it and OMITS every character already
    in it before picking - so between the two of you, you get two
    non-overlapping lists covering more of the Unicode oddity space instead
    of two copies of basically the same thing.
  - If the sibling has nothing yet either, this just builds its list
    normally (a random, category-distributed selection - not just the
    first N entries in the file, so the result isn't skewed toward
    whichever category happens to come first in unicode.json).

Whichever of the two scripts runs first "claims" nothing in particular -
it just goes first and the other one adapts. Run them in either order.

unicode.json is looked for, in order: this item's own Inputs/JSON/, then
the sibling item's Inputs/JSON/, then --unicode-file if given. One copy in
either folder is enough; you don't have to duplicate it, though you can.

Usage
-----
    python3 errh02_wordlist.py --project-root /path/to/Projects/MyProject
    python3 errh02_wordlist.py --project-root ... --count 120
    python3 errh02_wordlist.py --project-root ... --force
"""
import argparse
import json
import os
import random
import sys

SELF_ID = "WSTG-ERRH-02"
OTHER_ID = "WSTG-ERRH-01"
DEFAULT_COUNT = 80
UNICODE_FILENAME = "unicode.json"


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


# Characters that would break a newline-delimited "one value per line" text
# file if written raw - real line/paragraph separators (LF, CR, VT, FF, the
# C0/C1 control range, NEL, LS, PS) plus DEL. unicode.json's "C0 Control
# Characters" and "Invisible & Directional Characters" categories legitimately
# include several of these (that's the point - they're real ERRH/stack-trace
# payloads), so they can't just be skipped; they're backslash-escaped instead
# (\x00, \n, \r,  , ...), same style as the JSON's own unicode_escape
# field, so every line in the file stays exactly one entry.
LINE_BREAKING = {0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0x2028, 0x2029}


def escape_for_line(ch):
    cp = ord(ch)
    if cp < 0x20 or cp == 0x7f or cp in LINE_BREAKING:
        if cp <= 0xff:
            return f"\\x{cp:02x}"
        if cp <= 0xffff:
            return f"\\u{cp:04x}"
        return f"\\U{cp:08x}"
    return ch


def atomic_write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def read_existing_wordlist(path):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip() != ""]


def find_unicode_file(self_dir, other_dir, override):
    if override:
        if os.path.isfile(override):
            return override
        print(f"[error] --unicode-file not found: {override}", file=sys.stderr)
        sys.exit(1)
    for d in (self_dir, other_dir):
        if not d:
            continue
        candidate = os.path.join(d, "Inputs", "JSON", UNICODE_FILENAME)
        if os.path.isfile(candidate):
            return candidate
    return None


def load_pool(unicode_file):
    """unicode.json -> [(category, char), ...], one entry per codepoint. The
    actual character always comes from decimal/chr(), never the JSON's own
    "char" field - several categories (control chars, invisible chars,
    private-use-area) store a human-readable placeholder or an empty string
    there on purpose, since the real character either can't be shown safely
    in JSON or has no glyph at all outside a specific font. decimal is the
    one field that's always the real codepoint."""
    with open(unicode_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    pool = []
    for category, entries in data.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            dec = entry.get("decimal")
            if not isinstance(dec, int):
                continue
            try:
                ch = chr(dec)
            except (ValueError, OverflowError):
                continue
            pool.append((category, ch))
    return pool


def stratified_sample(pool, count, exclude, rng):
    """Random, category-distributed sample of `count` characters from pool,
    skipping anything in `exclude`. Distributed = roughly even picks per
    category rather than one global random.sample(), so a category with a
    lot of entries can't accidentally crowd out the smaller ones."""
    by_category = {}
    for category, ch in pool:
        if escape_for_line(ch) in exclude:  # exclude holds the *written* (escaped) form
            continue
        by_category.setdefault(category, []).append(ch)
    for chars in by_category.values():
        rng.shuffle(chars)

    categories = list(by_category.keys())
    rng.shuffle(categories)
    picked = []
    seen = set()  # the same raw char can legitimately appear under two
                   # categories in unicode.json (e.g. the benzene ring symbol
                   # is filed under both "Geometric & Symbols" and
                   # "Miscellaneous Oddities") - skip a repeat so one list
                   # never ends up with the same payload twice.
    cursors = {c: 0 for c in categories}
    while len(picked) < count and categories:
        progressed = False
        for c in list(categories):
            if len(picked) >= count:
                break
            chars = by_category[c]
            i = cursors[c]
            if i >= len(chars):
                categories.remove(c)
                continue
            ch = chars[i]
            cursors[c] = i + 1
            progressed = True
            if ch in seen:
                continue
            seen.add(ch)
            picked.append(ch)
        if not progressed:
            break
    rng.shuffle(picked)  # don't leave it grouped by the category round-robin
    return picked


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-root", required=True, help="Project directory.")
    ap.add_argument("--count", type=int, default=DEFAULT_COUNT, help=f"Target wordlist size (default {DEFAULT_COUNT}).")
    ap.add_argument("--unicode-file", default=None, help="Override: explicit path to unicode.json.")
    ap.add_argument("--force", action="store_true", help="Rebuild even if this item already has a wordlist.")
    ap.add_argument("--seed", type=int, default=None, help="Random seed, for a reproducible run (testing only).")
    args = ap.parse_args()

    project_root = os.path.abspath(args.project_root)
    if not os.path.isdir(project_root):
        print(f"[error] --project-root is not a directory: {project_root}", file=sys.stderr)
        sys.exit(1)

    self_dir = find_item_folder(project_root, SELF_ID)
    if not self_dir:
        print(f"[error] no folder found for {SELF_ID} under {project_root}", file=sys.stderr)
        sys.exit(1)
    other_dir = find_item_folder(project_root, OTHER_ID)
    if not other_dir:
        print(f"[warn] no folder found for {OTHER_ID} - proceeding as if it has no wordlist yet.", flush=True)

    self_out = os.path.join(self_dir, "Outputs", "test_outputs", f"{SELF_ID}_WL.txt")
    other_out = os.path.join(other_dir, "Outputs", "test_outputs", f"{OTHER_ID}_WL.txt") if other_dir else None

    if os.path.isfile(self_out) and not args.force:
        print(f"[skip] {SELF_ID} already has a wordlist at {self_out} - not regenerating (use --force to rebuild).", flush=True)
        return

    other_existing = read_existing_wordlist(other_out) if other_out else None
    exclude = set(other_existing) if other_existing else set()
    if other_existing:
        print(f"[info] {OTHER_ID} already has a wordlist ({len(other_existing)} entries) - "
              f"omitting those from {SELF_ID}'s list.", flush=True)
    else:
        print(f"[info] {OTHER_ID} has no wordlist yet - building {SELF_ID}'s list normally.", flush=True)

    unicode_file = find_unicode_file(self_dir, other_dir, args.unicode_file)
    if not unicode_file:
        print(f"[error] unicode.json not found in {SELF_ID}'s or {OTHER_ID}'s Inputs/JSON/, "
              f"and no --unicode-file given.", file=sys.stderr)
        sys.exit(1)

    pool = load_pool(unicode_file)
    if not pool:
        print(f"[error] {unicode_file} has no usable entries.", file=sys.stderr)
        sys.exit(1)

    rng = random.Random(args.seed)
    picked = stratified_sample(pool, args.count, exclude, rng)
    if not picked:
        print(f"[error] nothing left to pick after excluding {OTHER_ID}'s wordlist - "
              f"it already covers everything in {unicode_file}.", file=sys.stderr)
        sys.exit(1)

    atomic_write_text(self_out, "\n".join(escape_for_line(ch) for ch in picked) + "\n")
    skipped_note = f", {len(exclude)} chars omitted (already in {OTHER_ID}'s list)" if exclude else ""
    print(f"[+] {self_out} <- {len(picked)} entries from {unicode_file}{skipped_note}", flush=True)


if __name__ == "__main__":
    main()
