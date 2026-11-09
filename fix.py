#!/usr/bin/env python3
"""
scaffold_missing_folders.py

Fixes the "50/115 assessment folders present" discrepancy by creating empty
folders for every WSTG item that has no script/data file (and therefore
never got a folder created for it on this machine), so the folder count
matches the full 115-item checklist (as it already does on a machine where
these were scaffolded, e.g. the Windows copy).

This does NOT create any scripts or content - it only creates empty
directories named WSTG-XXXX-NN, which is all the preflight folder-presence
check (indexTestDirs in lib/resources.js) looks for.

Usage:
    python3 scaffold_missing_folders.py /path/to/WSTG_Repository
    python3 scaffold_missing_folders.py /path/to/WSTG_Repository --dry-run
"""
import argparse
import re
import sys
from pathlib import Path

# The 65 WSTG-IDs confirmed (via wstg_project_config.json) to have no script/data
# file of any kind - these never got a folder created on this Kali box.
MISSING_IDS = [
    "WSTG-APIT-01", "WSTG-APIT-02", "WSTG-APIT-03", "WSTG-APIT-04", "WSTG-APIT-99",
    "WSTG-ATHN-01", "WSTG-ATHN-04", "WSTG-ATHN-05", "WSTG-ATHN-06",
    "WSTG-ATHZ-01", "WSTG-ATHZ-03", "WSTG-ATHZ-05",
    "WSTG-BUSL-02", "WSTG-BUSL-07", "WSTG-BUSL-10",
    "WSTG-CLNT-01", "WSTG-CLNT-02", "WSTG-CLNT-03", "WSTG-CLNT-04", "WSTG-CLNT-05",
    "WSTG-CLNT-06", "WSTG-CLNT-07", "WSTG-CLNT-10", "WSTG-CLNT-11", "WSTG-CLNT-13",
    "WSTG-CLNT-14", "WSTG-CLNT-15",
    "WSTG-CONF-01", "WSTG-CONF-14", "WSTG-CONF-15",
    "WSTG-ERRH-01", "WSTG-ERRH-02",
    "WSTG-IDNT-01", "WSTG-IDNT-04", "WSTG-IDNT-05",
    "WSTG-INFO-06", "WSTG-INFO-07", "WSTG-INFO-09",
    "WSTG-INJT-01", "WSTG-INJT-02", "WSTG-INJT-03", "WSTG-INJT-05", "WSTG-INJT-06",
    "WSTG-INJT-07", "WSTG-INJT-08", "WSTG-INJT-09", "WSTG-INJT-10", "WSTG-INJT-11",
    "WSTG-INJT-12", "WSTG-INJT-13", "WSTG-INJT-14", "WSTG-INJT-15", "WSTG-INJT-16",
    "WSTG-INJT-17", "WSTG-INJT-18", "WSTG-INJT-19", "WSTG-INJT-20", "WSTG-INJT-21",
    "WSTG-INJT-22", "WSTG-INJT-23",
    "WSTG-SESS-05", "WSTG-SESS-08", "WSTG-SESS-10", "WSTG-SESS-11",
    "WSTG-WASM-01",
]

ID_RE = re.compile(r"^(WSTG-[A-Za-z]{4}-\d{2})(?:_.*)?$", re.IGNORECASE)


def find_category_dir(root: Path, wstg_id: str) -> Path | None:
    """Find the parent directory of any existing sibling folder sharing this
    item's 4-letter category (e.g. for WSTG-ATHN-01, locate the folder that
    already holds WSTG-ATHN-02, WSTG-ATHN-03, etc.) by walking up to 4 levels."""
    category = wstg_id.split("-")[1].upper()  # e.g. "ATHN"
    for path in root.rglob("WSTG-*"):
        if not path.is_dir():
            continue
        depth = len(path.relative_to(root).parts)
        if depth > 4:
            continue
        m = ID_RE.match(path.name)
        if m and m.group(1).split("-")[1].upper() == category:
            return path.parent
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo_root", help="Path to the WSTG_Repository folder")
    ap.add_argument("--dry-run", action="store_true", help="Show what would be created, create nothing")
    args = ap.parse_args()

    root = Path(args.repo_root).expanduser().resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    created, already_present, placed_at_root = [], [], []

    for wstg_id in MISSING_IDS:
        # Does a folder for this ID already exist somewhere (case-insensitive)?
        existing = next(
            (p for p in root.rglob("WSTG-*")
             if p.is_dir()
             and len(p.relative_to(root).parts) <= 4
             and (m := ID_RE.match(p.name))
             and m.group(1).upper() == wstg_id.upper()),
            None,
        )
        if existing:
            already_present.append(wstg_id)
            continue

        category_dir = find_category_dir(root, wstg_id)
        target_parent = category_dir if category_dir else root
        target = target_parent / wstg_id
        if not category_dir:
            placed_at_root.append(wstg_id)

        if args.dry_run:
            print(f"[dry-run] would create: {target}")
        else:
            target.mkdir(parents=True, exist_ok=True)
            print(f"created: {target}")
        created.append(wstg_id)

    print()
    print(f"{'Would create' if args.dry_run else 'Created'} {len(created)} folder(s).")
    if already_present:
        print(f"Already present (skipped): {', '.join(already_present)}")
    if placed_at_root:
        print(f"No existing category folder found for: {', '.join(placed_at_root)} "
              f"- placed directly under {root}")


if __name__ == "__main__":
    main()
