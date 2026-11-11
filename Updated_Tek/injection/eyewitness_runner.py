#!/usr/bin/env python3
"""
eyewitness_runner.py — Build and optionally run an EyeWitness screenshot command.

Prints the exact EyeWitness command it will run so you can copy/reuse it,
then launches EyeWitness unless --dry-run is passed.

Usage:
  python eyewitness_runner.py --input-urls urls.txt --images-folder ./shots \\
                              [--delay 2] [--resolution 1920x1080] [--dry-run]

Requirements:
  EyeWitness must be on your PATH or installed at /opt/EyeWitness/EyeWitness.py
  https://github.com/RedSiege/EyeWitness
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# EyeWitness discovery
# ---------------------------------------------------------------------------

EYEWITNESS_CANDIDATES = [
    "eyewitness",           # installed via pip / pipx / package manager
    "EyeWitness",           # case-sensitive PATH entry
    "/opt/EyeWitness/EyeWitness.py",    # common manual install location
    "/usr/share/eyewitness/EyeWitness.py",
]


def find_eyewitness() -> str | None:
    """Return the first usable EyeWitness executable found, or None."""
    for candidate in EYEWITNESS_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
        if shutil.which(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Command building
# ---------------------------------------------------------------------------

def build_command(
    eyewitness_bin: str,
    input_urls: str,
    images_folder: str,
    delay: int | None,
    resolution: str | None,
    extra_flags: list[str],
) -> list[str]:
    """Assemble the EyeWitness CLI command as a list of tokens."""
    cmd: list[str] = []

    # EyeWitness.py (Python script) vs compiled binary
    if eyewitness_bin.endswith(".py"):
        cmd += ["python3", eyewitness_bin]
    else:
        cmd.append(eyewitness_bin)

    cmd += [
        "--web",                   # web screenshot mode
        "-f", input_urls,          # URL list
        "-d", images_folder,       # output directory
        "--no-prompt",             # skip the interactive confirmation
    ]

    if delay is not None:
        cmd += ["--delay", str(delay)]

    if resolution:
        cmd += ["--resolution", resolution]

    cmd.extend(extra_flags)

    return cmd


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_resolution(value: str) -> str:
    """Validate that the resolution string is WIDTHxHEIGHT (e.g. 1920x1080)."""
    parts = value.lower().split("x")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        raise argparse.ArgumentTypeError(
            f"Resolution must be WIDTHxHEIGHT (e.g. 1920x1080), got: {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input-urls", required=True,
        metavar="FILE",
        help="URL wordlist produced by burp_scaffold.py (one URL per line)",
    )
    parser.add_argument(
        "--images-folder", required=True,
        metavar="DIR",
        help="Directory where EyeWitness will write screenshots and its report",
    )
    parser.add_argument(
        "--delay",
        metavar="SECONDS",
        type=int,
        default=None,
        help="Seconds to wait between requests (default: EyeWitness default)",
    )
    parser.add_argument(
        "--resolution",
        metavar="WxH",
        type=validate_resolution,
        default=None,
        help="Screenshot resolution, e.g. 1920x1080 (default: EyeWitness default)",
    )
    parser.add_argument(
        "--eyewitness-bin",
        metavar="PATH",
        default=None,
        help="Path to EyeWitness binary / script (auto-detected if not set)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the command and exit without running EyeWitness",
    )
    # Pass-through for any extra EyeWitness flags not explicitly modelled above
    parser.add_argument(
        "extra",
        nargs=argparse.REMAINDER,
        help="Any additional flags passed straight through to EyeWitness",
    )

    args = parser.parse_args()

    # --- Validate inputs ---
    input_path = Path(args.input_urls)
    if not input_path.exists():
        sys.exit(f"[!] Input URL file not found: {args.input_urls}")

    url_count = sum(
        1 for ln in input_path.read_text(encoding="utf-8").splitlines() if ln.strip()
    )
    if url_count == 0:
        sys.exit("[!] Input URL file is empty.")

    # --- Locate EyeWitness ---
    ew_bin = args.eyewitness_bin or find_eyewitness()
    if not ew_bin:
        print(
            "[!] EyeWitness not found on PATH or at common install locations.\n"
            "    Install it:  pip install eyewitness  or  clone from GitHub\n"
            "    Then re-run with --eyewitness-bin /path/to/EyeWitness.py"
        )
        sys.exit(1)

    # --- Build command ---
    cmd = build_command(
        eyewitness_bin=ew_bin,
        input_urls=str(input_path.resolve()),
        images_folder=args.images_folder,
        delay=args.delay,
        resolution=args.resolution,
        extra_flags=args.extra,
    )

    # --- Print the command (always) ---
    print(f"\n[*] EyeWitness binary : {ew_bin}")
    print(f"[*] URLs to process   : {url_count}")
    print(f"[*] Output folder     : {args.images_folder}")
    if args.delay is not None:
        print(f"[*] Delay             : {args.delay}s")
    if args.resolution:
        print(f"[*] Resolution        : {args.resolution}")
    print()
    print("─" * 64)
    print("  Command:")
    print("  " + " ".join(cmd))
    print("─" * 64)

    if args.dry_run:
        print("\n[~] --dry-run set. Exiting without running EyeWitness.\n")
        return

    # --- Run ---
    print(f"\n[*] Launching EyeWitness against {url_count} URL(s) ...\n")
    try:
        result = subprocess.run(cmd, check=False)
    except FileNotFoundError:
        sys.exit(f"[!] Could not execute: {cmd[0]}\n    Check the path and try again.")
    except KeyboardInterrupt:
        print("\n[~] Interrupted by user.")
        sys.exit(130)

    if result.returncode == 0:
        print(f"\n[+] EyeWitness finished. Screenshots in: {args.images_folder}")
    else:
        print(f"\n[!] EyeWitness exited with code {result.returncode}.")
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
