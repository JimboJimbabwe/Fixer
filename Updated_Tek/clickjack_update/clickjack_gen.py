#!/usr/bin/env python3
"""
Replace a string in an HTML file with first_half + each line from input_txt.
Produces one output HTML file per line in the input text file.

Usage:
    python replace_html.py <html_file> <input_txt> --search <search_string> --first-half <first_half>

Example:
    python replace_html.py template.html paths.txt --search "example.com" --first-half "example.com"
    # If paths.txt has "/path/here", replaces "example.com" with "example.com/path/here"
"""

import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Replace a string in an HTML file for each line in an input text file."
    )
    parser.add_argument("html_file", help="Path to the source HTML file")
    parser.add_argument("input_txt", help="Path to the input text file (one value per line)")
    parser.add_argument("--search", required=True, help="String to search for in the HTML")
    parser.add_argument("--first-half", required=True, dest="first_half",
                        help="First half of the replacement string (line from input_txt is appended)")

    args = parser.parse_args()

    html_path = Path(args.html_file)
    txt_path = Path(args.input_txt)

    if not html_path.exists():
        print(f"Error: HTML file '{html_path}' not found.", file=sys.stderr)
        sys.exit(1)

    if not txt_path.exists():
        print(f"Error: Input text file '{txt_path}' not found.", file=sys.stderr)
        sys.exit(1)

    html_content = html_path.read_text(encoding="utf-8")

    if args.search not in html_content:
        print(f"Warning: Search string '{args.search}' not found in '{html_path}'.")

    lines = txt_path.read_text(encoding="utf-8").splitlines()
    lines = [line for line in lines if line.strip()]  # skip blank lines

    if not lines:
        print("Error: Input text file is empty or has no non-blank lines.", file=sys.stderr)
        sys.exit(1)

    stem = html_path.stem
    suffix = html_path.suffix
    out_dir = html_path.parent

    for i, line in enumerate(lines, start=1):
        replacement = args.first_half + line.strip()
        new_content = html_content.replace(args.search, replacement)

        out_filename = out_dir / f"{stem}_{i}{suffix}"
        out_filename.write_text(new_content, encoding="utf-8")
        print(f"[{i}] '{args.search}' → '{replacement}'  →  {out_filename}")

    print(f"\nDone. {len(lines)} file(s) written.")


if __name__ == "__main__":
    main()
