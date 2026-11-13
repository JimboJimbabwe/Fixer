#!/usr/bin/env python3
"""
findings_tool.py - two-stage pentest findings workflow.

  Stage 1 (CLI):  python findings_tool.py
      Type finding titles one per line (blank line to finish). They are pushed
      straight into findings.json as empty templates.

  Stage 2 (GUI):  python findings_tool.py --stage_2 true
      Card list on the left, scrollable editor on the right. Switching findings,
      Ctrl/Cmd+S, the Save button and closing the window all write to the JSON.

Only the Python standard library (tkinter) is used.
Optional: --file path/to/other.json
"""
import argparse
import copy
import datetime
import json
import os
import shutil
import sys
import tempfile

DEFAULT_FILE = "findings.json"
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
def blank_finding(title=""):
    return {
        "title": title,
        "path": "",
        "images": [],
        "cwe": {"name": "", "number": "", "description": ""},
        "owasp_mapping": {"name": "", "number": "", "severity": ""},
        "description": {
            "owasp_sentence": "",
            "what_is_the_vuln": "",
            "why_is_it_bad": {"summary": "", "how": ""},
        },
        "impact": "",
        "remediation": "",
        "additional_recommendations": "",
        "testing_notes": "",
        "affected_urls": [],
    }


TEMPLATE = blank_finding()


def normalize(tmpl, data):
    """Fill missing keys from the template, never dropping unknown keys."""
    if isinstance(tmpl, dict):
        data = data if isinstance(data, dict) else {}
        out = {k: normalize(v, data.get(k)) for k, v in tmpl.items()}
        for k, v in data.items():
            if k not in out:
                out[k] = v
        return out
    if isinstance(tmpl, list):
        if isinstance(data, list):
            return [str(x) for x in data]
        if isinstance(data, str) and data.strip():
            return [data]
        return []
    if data is None:
        return ""
    return data if isinstance(data, str) else str(data)


def load_findings(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}")
    if isinstance(raw, dict) and isinstance(raw.get("findings"), list):
        raw = raw["findings"]
    if not isinstance(raw, list):
        raise ValueError(f"{path} must contain a JSON list of findings")
    return [normalize(TEMPLATE, f if isinstance(f, dict) else {"title": str(f)}) for f in raw]


def save_findings(path, findings):
    """Atomic write (temp file + replace) and a .bak of the previous version."""
    directory = os.path.dirname(os.path.abspath(path))
    if os.path.exists(path):
        try:
            shutil.copy2(path, path + ".bak")
        except OSError:
            pass
    fd, tmp = tempfile.mkstemp(prefix=".findings_", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def get_in(d, path):
    for k in path:
        d = d.get(k, "") if isinstance(d, dict) else ""
    return d


def set_in(d, path, value):
    for k in path[:-1]:
        d = d.setdefault(k, {})
    d[path[-1]] = value


def iter_leaves(tmpl, data, path=()):
    for k, tv in tmpl.items():
        if k == "title":
            continue
        v = data.get(k) if isinstance(data, dict) else None
        if isinstance(tv, dict):
            yield from iter_leaves(tv, v, path + (k,))
        else:
            yield path + (k,), v


def completeness(f):
    leaves = list(iter_leaves(TEMPLATE, f))
    filled = sum(1 for _, v in leaves if (v if isinstance(v, list) else (v or "").strip()))
    return int(round(100 * filled / len(leaves))) if leaves else 0


def preview_lines(f):
    """(indent, key, value_text, filled) rows - filled=None marks a group header."""
    rows = []

    def short(v, n=42):
        v = " ".join(str(v).split())
        return v if len(v) <= n else v[: n - 1] + "…"

    def walk(t, d, ind):
        for k, tv in t.items():
            if k == "title":
                continue
            v = d.get(k) if isinstance(d, dict) else None
            if isinstance(tv, dict):
                rows.append((ind, k, "", None))
                walk(tv, v, ind + 1)
            elif isinstance(v, list):
                rows.append((ind, k, f"[{len(v)}]", bool(v)))
            else:
                v = v or ""
                rows.append((ind, k, short(v) if v.strip() else "—", bool(v.strip())))

    walk(TEMPLATE, f, 0)
    return rows


# --------------------------------------------------------------------------
# Stage 1 - CLI
# --------------------------------------------------------------------------
def stage_1(path):
    findings = load_findings(path)
    seen = {f["title"].strip().lower() for f in findings}
    script = os.path.basename(sys.argv[0])

    print(f"\n=== Stage 1: enter findings by observed title ({path}) ===")
    if findings:
        print(f"Loaded {len(findings)} existing finding(s); new ones are appended.")
    print("One title per line. Blank line (or Ctrl+D) to finish.\n")

    added = 0
    while True:
        try:
            title = input(f"  Finding {len(findings) + 1:02d} title > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not title:
            break
        if title.lower() in seen:
            print("    (duplicate title - skipped)")
            continue
        findings.append(blank_finding(title))
        seen.add(title.lower())
        added += 1
        save_findings(path, findings)  # push immediately so nothing is lost

    print(f"\n✔ Stage 1 complete: {added} added, {len(findings)} total in {path}")
    print("  Next step - fill in the details with the GUI:\n")
    print(f"      python {script} --stage_2 true\n")


# --------------------------------------------------------------------------
# Stage 2 - GUI
# --------------------------------------------------------------------------
def stage_2(path, findings):
    if not HAVE_TK:
        sys.exit("tkinter is not installed (Debian/Ubuntu: sudo apt install python3-tk)")
    if not findings:
        print(f"No findings in {path}. Run stage 1 first (python {os.path.basename(sys.argv[0])}), "
              "or add one from the GUI.")
    App(path, findings).mainloop()


try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    import tkinter.font as tkfont
    HAVE_TK = True
except ImportError:  # stage 1 must still work without tkinter
    HAVE_TK = False

    class _Stub:
        pass

    class tk:  # noqa: N801 - minimal stand-in so the class definitions below still load
        Frame = Label = Entry = Text = Tk = Canvas = _Stub
        TclError = Exception

    filedialog = messagebox = simpledialog = ttk = tkfont = None

BG = "#0e1014"
PANEL = "#161920"
PANEL_DARK = "#12141a"
CARD = "#1c2028"
CARD_SEL = "#262d3d"
INPUT = "#0f1217"
BORDER = "#2b303b"
FG = "#e7eaf0"
MUTED = "#8a92a6"
ACCENT = "#6d8dff"
ACCENT_HI = "#8aa3ff"
GREEN = "#3fb97f"
AMBER = "#e5a93d"
RED = "#e5564f"
DARK_TXT = "#0b0d12"
SEV_COLORS = {
    "Critical": "#d6336c", "High": "#e5564f", "Medium": "#e5a93d",
    "Low": "#4c9be8", "Informational": "#8a92a6",
}
F = {}


def init_fonts():
    fams = set(tkfont.families())

    def pick(*names):
        return next((n for n in names if n in fams), "Helvetica")

    ui = pick("Inter", "Segoe UI", "SF Pro Text", "Helvetica Neue", "Noto Sans", "DejaVu Sans")
    mono = pick("Cascadia Mono", "SF Mono", "Menlo", "Consolas", "DejaVu Sans Mono", "Courier New")
    F["body"] = tkfont.Font(family=ui, size=10)
    F["small"] = tkfont.Font(family=ui, size=9)
    F["small_b"] = tkfont.Font(family=ui, size=9, weight="bold")
    F["bold"] = tkfont.Font(family=ui, size=10, weight="bold")
    F["h1"] = tkfont.Font(family=ui, size=17, weight="bold")
    F["title"] = tkfont.Font(family=ui, size=14, weight="bold")
    F["section"] = tkfont.Font(family=ui, size=10, weight="bold")
    F["mono"] = tkfont.Font(family=mono, size=9)
    F["mono_b"] = tkfont.Font(family=mono, size=10, weight="bold")


def paint(w, color):
    if getattr(w, "_keep_bg", False):
        return
    try:
        w.configure(bg=color)
    except tk.TclError:
        pass
    for c in w.winfo_children():
        paint(c, color)


def bind_tree(w, seq, fn):
    w.bind(seq, fn)
    for c in w.winfo_children():
        bind_tree(c, seq, fn)


def ensure_visible(w):
    p = w
    while p is not None and not isinstance(p, ScrollFrame):
        p = p.master
    if p is not None:
        w.after_idle(lambda: p.see(w))


# ----- basic widgets -------------------------------------------------------
class Btn(tk.Label):
    STYLES = {
        "primary": (ACCENT, DARK_TXT, ACCENT_HI),
        "default": (CARD, FG, CARD_SEL),
        "ghost": (PANEL_DARK, MUTED, CARD),
        "danger": (PANEL_DARK, RED, CARD),
    }

    def __init__(self, master, text, command, kind="default", padx=14, **kw):
        bg, fg, hover = self.STYLES[kind]
        super().__init__(master, text=text, bg=bg, fg=fg, padx=padx, pady=7,
                         font=F["bold"], cursor="hand2", **kw)
        self._bg, self._hover, self._cmd = bg, hover, command
        self._keep_bg = True
        self.bind("<Enter>", lambda e: self.configure(bg=self._hover))
        self.bind("<Leave>", lambda e: self.configure(bg=self._bg))
        self.bind("<ButtonRelease-1>", lambda e: self._cmd())


class ScrollFrame(tk.Frame):
    def __init__(self, master, bg):
        super().__init__(master, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0, yscrollincrement=20)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>",
                        lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",
                         lambda e: self.canvas.itemconfigure(self._win, width=e.width))

    def scroll(self, steps):
        if self.inner.winfo_reqheight() > self.canvas.winfo_height():
            self.canvas.yview_scroll(steps, "units")

    def to_top(self):
        self.canvas.yview_moveto(0)

    def see(self, widget):
        try:
            total = self.inner.winfo_height()
            vh = self.canvas.winfo_height()
            if total <= vh:
                return
            y = widget.winfo_rooty() - self.inner.winfo_rooty()
            h = widget.winfo_height()
            top = self.canvas.canvasy(0)
            if y < top:
                self.canvas.yview_moveto(max(0, (y - 16) / total))
            elif y + h > top + vh:
                self.canvas.yview_moveto(min(1, (y + h - vh + 16) / total))
        except tk.TclError:
            pass


class EntryField(tk.Entry):
    def __init__(self, master, **kw):
        kw.setdefault("font", F["body"])
        super().__init__(master, bg=INPUT, fg=FG, insertbackground=FG, relief="flat",
                         highlightthickness=1, highlightbackground=BORDER,
                         highlightcolor=ACCENT, selectbackground="#34406b",
                         selectforeground=FG, **kw)
        self.bind("<FocusIn>", lambda e: ensure_visible(self), add="+")

    def get_value(self):
        return self.get().strip()

    def set_value(self, v):
        self.delete(0, "end")
        self.insert(0, v or "")


class AutoText(tk.Text):
    """Multi-line field that grows with its content so the pane scrolls, not the box."""

    def __init__(self, master, min_lines=3):
        super().__init__(master, wrap="word", bg=INPUT, fg=FG, insertbackground=FG,
                         relief="flat", highlightthickness=1, highlightbackground=BORDER,
                         highlightcolor=ACCENT, font=F["body"], padx=10, pady=8,
                         undo=True, height=min_lines, selectbackground="#34406b",
                         selectforeground=FG)
        self.min_lines = min_lines
        for seq in ("<KeyRelease>", "<ButtonRelease-1>", "<<Paste>>", "<<Cut>>", "<Configure>"):
            self.bind(seq, lambda e: self.after_idle(self._grow), add="+")
        self.bind("<Tab>", lambda e: (self.tk_focusNext().focus_set(), "break")[1])
        self.bind("<<PrevWindow>>", lambda e: (self.tk_focusPrev().focus_set(), "break")[1])
        self.bind("<FocusIn>", lambda e: ensure_visible(self), add="+")

    def _grow(self):
        try:
            res = self.count("1.0", "end", "displaylines")
            n = res[0] if res else 1
        except tk.TclError:
            n = self.min_lines
        h = max(self.min_lines, min(int(n), 80))
        if int(self.cget("height")) != h:
            self.configure(height=h)

    def get_value(self):
        return self.get("1.0", "end-1c").strip()

    def set_value(self, v):
        self.delete("1.0", "end")
        self.insert("1.0", v or "")
        self.edit_reset()
        self.after_idle(self._grow)


class Segmented(tk.Frame):
    """Pill-style single choice; click again to clear."""

    def __init__(self, master, options, colors, bg=PANEL):
        super().__init__(master, bg=bg)
        self.options, self.colors, self.value, self.labels = options, colors, "", {}
        for o in options:
            lbl = tk.Label(self, text=o, font=F["bold"], padx=14, pady=6, cursor="hand2",
                           highlightthickness=1)
            lbl.pack(side="left", padx=(0, 8))
            lbl.bind("<Button-1>", lambda e, o=o: self.set_value("" if self.value == o else o))
            self.labels[o] = lbl
        self._style()

    def _style(self):
        for o, lbl in self.labels.items():
            if o == self.value:
                lbl.configure(bg=self.colors[o], fg=DARK_TXT, highlightbackground=self.colors[o])
            else:
                lbl.configure(bg=INPUT, fg=MUTED, highlightbackground=BORDER)

    def get_value(self):
        return self.value

    def set_value(self, v):
        self.value = v or ""
        self._style()


class ListEditor(tk.Frame):
    def __init__(self, master, browse=False, bulk=False, bg=PANEL):
        super().__init__(master, bg=bg)
        self._bg = bg
        self.rows = []
        self.rows_frame = tk.Frame(self, bg=bg)
        self.rows_frame.pack(fill="x")
        bar = tk.Frame(self, bg=bg)
        bar.pack(fill="x", pady=(6, 0))
        Btn(bar, "+ Add", lambda: self.add_row(focus=True)).pack(side="left")
        if browse:
            Btn(bar, "Browse…", self._browse).pack(side="left", padx=(8, 0))
        if bulk:
            Btn(bar, "Paste list…", self._bulk).pack(side="left", padx=(8, 0))

    def add_row(self, value="", focus=False):
        row = tk.Frame(self.rows_frame, bg=self._bg)
        row.pack(fill="x", pady=2)
        e = EntryField(row)
        e.set_value(value)
        e.pack(side="left", fill="x", expand=True, ipady=5)
        Btn(row, "✕", lambda r=row: self.remove(r), "ghost", padx=9).pack(side="right", padx=(6, 0))
        e.bind("<Return>", lambda ev: self.add_row(focus=True))
        self.rows.append((row, e))
        if focus:
            e.focus_set()

    def remove(self, row):
        row.destroy()
        self.rows = [(r, e) for r, e in self.rows if r is not row]
        self._collapse_if_empty()

    def get_value(self):
        vals = [e.get_value() for _, e in self.rows]
        return [v for v in vals if v]

    def set_value(self, values):
        for r, _ in self.rows:
            r.destroy()
        self.rows = []
        for v in values or []:
            self.add_row(v)
        self._collapse_if_empty()

    def _collapse_if_empty(self):
        # Tk keeps an emptied frame at its old size unless a height is forced
        if not self.rows:
            self.rows_frame.configure(height=1)

    def _browse(self):
        files = filedialog.askopenfilenames(
            title="Select image(s)",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.bmp *.webp"), ("All files", "*.*")])
        for f in files:
            self.add_row(f)

    def _bulk(self):
        top = tk.Toplevel(self)
        top.title("Add multiple entries")
        top.configure(bg=PANEL)
        top.geometry("620x380")
        top.transient(self.winfo_toplevel())
        tk.Label(top, text="One entry per line", font=F["small"], fg=MUTED, bg=PANEL,
                 anchor="w").pack(fill="x", padx=16, pady=(14, 6))
        t = tk.Text(top, bg=INPUT, fg=FG, insertbackground=FG, relief="flat", font=F["mono"],
                    highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT,
                    padx=10, pady=8)
        t.pack(fill="both", expand=True, padx=16)

        def ok():
            for line in t.get("1.0", "end").splitlines():
                if line.strip():
                    self.add_row(line.strip())
            top.destroy()

        bar = tk.Frame(top, bg=PANEL)
        bar.pack(fill="x", padx=16, pady=12)
        Btn(bar, "Add", ok, "primary").pack(side="right")
        Btn(bar, "Cancel", top.destroy, "default").pack(side="right", padx=(0, 8))
        t.focus_set()
        try:
            top.wait_visibility()
            top.grab_set()
        except tk.TclError:
            pass


# ----- editor form ---------------------------------------------------------
class FormPane:
    def __init__(self, master):
        self.scroll = ScrollFrame(master, PANEL)
        self.root = self.scroll.inner
        self.fields = {}
        self._build()

    # helpers
    def _section(self, title, hint=None):
        wrap = tk.Frame(self.root, bg=PANEL)
        wrap.pack(fill="x", padx=28, pady=(24, 0))
        hdr = tk.Frame(wrap, bg=PANEL)
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=ACCENT, width=3, height=16).pack(side="left", padx=(0, 10))
        tk.Label(hdr, text=title.upper(), font=F["section"], fg=FG, bg=PANEL).pack(side="left")
        if hint:
            tk.Label(hdr, text=hint, font=F["small"], fg=MUTED, bg=PANEL).pack(side="left", padx=12)
        tk.Frame(wrap, bg=BORDER, height=1).pack(fill="x", pady=(8, 12))
        body = tk.Frame(wrap, bg=PANEL)
        body.pack(fill="x")
        return body

    def _row(self, parent):
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill="x")
        row.columnconfigure(0, weight=3)
        row.columnconfigure(1, weight=1)
        return row

    def _box(self, parent, label, cell):
        box = tk.Frame(parent, bg=PANEL)
        if cell is None:
            box.pack(fill="x", pady=(0, 14))
        else:
            box.grid(row=0, column=cell, sticky="new", padx=(0 if cell == 0 else 12, 0), pady=(0, 14))
        tk.Label(box, text=label, font=F["small"], fg=MUTED, bg=PANEL, anchor="w").pack(fill="x", pady=(0, 4))
        return box

    def entry(self, parent, label, path, cell=None):
        box = self._box(parent, label, cell)
        w = EntryField(box)
        w.pack(fill="x", ipady=6)
        self.fields[path] = w

    def text(self, parent, label, path, lines=3, cell=None):
        box = self._box(parent, label, cell)
        w = AutoText(box, min_lines=lines)
        w.pack(fill="x")
        self.fields[path] = w

    def segmented(self, parent, label, path, options, colors):
        box = self._box(parent, label, None)
        w = Segmented(box, options, colors)
        w.pack(anchor="w")
        self.fields[path] = w

    def listing(self, parent, label, path, **kw):
        box = self._box(parent, label, None)
        w = ListEditor(box, **kw)
        w.pack(fill="x")
        self.fields[path] = w

    # layout
    def _build(self):
        s = self._section("Overview")
        self.entry(s, "Path", ("path",))
        self.listing(s, "Images (file paths)", ("images",), browse=True)

        s = self._section("CWE")
        r = self._row(s)
        self.entry(r, "Name", ("cwe", "name"), cell=0)
        self.entry(r, "Number", ("cwe", "number"), cell=1)
        self.text(s, "Description", ("cwe", "description"))

        s = self._section("OWASP mapping")
        r = self._row(s)
        self.entry(r, "Name", ("owasp_mapping", "name"), cell=0)
        self.entry(r, "Number", ("owasp_mapping", "number"), cell=1)
        self.segmented(s, "Severity", ("owasp_mapping", "severity"), SEVERITIES, SEV_COLORS)

        s = self._section("Description")
        self.text(s, "Sentence from OWASP", ("description", "owasp_sentence"))
        self.text(s, "What is the vulnerability", ("description", "what_is_the_vuln"), lines=4)
        self.text(s, "Why is it bad", ("description", "why_is_it_bad", "summary"))
        self.text(s, "How (attack / exploitation path)", ("description", "why_is_it_bad", "how"), lines=4)

        s = self._section("Impact")
        self.text(s, "Impact", ("impact",), lines=4)
        s = self._section("Remediation")
        self.text(s, "Remediation", ("remediation",), lines=4)
        s = self._section("Additional recommendations")
        self.text(s, "Additional recommendations", ("additional_recommendations",), lines=3)
        s = self._section("Testing notes")
        self.text(s, "Testing notes", ("testing_notes",), lines=4)
        s = self._section("Affected URLs")
        self.listing(s, "URLs", ("affected_urls",), bulk=True)
        tk.Frame(self.root, bg=PANEL, height=40).pack()

    def load(self, f):
        for path, w in self.fields.items():
            w.set_value(get_in(f, path))
        self.scroll.to_top()

    def collect(self, base):
        out = copy.deepcopy(base)
        for path, w in self.fields.items():
            set_in(out, path, w.get_value())
        return out


# ----- list cards ----------------------------------------------------------
class FindingCard(tk.Frame):
    def __init__(self, master, app, index):
        super().__init__(master, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        self.app, self.index, self.expanded, self.selected = app, index, False, False
        self.bg = CARD

        head = tk.Frame(self, bg=CARD)
        head.pack(fill="x", padx=12, pady=11)
        self.head = head
        self.chev = tk.Label(head, text="▸", font=F["bold"], fg=MUTED, bg=CARD, cursor="hand2", padx=4)
        self.pill = tk.Label(head, font=F["small_b"], padx=8, pady=2)
        self.pill._keep_bg = True
        self.num = tk.Label(head, text=f"{index + 1:02d}", font=F["mono_b"], fg=ACCENT, bg=CARD)
        self.title_lbl = tk.Label(head, font=F["bold"], fg=FG, bg=CARD, anchor="w", justify="left")
        self.chev.pack(side="right")
        self.pill.pack(side="right", padx=(8, 4))
        self.num.pack(side="left", padx=(0, 10))
        self.title_lbl.pack(side="left", fill="x", expand=True)
        head.bind("<Configure>",
                  lambda e: self.title_lbl.configure(wraplength=max(120, e.width - 160)))

        self.body = tk.Frame(self, bg=CARD)
        select = lambda e: self.app.select(self.index)  # noqa: E731
        for w in (head, self.num, self.title_lbl, self.pill):
            w.configure(cursor="hand2")
            w.bind("<Button-1>", select)
        self.chev.bind("<Button-1>", lambda e: self.toggle())
        self.refresh()

    def toggle(self):
        self.expanded = not self.expanded
        self.chev.configure(text="▾" if self.expanded else "▸")
        if self.expanded:
            self.body.pack(fill="x", padx=14, pady=(0, 12))
            self._fill_body()
        else:
            self.body.pack_forget()
            for c in self.body.winfo_children():
                c.destroy()

    def _fill_body(self):
        for c in self.body.winfo_children():
            c.destroy()
        tk.Frame(self.body, bg=BORDER, height=1).pack(fill="x", pady=(0, 8))
        f = self.app.findings[self.index]
        for ind, key, val, filled in preview_lines(f):
            if filled is None:
                txt, color = f"{'   ' * ind}{key}", ACCENT
            else:
                txt, color = f"{'   ' * ind}{key}: {val}", (FG if filled else MUTED)
            lbl = tk.Label(self.body, text=txt, font=F["mono"], fg=color, bg=self.bg, anchor="w")
            lbl.pack(fill="x")
            lbl.bind("<Button-1>", lambda e: self.app.select(self.index))

    def set_selected(self, sel):
        self.selected = sel
        self.bg = CARD_SEL if sel else CARD
        paint(self, self.bg)
        self.configure(highlightbackground=ACCENT if sel else BORDER)

    def refresh(self):
        f = self.app.findings[self.index]
        self.title_lbl.configure(text=f["title"] or "Untitled")
        pct = completeness(f)
        if pct == 0:
            self.pill.configure(text="Empty", bg="#262a33", fg=MUTED)
        elif pct < 100:
            self.pill.configure(text=f"{pct}%", bg="#3a3120", fg=AMBER)
        else:
            self.pill.configure(text="Done", bg="#16322a", fg=GREEN)
        if self.expanded:
            self._fill_body()


# ----- application ---------------------------------------------------------
class App(tk.Tk):
    def __init__(self, path, findings):
        super().__init__()
        init_fonts()
        self.path, self.findings = path, findings
        self.cards, self.cur, self.snapshot = [], None, None
        self.dirty, self.saved_at, self._last_poll = False, None, None

        self.title("Findings Editor")
        self.geometry("1380x880")
        self.minsize(1000, 620)
        self.configure(bg=BG)
        self._style()
        self._build_ui()
        self._rebuild_cards()

        self.bind_all("<MouseWheel>", self._wheel)
        self.bind_all("<Button-4>", self._wheel)
        self.bind_all("<Button-5>", self._wheel)
        self.bind_all("<Control-s>", lambda e: self.save())
        try:
            self.bind_all("<Command-s>", lambda e: self.save())
        except tk.TclError:
            pass
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(600, self._poll)
        if self.findings:
            self.select(0)
        else:
            self._show_editor(False)

    # setup
    def _style(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("Vertical.TScrollbar", background="#2a2f3a", troughcolor=BG,
                     bordercolor=BG, lightcolor="#2a2f3a", darkcolor="#2a2f3a",
                     arrowcolor=MUTED, gripcount=0)
        st.map("Vertical.TScrollbar", background=[("active", "#3a4150")])

    def _build_ui(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=22, pady=(16, 12))
        tk.Label(top, text="Findings Editor", font=F["h1"], fg=FG, bg=BG).pack(side="left")
        self.file_lbl = tk.Label(top, font=F["small"], fg=MUTED, bg=BG)
        self.file_lbl.pack(side="left", padx=16, pady=(6, 0))
        Btn(top, "+ Add finding", self.add_finding, "primary").pack(side="right")

        pw = tk.PanedWindow(self, orient="horizontal", bg=BG, sashwidth=8, sashrelief="flat", bd=0)
        pw.pack(fill="both", expand=True, padx=(22, 22), pady=(0, 20))

        # left
        left = tk.Frame(pw, bg=BG)
        self.search_var = tk.StringVar()
        sb = tk.Frame(left, bg=BG)
        sb.pack(fill="x", pady=(0, 10), padx=(0, 8))
        self.search = EntryField(sb, textvariable=self.search_var)
        self.search.pack(fill="x", ipady=7)
        self.search_var.trace_add("write", lambda *a: self._apply_filter())
        self.list = ScrollFrame(left, BG)
        self.list.pack(fill="both", expand=True)
        pw.add(left, minsize=340, width=430)

        # right
        right = tk.Frame(pw, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        pw.add(right, minsize=560, stretch="always")
        self.empty_lbl = tk.Label(right, text="No findings yet.\nUse “+ Add finding” to create one.",
                                  font=F["body"], fg=MUTED, bg=PANEL, justify="center")
        self.editor = tk.Frame(right, bg=PANEL)

        hdr = tk.Frame(self.editor, bg=PANEL)
        hdr.pack(fill="x", padx=28, pady=(20, 6))
        self.num_lbl = tk.Label(hdr, font=F["mono_b"], fg=ACCENT, bg=PANEL, anchor="w")
        self.num_lbl.pack(fill="x")
        self.title_entry = EntryField(hdr, font=F["title"])
        self.title_entry.pack(fill="x", ipady=7, pady=(6, 0))

        bar = tk.Frame(self.editor, bg=PANEL_DARK, highlightthickness=1, highlightbackground=BORDER)
        bar.pack(side="bottom", fill="x")
        inner = tk.Frame(bar, bg=PANEL_DARK)
        inner.pack(fill="x", padx=20, pady=12)
        Btn(inner, "‹ Prev", lambda: self.step(-1), "ghost").pack(side="left")
        Btn(inner, "Next ›", lambda: self.step(1), "ghost").pack(side="left", padx=(6, 0))
        self.status = tk.Label(inner, font=F["small_b"], bg=PANEL_DARK, fg=MUTED)
        self.status.pack(side="left", padx=18)
        Btn(inner, "Save to JSON", self.save, "primary").pack(side="right")
        Btn(inner, "Revert", self.revert, "default").pack(side="right", padx=(0, 8))
        Btn(inner, "Delete", self.delete_finding, "danger").pack(side="right", padx=(0, 8))

        self.form = FormPane(self.editor)
        self.form.scroll.pack(fill="both", expand=True, pady=(8, 0))

    def _show_editor(self, show):
        if show:
            self.empty_lbl.place_forget()
            self.editor.pack(fill="both", expand=True)
        else:
            self.editor.pack_forget()
            self.empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

    # mouse wheel -> whichever ScrollFrame is under the pointer
    def _wheel(self, event):
        try:
            w = self.winfo_containing(event.x_root, event.y_root)
        except (KeyError, tk.TclError):
            return
        while w is not None and not isinstance(w, ScrollFrame):
            w = getattr(w, "master", None)
        if w is None:
            return
        if getattr(event, "num", 0) == 4:
            step = -1
        elif getattr(event, "num", 0) == 5:
            step = 1
        else:
            step = -1 if event.delta > 0 else 1
        w.scroll(step * 3)

    # cards
    def _rebuild_cards(self):
        for c in self.cards:
            c.destroy()
        self.cards = [FindingCard(self.list.inner, self, i) for i in range(len(self.findings))]
        if self.cur is not None and self.cur < len(self.cards):
            self.cards[self.cur].set_selected(True)
        self._apply_filter()

    def _apply_filter(self):
        q = self.search_var.get().strip().lower()
        for c in self.cards:
            c.pack_forget()
        shown = 0
        for c in self.cards:
            if q in self.findings[c.index]["title"].lower():
                c.pack(fill="x", pady=5, padx=(0, 8))
                shown += 1
        base = os.path.basename(self.path)
        n = len(self.findings)
        self.file_lbl.configure(text=f"{base}  ·  {n} finding{'s' if n != 1 else ''}"
                                + (f"  ·  {shown} shown" if q else ""))

    # selection / saving
    def _collect(self):
        data = self.form.collect(self.findings[self.cur])
        data["title"] = self.title_entry.get_value() or "Untitled finding"
        return data

    def _is_dirty(self):
        return self.cur is not None and self._collect() != self.snapshot

    def select(self, idx):
        if idx == self.cur or not (0 <= idx < len(self.findings)):
            return
        if self.cur is not None and self._is_dirty():
            if not self.save():  # incremental save when leaving a finding
                return
        self.cur = idx
        for i, c in enumerate(self.cards):
            c.set_selected(i == idx)
        self._show_editor(True)
        self._load_current()
        self.list.see(self.cards[idx])

    def _load_current(self):
        f = self.findings[self.cur]
        self.num_lbl.configure(text=f"FINDING {self.cur + 1:02d} / {len(self.findings):02d}")
        self.title_entry.set_value(f["title"])
        self.form.load(f)
        self.snapshot = self._collect()
        self._last_poll = copy.deepcopy(self.snapshot)
        self.dirty = False
        self._set_status()

    def _set_status(self):
        if self.dirty:
            self.status.configure(text="● Unsaved changes", fg=AMBER)
        elif self.saved_at:
            self.status.configure(text=f"✓ Saved {self.saved_at}", fg=GREEN)
        else:
            self.status.configure(text="No changes", fg=MUTED)

    def save(self):
        if self.cur is None:
            return True
        data = self._collect()
        self.findings[self.cur] = data
        try:
            save_findings(self.path, self.findings)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Save failed", str(exc), parent=self)
            return False
        self.snapshot = copy.deepcopy(data)
        self._last_poll = copy.deepcopy(data)
        self.dirty = False
        self.saved_at = datetime.datetime.now().strftime("%H:%M:%S")
        self.cards[self.cur].refresh()
        self._set_status()
        return True

    def revert(self):
        if self.cur is None:
            return
        self.findings[self.cur] = copy.deepcopy(self.snapshot)
        self._load_current()
        self.cards[self.cur].refresh()

    def step(self, d):
        if self.cur is not None:
            self.select(self.cur + d)

    def _poll(self):
        try:
            if self.cur is not None:
                cur = self._collect()
                dirty = cur != self.snapshot
                if cur != self._last_poll:  # live-update the card without writing to disk
                    self.findings[self.cur] = cur
                    self.cards[self.cur].refresh()
                    self._last_poll = copy.deepcopy(cur)
                if dirty != self.dirty:
                    self.dirty = dirty
                    self._set_status()
        finally:
            self.after(600, self._poll)

    # add / delete
    def add_finding(self):
        title = simpledialog.askstring("New finding", "Observed title:", parent=self)
        if not title or not title.strip():
            return
        if self.cur is not None and self._is_dirty() and not self.save():
            return
        self.findings.append(blank_finding(title.strip()))
        try:
            save_findings(self.path, self.findings)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Save failed", str(exc), parent=self)
        self.cur = None
        self._rebuild_cards()
        self.select(len(self.findings) - 1)

    def delete_finding(self):
        if self.cur is None:
            return
        title = self.findings[self.cur]["title"]
        if not messagebox.askyesno("Delete finding", f"Delete “{title}”?\nThis writes to the JSON file.",
                                   parent=self):
            return
        del self.findings[self.cur]
        try:
            save_findings(self.path, self.findings)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Save failed", str(exc), parent=self)
        idx = min(self.cur, len(self.findings) - 1)
        self.cur = None
        self.snapshot = None
        self._rebuild_cards()
        if idx >= 0:
            self.select(idx)
        else:
            self._show_editor(False)

    def _close(self):
        if self.cur is not None and self._is_dirty():
            if not self.save():
                if not messagebox.askyesno("Unsaved changes", "Save failed. Quit anyway?", parent=self):
                    return
        self.destroy()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def str2bool(v):
    return str(v).strip().lower() in ("1", "true", "t", "yes", "y")


def main():
    # tolerate en/em dashes pasted from docs ("–stage_2")
    sys.argv = [("--" + a[1:] if a[:1] in ("–", "—") else a) for a in sys.argv]
    ap = argparse.ArgumentParser(description="Two-stage pentest findings tool")
    ap.add_argument("--stage_2", "--stage-2", dest="stage_2", nargs="?", const="true",
                    default="false", type=str2bool, help="launch the GUI editor (true/false)")
    ap.add_argument("--file", "-f", default=DEFAULT_FILE, help=f"JSON file (default {DEFAULT_FILE})")
    args = ap.parse_args()

    if args.stage_2:
        try:
            findings = load_findings(args.file)
        except ValueError as exc:
            sys.exit(f"Error: {exc}")
        stage_2(args.file, findings)
    else:
        stage_1(args.file)


if __name__ == "__main__":
    main()
