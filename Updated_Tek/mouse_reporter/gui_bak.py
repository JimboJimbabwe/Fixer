#!/usr/bin/env python3
"""
Security Testing Appendix Organizer
------------------------------------
Usage:  python3 app.py <project_name>

Creates (if not already present):
  data/<project_slug>/
    <cat_id>_<cat_slug>/
      <test_id>_<test_slug>/
        images/
        Report.json   ← written on save

Requires: Python 3.8+  (stdlib only)
"""

import sys
import tkinter as tk
from tkinter import filedialog, messagebox
import json, re, shutil
from pathlib import Path
from datetime import datetime

# ───────────────────────────── paths ─────────────────────────────────────────
CHECKLIST  = Path("checklist.json")
DATA_ROOT  = Path("data")          # base; each project lives in DATA_ROOT/<slug>/

# ───────────────────────────── palette ───────────────────────────────────────
BG        = "#0f0e17"
BG_PANEL  = "#16151f"
BG_CAT    = "#1a1927"
BG_ROW    = "#171620"
BG_HOVER  = "#1f1e2e"
BG_EXP    = "#13121c"
BG_CARD   = "#1c1b28"
BG_INPUT  = "#0f0e17"
BG_URL    = "#181724"

FG        = "#e2dff5"
FG_SUB    = "#7b78a0"
FG_DIM    = "#3e3c56"
FG_NA     = "#2e2c42"

GREEN     = "#3ddc84"
GREEN_BG  = "#152a1e"
BLUE      = "#60c3ff"
BLUE_BG   = "#0d2135"
PURPLE    = "#a67fff"
PURPLE_BG = "#1f1540"
YELLOW    = "#f4c842"
RED       = "#ff5f5f"
ACCENT    = "#7c5ff5"
ACCENT2   = "#5b8aff"

BORDER    = "#252338"
BORDER_HI = "#3a3660"

STATUS_SYM = {"pending": "○", "complete": "●", "na": "⊘"}
STATUS_FG  = {"pending": FG_DIM,  "complete": GREEN,  "na": PURPLE}
STATUS_BG  = {"pending": BG_ROW,  "complete": GREEN_BG, "na": PURPLE_BG}

# ───────────────────────────── fonts ──────────────────────────────────────────
F_TITLE   = ("Segoe UI", 15, "bold")
F_CAT     = ("Segoe UI", 11, "bold")
F_ROW     = ("Segoe UI", 10)
F_ROW_ID  = ("Courier New", 9)
F_LABEL   = ("Segoe UI", 9)
F_LABEL_B = ("Segoe UI", 9, "bold")
F_BTN     = ("Segoe UI", 9)
F_BTN_B   = ("Segoe UI", 9, "bold")
F_INPUT   = ("Consolas", 9)
F_STAT    = ("Segoe UI", 9)
F_STEP    = ("Segoe UI", 9, "bold")

# ─────────────────────────── utilities ───────────────────────────────────────
def slugify(s):
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")[:48]

def test_folder(cat_id, cat_title, test_id, test_title, project_root=None):
    base = project_root or DATA_ROOT
    return base / f"{cat_id}_{slugify(cat_title)}" / f"{test_id.replace('.','_')}_{slugify(test_title)}"


def scaffold_project(checklist: dict, project_root: Path) -> int:
    """Create every test folder + images/ subdirectory up front. Returns folder count."""
    count = 0
    for cat in checklist["categories"]:
        for test in cat["tests"]:
            folder = test_folder(cat["id"], cat["title"],
                                 test["id"], test["title"], project_root)
            (folder / "images").mkdir(parents=True, exist_ok=True)
            count += 1
    return count

def load_report(folder):
    rp = folder / "Report.json"
    if rp.exists():
        try: return json.loads(rp.read_text(encoding="utf-8"))
        except: pass
    return {"status": "pending", "affected_urls": [], "steps": []}

def save_report(folder, report):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "images").mkdir(exist_ok=True)
    (folder / "Report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

def copy_image(src, folder, step_n):
    p = Path(src)
    if p.exists():
        dst = folder / "images" / f"image_{step_n}{p.suffix.lower()}"
        shutil.copy2(src, dst)
        return str(dst)
    return ""

def pill_btn(parent, text, bg, fg, active_bg, cmd, padx=10, pady=4, font=None):
    return tk.Button(parent, text=text, font=font or F_BTN,
                     bg=bg, fg=fg, activebackground=active_bg,
                     activeforeground=fg, relief="flat", cursor="hand2",
                     padx=padx, pady=pady, bd=0, command=cmd,
                     highlightthickness=0)

# ───────────────────────── URL list widget ────────────────────────────────────
class URLListWidget(tk.Frame):
    """
    A dynamic list of individual URL entry rows.
    Each row: [entry field ──────────────────────] [×]
    Bottom:   [＋ Add URL]
    """
    def __init__(self, parent, existing_urls=None):
        super().__init__(parent, bg=BG_EXP)
        self._rows = []
        self._build_header()
        self._rows_frame = tk.Frame(self, bg=BG_EXP)
        self._rows_frame.pack(fill="x", pady=(4, 0))
        for url in (existing_urls or [""]):
            self._add_row(url)
        self._build_footer()

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG_EXP)
        hdr.pack(fill="x")
        tk.Label(hdr, text="AFFECTED URLs", font=("Segoe UI", 8, "bold"),
                 bg=BG_EXP, fg=FG_SUB).pack(side="left")

    def _build_footer(self):
        ft = tk.Frame(self, bg=BG_EXP)
        ft.pack(fill="x", pady=(6, 0))
        pill_btn(ft, "＋  Add URL", BG_URL, FG_SUB, BG_HOVER,
                 self._add_row, padx=8, pady=3).pack(side="left")

    def _add_row(self, url=""):
        row_frame = tk.Frame(self._rows_frame, bg=BG_EXP)
        row_frame.pack(fill="x", pady=2)

        # left accent bar
        tk.Frame(row_frame, bg=ACCENT2, width=2).pack(side="left", fill="y", pady=0)

        inner = tk.Frame(row_frame, bg=BG_URL,
                         highlightthickness=1, highlightbackground=BORDER)
        inner.pack(side="left", fill="x", expand=True, padx=(4, 0))

        var = tk.StringVar(value=url)
        ent = tk.Entry(inner, textvariable=var, font=F_INPUT,
                       bg=BG_URL, fg=FG, insertbackground=FG,
                       relief="flat", bd=0,
                       highlightthickness=0)
        ent.pack(side="left", fill="x", expand=True, padx=8, ipady=5)

        def remove(rf=row_frame, r=(row_frame, var)):
            rf.destroy()
            self._rows = [x for x in self._rows if x is not r]

        tk.Button(inner, text="×", font=("Segoe UI", 11),
                  bg=BG_URL, fg=FG_DIM, activebackground=BG_URL,
                  activeforeground=RED, relief="flat", cursor="hand2",
                  bd=0, padx=6, pady=0,
                  command=remove).pack(side="right")

        entry = (row_frame, var)
        self._rows.append(entry)
        return var

    def get_urls(self):
        return [v.get().strip() for _, v in self._rows if v.get().strip()]


# ───────────────────────────── step card ─────────────────────────────────────
class StepWidget(tk.Frame):
    def __init__(self, parent, number, url="", image="", desc=""):
        super().__init__(parent, bg=BG_CARD,
                         highlightthickness=1, highlightbackground=BORDER)
        self.number = number
        self.url    = url
        self._build(image, desc)

    def _build(self, image, desc):
        # ── top bar ──────────────────────────────────────────────────────
        top = tk.Frame(self, bg=BORDER)
        top.pack(fill="x")

        bar = tk.Frame(top, bg=BG_CARD)
        bar.pack(fill="x", padx=1, pady=(1, 0))

        step_lbl = tk.Frame(bar, bg=ACCENT, width=3)
        step_lbl.pack(side="left", fill="y")

        tk.Label(bar, text=f"  Step {self.number}",
                 font=F_STEP, bg=BG_CARD, fg=ACCENT,
                 pady=7).pack(side="left")

        if self.url:
            tk.Label(bar, text=f"  ·  {self.url}",
                     font=F_INPUT, bg=BG_CARD, fg=FG_SUB).pack(side="left")

        pill_btn(bar, "Remove", BG_CARD, FG_DIM, BG_HOVER,
                 self.destroy, padx=8, pady=3).pack(side="right", padx=8)

        # ── image row ────────────────────────────────────────────────────
        ir = tk.Frame(self, bg=BG_CARD)
        ir.pack(fill="x", padx=12, pady=(8, 4))

        tk.Label(ir, text="Screenshot", font=("Segoe UI", 8),
                 bg=BG_CARD, fg=FG_SUB, width=10, anchor="w").pack(side="left")

        self.img_var = tk.StringVar(value=image if image else "— none —")
        tk.Label(ir, textvariable=self.img_var,
                 font=F_INPUT, bg=BG_CARD, fg=YELLOW,
                 anchor="w", width=48).pack(side="left", padx=(0, 8))

        pill_btn(ir, "Browse", BLUE_BG, BLUE, "#1a3a55",
                 self._browse, padx=8, pady=2).pack(side="left", padx=(0, 4))
        pill_btn(ir, "Clear", BG_CARD, FG_DIM, BG_HOVER,
                 lambda: self.img_var.set("— none —"), padx=8, pady=2).pack(side="left")

        # ── description ──────────────────────────────────────────────────
        dr = tk.Frame(self, bg=BG_CARD)
        dr.pack(fill="x", padx=12, pady=(0, 10))

        tk.Label(dr, text="Description", font=("Segoe UI", 8),
                 bg=BG_CARD, fg=FG_SUB, width=10, anchor="nw").pack(
            side="left", anchor="n", pady=3)

        txt_wrap = tk.Frame(dr, bg=BORDER_HI,
                            highlightthickness=0)
        txt_wrap.pack(side="left", fill="x", expand=True)

        self.desc = tk.Text(txt_wrap, font=("Segoe UI", 9),
                            bg=BG_INPUT, fg=FG, insertbackground=FG,
                            relief="flat", height=3, wrap="word",
                            padx=8, pady=6,
                            highlightthickness=1,
                            highlightcolor=ACCENT,
                            highlightbackground=BORDER_HI)
        self.desc.pack(fill="both", expand=True, padx=1, pady=1)
        if desc:
            self.desc.insert("1.0", desc)

    def _browse(self):
        p = filedialog.askopenfilename(
            title="Select screenshot",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.bmp *.webp"),
                       ("All files", "*.*")])
        if p:
            self.img_var.set(p)

    @property
    def data(self):
        return {"step_number": self.number, "url": self.url,
                "image_src": self.img_var.get(),
                "description": self.desc.get("1.0", "end").strip()}


# ─────────────────────────── detail panel ────────────────────────────────────
class DetailPanel(tk.Frame):
    def __init__(self, parent, ci, ti, cat, test, on_status_change, project_root=None):
        super().__init__(parent, bg=BG_EXP)
        self.ci, self.ti        = ci, ti
        self.cat, self.test     = cat, test
        self.on_status_change   = on_status_change
        self.folder             = test_folder(cat["id"], cat["title"],
                                              test["id"], test["title"],
                                              project_root)
        self.report             = load_report(self.folder)
        self._build()

    def _build(self):
        # top gradient bar
        tk.Frame(self, bg=ACCENT, height=2).pack(fill="x")

        inner = tk.Frame(self, bg=BG_EXP)
        inner.pack(fill="x", padx=22, pady=16)

        # ── action bar ───────────────────────────────────────────────────
        abar = tk.Frame(inner, bg=BG_EXP)
        abar.pack(fill="x", pady=(0, 14))

        pill_btn(abar, "⊘  Not Applicable",
                 PURPLE_BG, PURPLE, "#2a1e5a",
                 self._mark_na, padx=12, pady=5,
                 font=F_BTN_B).pack(side="left")

        # status badge (shows current)
        status = self.report.get("status", "pending")
        badge_txt = {"pending": "Pending", "complete": "Complete ✓", "na": "N/A"}
        badge_fg  = {"pending": FG_DIM, "complete": GREEN, "na": PURPLE}
        tk.Label(abar, text=badge_txt[status],
                 font=("Segoe UI", 9, "bold"),
                 bg=BG_EXP, fg=badge_fg[status]).pack(side="left", padx=14)

        pill_btn(abar, "✓  Mark Complete",
                 GREEN_BG, GREEN, "#1f4030",
                 self._save, padx=14, pady=5,
                 font=F_BTN_B).pack(side="right")

        # ── URL section ──────────────────────────────────────────────────
        url_lbl_row = tk.Frame(inner, bg=BG_EXP)
        url_lbl_row.pack(fill="x", pady=(0, 6))

        tk.Label(url_lbl_row, text="AFFECTED URLS",
                 font=("Segoe UI", 8, "bold"),
                 bg=BG_EXP, fg=FG_SUB).pack(side="left")

        pill_btn(url_lbl_row, "↓ Generate Steps from URLs",
                 BLUE_BG, BLUE, "#1a3a55",
                 self._load_steps, padx=10, pady=3).pack(side="right")

        saved_urls = self.report.get("affected_urls", []) or [""]
        self.url_list = URLListWidget(inner, existing_urls=saved_urls)
        self.url_list.pack(fill="x", pady=(0, 16))

        # ── divider ──────────────────────────────────────────────────────
        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", pady=(0, 14))

        # ── steps section header ─────────────────────────────────────────
        sh = tk.Frame(inner, bg=BG_EXP)
        sh.pack(fill="x", pady=(0, 8))
        tk.Label(sh, text="EVIDENCE STEPS",
                 font=("Segoe UI", 8, "bold"),
                 bg=BG_EXP, fg=FG_SUB).pack(side="left")
        pill_btn(sh, "＋  Add Step", BG_EXP, FG_SUB, BG_HOVER,
                 self._add_step, padx=8, pady=3).pack(side="right")

        # ── steps container ──────────────────────────────────────────────
        self.sf = tk.Frame(inner, bg=BG_EXP)
        self.sf.pack(fill="x")

        for s in self.report.get("steps", []):
            StepWidget(self.sf,
                       number=s.get("step_number", "?"),
                       url=s.get("url", ""),
                       image=s.get("image", ""),
                       desc=s.get("description", "")
                       ).pack(fill="x", pady=4)

    # ── actions ───────────────────────────────────────────────────────────────

    def _load_steps(self):
        urls = self.url_list.get_urls()
        if not urls:
            messagebox.showwarning("No URLs",
                "Add at least one Affected URL before generating steps.")
            return
        for w in self.sf.winfo_children():
            w.destroy()
        for i, url in enumerate(urls, 1):
            StepWidget(self.sf, number=i, url=url).pack(fill="x", pady=4)

    def _add_step(self):
        n = len(self.sf.winfo_children()) + 1
        StepWidget(self.sf, number=n).pack(fill="x", pady=4)

    def _save(self):
        steps = []
        for sw in self.sf.winfo_children():
            if not isinstance(sw, StepWidget):
                continue
            d = sw.data
            img = ""
            if d["image_src"] not in ("", "— none —"):
                img = copy_image(d["image_src"], self.folder, d["step_number"])
            steps.append({"step_number": d["step_number"],
                           "url": d["url"], "image": img,
                           "description": d["description"]})

        report = {"test_id": self.test["id"], "title": self.test["title"],
                  "status": "complete",
                  "saved_at": datetime.now().isoformat(timespec="seconds"),
                  "affected_urls": self.url_list.get_urls(),
                  "steps": steps}
        save_report(self.folder, report)
        self.on_status_change(self.ci, self.ti, "complete")
        messagebox.showinfo("Saved", f"Test {self.test['id']} marked complete ✓")

    def _mark_na(self):
        r = load_report(self.folder)
        r["status"]   = "na"
        r["saved_at"] = datetime.now().isoformat(timespec="seconds")
        save_report(self.folder, r)
        self.on_status_change(self.ci, self.ti, "na")


# ───────────────────────────── main app ──────────────────────────────────────
class App:
    def __init__(self, root, project_root: Path):
        self.root         = root
        self.project_root = project_root
        root.withdraw()                    # hide until fully built
        root.title(f"Security Testing Appendix — {project_root.name}")
        root.geometry("1240x900")
        root.configure(bg=BG)
        root.minsize(900, 600)

        try: root.tk.call("tk", "scaling", 1.35)
        except: pass

        self.checklist   = json.loads(CHECKLIST.read_text(encoding="utf-8"))
        self.expanded    = None
        self.detail_ref  = None
        self.row_refs    = {}
        self.stats_var   = tk.StringVar()
        self.project_var = tk.StringVar(value=project_root.name)

        # scaffold every test folder up front
        scaffold_project(self.checklist, self.project_root)

        self._build()
        root.deiconify()                   # reveal once fully built

    # ── layout ────────────────────────────────────────────────────────────────

    def _build(self):
        self._build_header()
        self._build_scroll()
        self._populate()
        self._update_stats()

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG_PANEL)
        hdr.pack(fill="x")

        # accent top bar
        accent_bar = tk.Frame(hdr, height=3, bg=BG_PANEL)
        accent_bar.pack(fill="x")
        # gradient simulation via two colors
        tk.Frame(accent_bar, height=3, bg=ACCENT).place(relx=0, rely=0,
                                                         relwidth=0.5, relheight=1)
        tk.Frame(accent_bar, height=3, bg=ACCENT2).place(relx=0.5, rely=0,
                                                          relwidth=0.5, relheight=1)

        h2 = tk.Frame(hdr, bg=BG_PANEL)
        h2.pack(fill="x", padx=24, pady=12)

        # lock icon + title
        title_wrap = tk.Frame(h2, bg=BG_PANEL)
        title_wrap.pack(side="left")
        tk.Label(title_wrap, text="🔐", font=("Segoe UI", 18),
                 bg=BG_PANEL, fg=FG).pack(side="left", padx=(0, 10))
        txt_col = tk.Frame(title_wrap, bg=BG_PANEL)
        txt_col.pack(side="left")
        tk.Label(txt_col, text="Security Testing Appendix",
                 font=("Segoe UI", 14, "bold"),
                 bg=BG_PANEL, fg=FG, anchor="w").pack(anchor="w")
        proj_row = tk.Frame(txt_col, bg=BG_PANEL)
        proj_row.pack(anchor="w")
        tk.Label(proj_row, text="Project: ",
                 font=("Segoe UI", 9),
                 bg=BG_PANEL, fg=FG_SUB).pack(side="left")
        tk.Label(proj_row, textvariable=self.project_var,
                 font=("Segoe UI", 9, "bold"),
                 bg=BG_PANEL, fg=ACCENT).pack(side="left")

        # stats right side
        stats_wrap = tk.Frame(h2, bg=BG_PANEL)
        stats_wrap.pack(side="right")
        tk.Label(stats_wrap, textvariable=self.stats_var,
                 font=F_STAT, bg=BG_PANEL, fg=FG_SUB,
                 anchor="e").pack(anchor="e")
        # progress bar canvas
        self.prog_cv = tk.Canvas(stats_wrap, bg=BG_PANEL,
                                  height=4, width=220,
                                  highlightthickness=0, bd=0)
        self.prog_cv.pack(anchor="e", pady=(4, 0))

        # bottom border
        tk.Frame(hdr, bg=BORDER, height=1).pack(fill="x")

    def _build_scroll(self):
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill="both", expand=True)

        self.cv  = tk.Canvas(outer, bg=BG, highlightthickness=0, bd=0)
        vsb      = tk.Scrollbar(outer, orient="vertical", command=self.cv.yview,
                                bg=BG_PANEL, troughcolor=BG_PANEL,
                                activebackground=BORDER_HI)
        self.cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.cv.pack(side="left", fill="both", expand=True)

        self.frame = tk.Frame(self.cv, bg=BG)
        self._win  = self.cv.create_window((0, 0), window=self.frame, anchor="nw")

        self.frame.bind("<Configure>", self._on_frame_configure)
        self.cv.bind("<Configure>",
                     lambda e: self.cv.itemconfig(self._win, width=e.width))
        self.cv.bind_all("<MouseWheel>",
                         lambda e: self.cv.yview_scroll(-1 if e.delta > 0 else 1, "units"))
        self.cv.bind_all("<Button-4>", lambda _: self.cv.yview_scroll(-1, "units"))
        self.cv.bind_all("<Button-5>", lambda _: self.cv.yview_scroll(1,  "units"))

    def _on_frame_configure(self, _=None):
        self.cv.configure(scrollregion=self.cv.bbox("all"))

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate(self):
        for ci, cat in enumerate(self.checklist["categories"]):
            self._build_cat_header(ci, cat)
            for ti, test in enumerate(cat["tests"]):
                self._build_row(ci, ti, cat, test)
        # bottom spacer
        tk.Frame(self.frame, bg=BG, height=24).pack(fill="x")

    def _build_cat_header(self, ci, cat):
        # count complete/na for this category to show a mini badge
        complete = na = total = 0
        for test in cat["tests"]:
            total += 1
            s = load_report(test_folder(cat["id"], cat["title"],
                                         test["id"], test["title"],
                                         self.project_root))["status"]
            if s == "complete": complete += 1
            elif s == "na":     na += 1

        wrapper = tk.Frame(self.frame, bg=BG)
        wrapper.pack(fill="x", pady=(12, 0))

        # left color strip
        tk.Frame(wrapper, bg=ACCENT, width=4).pack(side="left", fill="y")

        inner = tk.Frame(wrapper, bg=BG_CAT)
        inner.pack(side="left", fill="x", expand=True)

        tk.Label(inner, text=f"  {cat['id']}.  {cat['title']}",
                 font=F_CAT, bg=BG_CAT, fg=FG, pady=11).pack(side="left", padx=8)

        # mini progress text
        pct = int(100 * (complete + na) / total) if total else 0
        tk.Label(inner,
                 text=f"{complete}/{total}  ({pct}%)",
                 font=("Segoe UI", 8), bg=BG_CAT, fg=FG_SUB).pack(side="right", padx=16)

    def _build_row(self, ci, ti, cat, test):
        folder = test_folder(cat["id"], cat["title"], test["id"], test["title"],
                             self.project_root)
        status = load_report(folder)["status"]

        wrapper = tk.Frame(self.frame, bg=BG)
        wrapper.pack(fill="x")

        row = tk.Frame(wrapper, bg=BG_ROW, cursor="hand2")
        row.pack(fill="x", pady=1, padx=(4, 0))

        # left status strip
        strip_color = {"pending": BG_ROW, "complete": GREEN, "na": PURPLE}
        strip = tk.Frame(row, bg=strip_color[status], width=3)
        strip.pack(side="left", fill="y")

        # status dot
        dot = tk.Label(row, text=STATUS_SYM[status],
                       font=("Segoe UI", 13),
                       bg=BG_ROW, fg=STATUS_FG[status],
                       width=2, pady=10)
        dot.pack(side="left", padx=(10, 6))

        # test id
        id_lbl = tk.Label(row, text=test["id"],
                          font=F_ROW_ID, bg=BG_ROW, fg=FG_SUB,
                          width=5, anchor="w")
        id_lbl.pack(side="left", padx=(0, 8))

        # title
        title_lbl = tk.Label(row,
                             text=test["title"],
                             font=F_ROW,
                             bg=BG_ROW,
                             fg=FG_NA if status == "na" else FG,
                             anchor="w")
        title_lbl.pack(side="left", fill="x", expand=True)

        # chevron
        chev = tk.Label(row, text="›",
                        font=("Segoe UI", 14),
                        bg=BG_ROW, fg=FG_DIM, padx=12, pady=10)
        chev.pack(side="right")

        all_widgets = (row, strip, dot, id_lbl, title_lbl, chev)
        for w in all_widgets:
            w.bind("<Enter>",    lambda e, ws=all_widgets, r=row:
                   self._hover(ws, True, status))
            w.bind("<Leave>",    lambda e, ws=all_widgets, r=row:
                   self._hover(ws, False, status))
            w.bind("<Button-1>", lambda e, ci=ci, ti=ti, cat=cat,
                                        test=test, wr=wrapper, sw=strip, c=chev:
                   self._toggle(ci, ti, cat, test, wr, sw, c))

        self.row_refs[(ci, ti)] = (wrapper, strip, dot, title_lbl, chev)

    def _hover(self, widgets, entering, status):
        bg = BG_HOVER if entering else BG_ROW
        for w in widgets:
            try: w.configure(bg=bg)
            except: pass

    # ── accordion ─────────────────────────────────────────────────────────────

    def _toggle(self, ci, ti, cat, test, wrapper, strip, chev):
        key = (ci, ti)
        if self.expanded == key:
            if self.detail_ref:
                self.detail_ref.destroy(); self.detail_ref = None
            self.expanded = None
            chev.configure(text="›", fg=FG_DIM)
            return

        # close current
        if self.detail_ref:
            # reset old chevron
            if self.expanded and self.expanded in self.row_refs:
                self.row_refs[self.expanded][4].configure(text="›", fg=FG_DIM)
            self.detail_ref.destroy(); self.detail_ref = None

        self.expanded = key
        chev.configure(text="⌄", fg=ACCENT)

        dp = DetailPanel(wrapper, ci, ti, cat, test,
                         on_status_change=self._on_status_change,
                         project_root=self.project_root)
        dp.pack(fill="x")
        self.detail_ref = dp
        self.root.after(60, self._scroll_to, dp)

    def _scroll_to(self, widget):
        self.root.update_idletasks()
        try:
            y = widget.winfo_rooty() - self.frame.winfo_rooty()
        except tk.TclError: return
        total = self.frame.winfo_height()
        vh    = self.cv.winfo_height()
        if total > vh:
            self.cv.yview_moveto(max(0.0, min(1.0, (y - 60) / total)))

    # ── status updates ────────────────────────────────────────────────────────

    def _on_status_change(self, ci, ti, status):
        key = (ci, ti)
        if key not in self.row_refs:
            return
        wrapper, strip, dot, title_lbl, chev = self.row_refs[key]
        dot.configure(text=STATUS_SYM[status], fg=STATUS_FG[status])
        title_lbl.configure(fg=FG_NA if status == "na" else FG)
        strip_color = {"pending": BG_ROW, "complete": GREEN, "na": PURPLE}
        strip.configure(bg=strip_color[status])

        if status == "na":
            if self.detail_ref:
                self.detail_ref.destroy(); self.detail_ref = None
            chev.configure(text="›", fg=FG_DIM)
            self.expanded = None

        self._update_stats()

    def _update_stats(self):
        total = complete = na = 0
        for cat in self.checklist["categories"]:
            for test in cat["tests"]:
                total += 1
                s = load_report(test_folder(cat["id"], cat["title"],
                                             test["id"], test["title"],
                                             self.project_root))["status"]
                if s == "complete": complete += 1
                elif s == "na":     na += 1
        pending = total - complete - na
        self.stats_var.set(
            f"●  {complete} done   ⊘  {na} N/A   ○  {pending} pending   /  {total}")

        # update progress bar
        self.prog_cv.delete("all")
        w = 220
        if total:
            done_w  = int(w * complete / total)
            na_w    = int(w * na      / total)
        else:
            done_w = na_w = 0
        self.prog_cv.create_rectangle(0,     0, w,              4, fill=BORDER,  width=0)
        self.prog_cv.create_rectangle(0,     0, done_w,         4, fill=GREEN,   width=0)
        self.prog_cv.create_rectangle(done_w,0, done_w + na_w,  4, fill=PURPLE,  width=0)


# ─────────────────────────── entry point ─────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 app.py <project_name>")
        print("  e.g. python3 app.py \"Acme Corp Q4 Pentest\"")
        sys.exit(1)

    project_name = " ".join(sys.argv[1:])   # allow spaces without quotes too
    project_slug = slugify(project_name)
    if not project_slug:
        print("Error: project name must contain at least one letter or digit.")
        sys.exit(1)

    project_root = DATA_ROOT / project_slug
    is_new = not project_root.exists()

    if not CHECKLIST.exists():
        print(f"Error: checklist.json not found at {CHECKLIST.resolve()}")
        sys.exit(1)

    root = tk.Tk()
    App(root, project_root)
    if is_new:
        print(f"Created project: {project_root}")
    else:
        print(f"Opened project:  {project_root}")
    root.mainloop()

if __name__ == "__main__":
    main()
