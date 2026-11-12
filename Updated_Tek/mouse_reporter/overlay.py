#!/usr/bin/env python3
"""
Standalone checklist screen-capture overlay.

This is the mouse/reporting overlay's own interaction model (global
middle-click category/item picker, Space-toggled capture rectangle,
Shift+scroll resize, a capture hotkey = real screenshot + description,
Esc = un-prime) wired to a plain checklist.json instead of a project's
wstg_reporting.json, and with no dependency on the red-team-audit-tool app,
its Node server, or find_wstg_folder - just this script, pynput, and
(optionally) Pillow/scrot.

Two hotkey schemes, picked with --mac:
  default (Linux/Windows): F9 = capture, F10 = complete, F11 = N/A,
      Ctrl+Alt+Q = quit.
  --mac (macOS): Ctrl+Alt+S = capture, Ctrl+Alt+C = complete,
      Ctrl+Alt+N = N/A, Ctrl+Alt+Q = quit. F9-F11 collide with Mission
      Control's "Show All Windows"/"Show Desktop" defaults on macOS, and a
      third action wouldn't fit under F12 alone, so --mac swaps all three
      to Ctrl+Alt+<letter> combos instead, which exist on every keyboard
      and aren't bound to anything in macOS by default.

It writes into the exact same tree and Report.json shape as the attached
"Security Testing Appendix Organizer" (app.py):

    data/<cat_id>_<cat_slug>/<test_id_with_dots_as_underscores>_<test_slug>/
        Report.json
        images/image_N.ext

...using the same slugify()/test_folder() rules and the same Report.json
fields (status, affected_urls, steps[].step_number/url/image/description),
so the two tools read and write the same folders interchangeably: start a
test's evidence here with real screen captures, then open app.py to add
affected URLs, tidy descriptions, or mark it complete/N-A - or do all of it
from here, since this also has its own complete/N-A hotkeys.

Flow
----
Idle            -> middle-click                      -> picking category
Picking cat     -> scroll / hover moves the highlight
                   middle-click confirms              -> picking test (same category)
Picking test    -> scroll / hover moves the highlight
                   middle-click confirms              -> PRIMED (category+test locked)
Primed          -> Space toggles the capture rectangle (it follows the cursor)
                   Shift_L / Shift_R pick the resize axis (length / height)
                   scroll resizes the rectangle along that axis
                   capture hotkey                      -> real screenshot + describe/URL window
                   complete hotkey                      -> mark this test Complete
                   N/A hotkey                            -> mark this test N/A
                   middle-click                         -> re-opens the category picker (re-prime)
                   Esc                                  -> un-prime, hide the rectangle
Describe window -> fill in URL (optional) + description, "Save step" (or
                   Ctrl+Enter) appends it to Report.json; "Cancel"/Esc
                   discards it (the screenshot file, if one was taken, is
                   deleted so it doesn't linger as an orphan)
Anywhere        -> Ctrl+Alt+Q quits

Usage
-----
    pip install pynput          # Pillow optional, only needed if scrot is unavailable
    python3 checklist_screencap_overlay.py [--checklist checklist.json] [--output-dir data] [--mac]
"""
import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tkinter as tk
from datetime import datetime
from pathlib import Path

from pynput import keyboard, mouse

try:
    from PIL import ImageGrab
except ImportError:
    ImageGrab = None

DIAMETER = 90
GAP = 14
MARGIN_TOP = 12
ALPHA = 0.82
KEY_COLOR = "#010203"          # becomes see-through on Windows

COL_IDLE = "#2b2f3a"
COL_IDLE_OUT = "#6b7280"
COL_ACTIVE = "#3b82f6"
COL_ACTIVE_OUT = "#ffffff"
COL_LOCKED = "#16a34a"
COL_TEXT = "#f3f4f6"

RECT_STEP = 20                 # pixels per scroll notch
RECT_MIN = 20
RECT_ALPHA = 0.40
COL_RECT = "#f59e0b"

HIDE_BEFORE_CAPTURE_MS = 150   # let the WM actually unmap the overlay windows first


# ─────────────────────── checklist.json / Report.json (app.py-compatible) ───────────────────────
def slugify(s):
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")[:48]


def test_folder(output_dir, cat_id, cat_title, test_id, test_title):
    return output_dir / f"{cat_id}_{slugify(cat_title)}" / f"{str(test_id).replace('.', '_')}_{slugify(test_title)}"


def load_report(folder):
    rp = folder / "Report.json"
    if rp.exists():
        try:
            return json.loads(rp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"status": "pending", "affected_urls": [], "steps": []}


def save_report(folder, report):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "images").mkdir(exist_ok=True)
    (folder / "Report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def load_checklist(path: Path):
    """checklist.json -> (category_order, {(cat_id, cat_title): [(test_id, test_title), ...]}).
    Same shape as the attached checklist.json: {"categories": [{"id", "title", "tests": [{"id","title"}, ...]}, ...]}.
    Categories with no tests are dropped rather than shown as an empty, unusable circle."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    cats = raw.get("categories") if isinstance(raw, dict) else None
    if not isinstance(cats, list):
        raise SystemExit(f'{path}: no "categories" list.')
    order = []
    items_by_cat = {}
    for cat in cats:
        if not isinstance(cat, dict):
            continue
        cat_id = cat.get("id")
        cat_title = str(cat.get("title") or cat_id)
        if cat_id is None:
            continue
        tests = cat.get("tests")
        pairs = []
        for t in (tests or []):
            if not isinstance(t, dict):
                continue
            tid = t.get("id")
            if tid is None:
                continue
            pairs.append((tid, str(t.get("title") or tid)))
        if pairs:
            key = (cat_id, cat_title)
            order.append(key)
            items_by_cat[key] = pairs
    if not order:
        raise SystemExit(f'{path}: no categories with any tests.')
    return order, items_by_cat


# ─────────────────────────────────────── overlay ───────────────────────────────────────
class ChecklistOverlay:
    def __init__(self, output_dir: Path, categories, items_by_category, mac=False):
        self.output_dir = output_dir
        self.categories = categories                  # [(cat_id, cat_title), ...]
        self.items_by_category = items_by_category     # {(cat_id, cat_title): [(test_id, test_title), ...]}
        self.mac = mac
        # Display labels for whichever hotkey scheme is active - used only in the status bar.
        self.key_labels = (
            {"capture": "Ctrl+Alt+S", "complete": "Ctrl+Alt+C", "na": "Ctrl+Alt+N"}
            if mac else
            {"capture": "F9", "complete": "F10", "na": "F11"}
        )

        # picking state: None | "category" | "item"
        self.mode = None
        self.index = 0
        self.locked_category = None                    # (cat_id, cat_title)
        self.locked_item = None                         # (test_id, test_title)
        self.primed = False

        # rectangle state (this rectangle IS the capture frame - F9 refuses without it)
        self.rect_on = False
        self.rect_w, self.rect_h = 240, 140
        self.resize_axis = None        # None | "length" | "height"
        self.rect_win = None
        self.rect_canvas = None
        self.mx = self.my = 0

        self.pressed = set()           # swallow key auto-repeat
        self.quit_requested = False
        self.describe_win = None
        self.capture_in_progress = False
        self.step_counts = {}          # (cat_id, test_id) -> last step number

        # Borderless (overrideredirect) + transparent-color-keyed windows are a known
        # unreliable combination on macOS/Cocoa - they can exist with no error and still
        # never actually draw. Rather than patch that combination, macOS gets ordinary
        # bordered, opaque, always-on-top windows instead: a ordinary window is
        # guaranteed to render and get normal Dock/activation handling like any other
        # Mac app, at the cost of a visible title bar.
        self.is_mac = sys.platform == "darwin"
        self.root = tk.Tk()
        self.root.title("checklist-screencap-overlay")
        if not self.is_mac:
            self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self._setup_transparency()

        self.w = max(1, len(self.categories)) * DIAMETER + (len(self.categories) + 1) * GAP
        self.h = DIAMETER + MARGIN_TOP + GAP
        sw = self.root.winfo_screenwidth()
        self.x0 = max(0, (sw - self.w) // 2)
        # y=0 sits under/behind the macOS menu bar - an overrideredirect window placed
        # there can end up not drawn at all rather than just clipped. A modest offset
        # clears it on macOS and is harmless on Linux/Windows too.
        self.y0 = 40
        self.root.geometry(f"{self.w}x{self.h}+{self.x0}+{self.y0}")

        self.canvas = tk.Canvas(self.root, width=self.w, height=self.h,
                                 bg=self._bg, highlightthickness=0)
        self.canvas.pack()

        self.status_win = tk.Toplevel(self.root)
        self.status_win.title("checklist-screencap-overlay-status")
        if not self.is_mac:
            self.status_win.overrideredirect(True)
        self.status_win.attributes("-topmost", True)
        if not self.is_mac:
            try:
                self.status_win.attributes("-alpha", ALPHA)
            except tk.TclError:
                pass
        self.status_label = tk.Label(self.status_win, text="", fg="#f3f4f6",
                                      bg="#111318", font=("Helvetica", 10),
                                      padx=10, pady=4, justify="left", anchor="nw",
                                      wraplength=540)
        self.status_label.pack(fill="both", expand=True)
        self.status_win.geometry(f"560x56+{self.x0}+{self.y0 + self.h + 6}")

        self.draw()
        self._refresh_status()
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)
        self.root.after(200, self._poll)
        print(f"[overlay] platform={sys.platform} tk={self.root.tk.call('info', 'patchlevel')} "
              f"screen={sw}x{self.root.winfo_screenheight()} "
              f"hud_geometry={self.w}x{self.h}+{self.x0}+{self.y0}", flush=True)

    # ---- transparency ---------------------------------------------------
    def _setup_transparency(self):
        self._bg = "black"
        if self.is_mac:
            # Deliberately NOT using "-transparent"/"systemTransparent" here - that
            # Cocoa-only color-keying path is exactly the combination that was leaving
            # the window undrawn. A plain opaque dark window is the trade-off: it looks
            # like a small normal app window instead of a borderless floating HUD, but
            # it is guaranteed to actually show up.
            return
        try:
            if sys.platform.startswith("win"):
                self._bg = KEY_COLOR
                self.root.attributes("-transparentcolor", KEY_COLOR)
                self.root.attributes("-alpha", ALPHA)
            else:
                self.root.attributes("-alpha", ALPHA)
        except tk.TclError:
            pass

    # ---- drawing: category/item HUD -------------------------------------
    def _cat_labels(self):
        return [title for _id, title in self.categories]

    def _item_labels(self, cat_key):
        return [f"{tid}\n{title}" for tid, title in self.items_by_category[cat_key]]

    def _labels(self):
        if self.mode == "category":
            idx = self.categories.index(self.locked_category) if self.locked_category in self.categories else None
            return self._cat_labels(), idx
        if self.mode == "item":
            return self._item_labels(self.locked_category), None
        if self.primed and self.locked_category:
            items = self.items_by_category[self.locked_category]
            idx = next((i for i, it in enumerate(items) if it == self.locked_item), None)
            return self._item_labels(self.locked_category), idx
        return self._cat_labels(), None

    def circle_center(self, i, n):
        cx = GAP + DIAMETER / 2 + i * (DIAMETER + GAP)
        cy = MARGIN_TOP + DIAMETER / 2
        return cx, cy

    def draw(self):
        c = self.canvas
        c.delete("all")
        labels, locked_idx = self._labels()
        n = max(1, len(labels))
        r = DIAMETER / 2
        picking = self.mode in ("category", "item")
        for i, label in enumerate(labels):
            cx, cy = self.circle_center(i, n)
            if picking and i == self.index:
                fill, outline, width = COL_ACTIVE, COL_ACTIVE_OUT, 3
            elif locked_idx is not None and i == locked_idx:
                fill, outline, width = COL_LOCKED, COL_IDLE_OUT, 2
            else:
                fill, outline, width = COL_IDLE, COL_IDLE_OUT, 2
            c.create_oval(cx - r, cy - r, cx + r, cy + r,
                          fill=fill, outline=outline, width=width)
            c.create_text(cx, cy, text=label, fill=COL_TEXT,
                          width=DIAMETER - 14, font=("Helvetica", 9, "bold"),
                          justify="center")

    def _refresh_status(self):
        if self.mode == "category":
            msg = "Pick category - scroll/hover to move, middle-click to confirm"
        elif self.mode == "item":
            msg = f"[{self.locked_category[1]}] pick test - scroll/hover, middle-click to confirm"
        elif self.primed:
            tid, _title = self.locked_item
            kl = self.key_labels
            msg = (f"PRIMED: {self.locked_category[1]} / {tid}\n"
                   f"Space=toggle rect | Shift_L+scroll=width | Shift_R+scroll=height | "
                   f"{kl['capture']}=capture | {kl['complete']}=complete | {kl['na']}=N/A | Esc=unprime")
        else:
            msg = "Idle - middle-click to pick a category"
        self.status_label.config(text=msg)

    # ---- category/item picking state machine -----------------------------
    def on_middle_click(self):
        if self.describe_win is not None or self.capture_in_progress:
            return
        if self.mode is None:
            if self.rect_win:
                self.rect_win.destroy()
                self.rect_win = None
            self.rect_on = False
            self.resize_axis = None
            self.mode = "category"
            self.index = (self.categories.index(self.locked_category)
                          if self.locked_category in self.categories else 0)
        elif self.mode == "category":
            self.locked_category = self.categories[self.index]
            self.mode = "item"
            self.index = 0
        elif self.mode == "item":
            items = self.items_by_category[self.locked_category]
            self.locked_item = items[self.index]
            self.mode = None
            self.primed = True
        self.draw()
        self._refresh_status()

    def move_highlight(self, delta):
        if self.mode not in ("category", "item"):
            return
        n = len(self.categories) if self.mode == "category" else len(self.items_by_category[self.locked_category])
        if n == 0:
            return
        self.index = (self.index + delta) % n
        self.draw()

    def hover(self, x, y):
        self.mx, self.my = int(x), int(y)
        if self.rect_on:
            self.update_rect()
        if self.mode not in ("category", "item"):
            return
        lx, ly = x - self.x0, y - self.y0
        if not (0 <= ly <= self.h):
            return
        labels, _ = self._labels()
        n = max(1, len(labels))
        for i in range(n):
            cx, cy = self.circle_center(i, n)
            if (lx - cx) ** 2 + (ly - cy) ** 2 <= (DIAMETER / 2) ** 2:
                if i != self.index:
                    self.index = i
                    self.draw()
                return

    def scroll(self, dy):
        if dy == 0:
            return
        if self.mode in ("category", "item"):
            self.move_highlight(1 if dy < 0 else -1)
            return
        if self.rect_on and self.resize_axis:
            self.resize_rect(dy)

    # ---- capture rectangle ------------------------------------------------
    def toggle_rect(self):
        if not self.primed or self.mode is not None or self.describe_win is not None or self.capture_in_progress:
            return
        if self.rect_on:
            self.rect_on = False
            self.resize_axis = None
            if self.rect_win:
                self.rect_win.destroy()
                self.rect_win = None
            return
        self.rect_on = True
        w = tk.Toplevel(self.root)
        w.title("checklist-screencap-overlay-rect")
        if not self.is_mac:
            w.overrideredirect(True)
        w.attributes("-topmost", True)
        if not self.is_mac:
            try:
                w.attributes("-alpha", RECT_ALPHA)
            except tk.TclError:
                pass
        self.rect_canvas = tk.Canvas(w, bg=COL_RECT, highlightthickness=3,
                                      highlightbackground="#ffffff")
        self.rect_canvas.pack(fill="both", expand=True)
        self.rect_win = w
        self.update_rect()

    def set_resize_axis(self, axis):
        if not (self.primed and self.rect_on) or self.mode is not None:
            return
        self.resize_axis = None if self.resize_axis == axis else axis
        self.update_rect()

    def update_rect(self):
        if not (self.rect_on and self.rect_win):
            return
        self.rect_win.geometry(f"{self.rect_w}x{self.rect_h}+{self.mx}+{self.my}")
        label = {"length": "LENGTH <-> (scroll)",
                 "height": "HEIGHT ^v (scroll)"}.get(self.resize_axis, "")
        c = self.rect_canvas
        c.delete("all")
        c.create_text(self.rect_w / 2, self.rect_h / 2,
                      text=f"{label}\n{self.rect_w} x {self.rect_h}".strip(),
                      fill="black", font=("Helvetica", 11, "bold"), justify="center")

    def resize_rect(self, dy):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        d = RECT_STEP if dy > 0 else -RECT_STEP
        if self.resize_axis == "length":
            self.rect_w = max(RECT_MIN, min(sw, self.rect_w + d))
        else:
            self.rect_h = max(RECT_MIN, min(sh, self.rect_h + d))
        self.update_rect()

    # ---- folder / report helpers --------------------------------------------
    def _current_folder(self):
        cat_id, cat_title = self.locked_category
        test_id, test_title = self.locked_item
        return test_folder(self.output_dir, cat_id, cat_title, test_id, test_title)

    # ---- real capture + description ----------------------------------------
    def capture(self):
        if not self.primed or self.mode is not None or self.describe_win is not None or self.capture_in_progress:
            return
        if not (self.rect_on and self.rect_win):
            print("[capture] no capture rectangle is shown - press Space first.", flush=True)
            return
        self.capture_in_progress = True
        x, y, w, h = self.mx, self.my, self.rect_w, self.rect_h
        test_id = self.locked_item[0]
        key = (self.locked_category[0], test_id)
        step_no = self.step_counts.get(key, 0) + 1

        folder = self._current_folder()
        images_dir = folder / "images"
        image_path = images_dir / f"image_{step_no}.png"

        # Hide the overlay (HUD, status, rectangle) before grabbing, so the overlay never
        # captures itself; a short delay lets the window manager actually unmap them first.
        self.root.withdraw()
        self.status_win.withdraw()
        if self.rect_win:
            self.rect_win.withdraw()
        self.root.after(HIDE_BEFORE_CAPTURE_MS,
                        lambda: self._do_capture(x, y, w, h, images_dir, image_path, step_no))

    def _do_capture(self, x, y, w, h, images_dir, image_path, step_no):
        images_dir.mkdir(parents=True, exist_ok=True)
        saved = self._take_screenshot(x, y, w, h, str(image_path))
        if not saved:
            image_path = None

        self.root.deiconify()
        self.status_win.deiconify()
        if self.rect_win:
            self.rect_win.deiconify()
        self.capture_in_progress = False
        self._open_describe_window(step_no, image_path)

    def _take_screenshot(self, x, y, w, h, filepath):
        try:
            subprocess.run(["scrot", "-a", f"{x},{y},{w},{h}", filepath],
                            check=True, capture_output=True, timeout=10)
            print(f"[captured] {filepath} (scrot)", flush=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            if ImageGrab is None:
                print(f"[capture] scrot unavailable ({e}) and Pillow is not installed - "
                      f"no image saved. Install scrot or run: pip install pillow", flush=True)
                return False
            try:
                im = ImageGrab.grab(bbox=(x, y, x + w, y + h))
                im.save(filepath)
                print(f"[captured] {filepath} (PIL.ImageGrab fallback)", flush=True)
                return True
            except Exception as e2:
                print(f"[capture] screenshot failed: {e2}", flush=True)
                return False

    def _open_describe_window(self, step_no, image_path):
        win = tk.Toplevel(self.root)
        win.title(f"Describe step {step_no}")
        win.attributes("-topmost", True)
        win.geometry(f"440x260+{self.x0}+{self.y0 + 80}")
        shot_note = f" - {image_path}" if image_path else " - no image saved"
        tk.Label(win, text=f"{self.locked_category[1]} / {self.locked_item[0]} - step {step_no}{shot_note}",
                font=("Helvetica", 10, "bold"), wraplength=420, justify="left").pack(anchor="w", padx=8, pady=(8, 2))

        tk.Label(win, text="Affected URL (optional):", font=("Helvetica", 9)).pack(anchor="w", padx=8, pady=(6, 0))
        url_var = tk.StringVar()
        url_entry = tk.Entry(win, textvariable=url_var)
        url_entry.pack(fill="x", padx=8, pady=(0, 6))

        tk.Label(win, text="Description:", font=("Helvetica", 9)).pack(anchor="w", padx=8)
        text = tk.Text(win, height=5, wrap="word")
        text.pack(fill="both", expand=True, padx=8, pady=4)
        text.focus_set()

        def save(_event=None):
            desc = text.get("1.0", "end").strip()
            url = url_var.get().strip()
            self._save_step(step_no, url, desc, image_path)
            close()

        def close(_event=None):
            # Discard an orphan screenshot if the step wasn't saved.
            if image_path is not None and image_path.exists():
                try:
                    image_path.unlink()
                except OSError:
                    pass
            self.describe_win = None
            win.destroy()
            self.draw()
            self._refresh_status()

        btns = tk.Frame(win)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        tk.Button(btns, text="Save step (Ctrl+Enter)", command=save).pack(side="left")
        tk.Button(btns, text="Cancel (Esc)", command=close).pack(side="left", padx=(8, 0))
        win.bind("<Control-Return>", save)
        win.bind("<Escape>", close)
        win.protocol("WM_DELETE_WINDOW", close)
        self.describe_win = win

    def _save_step(self, step_no, url, description, image_path):
        folder = self._current_folder()
        report = load_report(folder)
        test_id, test_title = self.locked_item
        report.setdefault("test_id", test_id)
        report.setdefault("title", test_title)
        report["saved_at"] = datetime.now().isoformat(timespec="seconds")
        if report.get("status") not in ("complete", "na"):
            report["status"] = "pending"
        if url and url not in report.get("affected_urls", []):
            report.setdefault("affected_urls", []).append(url)
        rel_image = None
        if image_path is not None:
            try:
                rel_image = str(image_path.relative_to(Path.cwd()))
            except ValueError:
                rel_image = str(image_path)
        report.setdefault("steps", []).append({
            "step_number": step_no, "url": url, "image": rel_image or "", "description": description,
        })
        save_report(folder, report)
        self.step_counts[(self.locked_category[0], test_id)] = step_no
        print(f"[saved] {folder / 'Report.json'} <- step {step_no}", flush=True)

    # ---- finishing a test without leaving the overlay ----------------------
    def mark_status(self, status):
        if not self.primed or self.mode is not None or self.describe_win is not None or self.capture_in_progress:
            return
        folder = self._current_folder()
        report = load_report(folder)
        report["status"] = status
        report["saved_at"] = datetime.now().isoformat(timespec="seconds")
        save_report(folder, report)
        print(f"[saved] {folder / 'Report.json'} <- status={status}", flush=True)
        self._refresh_status()

    # ---- un-prime / quit ----------------------------------------------------
    def unprime(self):
        if self.capture_in_progress:
            return
        if self.describe_win is not None:
            self.describe_win.destroy()
            self.describe_win = None
        self.mode = None
        self.primed = False
        self.locked_category = None
        self.locked_item = None
        if self.rect_win:
            self.rect_win.destroy()
            self.rect_win = None
        self.rect_on = False
        self.resize_axis = None
        self.draw()
        self._refresh_status()

    def request_quit(self, *_):
        self.quit_requested = True   # safe to call from signal/listener threads

    def _poll(self):
        if self.quit_requested:
            self.shutdown()
        else:
            self.root.after(200, self._poll)

    def shutdown(self):
        if getattr(self, "_closing", False):
            return
        self._closing = True
        for l in (getattr(self, "mouse_listener", None), getattr(self, "kb_listener", None)):
            try:
                if l:
                    l.stop()
            except Exception:
                pass
        try:
            if self.rect_win:
                self.rect_win.destroy()
            if self.describe_win:
                self.describe_win.destroy()
            self.status_win.destroy()
            self.root.quit()
            self.root.destroy()
        except tk.TclError:
            pass

    # ---- global listeners (run in their own threads) -----------------------
    def start_listeners(self):
        def on_click(x, y, button, pressed):
            if button == mouse.Button.middle and pressed:
                self.root.after(0, self.on_middle_click)

        def on_scroll(x, y, dx, dy):
            self.root.after(0, self.scroll, dy)

        def on_move(x, y):
            self.root.after(0, self.hover, x, y)

        self.mouse_listener = mouse.Listener(on_click=on_click,
                                              on_scroll=on_scroll,
                                              on_move=on_move)
        self.mouse_listener.start()

        def ctrl_alt_down():
            ctrl = keyboard.Key.ctrl_l in self.pressed or keyboard.Key.ctrl in self.pressed or keyboard.Key.ctrl_r in self.pressed
            alt = keyboard.Key.alt_l in self.pressed or keyboard.Key.alt in self.pressed or keyboard.Key.alt_r in self.pressed
            return ctrl and alt

        def on_press(key):
            if key in self.pressed:
                return                      # ignore auto-repeat
            self.pressed.add(key)
            if key == keyboard.Key.space:
                self.root.after(0, self.toggle_rect)
            elif key == keyboard.Key.shift_l:
                self.root.after(0, self.set_resize_axis, "length")
            elif key == keyboard.Key.shift_r:
                self.root.after(0, self.set_resize_axis, "height")
            elif key == keyboard.Key.esc:
                self.root.after(0, self.unprime)
            elif not self.mac and key == keyboard.Key.f9:
                self.root.after(0, self.capture)
            elif not self.mac and key == keyboard.Key.f10:
                self.root.after(0, self.mark_status, "complete")
            elif not self.mac and key == keyboard.Key.f11:
                self.root.after(0, self.mark_status, "na")
            elif self.mac and ctrl_alt_down() and key == keyboard.KeyCode.from_char("s"):
                self.root.after(0, self.capture)
            elif self.mac and ctrl_alt_down() and key == keyboard.KeyCode.from_char("c"):
                self.root.after(0, self.mark_status, "complete")
            elif self.mac and ctrl_alt_down() and key == keyboard.KeyCode.from_char("n"):
                self.root.after(0, self.mark_status, "na")
            elif ctrl_alt_down() and key == keyboard.KeyCode.from_char("q"):
                self.request_quit()         # Ctrl+Alt+Q, both schemes

        def on_release(key):
            self.pressed.discard(key)

        self.kb_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        self.kb_listener.start()

    def _activate_mac(self):
        """A plain CLI python3 process launched from Terminal never becomes the
        foreground/active macOS app on its own, so Tk's windows can exist in the
        window server's list without ever being drawn on top of anything - no
        error, no crash, just invisible. Explicitly telling System Events to make
        this process frontmost is the standard workaround. This needs Automation
        permission (Privacy & Security -> Automation -> Terminal -> System Events)
        - macOS will prompt for it the first time; allow it."""
        if sys.platform != "darwin":
            return
        try:
            subprocess.run(
                ["osascript", "-e",
                 f'tell application "System Events" to set frontmost of '
                 f'(first process whose unix id is {os.getpid()}) to true'],
                check=False, capture_output=True, timeout=5,
            )
        except Exception as e:
            print(f"[overlay] could not activate via osascript: {e}", flush=True)
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.status_win.lift()

        # Content drawn into a widget BEFORE the window was actually mapped/activated
        # by the window manager can end up never painted into the visible backing
        # store on Cocoa - the window and widgets exist, nothing on screen reflects
        # them. Re-issue the drawing now that the window is actually up, and force a
        # geometry round-trip on each window, which makes Tk re-expose/repaint it.
        self.draw()
        self._refresh_status()
        for win, geom in ((self.root, f"{self.w}x{self.h}+{self.x0}+{self.y0}"),
                           (self.status_win, f"560x56+{self.x0}+{self.y0 + self.h + 6}")):
            try:
                win.withdraw()
                win.update_idletasks()
                win.deiconify()
                win.geometry(geom)
                win.update_idletasks()
            except tk.TclError:
                pass
        print("[overlay] activation + forced redraw done", flush=True)

    def run(self):
        signal.signal(signal.SIGINT, self.request_quit)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self.request_quit)
        self.start_listeners()
        self.root.after(200, self._activate_mac)
        self.root.after(1000, self._activate_mac)  # a second nudge in case the first raced window creation
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--checklist", default="checklist.json",
                     help="Path to the checklist JSON (default: ./checklist.json)")
    ap.add_argument("--output-dir", default="data",
                     help="Folder to write Report.json/images into, same layout app.py uses (default: ./data)")
    ap.add_argument("--mac", action="store_true",
                     help="Use mac-safe hotkeys (Ctrl+Alt+S/C/N) instead of F9/F10/F11, which collide "
                          "with Mission Control's defaults on macOS.")
    args = ap.parse_args()

    checklist_path = Path(args.checklist)
    if not checklist_path.is_file():
        raise SystemExit(f"--checklist not found: {checklist_path}")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    order, items_by_cat = load_checklist(checklist_path)
    overlay = ChecklistOverlay(output_dir, order, items_by_cat, mac=args.mac)
    overlay.run()


if __name__ == "__main__":
    main()
