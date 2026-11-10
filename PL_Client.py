#!/usr/bin/env python3
"""
word_picker.py — A global clipboard word-picker.

Usage:
    python3 word_picker.py wordlist.txt

Behavior:
  1. Started with a wordlist file as an argument.
  2. The wordlist is read line by line into a list of words.
  3. Middle-mouse-click opens a small popup near the mouse cursor showing
     a window of ten words from the list.
  4. Mouse-wheel scroll (while the popup is open) moves up/down through
     the wordlist, sliding the ten-word window and the highlighted word.
  5. Pressing LEFT SHIFT copies the currently highlighted word to the
     clipboard and closes the popup.
  6. After the copy, the script waits ~0.8s and then sends a "paste"
     keystroke (Ctrl+V) to whatever window currently has focus.

Dependencies:
    pip install pynput pyperclip

Notes:
  - This uses OS-level input hooks (pynput), so on Linux it needs an X11
    session (Wayland support is limited/absent for global hooks), and on
    macOS you must grant your terminal/python Accessibility + Input
    Monitoring permissions (System Settings -> Privacy & Security).
  - The popup is a borderless, non-activating window so it should not
    steal focus from whatever app you plan to paste into.
"""

import sys
import argparse
import queue
import threading
import time
import tkinter as tk

try:
    import pyperclip
except ImportError:
    pyperclip = None

from pynput import mouse, keyboard

PASTE_DELAY_SECONDS = 0.8
WINDOW_SIZE = 10  # how many words shown at once


def load_wordlist(path):
    with open(path, "r", encoding="utf-8") as f:
        words = [line.rstrip("\n").rstrip("\r") for line in f]
    words = [w for w in words if w != ""]
    if not words:
        print(f"Wordlist '{path}' is empty.", file=sys.stderr)
        sys.exit(1)
    return words


class WordPickerApp:
    def __init__(self, words):
        self.words = words
        self.window_start = 0  # index of the first (highlighted) word shown
        self.popup_open = False

        # Thread-safe queue: pynput callbacks run on background threads,
        # Tkinter must only be touched from the main thread.
        self.events = queue.Queue()

        # Hidden root window (needed for Tkinter to run at all).
        self.root = tk.Tk()
        self.root.withdraw()

        self.popup = None
        self.listbox = None

        # Keyboard controller used to send the paste keystroke.
        self.kb_controller = keyboard.Controller()

        # Start global listeners in background threads.
        self.mouse_listener = mouse.Listener(
            on_click=self._on_click, on_scroll=self._on_scroll
        )
        self.keyboard_listener = keyboard.Listener(on_press=self._on_press)
        self.mouse_listener.start()
        self.keyboard_listener.start()

        # Poll the event queue regularly on the main (Tk) thread.
        self.root.after(30, self._poll_events)

    # ---------- pynput callbacks (run on background threads) ----------

    def _on_click(self, x, y, button, pressed):
        if pressed and button == mouse.Button.middle:
            self.events.put(("middle_click", x, y))

    def _on_scroll(self, x, y, dx, dy):
        self.events.put(("scroll", dy))

    def _on_press(self, key):
        if key == keyboard.Key.shift_l:
            self.events.put(("left_shift",))

    # ---------- main-thread event processing ----------

    def _poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.root.after(30, self._poll_events)

    def _handle_event(self, event):
        kind = event[0]
        if kind == "middle_click":
            _, x, y = event
            self._open_popup(x, y)
        elif kind == "scroll":
            if self.popup_open:
                _, dy = event
                self._scroll(dy)
        elif kind == "left_shift":
            if self.popup_open:
                self._choose_current_word()

    # ---------- popup management ----------

    def _open_popup(self, x, y):
        if self.popup_open:
            self._close_popup()

        self.window_start = 0
        self.popup = tk.Toplevel(self.root)
        self.popup.overrideredirect(True)  # borderless
        self.popup.attributes("-topmost", True)
        try:
            # Keep it from stealing focus on platforms that support this.
            self.popup.attributes("-type", "utility")
        except tk.TclError:
            pass

        # Position near the mouse, offset to the bottom-right.
        pos_x = x + 12
        pos_y = y - 10
        self.popup.geometry(f"+{pos_x}+{pos_y}")

        frame = tk.Frame(self.popup, bg="black", bd=1)
        frame.pack()

        self.listbox = tk.Listbox(
            frame,
            height=WINDOW_SIZE,
            width=30,
            activestyle="none",
            bg="#222222",
            fg="white",
            selectbackground="#4a90d9",
            selectforeground="white",
            highlightthickness=0,
            bd=0,
            font=("TkDefaultFont", 10),
        )
        self.listbox.pack()

        self.popup_open = True
        self._render()

    def _close_popup(self):
        if self.popup is not None:
            self.popup.destroy()
            self.popup = None
        self.listbox = None
        self.popup_open = False

    def _render(self):
        if not self.popup_open or self.listbox is None:
            return
        self.listbox.delete(0, tk.END)
        end = min(self.window_start + WINDOW_SIZE, len(self.words))
        for w in self.words[self.window_start:end]:
            self.listbox.insert(tk.END, w)
        # Highlight the first (current) item in the visible window.
        if self.listbox.size() > 0:
            self.listbox.selection_clear(0, tk.END)
            self.listbox.selection_set(0)
            self.listbox.activate(0)

    def _scroll(self, dy):
        # dy > 0 usually means "scroll up" on most platforms; adjust the
        # sign below if your mouse feels inverted.
        max_start = max(0, len(self.words) - 1)
        if dy > 0:
            self.window_start = max(0, self.window_start - 1)
        elif dy < 0:
            self.window_start = min(max_start, self.window_start + 1)
        self._render()

    def _choose_current_word(self):
        if self.window_start >= len(self.words):
            self._close_popup()
            return
        chosen = self.words[self.window_start]
        self._close_popup()
        self._copy_to_clipboard(chosen)
        threading.Thread(target=self._delayed_paste, daemon=True).start()

    # ---------- clipboard / paste ----------

    def _copy_to_clipboard(self, text):
        if pyperclip is not None:
            pyperclip.copy(text)
        else:
            # Fallback: Tk's own clipboard (works, but only while the
            # process keeps running).
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()

    def _delayed_paste(self):
        time.sleep(PASTE_DELAY_SECONDS)
        try:
            self.kb_controller.press(keyboard.Key.ctrl)
            self.kb_controller.press("v")
            self.kb_controller.release("v")
            self.kb_controller.release(keyboard.Key.ctrl)
        except Exception as exc:
            print(f"Paste failed: {exc}", file=sys.stderr)

    def run(self):
        try:
            self.root.mainloop()
        finally:
            self.mouse_listener.stop()
            self.keyboard_listener.stop()


def main():
    parser = argparse.ArgumentParser(description="Global clipboard word-picker.")
    parser.add_argument("wordlist", help="Path to a text file, one word per line.")
    args = parser.parse_args()

    words = load_wordlist(args.wordlist)

    if pyperclip is None:
        print(
            "Note: pyperclip not installed, falling back to Tk's clipboard "
            "(pip install pyperclip for a more robust clipboard).",
            file=sys.stderr,
        )

    print(f"Loaded {len(words)} words from '{args.wordlist}'.")
    print("Middle-click anywhere to open the picker. Scroll to browse, "
          "Left Shift to pick + paste.")

    app = WordPickerApp(words)
    app.run()


if __name__ == "__main__":
    main()
