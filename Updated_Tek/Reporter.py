#!/usr/bin/env python3
"""
Mac input probe - find out what your mouse's extra buttons actually send.

This exists to answer one question before wiring anything into the overlay:
on a Bluetooth mouse (no vendor dongle/driver), do the side buttons and the
extra middle button show up as real mouse-button events at all, and if so,
which identifier does pynput report for each one? A lot of third-party
mice's side buttons are only "Back/Forward" because a vendor driver (or the
OS's own Back/Forward gesture mapping) is translating them - over Bluetooth,
with no such driver running, they may come through as a raw button number,
as nothing at all, or (rarely) as a keyboard event instead. There's no way
to know without watching what macOS actually delivers, which is what this
does.

It opens two global listeners (pynput) and just prints everything it sees:
every mouse click (with pynput's Button object - for anything beyond
left/middle/right this is usually "Button.unknown" plus a raw button
number on macOS), every scroll tick (including horizontal dx, in case a
side button or tilt-wheel action shows up as a scroll event instead of a
click), and every keypress (in case a side button is actually surfaced as
a media/navigation key rather than a mouse button).

Nothing is written anywhere - this only prints to the terminal.

Setup on macOS
---------------
System Settings -> Privacy & Security -> grant BOTH:
    Accessibility       (lets pynput's listeners receive events at all)
    Input Monitoring    (specifically required for the keyboard listener)
Grant it to whatever actually runs python3 - Terminal.app/iTerm if you run
this directly, or the venv's python3 binary if you use one. If you add
these after already launching Terminal, quit and reopen Terminal once.

Usage
-----
    pip install pynput
    python3 mac_mouse_probe.py

Then, one at a time: click left, click right, click the standard middle
button (if there is one), click each of the two side buttons, click
whatever that "even another middle button" is, and spin the scroll wheel
in every direction it moves (straight up/down, and sideways/tilt if it
tilts). Watch what prints after each one. Ctrl+C to quit.
"""
import sys
from datetime import datetime

from pynput import keyboard, mouse


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def on_click(x, y, button, pressed):
    state = "DOWN" if pressed else "UP  "
    # repr(button) is the thing to go by - for a standard button this is
    # "Button.left" etc.; for anything else pynput on macOS typically prints
    # something like "Button.unknown" together with a raw value, or a plain
    # integer-backed button object depending on pynput version.
    print(f"[{ts()}] CLICK  {state}  button={button!r}  (x={x}, y={y})", flush=True)


def on_scroll(x, y, dx, dy):
    direction = []
    if dy > 0:
        direction.append("up")
    elif dy < 0:
        direction.append("down")
    if dx > 0:
        direction.append("right-tilt")
    elif dx < 0:
        direction.append("left-tilt")
    print(f"[{ts()}] SCROLL dx={dx} dy={dy}  ({', '.join(direction) or 'none'})  (x={x}, y={y})", flush=True)


def on_press(key):
    print(f"[{ts()}] KEY    DOWN  {key!r}", flush=True)


def on_release(key):
    print(f"[{ts()}] KEY    UP    {key!r}", flush=True)


def main():
    print(__doc__, flush=True)
    print("Listening... press each button / move the wheel, Ctrl+C to stop.\n", flush=True)
    try:
        m = mouse.Listener(on_click=on_click, on_scroll=on_scroll)
        k = keyboard.Listener(on_press=on_press, on_release=on_release)
        m.start()
        k.start()
        m.join()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n[probe] Could not start listeners: {e}", file=sys.stderr)
        print("[probe] On macOS this almost always means Accessibility / Input Monitoring "
              "permission hasn't been granted to this terminal/python yet - see the docstring above.",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
