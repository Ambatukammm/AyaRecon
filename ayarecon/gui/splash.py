"""
AyaForge — animated startup screen.
Made by Ruel · AyaLabs.

Shows the AyaForge mark (furnace peak · hearth · spark) and spins it three full
turns, then fades out and hands control to the main app. No text — just the logo.

Fully non-blocking: every step is scheduled via Tk's `after`, so the UI thread
never sleeps. Click or press any key to skip. If anything here misbehaves it
fails open — the caller's `on_done` still runs, so the app always launches.
"""

from __future__ import annotations

import math
import tkinter as tk

BG = "#0c0914"          # deep forge-black
STROKE = "#ffffff"      # furnace strokes
SPARK = "#d7a3ff"       # Aya's spark — project purple
SPINS = 3               # full rotations before it settles


def _ease(t):
    """Ease-in-out cubic — slow start, fast middle, gentle settle."""
    return 4 * t * t * t if t < 0.5 else 1 - (-2 * t + 2) ** 3 / 2


def _mark(c, cx, cy, size, stroke, spark, angle):
    """Draw the AyaForge mark rotated by `angle` radians (self-contained copy so
    the splash works even before the main app module is importable)."""
    s = size / 100.0
    cos, sin = math.cos(angle), math.sin(angle)

    def P(px, py):                       # rotate around the mark's visual centre
        dx, dy = px - 50, py - 52
        return (cx + (dx * cos - dy * sin) * s, cy + (dx * sin + dy * cos) * s)

    sw = max(2, 12 * s)
    (ax, ay), (bx, by), (dx, dy) = P(18, 70), P(50, 14), P(82, 70)
    c.create_line(ax, ay, bx, by, dx, dy, fill=stroke, width=sw,
                  capstyle="round", joinstyle="round")
    (hx1, hy1), (hx2, hy2) = P(14, 90), P(86, 90)
    c.create_line(hx1, hy1, hx2, hy2, fill=stroke, width=sw, capstyle="round")
    (sx, sy) = P(50, 56)
    r = max(2, 8 * s)
    c.create_oval(sx - r, sy - r, sx + r, sy + r, fill=spark, outline="")


class SplashScreen:
    # Three deliberate single rotations, each eased (slow → fast → slow) and
    # followed by a clear pause, so it reads as three turns rather than a blur.
    SPIN = 44            # frames for one 360° turn
    PAUSE = 20           # frames of stillness after each turn
    TAIL = 8             # small hold before the fade

    def __init__(self, root, on_done, hold_ms: int = 22):
        self.root = root
        self.on_done = on_done
        self.hold = hold_ms
        self._done = False
        self.frame = 0
        self.cycle = self.SPIN + self.PAUSE
        self.end_frames = self.cycle * SPINS + self.TAIL

        self.win = tk.Toplevel(root, bg=BG)
        self.win.overrideredirect(True)
        try:
            self.win.attributes("-topmost", True)
        except Exception:
            pass
        self.S = 440
        sw = self.win.winfo_screenwidth() or 1280
        sh = self.win.winfo_screenheight() or 800
        self.win.geometry(f"{self.S}x{self.S}+{(sw - self.S)//2}+{(sh - self.S)//2}")
        self.c = tk.Canvas(self.win, width=self.S, height=self.S, bg=BG,
                           highlightthickness=1, highlightbackground="#2a1a44", bd=0)
        self.c.pack(fill="both", expand=True)

        for seq in ("<Button-1>", "<Key>"):
            self.win.bind(seq, lambda e: self._finish())
        try:
            self.win.focus_force()
        except Exception:
            pass

    def start(self):
        self._loop()

    def _angle(self):
        """Angle for the current frame: spin one turn, hold, repeat 3×."""
        f = self.frame
        done = min(f // self.cycle, SPINS)       # whole turns already completed
        within = f - done * self.cycle
        if done >= SPINS:
            return SPINS * 2 * math.pi
        if within < self.SPIN:                   # mid-turn — eased
            frac = _ease(within / self.SPIN)
        else:                                    # paused between turns
            frac = 1.0
        return (done + frac) * 2 * math.pi

    def _loop(self):
        if self._done:
            return
        c, mid = self.c, self.S / 2
        angle = self._angle()
        c.delete("all")
        # Soft radial backdrop behind the mark.
        for i, col in enumerate(("#17102a", "#120c20")):
            rr = 180 - i * 46
            c.create_oval(mid - rr, mid - rr, mid + rr, mid + rr,
                          outline="", fill=col)
        _mark(c, mid, mid, 240, STROKE, SPARK, angle)

        self.frame += 1
        if self.frame <= self.end_frames:
            self.root.after(self.hold, self._loop)
        else:
            self._finish()

    def _finish(self):
        if self._done:
            return
        self._done = True
        self._fade(1.0)

    def _fade(self, a):
        if a <= 0:
            self._close()
            return
        try:
            self.win.attributes("-alpha", a)
            self.root.after(26, lambda: self._fade(a - 0.14))
        except Exception:
            self._close()

    def _close(self):
        try:
            self.win.destroy()
        except Exception:
            pass
        if self.on_done:
            cb, self.on_done = self.on_done, None
            cb()


def run_splash(root, on_done):
    """Spin the AyaForge logo, then call on_done(). Fails open to on_done()."""
    try:
        SplashScreen(root, on_done).start()
    except Exception:
        if on_done:
            on_done()
