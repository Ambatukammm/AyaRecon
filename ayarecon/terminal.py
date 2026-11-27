"""
AyaRecon — embedded terminal engine.
Made by Ruel.

A real interactive shell the GUI can host, so a pentester can run any CLI tool
(nmap, netcat, ssh, python, sqlmap prompts, …) without leaving AyaRecon.

Backends, chosen automatically:
  • Unix/macOS — the stdlib `pty` module gives a genuine pseudo-terminal:
    colours, prompts and line-interactive programs all behave correctly.
  • Windows — `pywinpty` (ConPTY) if installed gives the same; otherwise it
    falls back to a piped shell subprocess (works for non-interactive commands;
    full interactivity needs pywinpty).

Honest limitation: a Tk Text widget is not a terminal grid, so full-screen TUI
apps (vim in fullscreen, msfconsole's live UI, top) won't redraw perfectly even
with a real PTY underneath. Everything line-oriented works. For pixel-perfect
TUI rendering, a Qt/xterm.js front-end is the upgrade path.

The engine is GUI-agnostic: it takes an `on_output(text)` callback and exposes
send()/resize()/stop(). The GUI wires a Text widget to it.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import sys
import threading
from typing import Callable, Optional

IS_WINDOWS = sys.platform.startswith("win")


def default_shell() -> str:
    if IS_WINDOWS:
        return os.environ.get("COMSPEC", "cmd.exe")
    return os.environ.get("SHELL", shutil.which("bash") or "/bin/sh")


class TerminalEngine:
    """Backend-agnostic interactive shell."""

    def __init__(self, on_output: Callable[[str], None], shell: Optional[str] = None,
                 cwd: Optional[str] = None):
        self.on_output = on_output
        self.shell = shell or default_shell()
        self.cwd = cwd or os.path.expanduser("~")
        self.running = False
        self.backend = "none"
        self._reader: Optional[threading.Thread] = None
        # unix pty
        self._master_fd: Optional[int] = None
        self._pid: Optional[int] = None
        # windows / fallback
        self._winpty = None
        self._proc = None

    # ------------------------------------------------------------------ start
    def start(self) -> bool:
        if self.running:
            return True
        try:
            if IS_WINDOWS:
                return self._start_windows()
            return self._start_unix()
        except Exception as exc:
            self.on_output(f"\n[AyaRecon] Failed to start terminal: {exc}\n")
            return False

    def _start_unix(self) -> bool:
        import pty
        pid, master_fd = pty.fork()
        if pid == 0:
            # Child: become the shell.
            try:
                os.chdir(self.cwd)
            except Exception:
                pass
            os.environ.setdefault("TERM", "xterm-256color")
            os.execvp(self.shell, [self.shell])
            os._exit(1)  # unreachable on success
        # Parent.
        self._pid = pid
        self._master_fd = master_fd
        self.running = True
        self.backend = "pty"
        self._reader = threading.Thread(target=self._read_unix, daemon=True)
        self._reader.start()
        return True

    def _start_windows(self) -> bool:
        try:
            import winpty  # type: ignore
            self._winpty = winpty.PtyProcess.spawn(self.shell, cwd=self.cwd)
            self.running = True
            self.backend = "winpty"
            self._reader = threading.Thread(target=self._read_winpty, daemon=True)
            self._reader.start()
            return True
        except Exception:
            # Fallback: piped subprocess (no true PTY).
            import subprocess
            self._proc = subprocess.Popen(
                self.shell, cwd=self.cwd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=0, universal_newlines=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.running = True
            self.backend = "pipe"
            self.on_output(
                "[AyaRecon] Using a piped shell (no ConPTY). Install 'pywinpty' for "
                "full interactivity: pip install pywinpty\n")
            self._reader = threading.Thread(target=self._read_pipe, daemon=True)
            self._reader.start()
            return True

    # ------------------------------------------------------------------ readers
    def _read_unix(self):
        while self.running and self._master_fd is not None:
            try:
                data = os.read(self._master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            self.on_output(data.decode("utf-8", errors="replace"))
        self.running = False
        self.on_output("\n[AyaRecon] Terminal session ended.\n")

    def _read_winpty(self):
        while self.running and self._winpty is not None:
            try:
                data = self._winpty.read(4096)
            except Exception:
                break
            if not data:
                if not self._winpty.isalive():
                    break
                continue
            self.on_output(data if isinstance(data, str)
                           else data.decode("utf-8", "replace"))
        self.running = False
        self.on_output("\n[AyaRecon] Terminal session ended.\n")

    def _read_pipe(self):
        while self.running and self._proc and self._proc.stdout:
            data = self._proc.stdout.read(1)
            if not data:
                break
            self.on_output(data.decode("utf-8", errors="replace"))
        self.running = False
        self.on_output("\n[AyaRecon] Terminal session ended.\n")

    # ------------------------------------------------------------------ input
    def send(self, text: str) -> None:
        if not self.running:
            return
        try:
            if self.backend == "pty" and self._master_fd is not None:
                os.write(self._master_fd, text.encode("utf-8", "replace"))
            elif self.backend == "winpty" and self._winpty is not None:
                self._winpty.write(text)
            elif self.backend == "pipe" and self._proc and self._proc.stdin:
                self._proc.stdin.write(text.encode("utf-8", "replace"))
                self._proc.stdin.flush()
        except Exception:
            pass

    def send_line(self, line: str) -> None:
        self.send(line + ("\r\n" if self.backend == "pipe" and IS_WINDOWS else "\n"))

    # ------------------------------------------------------------------ resize
    def resize(self, rows: int, cols: int) -> None:
        try:
            if self.backend == "pty" and self._master_fd is not None:
                import fcntl
                import struct
                import termios
                fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ,
                            struct.pack("HHHH", rows, cols, 0, 0))
            elif self.backend == "winpty" and self._winpty is not None:
                self._winpty.setwinsize(rows, cols)
        except Exception:
            pass

    # ------------------------------------------------------------------ stop
    def stop(self) -> None:
        self.running = False
        try:
            if self.backend == "pty":
                if self._pid:
                    os.kill(self._pid, signal.SIGTERM)
                if self._master_fd is not None:
                    os.close(self._master_fd)
            elif self.backend == "winpty" and self._winpty is not None:
                self._winpty.terminate(force=True)
            elif self.backend == "pipe" and self._proc is not None:
                self._proc.terminate()
        except Exception:
            pass


# ---------------------------------------------------------------- ANSI helpers
_ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")
# SGR colour code -> a tag name the GUI maps to a hex colour.
_SGR_FG = {
    "30": "black", "31": "red", "32": "green", "33": "yellow",
    "34": "blue", "35": "magenta", "36": "cyan", "37": "white",
    "90": "brgray", "91": "brred", "92": "brgreen", "93": "bryellow",
    "94": "brblue", "95": "brmagenta", "96": "brcyan", "97": "brwhite",
}


def parse_ansi(text: str) -> list[tuple[str, str]]:
    """
    Split text into (segment, color_tag) pairs, honouring SGR colour codes and
    stripping other escape sequences. color_tag is '' for default.
    The GUI applies the tag; unknown/overlong sequences are dropped.
    """
    # Remove non-SGR CSI sequences (cursor moves, clears) — Tk can't honour them.
    text = re.sub(r"\x1b\[[0-9;?]*[A-HJKlh]", "", text)
    text = text.replace("\x1b[2J", "").replace("\x1b[H", "").replace("\r", "")
    out: list[tuple[str, str]] = []
    pos = 0
    current = ""
    for m in _ANSI_RE.finditer(text):
        if m.start() > pos:
            out.append((text[pos:m.start()], current))
        codes = m.group(1).split(";") if m.group(1) else ["0"]
        for c in codes:
            if c in ("0", ""):
                current = ""
            elif c in _SGR_FG:
                current = _SGR_FG[c]
        pos = m.end()
    if pos < len(text):
        out.append((text[pos:], current))
    return out


ANSI_COLORS = {
    "black": "#555", "red": "#e06c75", "green": "#98c379", "yellow": "#e5c07b",
    "blue": "#61afef", "magenta": "#c678dd", "cyan": "#56b6c2", "white": "#dcdfe4",
    "brgray": "#7f848e", "brred": "#ff7b86", "brgreen": "#b5e890",
    "bryellow": "#f0d399", "brblue": "#82c0ff", "brmagenta": "#e096f0",
    "brcyan": "#74d4e0", "brwhite": "#ffffff",
}


# ---------------------------------------------------------------- command runner
class CommandRunner:
    """
    Runs ONE command at a time as a subprocess and streams its output. This is
    the reliable, cross-platform core of AyaRecon's terminal: no PTY, no
    interactive echo games — you type/click a command, it runs, output streams.

    It keeps a working directory so `cd` behaves, and `stop()` kills a long
    command (nmap, ping -t, …). Interactive full-screen programs (vim) are out of
    scope by design — this is a command console, not a TTY emulator.
    """

    def __init__(self, on_output: Callable[[str], None],
                 on_done: Callable[[int], None], cwd: Optional[str] = None):
        self.on_output = on_output
        self.on_done = on_done
        self.cwd = cwd or os.path.expanduser("~")
        self._proc = None
        self._thread: Optional[threading.Thread] = None

    def busy(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def run(self, cmdline: str) -> None:
        cmdline = cmdline.strip()
        if not cmdline:
            return
        if self.busy():
            self.on_output("\n[AyaRecon] A command is still running — press Stop first.\n")
            return

        # Handle `cd` ourselves so the working directory persists between commands.
        if cmdline == "cd" or cmdline.startswith("cd ") or cmdline.startswith("cd\t"):
            target = cmdline[2:].strip().strip('"') or os.path.expanduser("~")
            new = target if os.path.isabs(target) else os.path.join(self.cwd, target)
            new = os.path.normpath(new)
            if os.path.isdir(new):
                self.cwd = new
                self.on_output(f"{self.cwd}\n")
            else:
                self.on_output(f"cd: no such directory: {target}\n")
            self.on_done(0)
            return
        if cmdline in ("cls", "clear"):
            self.on_output("\x00CLEAR\x00")
            self.on_done(0)
            return

        self._thread = threading.Thread(target=self._run, args=(cmdline,), daemon=True)
        self._thread.start()

    def _run(self, cmdline: str) -> None:
        import subprocess
        try:
            self._proc = subprocess.Popen(
                cmdline, shell=True, cwd=self.cwd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, text=True, bufsize=1,
                errors="replace",
            )
        except Exception as exc:
            self.on_output(f"[AyaRecon] Could not run: {exc}\n")
            self.on_done(-1)
            return
        try:
            for line in iter(self._proc.stdout.readline, ""):
                self.on_output(line)
            self._proc.wait()
            rc = self._proc.returncode
        except Exception as exc:
            self.on_output(f"[AyaRecon] {exc}\n")
            rc = -1
        finally:
            self._proc = None
        self.on_done(rc)

    def stop(self) -> None:
        if self.busy():
            try:
                self._proc.terminate()
            except Exception:
                pass
