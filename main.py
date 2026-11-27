#!/usr/bin/env python3
"""
AyaRecon — Professional Penetration Testing Toolkit.
Made by Ruel.

Entry point. Launches the GUI by default; falls back to a small CLI if tkinter
is unavailable or the user passes `--cli`.

    python main.py                 # launch the GUI
    python main.py --cli           # interactive CLI
    python main.py --cli dns example.com

This launcher is crash-resistant: if anything fails at startup it prints the full
error, writes it to 'ayarecon_error.log' next to this file, and (when run by
double-click) keeps the window open so you can read it.
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Make sure the package is importable no matter where AyaRecon is launched from.
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def _report_crash(exc: BaseException) -> None:
    """Print the traceback, save it, and pause so a double-clicked window stays open."""
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    msg = (
        "\n" + "=" * 68 + "\n"
        "  AyaRecon hit an error at startup. Details below (and saved to\n"
        "  ayarecon_error.log). Send this to get it fixed. — made by Ruel\n"
        + "=" * 68 + "\n\n" + tb
    )
    print(msg)
    try:
        (HERE / "ayarecon_error.log").write_text(msg, encoding="utf-8")
    except Exception:
        pass
    # Keep a double-clicked console window open.
    try:
        input("\nPress Enter to close…")
    except Exception:
        pass


def _run_gui() -> int:
    try:
        import tkinter  # noqa: F401  (clear message if the GUI toolkit is absent)
    except Exception:
        print(
            "[AyaRecon] Python's Tkinter GUI toolkit isn't available.\n"
            "  • Windows/macOS: reinstall Python from python.org (Tkinter is included).\n"
            "  • Linux: sudo apt install python3-tk\n"
            "You can still use the command line:  python main.py --cli\n"
        )
        try:
            input("Press Enter to close…")
        except Exception:
            pass
        return 1

    from ayarecon.gui import launch
    launch()
    return 0


def _run_cli(argv: list[str]) -> int:
    from ayarecon.cli import main as cli_main
    return cli_main(argv)


def main() -> int:
    argv = sys.argv[1:]
    try:
        if argv and argv[0] in ("--cli", "-c"):
            return _run_cli(argv[1:])
        return _run_gui()
    except SystemExit:
        raise
    except BaseException as exc:
        _report_crash(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
