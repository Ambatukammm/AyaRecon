"""
AyaRecon integrations — wrappers around external recon tools.
Made by Ruel.

AyaRecon aims to be an all-in-one cockpit: rather than making the user switch
between applications, it drives the standard tools (nmap, tshark/Wireshark, and
friends) from one place and funnels their output into the same findings
database and AI analysis.

These are integration *wrappers*, not reimplementations — AyaRecon shells out to
tools the user already has (or installs via the bootstrap) and parses their
output. Each wrapper degrades gracefully when the underlying tool is absent.
"""

from . import tools, nmap_tool, capture, nvd  # noqa: F401
