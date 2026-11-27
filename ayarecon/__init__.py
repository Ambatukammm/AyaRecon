"""
AyaRecon — Professional Penetration Testing Toolkit for Windows.
Made by Ruel.

A Python-based, GUI-driven toolkit that runs a structured 5-phase engagement
workflow against authorised targets:

    Phase 1  Passive Reconnaissance
    Phase 2  Port & Service Scanning
    Phase 3  Service Enumeration (SMB, HTTP, DNS, FTP, SMTP, SNMP, LDAP)
    Phase 4  Vulnerability Assessment (CVE matching + misconfiguration — no exploit code)
    Phase 5  AI Analysis & Reporting

All data stays local in a SQLite database. Passive work is safe by default,
active work requires confirmation, and brute-force / credential-testing modules
are disabled by default behind a legal warning and explicit confirmation.
"""

__app_name__ = "AyaRecon"
__author__ = "Ruel"
__version__ = "3.0.0"
__tagline__ = "All-in-one recon cockpit: 5-phase workflow, nmap, live capture, terminal, AI — made by Ruel."

# Ordered phase definitions used by the GUI and the workflow runner.
PHASES = [
    ("1", "Passive Reconnaissance"),
    ("2", "Port & Service Scanning"),
    ("3", "Service Enumeration"),
    ("4", "Vulnerability Assessment"),
    ("5", "AI Analysis & Reporting"),
]
