"""
AyaRecon scanning modules.
Made by Ruel.

Each module exposes plain functions that return a list of *finding dicts*:

    {
        "category": "dns",
        "title": "MX record",
        "detail": "mail.example.com (priority 10)",
        "data": {...},
        "severity": "info",
    }

The orchestrator (aya.engine-level code / GUI) decides permission, persists
findings to the database, and hands them to the AI engine for scoring.
This keeps modules pure and easy to unit-test or extend.
"""

from . import (  # noqa: F401
    passive, active, recon_enum, defensive, enumeration, vuln_assessment,
    exploitation, network_discovery,
)
