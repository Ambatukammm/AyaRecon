"""
AyaRecon — permission gating and safety boundaries.
Made by Ruel.

This is the heart of AyaRecon's "safety first" principle. Every operation is
classified into a MODE, and each mode has a rule for whether it may run:

  passive      -> always allowed (no packets sent to the target)
  active       -> requires explicit per-run confirmation
  enumeration  -> requires the global "I have permission" gate to be unlocked
                  AND per-run confirmation. All runs are written to the audit log.
  defensive    -> allowed against assets the user has registered as their own

Nothing here can scan on its own — it only decides whether the GUI/CLI is
permitted to launch a module, and records the decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .config import Config
from .db import Database


class Mode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    ENUMERATION = "enumeration"
    DEFENSIVE = "defensive"


# The exact sentence the user must type to unlock enumeration modules.
PERMISSION_PHRASE = "I HAVE PERMISSION"

LEGAL_WARNING = (
    "LEGAL WARNING\n\n"
    "Scanning or enumerating systems without EXPLICIT WRITTEN PERMISSION "
    "from the system owner is ILLEGAL in most countries — including Australia "
    "(Criminal Code Act 1995, Part 10.7) and under laws such as the US CFAA "
    "and the UK Computer Misuse Act.\n\n"
    "Use AyaRecon only on:\n"
    "  • systems you own, or\n"
    "  • systems you have clear, written authorisation to test.\n\n"
    "Aggressive / enumeration operations are noisy and may be logged, alarmed, "
    "or treated as an attack by the target. You are solely responsible for how "
    "you use this tool."
)


@dataclass
class Decision:
    allowed: bool
    reason: str


class PermissionManager:
    """Decides whether a given module may run, and records every decision."""

    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db

    # ------------------------------------------------------------------ gate
    def unlock_enumeration(self, typed_phrase: str) -> bool:
        """Unlock enumeration modules only if the exact phrase is typed."""
        ok = typed_phrase.strip().upper() == PERMISSION_PHRASE
        self.config.set("enumeration_unlocked", ok)
        self.config.save()
        return ok

    def lock_enumeration(self) -> None:
        self.config.set("enumeration_unlocked", False)
        self.config.save()

    @property
    def enumeration_unlocked(self) -> bool:
        return bool(self.config.get("enumeration_unlocked", False))

    # ------------------------------------------------------------------ checks
    def check(
        self,
        mode: Mode,
        target: str,
        module: str,
        confirmed: bool = False,
        workspace_id: int | None = None,
        confirmation_text: str = "",
    ) -> Decision:
        """
        Return a Decision for whether `module` may run against `target`.
        For active/enumeration/defensive, the caller must pass confirmed=True
        after the user has agreed in the UI.
        """
        mode = Mode(mode)

        if mode is Mode.PASSIVE:
            return Decision(True, "Passive OSINT sends nothing to the target.")

        if mode is Mode.DEFENSIVE:
            if self.config.is_owned(target) or confirmed:
                self._audit(workspace_id, target, module, mode, True, confirmation_text)
                return Decision(True, "Defensive self-audit of a registered/own asset.")
            return Decision(
                False,
                "Defensive mode runs against YOUR assets. Register this target as "
                "owned in Settings, or confirm you own it.",
            )

        if mode is Mode.ACTIVE:
            if not confirmed:
                return Decision(False, "Active scanning requires explicit confirmation.")
            self._audit(workspace_id, target, module, mode, True, confirmation_text)
            return Decision(True, "Active scan confirmed by user.")

        if mode is Mode.ENUMERATION:
            if not self.enumeration_unlocked:
                return Decision(
                    False,
                    "Enumeration is locked. Unlock it with the permission gate first.",
                )
            if not confirmed:
                return Decision(False, "Enumeration requires per-run confirmation.")
            self._audit(workspace_id, target, module, mode, True, confirmation_text)
            return Decision(True, "Enumeration confirmed and unlocked.")

        return Decision(False, "Unknown mode.")

    def _audit(
        self,
        workspace_id: int | None,
        target: str,
        module: str,
        mode: Mode,
        confirmed: bool,
        confirmation_text: str,
    ) -> None:
        try:
            self.db.log_permission(
                workspace_id=workspace_id,
                target=target,
                module=module,
                mode=mode.value,
                confirmed=confirmed,
                confirmation_text=confirmation_text,
            )
        except Exception:
            # Auditing must never crash a scan; failures are non-fatal.
            pass
