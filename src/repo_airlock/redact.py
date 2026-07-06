"""Redaction helpers — never let a real secret reach a report or stdout."""

from __future__ import annotations


def redact(value: str, keep: int = 4) -> str:
    """Show only the first/last ``keep`` characters of ``value``.

    Short values (too short to safely partially reveal) are fully masked.
    """
    value = value.strip()
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"
