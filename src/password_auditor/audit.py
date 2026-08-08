"""Local password-strength analysis without persistence or network access."""

from __future__ import annotations

import math
import re
from functools import lru_cache
from importlib.resources import files

from .models import PasswordAuditResult, PasswordFinding

KEYBOARD_RUNS = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
)
SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
)


@lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    text = files("password_auditor").joinpath("data/common_passwords.txt").read_text(
        encoding="utf-8"
    )
    return frozenset(line.strip().casefold() for line in text.splitlines() if line.strip())


def _character_pool(password: str) -> tuple[int, int]:
    pool = 0
    classes = 0
    tests = (
        (r"[a-z]", 26),
        (r"[A-Z]", 26),
        (r"[0-9]", 10),
        (r"[^A-Za-z0-9]", 33),
    )
    for pattern, size in tests:
        if re.search(pattern, password):
            pool += size
            classes += 1
    return pool, classes


def _contains_run(password: str, run_length: int = 4) -> bool:
    folded = password.casefold()
    for sequence in SEQUENCES + KEYBOARD_RUNS:
        for index in range(len(sequence) - run_length + 1):
            chunk = sequence[index : index + run_length]
            if chunk in folded or chunk[::-1] in folded:
                return True
    return False


def audit_password(password: str) -> PasswordAuditResult:
    """Return a deterministic strength assessment without retaining the password."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    pool_size, classes = _character_pool(password)
    entropy = len(password) * math.log2(pool_size) if pool_size else 0.0
    findings: list[PasswordFinding] = []
    recommendations: list[str] = []

    if len(password) < 12:
        findings.append(
            PasswordFinding("SHORT_LENGTH", "high", "Password is shorter than 12 characters.")
        )
        recommendations.append("Use at least 14 characters; a multi-word passphrase is ideal.")
    elif len(password) < 14:
        findings.append(
            PasswordFinding("MODERATE_LENGTH", "medium", "Password meets 12 characters but is below the preferred 14.")
        )

    folded = password.casefold()
    if folded in _common_passwords():
        findings.append(
            PasswordFinding("COMMON_PASSWORD", "critical", "Password appears in the bundled common-password dictionary.")
        )
        recommendations.append("Replace common passwords with a unique passphrase.")

    if re.search(r"(.)\1{2,}", password, flags=re.IGNORECASE):
        findings.append(
            PasswordFinding("REPEATED_CHARACTERS", "medium", "Password contains repeated characters.")
        )
        recommendations.append("Avoid repeated characters and predictable padding.")

    if _contains_run(password):
        findings.append(
            PasswordFinding("PREDICTABLE_SEQUENCE", "high", "Password contains a keyboard, alphabetic, or numeric sequence.")
        )
        recommendations.append("Remove keyboard walks and sequential characters.")

    if re.search(r"(?:19|20)\d{2}", password):
        findings.append(
            PasswordFinding("YEAR_PATTERN", "medium", "Password contains a likely year.")
        )
        recommendations.append("Do not rely on dates or years as memorable substitutions.")

    if classes < 3:
        findings.append(
            PasswordFinding("LOW_VARIETY", "medium", "Password uses fewer than three character classes.")
        )
        recommendations.append("Prefer length first, then mix character types where practical.")

    deduction = sum(
        {"critical": 45, "high": 25, "medium": 10, "low": 5}[finding.severity]
        for finding in findings
    )
    entropy_score = min(100, int(round(entropy / 1.1)))
    length_bonus = min(10, max(0, len(password) - 12) * 2)
    score = max(0, min(100, entropy_score + length_bonus - deduction))

    if score >= 80:
        rating = "strong"
    elif score >= 60:
        rating = "moderate"
    elif score >= 35:
        rating = "weak"
    else:
        rating = "critical"

    if not findings:
        recommendations.append("Keep this password unique and store it in a reputable password manager.")

    return PasswordAuditResult(
        score=score,
        rating=rating,
        entropy_bits=round(entropy, 2),
        length=len(password),
        character_classes=classes,
        findings=tuple(findings),
        recommendations=tuple(dict.fromkeys(recommendations)),
    )
