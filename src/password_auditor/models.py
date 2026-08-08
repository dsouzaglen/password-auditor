"""Typed data structures shared by the auditor and detector."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class PasswordFinding:
    code: str
    severity: str
    message: str


@dataclass(frozen=True)
class PasswordAuditResult:
    score: int
    rating: str
    entropy_bits: float
    length: int
    character_classes: int
    findings: tuple[PasswordFinding, ...] = field(default_factory=tuple)
    recommendations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: str
    source_ip: str
    username: str
    status: str
    service: str = "unknown"
    destination: str = "unknown"


@dataclass(frozen=True)
class Alert:
    timestamp: str
    rule_id: str
    level: int
    description: str
    pattern: str
    source_ip: str | None
    username: str | None
    attempts: int
    window_seconds: int
    mitre_id: str
    mitre_technique: str
    recommendation: str
    service: str = "unknown"

    def to_siem_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "rule": {
                "id": self.rule_id,
                "level": self.level,
                "description": self.description,
                "mitre": {
                    "id": [self.mitre_id],
                    "technique": [self.mitre_technique],
                    "tactic": ["Credential Access"],
                },
            },
            "event": {"kind": "alert", "category": ["authentication"]},
            "source": {"ip": self.source_ip},
            "user": {"name": self.username},
            "service": {"name": self.service},
            "authentication": {
                "pattern": self.pattern,
                "attempts": self.attempts,
                "window_seconds": self.window_seconds,
            },
            "recommendation": self.recommendation,
            "labels": ["password-auditor", "soc-lab", "wazuh-compatible"],
        }
