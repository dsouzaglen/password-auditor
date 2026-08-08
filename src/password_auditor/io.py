"""Input and output helpers for newline-delimited JSON events."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from .models import Alert, AuthEvent


def read_auth_events(path: Path) -> Iterator[AuthEvent]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                yield AuthEvent(
                    timestamp=str(payload["timestamp"]),
                    source_ip=str(payload["source_ip"]),
                    username=str(payload["username"]),
                    status=str(payload["status"]),
                    service=str(payload.get("service", "unknown")),
                    destination=str(payload.get("destination", "unknown")),
                )
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                raise ValueError(f"Invalid event at line {line_number}: {exc}") from exc


def write_alerts(path: Path, alerts: list[Alert]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for alert in alerts:
            handle.write(json.dumps(alert.to_siem_dict(), separators=(",", ":")) + "\n")
