"""Sliding-window detection for common high-volume authentication attacks."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .models import Alert, AuthEvent


def parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class DetectionConfig:
    window_seconds: int = 60
    brute_force_threshold: int = 5
    multi_account_threshold: int = 10
    distributed_source_threshold: int = 10
    cooldown_seconds: int = 60

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")


class AuthEventDetector:
    """Detect single-account, multi-account, and distributed failure bursts."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self._by_pair: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self._by_source: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        self._by_user: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], datetime] = {}
        self._latest_event_time: datetime | None = None

    def _trim_times(self, items: deque[datetime], now: datetime) -> None:
        while items and (now - items[0]).total_seconds() > self.config.window_seconds:
            items.popleft()

    def _trim_pairs(self, items: deque[tuple[datetime, str]], now: datetime) -> None:
        while items and (now - items[0][0]).total_seconds() > self.config.window_seconds:
            items.popleft()

    def _ready(self, key: tuple[str, str], now: datetime) -> bool:
        previous = self._last_alert.get(key)
        if previous and (now - previous).total_seconds() < self.config.cooldown_seconds:
            return False
        self._last_alert[key] = now
        return True

    def process(self, event: AuthEvent) -> list[Alert]:
        now = parse_timestamp(event.timestamp)
        if self._latest_event_time is not None and now < self._latest_event_time:
            raise ValueError("authentication events must be ordered by timestamp")
        self._latest_event_time = now
        if event.status.casefold() not in {"failure", "failed", "denied"}:
            return []
        pair_key = (event.source_ip, event.username)
        pair_events = self._by_pair[pair_key]
        source_events = self._by_source[event.source_ip]
        user_events = self._by_user[event.username]

        pair_events.append(now)
        source_events.append((now, event.username))
        user_events.append((now, event.source_ip))
        self._trim_times(pair_events, now)
        self._trim_pairs(source_events, now)
        self._trim_pairs(user_events, now)

        alerts: list[Alert] = []
        timestamp = now.isoformat().replace("+00:00", "Z")
        unique_users = {username for _, username in source_events}
        unique_sources = {source for _, source in user_events}

        if len(pair_events) >= self.config.brute_force_threshold and self._ready(
            ("brute_force", f"{event.source_ip}|{event.username}"), now
        ):
            alerts.append(
                Alert(
                    timestamp, "PA1001", 10, "Repeated authentication failures from one source against one account",
                    "brute_force", event.source_ip, event.username, len(pair_events), self.config.window_seconds,
                    "T1110.001", "Password Guessing", "Temporarily block the source and validate the targeted account.", event.service,
                )
            )

        if len(unique_users) >= self.config.multi_account_threshold and self._ready(
            ("multi_account_burst", event.source_ip), now
        ):
            alerts.append(
                Alert(
                    timestamp, "PA1002", 12, "One source attempted authentication against many accounts",
                    "multi_account_burst", event.source_ip, None, len(source_events), self.config.window_seconds,
                    "T1110", "Brute Force", "Block or challenge the source and review the accounts for password-spray or credential-stuffing indicators.", event.service,
                )
            )

        if len(unique_sources) >= self.config.distributed_source_threshold and self._ready(
            ("distributed_brute_force", event.username), now
        ):
            alerts.append(
                Alert(
                    timestamp, "PA1003", 12, "Many sources attempted authentication against one account",
                    "distributed_brute_force", None, event.username, len(user_events), self.config.window_seconds,
                    "T1110.001", "Password Guessing", "Protect the account, require MFA, and investigate the distributed sources.", event.service,
                )
            )
        return alerts

    def process_many(self, events: Iterable[AuthEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            alerts.extend(self.process(event))
        return alerts
