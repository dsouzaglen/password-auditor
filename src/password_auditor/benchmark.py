"""Reproducible performance benchmark for authentication-event processing."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from .detector import AuthEventDetector
from .models import AuthEvent


def run_benchmark(event_count: int = 10_000) -> dict[str, object]:
    if event_count < 100 or event_count > 1_000_000:
        raise ValueError("event_count must be between 100 and 1,000,000")
    start_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    detector = AuthEventDetector()
    alerts = 0
    started = time.perf_counter()
    for index in range(event_count):
        event = AuthEvent(
            timestamp=(start_time + timedelta(milliseconds=index * 5)).isoformat(),
            source_ip=f"198.51.100.{(index % 200) + 1}",
            username=f"lab-user-{index % 50}",
            status="failure",
            service="ssh",
        )
        alerts += len(detector.process(event))
    elapsed = max(time.perf_counter() - started, 1e-9)
    return {
        "event_count": event_count,
        "alerts_generated": alerts,
        "elapsed_seconds": round(elapsed, 6),
        "events_per_second": round(event_count / elapsed, 2),
        "events_per_minute": round((event_count / elapsed) * 60, 2),
        "runtime": "python-stdlib",
        "note": "Synthetic local benchmark; results vary by hardware.",
    }


def benchmark_json(event_count: int = 10_000) -> str:
    return json.dumps(run_benchmark(event_count), indent=2)
