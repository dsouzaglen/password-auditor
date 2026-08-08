"""Bounded dictionary simulation for authorized lab hashes only."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import asdict, dataclass
from pathlib import Path

SUPPORTED_ALGORITHMS = {"sha256", "sha512"}


@dataclass(frozen=True)
class SimulationResult:
    matched: bool
    matched_candidate: str | None
    attempts: int
    elapsed_seconds: float
    attempts_per_second: float
    stopped_reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def simulate_dictionary_match(
    target_hash: str,
    wordlist: Path,
    *,
    algorithm: str = "sha256",
    max_candidates: int = 100_000,
) -> SimulationResult:
    """Try a bounded local wordlist against a test hash.

    This intentionally supports only unsalted SHA-256/SHA-512 lab examples. It is
    not a password recovery service and performs no network activity.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"algorithm must be one of: {', '.join(sorted(SUPPORTED_ALGORITHMS))}")
    if max_candidates <= 0 or max_candidates > 1_000_000:
        raise ValueError("max_candidates must be between 1 and 1,000,000")
    digest_size = hashlib.new(algorithm).digest_size * 2
    normalized_hash = target_hash.strip().casefold()
    if len(normalized_hash) != digest_size or any(ch not in "0123456789abcdef" for ch in normalized_hash):
        raise ValueError(f"target_hash must be a valid {algorithm} hexadecimal digest")

    start = time.perf_counter()
    attempts = 0
    match: str | None = None
    stopped_reason = "wordlist_exhausted"
    with wordlist.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_candidate in handle:
            if attempts >= max_candidates:
                stopped_reason = "candidate_limit"
                break
            candidate = raw_candidate.rstrip("\r\n")
            attempts += 1
            digest = hashlib.new(algorithm, candidate.encode("utf-8")).hexdigest()
            if hmac.compare_digest(digest, normalized_hash):
                match = candidate
                stopped_reason = "match_found"
                break
    elapsed = max(time.perf_counter() - start, 1e-9)
    return SimulationResult(
        matched=match is not None,
        matched_candidate=match,
        attempts=attempts,
        elapsed_seconds=round(elapsed, 6),
        attempts_per_second=round(attempts / elapsed, 2),
        stopped_reason=stopped_reason,
    )
