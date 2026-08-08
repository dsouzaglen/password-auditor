"""Command-line interface for the defensive password auditor."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .audit import audit_password
from .benchmark import run_benchmark
from .detector import AuthEventDetector, DetectionConfig
from .dictionary import simulate_dictionary_match
from .io import read_auth_events, write_alerts


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-auditor",
        description="Local password auditing and SOC authentication-event detection.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="Audit one password without saving it.")
    audit.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    detect = subparsers.add_parser("detect", help="Detect attacks in JSONL authentication events.")
    detect.add_argument("--input", type=Path, required=True, help="Input JSONL event file.")
    detect.add_argument("--output", type=Path, required=True, help="Output JSONL alert file.")
    detect.add_argument("--window", type=int, default=60, help="Detection window in seconds.")

    simulation = subparsers.add_parser(
        "dictionary-test", help="Run a bounded dictionary simulation on an authorized lab hash."
    )
    simulation.add_argument("--hash", required=True, dest="target_hash")
    simulation.add_argument("--wordlist", required=True, type=Path)
    simulation.add_argument("--algorithm", choices=("sha256", "sha512"), default="sha256")
    simulation.add_argument("--max-candidates", type=int, default=100_000)

    benchmark = subparsers.add_parser("benchmark", help="Benchmark synthetic event processing.")
    benchmark.add_argument("--events", type=int, default=10_000)
    return parser


def _print_human_audit(result: object) -> None:
    data = result.to_dict()
    print(f"Rating: {data['rating']} ({data['score']}/100)")
    print(f"Estimated entropy: {data['entropy_bits']} bits")
    print(f"Length: {data['length']} | Character classes: {data['character_classes']}")
    findings = data["findings"]
    if findings:
        print("Findings:")
        for finding in findings:
            print(f"  - [{finding['severity'].upper()}] {finding['message']}")
    print("Recommendations:")
    for recommendation in data["recommendations"]:
        print(f"  - {recommendation}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            password = getpass.getpass("Password to audit (input hidden): ")
            result = audit_password(password)
            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                _print_human_audit(result)
            return 0

        if args.command == "detect":
            detector = AuthEventDetector(DetectionConfig(window_seconds=args.window))
            alerts = detector.process_many(read_auth_events(args.input))
            write_alerts(args.output, alerts)
            print(json.dumps({"events_file": str(args.input), "alerts": len(alerts), "output": str(args.output)}))
            return 0

        if args.command == "dictionary-test":
            print(
                json.dumps(
                    simulate_dictionary_match(
                        args.target_hash,
                        args.wordlist,
                        algorithm=args.algorithm,
                        max_candidates=args.max_candidates,
                    ).to_dict(),
                    indent=2,
                )
            )
            return 0

        if args.command == "benchmark":
            print(json.dumps(run_benchmark(args.events), indent=2))
            return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
