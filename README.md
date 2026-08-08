# SOC Password Auditor

A defensive Python project for local password-strength assessment and SOC authentication-event detection. It combines practical password guidance with detection of brute-force and suspicious multi-account authentication bursts, then emits newline-delimited JSON alerts suitable for SIEM ingestion.

**Project page:** https://dsouzaglen.github.io/password-auditor/

## Safety and privacy

- Password audits run locally and make no network requests.
- Entered passwords are hidden and are never written to disk, printed, hashed into logs, or included in results.
- Dictionary simulation is bounded to 1,000,000 candidates and is intended only for hashes you own or are authorized to test in a lab.
- The bundled wordlist is deliberately small and exists to demonstrate detection behavior, not to recover real credentials.

## Features

- Estimated search-space entropy and a 0-100 strength score
- Checks for common passwords, short length, repeated characters, dates, keyboard walks, and sequential patterns
- Sliding-window detection mapped to MITRE ATT&CK T1110 Brute Force and T1110.001 Password Guessing
- Wazuh-friendly JSONL alerts with rule IDs, severity levels, MITRE mappings, and response guidance
- Reproducible event-processing benchmark
- Standard-library implementation with no runtime dependencies

## Quick start

Requires Python 3.10 or newer.

```powershell
cd password-auditor
$env:PYTHONPATH = "src"
python -m password_auditor audit
```

The prompt hides your password. Add `--json` for structured output; the password itself is still excluded.

Analyze authentication events:

```powershell
$env:PYTHONPATH = "src"
python -m password_auditor detect --input examples/auth_events.jsonl --output alerts.jsonl
Get-Content alerts.jsonl
```

Run an authorized dictionary simulation. The example digest below is SHA-256 for the bundled lab candidate `correct-horse-demo`.

```powershell
$env:PYTHONPATH = "src"
python -m password_auditor dictionary-test `
  --hash f677d1b8244eb44da0d61a90760782725cc0cd768fd159325be7dcb163d8bf25 `
  --wordlist examples/lab_wordlist.txt
```

Run tests and the benchmark:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m password_auditor benchmark --events 10000
```

## Authentication event schema

Each input line is one JSON object:

```json
{"timestamp":"2026-08-08T08:00:00Z","source_ip":"198.51.100.25","username":"alex","status":"failure","service":"ssh","destination":"lab-server"}
```

Required fields are `timestamp`, `source_ip`, `username`, and `status`. Timestamps must be ISO 8601. The detector accepts `failure`, `failed`, or `denied` as failed states.

## Detection logic

| Rule | Pattern | Default threshold | MITRE ATT&CK |
|---|---|---:|---|
| PA1001 | One source, one account | 5 failures / 60 seconds | T1110.001 |
| PA1002 | One source, many accounts | 10 unique accounts / 60 seconds | T1110 |
| PA1003 | Many sources, one account | 10 unique sources / 60 seconds | T1110.001 |

Alerts have a 60-second cooldown per entity and pattern to reduce duplicates. Tune these defaults against an environment baseline before production use.

PA1002 is intentionally labeled as a multi-account burst. Without exposing or correlating password material, an authentication log alone cannot reliably distinguish password spraying from credential stuffing. Analysts should use surrounding identity, endpoint, and threat-intelligence evidence to classify the incident.

## Project limitations

- Entropy is an estimate based on observed character classes; human password choices are rarely truly random.
- This is a portfolio and lab tool, not a replacement for enterprise password policy, breached-password services, MFA, or an identity protection platform.
- Wazuh deployments may require a decoder or field mapping suited to the local ingestion pipeline.
- Input events must be sorted chronologically; out-of-order streams are rejected rather than silently miscounted.
- Benchmark results measure local synthetic processing, not detection quality or production capacity.

## Responsible use

Use this project only on systems and data you own or have explicit permission to test. Do not provide real passwords to screenshots, demos, issue reports, or committed files.
