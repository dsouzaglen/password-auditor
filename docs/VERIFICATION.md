# Verification record

Date: 2026-08-08
Environment: Windows, bundled Python runtime
Project version: 1.0.0

## Automated tests

Command:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Result: 11 of 11 tests passed. The suite covers password findings, non-disclosure of the tested password, all three authentication-event patterns, successful-login handling, event ordering, authorized dictionary matching, and invalid-hash rejection.

## Authentication-event sample

The bundled six-event sample produced one PA1001 alert after five failed SSH authentications from the same source against the same account within 20 seconds. The alert contains a Wazuh-friendly JSON structure, severity level 10, MITRE ATT&CK T1110.001 mapping, source, user, service, count, time window, and response recommendation.

## Local synthetic benchmark

Command:

```powershell
$env:PYTHONPATH = "src"
python -m password_auditor benchmark --events 10000
```

Observed result:

- Events processed: 10,000
- Alerts generated: 200
- Elapsed time: 0.222583 seconds
- Throughput: 44,927.14 events/second
- Equivalent throughput: 2,695,628.50 events/minute

This comfortably validates a conservative portfolio claim of processing more than 500 authentication events per minute. It is a synthetic throughput measurement on one local machine, not a production-capacity or detection-accuracy claim. Performance varies by hardware and workload.

## Safe résumé wording

> Built a defensive Python password-auditing and authentication-monitoring tool with entropy and pattern checks, bounded dictionary simulation, and SIEM-ready JSON alerts; processed 10,000 synthetic authentication events in 0.23 seconds in a reproducible local benchmark.

Do not claim a percentage reduction in manual review time until a timed comparison against a documented manual workflow has been performed.
