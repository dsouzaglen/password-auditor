# Security policy

## Supported version

Security fixes are applied to the latest version on the default branch.

## Reporting a vulnerability

Do not open a public issue containing passwords, hashes from real users, private authentication logs, API keys, or other sensitive data. Contact the repository owner privately with a minimal reproduction that uses synthetic data.

## Data handling

The audit command reads one password from a hidden terminal prompt and returns derived findings only. The detector reads local JSONL files and writes local alerts. No command performs network communication.

Dictionary simulation is for authorized lab hashes only. Its candidate limit is a safety and resource-control boundary, not authorization to test third-party credentials.
