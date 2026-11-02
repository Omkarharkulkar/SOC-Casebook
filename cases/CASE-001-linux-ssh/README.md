# CASE-001: SSH Brute-Force Investigation

## Objective

Investigate SSH authentication events to identify repeated
failed login attempts and assess whether the observed activity
is suspicious.

## Scope

- Review Linux SSH authentication logs.
- Identify failed and successful authentication events.
- Examine timestamps, source addresses, and targeted accounts.
- Correlate relevant events.
- Assess the evidence and document a verdict.

## Data Source

Ubuntu authentication logs or systemd journal.

## Tools

- Linux journalctl and log utilities
- Python
- SQLite
- MiniSOC detection module

## Evidence Provenance

To be documented after selecting and reviewing the log source.

## Investigation Status

In Progress
