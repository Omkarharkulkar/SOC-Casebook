# CASE-003 SUPP-001 — Public Windows Event Dataset Analysis

## Dataset and scope

The source is the Windows Security, System and AD Event Log Test Set, supplied as six CSV tables. The event catalogue identifies itself as a `teaching-subset`. This is synthetic/sample data, not a live collection from a production Windows environment.

The six source files passed verification using `evidence/SOURCE-SHA256SUMS`.

| Dataset table | Records |
|---|---:|
| accounts.csv | 110 |
| computers.csv | 36 |
| domain_controllers.csv | 4 |
| event_types.csv | 14 |
| directory_events.csv | 180 |
| host_events.csv | 443 |

## Event summary

| Source | Event ID | Category | Count |
|---|---:|---|---:|
| Host | 4624 | Successful logon | 135 |
| Host | 4625 | Failed logon | 44 |
| Host | 4634 | Logoff | 98 |
| Host | 4648 | Explicit credentials | 14 |
| Host | 4672 | Special privileges | 36 |
| Host | 4688 | Process creation | 72 |
| Host | 1102 | Audit log cleared | 3 |
| Host | 6005 | Event log started | 8 |
| Host | 7036 | Service state changed | 30 |
| Host | 7045 | Service installed | 3 |
| Directory | 4728 | Group member added | 6 |
| Directory | 4740 | Account locked out | 10 |
| Directory | 4768 | Kerberos TGT requested | 133 |
| Directory | 4771 | Kerberos pre-authentication failed | 31 |

## Review performed

The analysis script selected 161 events for review: 3 Event ID 1102, 36 Event ID 4672, 72 Event ID 4688, 6 Event ID 4728, 10 Event ID 4740, 31 Event ID 4771 and 3 Event ID 7045. The chronological output is `review-timeline.csv`; counts are in `event-summary.csv`.

Notable records:

- Three Event ID 1102 records report Security audit-log clearing: one on HOST-9211 and two on HOST-2105.
- Three Event ID 7045 records report service installations: two named Spooler and one named PSEXESVC on HOST-5541.
- Six Event ID 4728 records report additions to privileged or operational groups, including Helpdesk Operators, VPN Users and Remote Desktop Users.
- Event ID 4672 records show special privileges assigned to logon sessions. This event alone does not establish misuse.
- Event ID 4688 records show process creation, including cmd.exe, powershell.exe, wmic.exe, rundll32.exe, svchost.exe and msedge.exe. Process names alone do not establish malicious execution.

## Assessment

The audit-log clearing, service installation and group-membership events warrant follow-up. However, the dataset does not provide enough context to determine whether the changes were approved or malicious. In particular, service paths, full process command lines, change tickets, administrator approvals and surrounding event details are not available in the supplied tables.

The presence of PSEXESVC is notable, but it does not independently prove unauthorized remote execution. Similarly, Event ID 1102 is a high-priority investigation lead, not proof of an attacker covering tracks.

The source uses reserved example IP ranges and a teaching-subset event catalogue. Findings must not be presented as evidence of a real organization or real compromise.

## SUPP-001 conclusion

**Review Required — notable security events identified; authorization and malicious intent cannot be established from the available synthetic dataset.**

## Reproducibility

Run from the repository root:

`python3 supplementary/SUPP-001-synthetic-windows-events/analysis/analyze_public_dataset.py`

The script reads the six source CSVs and regenerates the event summary and selected chronological review timeline. The source files are separately checked with `sha256sum -c SOURCE-SHA256SUMS` from `evidence/`.
