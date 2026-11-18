# CASE-003 — Incident Investigation Report

## 1. Case Information

| Field | Details |
|---|---|
| Case ID | CASE-003 |
| Title | Legitimate Windows Administrative Activity |
| Category | Windows Process Monitoring |
| Analyst | Omkar Harkulkar |
| System | Local Windows 11 PC |
| Evidence source | Windows Security Event Log |
| Primary event | Security Event ID 4688 |
| Analysis tool | Hayabusa v4.4.0 |
| Overall assessment | Expected administrative activity observed; background activity remains unresolved |
| Status | Complete |

## 2. Executive Summary

Seven planned Windows administrative discovery commands were executed in an elevated PowerShell session on the analyst's Windows PC.

A short Security Event ID 4688 time window was exported and analysed with Hayabusa. The export contained 13 unique process-creation events. Hayabusa produced 13 informational `Proc Exec` detections and three additional low-severity `Possible LOLBIN` detections.

The three low-severity matches were associated with `ipconfig.exe`, `sc.exe` and `NETSTAT.EXE`. Review of the detection rule showed that these matches were explained by its process-name conditions, including a suffix condition that matched `NETSTAT.EXE`.

The separate ground-truth comparison linked seven process events directly to the seven commands. The `net user` command also generated a related `net1.exe` child process. Five other events occurred during or shortly before the command window and were not direct children of the commands.

The collected evidence supports the recorded administrative activity. It does not establish malicious activity. The five concurrent background events remain unverified beyond their recorded process relationships and event context.

## 3. Scope and Objective

The investigation aimed to:

- Collect process-creation events associated with controlled administrative discovery activity.
- Review the resulting detections without assuming that the commands were malicious.
- Compare the event records with a separate ground-truth reference.
- Identify unrelated or concurrent process activity.
- Assess what the available logs establish and what remains unknown.

The investigation was limited to the local Windows system and the selected Security Event ID 4688 window. No separate public benign dataset was included.

## 4. System and Audit Baseline

The collection system was:

- Windows 11 Home Single Language, version 26H2, build 26300.9818.
- PowerShell 5.1.
- 8 GB RAM.
- India Standard Time (UTC+05:30).

The collection was performed in an elevated PowerShell session.

The baseline review found:

- Process Creation auditing: Success.
- Command-line inclusion registry setting: enabled (`0x1`).
- Security event log: enabled.
- Configured Security log maximum size: 20 MiB.
- Retention: disabled.
- Automatic backup: disabled.

The audit settings were already enabled. No audit-policy or registry changes were made, so no restoration was required.

## 5. Controlled Administrative Activity

The following commands were executed:

1. `whoami /all`
2. `systeminfo`
3. `ipconfig /all`
4. `tasklist`
5. `sc.exe query`
6. `netstat -ano`
7. `net user`

The recorded execution interval was:

- Start: 16 November 2026, 11:22:10.077 IST.
- End: 16 November 2026, 11:22:18.944 IST.
- UTC: 05:52:10.077–05:52:18.944.

The ground-truth CSV was found to contain only its header during review. It was reconstructed using the actual per-command execution timestamps retained in the collection records. All seven entries and their IST/UTC intervals were subsequently validated.

This reconstructed CSV is a reference for comparison; it is not an untouched contemporaneous copy of the original file.

## 6. Event Collection

Security Event ID 4688 was exported using `wevtutil`.

The event window was:

- Start: 16 November 2026, 05:52:05 UTC.
- End: 16 November 2026, 05:52:24 UTC.
- Equivalent IST: 11:22:05–11:22:24.

The window included a five-second margin around the command execution interval.

Collection results:

| Item | Result |
|---|---|
| Event ID | 4688 |
| Exported events | 13 |
| EVTX size | 69,632 bytes |
| SHA-256 | `160F89E3D67838A423791070ED6D1D726A534952347AC2759A43449775F7BB9F` |

The original EVTX was retained locally and excluded from the public repository.

## 7. Hayabusa Analysis

Hayabusa v4.4.0 was used with the local rules repository.

Rules repository revision:

`58f8f145c65ed0bc0dcf888efde4ca9ca87ba846`

Detection results:

| Detection | Rule severity | Detection rows |
|---|---:|---:|
| Proc Exec | Informational | 13 |
| Possible LOLBIN | Low | 3 |
| Medium or higher | — | 0 |

There were 16 detection rows but only 13 unique process-creation events. The three `Possible LOLBIN` rows were additional detections associated with events already represented by `Proc Exec`.

### 7.1 Possible LOLBIN Rule Review

- Rule title: `Possible LOLBIN`
- Rule ID: `6c34b782-a5b5-4298-80f3-1918caf1f558`
- Rule severity: Low
- Rule status: Stable

The rule checks for a command line containing a space and a process name matching one of its configured conditions.

The three matching processes were:

| Process | Explanation |
|---|---|
| `ipconfig.exe` | Explicit process-name condition |
| `sc.exe` | Explicit process-name condition |
| `NETSTAT.EXE` | Matched the configured `At.exe` suffix condition |

The `NETSTAT.EXE` result is an example of a broad suffix condition producing a match that does not, by itself, indicate abuse.

The rule matches are valid matches against the configured conditions. They are not evidence of malicious activity on their own.

## 8. Ground-Truth Comparison

The 13 unique event records were compared separately with the reconstructed ground-truth log.

| Relationship | Count |
|---|---:|
| Direct command match | 7 |
| Related child process | 1 |
| Concurrent background activity | 5 |
| **Total unique events** | **13** |

The seven direct matches corresponded to the seven commands executed by the analyst.

The `net user` command generated `net.exe`, followed by `net1.exe`. The latter was classified as a related child process rather than a separate direct command match.

Five other events involved:

- `SearchProtocolHost.exe`
- `TrustedInstaller.exe`
- `TiWorker.exe`
- `WmiApSrv.exe` (two records)

These events were not direct children of the seven command processes. Their timing overlapped with or preceded the controlled activity.

The event records alone do not establish that these background processes were caused by the commands. Their presence also does not establish maliciousness or independently prove that they were benign.

## 9. Findings

### Finding 1 — Administrative command execution

The seven planned commands were represented in the process-creation records.

**Assessment:** Consistent with the recorded ground truth.

### Finding 2 — Additional `net1.exe` process

The `net user` command was followed by a `net1.exe` child process.

**Assessment:** Related child process in the observed process chain.

### Finding 3 — Low-severity Possible LOLBIN detections

Three process events matched the `Possible LOLBIN` rule.

**Assessment:** The matches were explained by the configured process-name conditions. No malicious activity was established by these detections.

### Finding 4 — Concurrent background processes

Five records were not directly attributable to the seven commands.

**Assessment:** Unresolved background activity. Additional process context would be required to establish their origin and purpose.

## 10. What Would Have Made This Malicious?

The administrative commands observed in this case can also appear during legitimate troubleshooting and system administration. Their presence alone is not enough to establish malicious activity.

Further investigation would be warranted if similar process activity were accompanied by evidence such as:

- Execution from an unexpected account or logon session.
- An unusual parent process or unexpected execution context.
- Command-line arguments inconsistent with the stated administrative task.
- Related suspicious network connections or file activity.
- Evidence of unauthorised account, service or configuration changes.
- Corroborating endpoint or security alerts.

These are investigation leads, not findings from this collection. The available evidence does not establish that any of them occurred.

## 11. Verdict and Severity Assessment

**Verdict:** Expected administrative activity observed; three low-severity detection matches explained; no malicious activity established by the collected evidence.

The ground-truth comparison supports the seven planned commands and the related `net1.exe` child process.

The three `Possible LOLBIN` detections are assessed as explainable rule matches in this controlled activity. They do not establish a security incident.

The five concurrent background events remain unresolved as to their underlying purpose. They were not directly attributable to the controlled commands, and the available records do not support classifying them as malicious.

**Overall assessment:** Informational. The low-severity rule matches should be reviewed in context rather than treated as confirmed malicious activity.

## 12. Recommended SOC Actions

1. Correlate process-creation alerts with parent process, logon session and execution context.
2. Review the exact detection-rule conditions before escalating a low-severity match.
3. Check supporting network, file, service and authentication telemetry when investigating unexplained process activity.
4. Preserve the original EVTX and its hash for further review.
5. Consider refining broad process-name suffix conditions to reduce false positives.
6. Avoid treating a process-creation event or a rule match as proof of compromise without corroborating evidence.

## 13. Limitations

- The investigation used one local Windows system and did not include a separate public benign dataset.
- The selected export contains only Event ID 4688.
- Process creation does not independently establish user intent or business purpose.
- The Security log was close to its configured 20 MiB maximum.
- Retention and automatic backup were disabled. The available snapshots do not establish whether event overwriting occurred during collection.
- Five concurrent background events could not be fully attributed using the selected records.
- The ground-truth CSV was reconstructed from retained timestamps after the original file was found to contain only its header.
- The original EVTX and raw Hayabusa timeline are retained locally and are not part of the public evidence package.

## 14. Evidence Inventory

| File | Purpose |
|---|---|
| `evidence/collection-methodology.md` | Collection method and environment |
| `evidence/collection-checklist.md` | Collection and review checklist |
| `evidence/policy-before.txt` | Audit and Security log baseline |
| `evidence/ground-truth-log.csv` | Reconstructed command execution reference |
| `analysis/ground-truth-comparison.csv` | Event-to-command comparison |
| `analysis/sanitized-timeline.csv` | Reviewed 13-event timeline and detection summary |

The original EVTX and raw Hayabusa timeline are excluded from the public repository.

## 15. Conclusion

This case demonstrates how ordinary Windows administrative commands appear in Security Event ID 4688 and how broad detection-rule conditions can generate low-severity matches.

The ground-truth comparison helped separate the seven planned commands and their related child process from five concurrent background events. It also showed why detections need to be reviewed in context.

The evidence supports the recorded administrative activity but does not establish malicious activity or compromise. The background events remain a documented limitation rather than being assigned an unsupported verdict.

## Part B — Public Dataset Investigation

Part B reviewed a synthetic Windows event-log teaching dataset containing 443 host events and 180 domain-controller events. A reproducible analysis selected 161 records for focused review. Three audit-log-clearing events (1102), three service installations (7045), and six group-membership additions (4728) were identified alongside logon, privilege, process-creation and Kerberos activity.

The notable events require validation against authorization records and fuller endpoint context. The supplied dataset does not establish whether they were approved or malicious. Part B is therefore assessed as **Review Required**, not as a confirmed incident or confirmed benign activity.

Detailed counts, notable records, limitations and reproduction steps are documented in `analysis/part-b-findings.md`.
