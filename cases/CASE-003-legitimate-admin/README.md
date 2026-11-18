# CASE-003 — Legitimate Windows Administrative Activity

**Status:** Complete  
**Category:** Windows Process Monitoring  
**Focus:** Administrative process activity, Event ID 4688, detection validation  
**Analyst:** Omkar Harkulkar

## Overview

This case examines process-creation activity generated while executing seven planned Windows administrative discovery commands on my own Windows PC.

Windows Security Event ID 4688 records were exported and analysed with Hayabusa. The investigation compares the recorded process activity with a separate ground-truth reference containing the commands and their execution timestamps.

The objective was to understand how legitimate administrative activity appears in process-creation logs and how detection rules can produce low-severity alerts for ordinary system utilities.

## Investigation Summary

A total of 13 unique Event ID 4688 records were collected from the selected event window.

Hayabusa generated:

- 13 informational `Proc Exec` detections.
- 3 low-severity `Possible LOLBIN` detections.
- No Medium, High or Critical detections.

The three low-severity matches were associated with `ipconfig.exe`, `sc.exe` and `NETSTAT.EXE`. Review of the rule conditions explained these matches, including a suffix-matching condition that also matched `NETSTAT.EXE`.

The ground-truth comparison identified seven direct command matches, one related child process (`net1.exe`) and five concurrent background events.

**Outcome:** The observed administrative commands matched the recorded ground truth. The three low-severity detections were explained by the rule conditions. The five background events were not directly attributable to the commands and were not independently established as benign or malicious.

## Collection Environment

- Windows 11 Home Single Language, version 26H2.
- PowerShell 5.1.
- Elevated PowerShell session.
- Process Creation auditing was already enabled.
- Command-line inclusion was already enabled.
- No audit-policy or registry changes were made.

Seven commands were executed:

1. `whoami /all`
2. `systeminfo`
3. `ipconfig /all`
4. `tasklist`
5. `sc.exe query`
6. `netstat -ano`
7. `net user`

Command output was not retained in the public evidence package.

## Evidence and Analysis

| File | Purpose |
|---|---|
| `evidence/collection-methodology.md` | Collection environment, method and limitations |
| `evidence/collection-checklist.md` | Collection and review checklist |
| `evidence/policy-before.txt` | Audit and Security log baseline |
| `evidence/ground-truth-log.csv` | Command execution timestamps and ground-truth reference |
| `analysis/ground-truth-comparison.csv` | Comparison of process events with the executed commands |
| `analysis/sanitized-timeline.csv` | Reviewed, sanitized process-event and detection summary |

The original EVTX is retained locally and excluded from the public repository. The raw Hayabusa timeline is also retained privately.

The ground-truth CSV was reconstructed from retained execution timestamps after the original file was found to contain only its header. The seven entries and their timestamp intervals were validated.

## Detection Details

- **Tool:** Hayabusa v4.4.0
- **Rules repository revision:** `58f8f145c65ed0bc0dcf888efde4ca9ca87ba846`
- **Detection:** `Possible LOLBIN`
- **Rule ID:** `6c34b782-a5b5-4298-80f3-1918caf1f558`
- **Rule severity:** Low

The rule matched three process events. Its process-name conditions include `ipconfig.exe`, `Sc.exe` and a suffix condition for `At.exe`. The latter also matches `NETSTAT.EXE` because its name ends with that suffix.

These matches demonstrate a limitation of broad process-name suffix conditions. A detection match alone does not establish malicious intent.

## Limitations

- The investigation uses one local Windows system as its evidence source; no separate public benign dataset was included.
- Event ID 4688 records process creation but does not independently establish user intent or business purpose.
- Five concurrent background events were not directly attributable to the seven commands.
- The available records do not independently establish whether those background events were benign.
- The Security log was close to its configured maximum size, with retention and automatic backup disabled.
- The ground-truth CSV was reconstructed from retained timestamps rather than preserved as a complete original CSV.
- The original EVTX and raw Hayabusa timeline are not included in the public repository.

See [`incident-report.md`](incident-report.md) for the detailed findings, assessment and recommendations.
