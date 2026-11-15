# CASE-002 — Suspicious Windows Process Execution

**Status:** Ready for publication
**Category:** Windows Process Monitoring
**Focus:** Process creation, parent-child relationships, and detection validation
**Analyst:** Omkar Harkulkar

## Overview

This case examines Windows process-creation activity using two separate evidence sources:

- **Part A:** A limited collection of Windows Security Event ID 4688 records from my own Windows PC.
- **Part B:** A public Sysmon EVTX sample analysed with Hayabusa.

The investigation focuses on understanding process relationships and reviewing a Medium detection related to FTP parent-process activity.

## Investigation Summary

### Part A — Local Windows PC

Four Windows Security Event ID 4688 records were collected on 13 November 2026.

The collection was validated, but no alert was generated, so no incident verdict is required. Two WMI-related process records remain unresolved because the sanitised export does not contain full executable paths or additional process context.

**Outcome:** Collection validated; no alert generated.

### Part B — Public Sysmon Sample

The public sample contains four unique Sysmon Event ID 1 process-creation events.

Hayabusa identified a Medium detection:

`Potential Arbitrary Command Execution Via FTP.EXE`

The detection matched Sysmon Event ID 1, Record ID 16513.

**Detection verdict:** True Positive for the rule match in a dataset described as attack samples; the original environment was not independently verified.

**Incident assessment:** The available evidence does not establish successful file transfer, persistence, or system compromise.

## Key Findings

- Four unique process-creation events were identified in the public sample.
- One Medium FTP-related detection was generated.
- The detection was reproduced during a dated re-analysis on 15 November 2026.
- The process records show two separate process chains.
- No supporting network, file-activity, or authentication telemetry was available to confirm impact.

## Evidence and Analysis

| File | Purpose |
|---|---|
| `evidence/part-a-windows-4688.csv` | Sanitised local Windows process-creation records |
| `evidence/README.md` | Evidence provenance and collection notes |
| `analysis/process-tree.csv` | Four unique public-sample process events |
| `analysis/timeline.csv` | Hayabusa timeline with PID and ParentPID columns added after initial analysis |
| `analysis/log-metrics.csv` | Original event-log metrics |
| `analysis/SHA256SUMS` | Original analysis integrity manifest |
| `analysis/rerun-2026-11-15/timeline-public.csv` | Sanitised dated re-analysis timeline |
| `analysis/rerun-2026-11-15/log-metrics.csv` | Dated re-analysis metrics |
| `analysis/rerun-2026-11-15/run-notes.txt` | Re-analysis tool and rule provenance |
| `analysis/rerun-2026-11-15/SHA256SUMS` | Dated re-analysis integrity manifest |
| `playbooks/ftp-process-investigation.md` | SOC L1 investigation checklist |

The original EVTX sample and raw re-analysis timeline are not included in the public repository.

## Detection Rule

- **Rule:** `proc_creation_win_ftp_arbitrary_command_execution.yml`
- **Rule ID:** `086262f5-1aee-ce11-2ddf-4692b9e51b3e`
- **Status:** `test`
- **Severity:** Medium
- **Source revision:** `58f8f145c65ed0bc0dcf888efde4ca9ca87ba846`

The exact ruleset revision used in the original analysis was not recorded. The source revision above was used for the 15 November re-analysis.

## Limitations

- Part A contains only four selected process-creation records.
- The Part A CSV is a sanitised export, not the original Windows event log.
- Full executable paths and other process context were not retained in the public Part A evidence.
- Part B is a public dataset sample, not activity from my own Windows PC.
- The original environment of the public sample has not been independently verified.
- Process creation alone does not confirm file transfer, payload execution, or compromise.

## References

- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [Hayabusa](https://github.com/Yamato-Security/Hayabusa)
- [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules)
- [MITRE ATT&CK T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK T1202 — Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)

## Current Status

The investigation and dated re-analysis are documented. Report review, checksum validation, and Git review are complete. The final documentation changes are prepared for publication.
