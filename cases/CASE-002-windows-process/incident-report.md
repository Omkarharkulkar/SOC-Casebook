# Incident Report — CASE-002: Suspicious Windows Process Execution

## 1. Case Information

| Field | Details |
|---|---|
| Case ID | CASE-002 |
| Case Title | Suspicious Windows Process Execution |
| Analyst | Omkar Harkulkar |
| Investigation Date | 13–15 November 2026 |
| Evidence Sources | Local Windows Security logs and public Sysmon EVTX sample |
| Primary Tool | Hayabusa v4.4.0 CODE BLUE |
| Case Status | Ready for publication |

This case contains two separate evidence sources. Part A is a limited collection from my own Windows PC. Part B is a public Windows Sysmon sample. Their timelines and findings are assessed separately.

## 2. Executive Summary

This investigation reviewed Windows process-creation activity from two sources. Part A contains four locally collected Windows Security Event ID 4688 records and did not generate an alert. Part B contains four unique Sysmon process-creation events from a public EVTX sample. Hayabusa generated a Medium detection named `Potential Arbitrary Command Execution Via FTP.EXE`, matching Record ID 16513. A re-analysis on 15 November 2026 reproduced the detection using a pinned rules repository revision. The rule match is supported by the available event data, but the original environment and any real-world impact have not been independently verified.

## 3. Alert Details

### Part A — Local Windows PC

- Log source: Windows Security
- Event ID: 4688 — Process Creation
- Collection date: 13 November 2026
- Records collected: 4
- Alert generated: No
- Severity: Informational

No detection alert was generated from this limited collection. Therefore, an incident verdict is not required for Part A.

### Part B — Public Sysmon Sample

- Log source: Sysmon
- Event ID: 1 — Process Creation
- Computer recorded in sample: `IEWIN7`
- Unique process-creation events: 4
- Detection: `Potential Arbitrary Command Execution Via FTP.EXE`
- Detection level: Medium
- Rule ID: `086262f5-1aee-ce11-2ddf-4692b9e51b3e`
- Rule status: `test`
- Rule file: `proc_creation_win_ftp_arbitrary_command_execution.yml`

The detection matched the parent-process condition involving `ftp.exe`. The presence of the alert is evidence of a rule match, not by itself proof of successful file transfer or compromise.

## 4. Investigation Timeline

### Part A — Local Windows PC

All times are local time (IST, UTC+05:30).

| Time | Record ID | Process | Parent Process |
|---|---:|---|---|
| 11:33:45 | 1934519 | auditpol.exe | powershell.exe |
| 11:34:04 | 1934528 | whoami.exe | powershell.exe |
| 11:34:25 | 1934539 | WmiApSrv.exe | services.exe |
| 11:34:26 | 1934540 | WmiPrvSE.exe | svchost.exe |

These are the four selected records in the local export. The export does not contain full executable paths or enough context to independently validate the two WMI-related process records.

Process Creation auditing was temporarily enabled for collection. The recorded follow-up check on 15 November 2026 at 12:12:33 IST showed `No Auditing`. The command output is preserved in `evidence/part-a-audit-policy-follow-up-2026-11-15.txt`. This confirms the policy state at that time only; the original post-collection restoration was not independently recorded.

### Part B — Public Sysmon Sample

The following timestamps are from the Hayabusa timeline, displayed in IST.

| Time | Record ID | Process | Parent Process | Hayabusa Level |
|---|---:|---|---|---|
| 22:50:01.980 | 16511 | cmd.exe | explorer.exe | info |
| 22:50:31.183 | 16512 | python.exe | cmd.exe | info |
| 22:50:49.443 | 16513 | cmd.exe | ftp.exe | info |
| 22:50:49.458 | 16514 | calc.exe | cmd.exe | info |

An additional Medium detection row was associated with Record ID 16513:

`Potential Arbitrary Command Execution Via FTP.EXE`

The four process events form two separate chains:

1. Explorer → Command Prompt → Python
2. FTP → Command Prompt → Calculator

The FTP process appears as the parent of the Command Prompt event. The available four records do not include an event showing the creation of the FTP process itself.

The Hayabusa timeline timestamps and Sysmon `UtcTime` values are retained as separate fields in the original process-tree analysis because they can differ slightly.

## 5. Evidence Collected

| Evidence ID | Description | Source | Availability |
|---|---|---|---|
| E-001 | Sanitised Windows Security Event ID 4688 CSV | Local Windows PC | Included in repository |
| E-002 | Original Windows CSV export | Local Windows PC | Retained locally; not published |
| E-003 | Public Sysmon EVTX sample | EVTX-ATTACK-SAMPLES repository | Source file not redistributed |

### Analysis Outputs

- `analysis/timeline.csv` — original Hayabusa timeline.
- `analysis/process-tree.csv` — four unique process events with process and parent-process details.
- `analysis/log-metrics.csv` — original EVTX processing metrics.
- `analysis/rerun-2026-11-15/timeline-public.csv` — sanitised dated re-analysis timeline.
- `analysis/rerun-2026-11-15/log-metrics.csv` — dated re-analysis metrics.

### Integrity and Provenance Records

- `evidence/SHA256SUMS` and `analysis/SHA256SUMS` — checksums for the corresponding evidence and analysis files.
- `analysis/rerun-2026-11-15/run-notes.txt` — dated re-analysis tool, ruleset, input and execution details.
- `analysis/rerun-2026-11-15/SHA256SUMS` — checksums for the published dated re-analysis outputs.

### Evidence and Rule Hashes

The following hashes identify the evidence and relevant analysis files.

**Part A — Local Windows CSV**

- Original export: `B5CF68E240263C4C971387D08DFD6235109A00CB34E951D6EE73C42AD818A44F`
- Normalised repository copy: `092094762cda223cef201090e01095359d6734901c2e68cf1a17f18a4f2c825f`

The original export was 452 bytes. The normalised repository copy was 444 bytes. The difference is due to removal of the UTF-8 BOM and conversion of CRLF line endings to LF.

**Part B — Public EVTX**

- SHA-256: `aadae0e31b5f2310284687062010251fdd9ed9b8e8d76be14b79896d05f970ef`

**Detection Rule Source Snapshot**

- Rule SHA-256: `4f003775e7c36d1f9a8c1de50cf326e3e01101fbd0d4ae280a1081938f7c9d7d`
- Rules repository commit: `58f8f145c65ed0bc0dcf888efde4ca9ca87ba846`

The evidence and analysis directories contain separate SHA256SUMS manifests. These manifests are integrity records rather than independent event evidence.

## 6. Investigation and Analysis

### Part A — Local Windows PC

Four Windows Security Event ID 4688 records were collected.

The records include two process events initiated under PowerShell and two WMI-related process events with service-related parent processes. However, the sanitised CSV does not contain full executable paths, command lines, usernames, or file signatures.

Because this context is unavailable, the WMI-related records cannot be independently validated as expected activity from the evidence retained in this case.

Process Creation auditing was initially reported as `No Auditing` and was temporarily enabled for collection. A recorded follow-up check on 15 November 2026 at 12:12:33 IST again showed `No Auditing`; its command output is preserved in `evidence/part-a-audit-policy-follow-up-2026-11-15.txt`. This confirms the policy state at the time of the follow-up check, but the original post-collection restoration was not independently recorded.

**Part A outcome:** Collection validated; no alert was generated, so no incident verdict is required.

### Part B — Public Sysmon Sample

The public EVTX file was analysed with Hayabusa v4.4.0 CODE BLUE.

The original analysis identified four unique Event ID 1 records and a Medium alert. The additional alert row does not represent a fifth unique process event.

The 15 November 2026 re-analysis produced a timeline that is byte-identical to the original analysis timeline. Both files have SHA-256 `6c041760e9690726f49f7533812f67d7792c2e5340dcf87a3016564143dd6d89`. This confirms that the re-analysis reproduced the original timeline for this sample.

The detection rule is:

`proc_creation_win_ftp_arbitrary_command_execution.yml`

Its rule ID is:

`086262f5-1aee-ce11-2ddf-4692b9e51b3e`

The rule has status `test` and severity `medium`. Its detection logic includes a condition involving the parent image ending in `\ftp.exe`.

The matching event is Record ID 16513, where `cmd.exe` (PID 2392) has `ftp.exe` (PID 3668) as its parent process.

The available four process-creation records do not include a creation event for `ftp.exe` (PID 3668). Its own parent process, creation time, and launch context therefore cannot be established from this sample.

The four records show two separate process chains. The Python process is a child of the first Command Prompt process, not the FTP process. The available records do not establish that Python was launched by FTP or that the two chains are related.

The dataset repository describes its contents as Windows event samples associated with attack and post-exploitation techniques. Its README also states that ATT&CK mapping is at the technique level rather than the procedure level. The original environment and whether the recorded activity was confined to a simulation have not been independently verified.

### Dated Re-analysis — 15 November 2026

The EVTX sample was re-analysed using:

- Hayabusa v4.4.0 CODE BLUE
- One processing thread
- Timezone: UTC+05:30
- Rules repository commit: `58f8f145c65ed0bc0dcf888efde4ca9ca87ba846`
- Rule SHA-256: `4f003775e7c36d1f9a8c1de50cf326e3e01101fbd0d4ae280a1081938f7c9d7d`

The re-analysis processed four events and produced five detection rows: four informational rows and one Medium alert.

The Medium alert again matched Record ID 16513 with rule ID `086262f5-1aee-ce11-2ddf-4692b9e51b3e`.

The result is consistent with the original analysis.

The exact ruleset revision used during the original analysis was not recorded. Therefore, the 15 November run is a reproducible re-analysis using the pinned revision above, not proof of the exact historical ruleset version.

The raw re-analysis timeline contains detailed process metadata and is retained locally. The repository contains a sanitised timeline that excludes sensitive process details.

### ATT&CK Context

The detection rule includes references to:

- T1059 — Command and Scripting Interpreter (Execution)
- T1202 — Indirect Command Execution (Stealth)

These are mappings included in the detection rule. They provide technique context but do not independently establish that a specific adversary procedure occurred in this sample.

## 7. Impact Assessment

### Part A

No alert was generated from the four selected local records. The available evidence does not establish malicious activity or system impact.

The two WMI-related process records remain unresolved because the exported evidence lacks full executable paths and supporting context.

### Part B

The Medium detection indicates a process relationship that warrants investigation on a production endpoint.

However, the available evidence contains process-creation events only. It does not include supporting network connection records, file activity, authentication events, or endpoint-response telemetry.

The investigation therefore cannot confirm:

- A successful FTP file transfer
- Successful execution of a transferred payload
- Persistence
- Unauthorised access
- System compromise or operational impact

No production asset is evidenced as affected by this portfolio investigation.

## 8. Investigation Verdict

### Part A — Local Windows PC

**Outcome:** Collection validated; no alert generated, so no incident verdict is required.

The WMI-related process context remains unresolved because the sanitised evidence does not include full executable paths or supporting telemetry.

**Severity:** Informational.

### Part B — Public Sysmon Sample

**Detection verdict:** True Positive for the rule match in a dataset described as attack samples; the original environment was not independently verified.

**Incident assessment:** Inconclusive regarding real-world impact. The available process events do not establish successful file transfer, persistence, or compromise.

**Analyst severity:** Medium, assessed as if the observed activity occurred on a production endpoint, because the rule matched an unusual FTP-parent process relationship. This is an investigation priority, not evidence of confirmed impact.

**Classification confidence:** High confidence that the public sample matches the stated detection rule; low confidence in any assessment of real-world impact because the original environment and supporting telemetry are unavailable.

## 9. Response and Escalation

This was a retrospective portfolio investigation. No containment or remediation action was performed on the public sample.

For a production alert with similar characteristics, a SOC analyst should:

1. Validate the detection rule and its status.
2. Review the parent-child process relationship and surrounding events.
3. Collect authorised executable-path, command-line, user, and signature information.
4. Correlate available network, file, and authentication telemetry.
5. Determine whether the activity is expected for the host and user.
6. Escalate unexplained activity according to the organisation's incident-response process.

The investigation checklist is documented in:

`playbooks/ftp-process-investigation.md`

## 10. Detection Improvements

- Review the rule's `test` status before treating the alert as a confirmed incident.
- Monitor FTP-related process relationships and correlate them with surrounding process activity.
- Where authorised, enrich alerts with executable paths, user context, signatures, and available file hashes.
- Correlate process creation with network and file telemetry before assessing transfer or impact.
- Test detection logic against both suspicious and expected administrative activity.

## 11. Lessons Learned

- A detection alert identifies activity for investigation; it does not independently prove compromise.
- Parent-child process relationships help explain why a rule matched, but surrounding telemetry is needed to assess impact.
- Recording tool versions, rule revisions, input hashes, and analysis commands makes a re-analysis more reproducible.

## 12. Limitations

- Part A contains only four selected Windows Security Event ID 4688 records.
- The local export is sanitised and is not the original Windows event log.
- Full executable paths, command lines, usernames, and signatures were not retained in the public Part A evidence.
- The original post-collection audit-policy restoration was not independently recorded.
- Part B is a public dataset sample and not activity from the analyst's own Windows PC.
- The original environment of the public sample has not been independently verified.
- The available Part B records do not include a process-creation event for `ftp.exe` (PID 3668), so its launch context and parent process cannot be established.
- The exact Hayabusa ruleset revision used in the original analysis was not recorded.
- The re-analysis uses a pinned rules repository revision and does not establish the exact historical ruleset.
- No network, file-activity, authentication, or endpoint-response telemetry was available to confirm impact.

## 13. References

1. EVTX-ATTACK-SAMPLES repository:
   https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

2. Public sample path:
   `Execution/exec_sysmon_1_ftp.evtx`

3. Dataset source revision:
   `4ceed2f4706daf601c212a8f91c113dd85349a2c`

4. Hayabusa project:
   https://github.com/Yamato-Security/Hayabusa

5. Hayabusa rules repository:
   https://github.com/Yamato-Security/hayabusa-rules

6. Pinned rules revision used for the dated re-analysis:
   `58f8f145c65ed0bc0dcf888efde4ca9ca87ba846`

7. MITRE ATT&CK T1059 — Command and Scripting Interpreter:
   https://attack.mitre.org/techniques/T1059/

8. MITRE ATT&CK T1202 — Indirect Command Execution:
   https://attack.mitre.org/techniques/T1202/

## 14. Evidence That Could Change the Verdict

The assessment could be strengthened or changed by obtaining:

- Full executable paths, command lines, user context, and file signatures for the relevant process events.
- The process-creation event for `ftp.exe` (PID 3668), including its parent process, command line, and timestamp, to establish how the FTP process was launched.
- Additional Sysmon process and network connection events from the same time period.
- Windows file-creation and file-modification records.
- FTP client and server logs showing whether a transfer occurred.
- Authentication records and endpoint telemetry from the original environment.
- Documentation identifying the original environment and explaining whether the activity was part of a controlled test.
- The exact historical Hayabusa ruleset revision and original analysis configuration.

These records could help determine whether the activity was expected, simulated, or associated with a real security incident.
