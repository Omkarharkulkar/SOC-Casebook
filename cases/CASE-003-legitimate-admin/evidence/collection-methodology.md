# Evidence Collection Methodology

## 1. Collection Objective

The objective was to record Windows administrative discovery activity on a controlled workstation and examine the corresponding Windows Security process-creation events.

The collection was designed to establish a ground-truth reference for comparing commands executed by the analyst with process-creation events recorded by Windows.

## 2. Collection Environment

- Operating system: Windows 11 Home Single Language
- Version: 26H2
- OS build: 26300.9818
- Shell: Windows PowerShell 5.1
- Execution context: Elevated PowerShell session
- Time zone: India Standard Time (UTC+05:30)

Raw system-discovery output was retained locally and excluded from the public repository because it contained host, account and network information.

## 3. Audit Configuration Before Collection

The following settings were checked before collection:

- Security Process Creation auditing: Success
- ProcessCreationIncludeCmdLine_Enabled: REG_DWORD 0x1
- Security event log: Enabled
- Configured maximum log size: 20 MiB
- Retention: Disabled
- Auto-backup: Disabled

No audit-policy, registry or event-log configuration changes were made for this collection.

## 4. Ground-Truth Collection

Seven administrative discovery commands were executed in an elevated PowerShell session:

1. whoami /all
2. systeminfo
3. ipconfig /all
4. tasklist
5. sc.exe query
6. netstat -ano
7. net user

The seven-command list is the known ground-truth reference for this exercise. The original ground-truth CSV was found to contain only its header. A replacement CSV was reconstructed retrospectively with command timestamp intervals in IST and UTC. The independent source records for those individual timestamps were not present in the retained package, so the timestamps cannot be independently verified. The replacement CSV is a retrospective comparison aid, not contemporaneously preserved independent evidence. Command output was not included.

Actual command execution interval:
Start: 2026-11-16 11:22:10.077 IST
End:   2026-11-16 11:22:18.944 IST

UTC equivalent:
Start: 2026-11-16 05:52:10.077 UTC
End:   2026-11-16 05:52:18.944 UTC

## 5. Windows Event Collection

Windows Security Event ID 4688 was selected to examine process creation.

The Security log was exported using `wevtutil epl` with an XPath query filtering Event ID 4688 within the following UTC window:

- Start: 2026-11-16 05:52:05 UTC
- End: 2026-11-16 05:52:24 UTC

The window included a five-second margin around the recorded command execution period.

The export was opened and inspected using PowerShell `Get-WinEvent`.

The export contained 13 Event ID 4688 records. Eight process-creation
records corresponded to the seven planned commands, including the
net1.exe child process launched by net.exe. Five additional records
represented concurrent background process activity.

## 6. Exported Evidence

- File: CASE-003-4688-window.evtx
- Size: 69,632 bytes
- Event records: 13
- SHA-256: 160F89E3D67838A423791070ED6D1D726A534952347AC2759A43449775F7BB9F

The original EVTX was retained locally. It was not committed to the public repository.

## 7. Evidence Handling

The EVTX export and ground-truth CSV were treated as separate evidence sources.

The known seven-command list was compared with the recorded process-creation events. The reconstructed timestamp CSV provides retrospective context only. Because its independent timestamp source records were not retained, timestamp-based correlation is not independent confirmation.

The public analysis timeline is a reviewed and sanitized CSV containing 13 unique Event ID 4688 records derived from the 16-row Hayabusa timeline. The 16 detection rows represent 13 process events, including three additional Possible LOLBIN detections. The sanitized CSV includes timestamps, record IDs, event IDs, process and parent-process names, detection titles, levels, rule IDs and the separate ground-truth comparison. Hostnames, account identifiers, SIDs, raw command lines, full paths and network details are excluded.

## 8. Collection Limitations

- The Security log was close to its configured 20 MiB maximum.
- Retention and automatic backup were disabled. Older events could
  therefore be overwritten as new events were recorded, but the
  available record-count snapshots do not establish that overwriting
  occurred during this collection.
- The collection therefore relied on a short event window and prompt export.
- The export contains only Event ID 4688, not all Security events.
- The five-second margins may include unrelated background activity.
- Event ID 4688 establishes process creation but does not independently establish the user's intent or the business purpose of a command.
- The original EVTX and ground-truth CSV remain local for further verification.

## 9. Reproducibility

The collection can be reviewed using the documented operating-system context, audit settings, known command list, UTC event window, export method and SHA-256 hash. The reconstructed individual command timestamps are not independently verifiable from the retained package. The reviewed sanitized timeline provides a public-facing summary of the 13 unique process-creation events and their associated detections.

## 10. Analysis Reproducibility

### Tools and commands

- Analysis system: Ubuntu.
- Tool: Hayabusa v4.4.0 CODE BLUE.
- Rules commit: 58f8f145c65ed0bc0dcf888efde4ca9ca87ba846.
- Input: CASE-003 Security EVTX export, retained privately.
- Original timeline: ~/case003-private/analysis/timeline-original.csv, retained privately.

Timeline generation command (executed from `~/tools/hayabusa`):

```bash
./hayabusa-4.4.0-lin-x64-gnu dfir-timeline -f ~/SOC-Casebook/cases/CASE-003-legitimate-admin/evidence/CASE-003-4688-window.evtx -r ~/tools/hayabusa/rules/hayabusa -c ~/tools/hayabusa/rules/config -w -o ~/case003-private/analysis/timeline-original.csv -Z "+05:30"
```


The original timeline contained 16 detection rows representing 13 unique Event ID 4688 records. Its SHA-256 was 7d6e3aa444cd91d00eac9317ad0a433f4d30b90d51d5a59961a2ca669690d7cf.

### Independent rerun

On 2026-11-18, the same command and inputs generated a separate private output, `timeline-rerun.csv`. The original and rerun files had identical SHA-256 hashes: `7d6e3aa444cd91d00eac9317ad0a433f4d30b90d51d5a59961a2ca669690d7cf`. A byte-for-byte comparison using `cmp` returned `IDENTICAL`. The rerun also reported 16 detection rows across 13 events: 13 informational Proc Exec detections and three low-severity Possible LOLBIN detections. This confirms reproducibility with the recorded tool and rules configuration.

### Ground-truth comparison

The seven administrative commands were compared with the 13 unique events: seven direct command matches, one related child process (net1.exe), and five concurrent background events.

### Detection review and sanitization

Hayabusa produced 13 informational Proc Exec rows and three low-severity Possible LOLBIN rows. The latter involved ipconfig.exe, sc.exe and NETSTAT.EXE. The public sanitized timeline contains 13 unique event records. Hostnames, account identifiers, SIDs, raw command lines, full paths and network details were excluded.

The original one-off Python CSV transformation was not retained as a standalone script. This section documents the analysis process and does not claim to reproduce that original script.

### Validation

The public analysis outputs were reviewed for unique event records, Event ID 4688, ground-truth relationships, detection totals and unnecessary identifying details. The raw EVTX and original timeline remain private.


## Process Timeline Enrichment and Anonymization

The Hayabusa timeline was enriched using the `Details` field from the original private timeline CSV. Records were matched by Windows Event Record ID.

The enrichment retained:
- Executable image path.
- Process command line.
- An anonymized account reference.
- An anonymized logon-session reference.

The controlled activity was assigned `USER-01` and `SESSION-01`. The machine account was assigned `HOST-ACCOUNT-01`, and its SYSTEM logon context was assigned `SYSTEM-SESSION`. Actual account names, hostnames, and logon IDs were not included in the published analysis CSV.

The enriched timeline contains 13 unique Event ID 4688 records. Eight records were grouped with the controlled administrative commands, including the `net1.exe` child process. Five records were grouped separately as SYSTEM-context background activity.

The three `Possible LOLBIN` detections were not counted as additional process events because they refer to records already represented by the 13 unique Event ID 4688 events.

### Ground-truth limitation

The seven-command list is known, but the individual timestamps in the reconstructed CSV are not independently verifiable. The independent source records were not present in the retained private package, and the reference was not frozen before analysis.

It is used as a retrospective comparison reference, not as contemporaneously preserved independent evidence.

### Data handling

The original Hayabusa timeline and exported EVTX remain private. The published timeline contains selected process details and anonymized account/session references. The local EVTX is excluded from Git tracking.
