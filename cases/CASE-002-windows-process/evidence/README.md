# Evidence Provenance

This case uses two separate Windows process-creation evidence sources.

## Part A — Local Windows PC

- Source: My own Windows PC
- Log source: Windows Security
- Event ID: 4688 — Process Creation
- Collection date: 13 November 2026
- Records collected: 4
- Collection method: PowerShell `Get-WinEvent`
- Export format: Sanitised CSV
- File: `part-a-windows-4688.csv`

The CSV contains selected event fields: timestamp, event ID, record ID, process name, parent process, and process identifiers.

Usernames, full executable paths, and command-line arguments were excluded from the exported evidence.

SHA-256 hashes:

- Original Windows export (452 bytes):
  `B5CF68E240263C4C971387D08DFD6235109A00CB34E951D6EE73C42AD818A44F`
- Normalized repository copy (444 bytes):
  `092094762cda223cef201090e01095359d6734901c2e68cf1a17f18a4f2c825f`

The original Windows export hash was verified against the file retained in the Windows Documents folder. Before publication, the CSV was normalized to UTF-8 without BOM and LF line endings. The second hash identifies the normalized file committed to this repository.

Process Creation auditing was temporarily enabled for collection and restored to its original `No Auditing` setting afterwards.

This is a small sample collected during normal system activity. It is not a complete Windows activity record or a comprehensive security assessment.

## Part B — Public Windows Event Sample

- Dataset: EVTX-ATTACK-SAMPLES
- Repository: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Sample path: `Execution/exec_sysmon_1_ftp.evtx`
- Dataset revision: `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- Revision date: 24 January 2023
- Evidence type: Windows Sysmon EVTX

### Sample Integrity

- Original filename: `exec_sysmon_1_ftp.evtx`
- SHA-256: `aadae0e31b5f2310284687062010251fdd9ed9b8e8d76be14b79896d05f970ef`

The original sample was downloaded from the dataset repository and analysed locally. The binary is not redistributed in this portfolio repository. To obtain it, use the source repository, revision, and file path listed above.

The upstream repository includes a GNU General Public License, version 3. Refer to the original repository for its licence and terms.

### Dataset Notes

The dataset contains Windows event samples associated with attack and post-exploitation techniques. Its README states that ATT&CK mapping is at the technique level, not the procedure level.

## Analysis Outputs

- `../analysis/timeline.csv` contains the Hayabusa detection timeline with timestamps displayed in IST (+05:30).
- `../analysis/process-tree.csv` contains the four unique process events, including process and parent-process names and IDs.
- The process-tree file preserves `HayabusaTimestampUTC` and `SysmonUtcTime` as separate UTC fields. They may differ slightly because they originate from different event timestamp fields.
- `../analysis/SHA256SUMS` contains the integrity hashes for the analysis CSV files.

## Evidence Limitations

- Part A contains only four selected process-creation records.
- Part A is a sanitised CSV export, not the original Windows event log.
- Part B is a public sample, not activity from my own Windows PC.
- The original context of the public sample has not been independently verified.
- Neither source alone establishes successful file transfer, payload execution, or system compromise.
