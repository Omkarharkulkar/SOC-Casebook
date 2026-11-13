# Evidence Provenance

## Source

- Dataset: EVTX-ATTACK-SAMPLES
- Repository: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Sample path: `Execution/exec_sysmon_1_ftp.evtx`
- Dataset revision: `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- Revision date: 24 January 2023
- Evidence type: Windows Sysmon EVTX

## Sample Integrity

- Original filename: `exec_sysmon_1_ftp.evtx`
- SHA-256: `aadae0e31b5f2310284687062010251fdd9ed9b8e8d76be14b79896d05f970ef`

The original sample was downloaded from the dataset repository and analyzed locally. The binary is not redistributed in this portfolio repository. To obtain it, use the source repository and the revision and file path listed above.

## Dataset Notes

The dataset contains Windows event samples associated with attack and post-exploitation techniques. Its README states that ATT&CK mapping is at the technique level, not the procedure level.

The upstream repository includes a GNU General Public License, version 3. Refer to the original repository for its licence and terms.

## Limitations

- This is a public sample, not a capture from my own Windows lab.
- The original activity context has not been independently verified.
- The selected sample contains four Sysmon process-creation events.
- The reviewed events do not confirm successful file transfer, payload execution, or system compromise.
