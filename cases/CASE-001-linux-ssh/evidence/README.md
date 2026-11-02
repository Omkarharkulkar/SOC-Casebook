# CASE-001 Evidence Inventory

## Investigation

SSH authentication activity investigation using two separate evidence sources:

1. SSH logs collected from the Ubuntu lab VM.
2. A publicly available SSH honeypot dataset.

## Host Information — Lab Evidence

- Hostname: lab-ubuntu-01
- Operating system: Ubuntu 24.04.5 LTS
- Log timezone: UTC+05:30

## Evidence Sources

| Evidence file | Original source | Purpose |
|---|---|---|
| ssh-auth-events.txt | `/var/log/auth.log` | SSH authentication and connection events from the lab VM |
| ssh-journal.txt | systemd journal, SSH service | Supporting SSH service activity |
| ssh_honeypot_dataset.csv | Public Zenodo SSH honeypot dataset | External SSH connection, login, and command activity |
| ssh_honeypot_dataset.csv.v2.tar.gz | Original downloaded Zenodo archive | Preserved copy of the downloaded dataset |

### Evidence Redaction

The public evidence files use sanitized identifiers. The original VM hostname and Linux username were replaced with `lab-ubuntu-01` and `labuser` respectively before publication. Event timestamps, source addresses, destination addresses, process IDs, and authentication outcomes were retained.

## Evidence 1: Ubuntu SSH Authentication Events

- Collection method: Read-only grep filtering
- Observed event dates: 27–29 October 2026
- Records collected: 21

Collection command:

    sudo grep -aE 'sshd\[[0-9]+\]: (Failed password|Accepted password|Accepted publickey|Invalid user|Connection closed)' /var/log/auth.log

## Evidence 2: Ubuntu SSH Service Journal

- Collection method: journalctl
- Requested collection window: 27–29 October 2026
- Records collected: 71

Collection command:

    sudo journalctl -u ssh --since "2026-10-27" --until "2026-10-30" --no-pager

## Evidence 3: Public SSH Honeypot Dataset

- Dataset: A 6-Month Dataset of SSH Botnet Interactions and Command Payloads
- Source: Zenodo
- Dataset page: https://zenodo.org/records/19731615
- Downloaded file: `ssh_honeypot_dataset.csv.v2.tar.gz`
- Extracted file: `ssh_honeypot_dataset.csv`
- Format: CSV
- Records analysed: 145,425
- Date range observed in the CSV: 27 July 2025 to 14 November 2025
- Unique sessions: 137,506
- Unique source IPs: 13,897

The CSV contained these event types:

| Event type | Records |
|---|---:|
| SSH connect | 137,506 |
| SSH login | 4,797 |
| SSH disconnect | 3,094 |
| exec_command | 28 |

The most frequently recorded login username was `root`, with 1,618 events.

### Command Activity Review

The 28 command events occurred across 16 sessions.

One session was selected for closer investigation:

- Date: 7 September 2025
- Source IP: `47[.]251[.]118[.]172`
- Session ID: `9caa7e8b-7378-41b7-9bdd-4ae800e2466e`
- Events: SSH connect, SSH login, and two command events.

The session recorded a submitted `root` login followed by commands that attempted to retrieve a remote file, save it under `/tmp`, make it executable, and launch it. A second command attempted to write approximately 1.9 MB of data to another temporary file.

This sequence is consistent with attempted payload delivery. The honeypot records do not establish whether the download or execution succeeded.

### Dataset Analysis Method

The Python standard library CSV module was used to:

- Count total records and event types.
- Identify unique sessions and source IPs.
- Review frequently submitted usernames.
- Identify sessions containing command events.
- Correlate the events in the selected session.

The dataset was analysed as recorded. Submitted commands and payloads were not executed.

### Analysis Scripts

Four Python scripts were created to make the public dataset
investigation repeatable.

| Script | Purpose |
|---|---|
| 01_dataset_summary.py | Summarizes records, event types, sessions, and source IPs |
| 02_login_and_session_summary.py | Reviews submitted usernames and identifies command sessions |
| 03_command_event_review.py | Reviews recorded command events |
| 04_session_correlation.py | Reconstructs the selected session in timestamp order |

All scripts use Python's built-in CSV module.
They read the dataset without executing recorded commands.

## Analysis Performed

The Python SSH parser at `minisoc/normalizer/ssh_parser.py` was used to identify SSH authentication events in the Ubuntu evidence.

The parser currently recognizes:

- Failed password authentication
- Failed public-key authentication
- Accepted password authentication
- Accepted public-key authentication
- Invalid username attempts
- SSH connection closures
- SSH disconnection events
- PAM authentication failures
- PAM session opened and closed events
- SSH server listening events

It supports ISO-format timestamps with timezone information and classic syslog timestamps. Timezone-aware timestamps are also converted to UTC. Classic syslog timestamps are preserved without assigning an assumed year or timezone.

Parser results for `ssh-auth-events.txt`:

- Total input lines: 21
- Recognized events: 21
- Unrecognized lines: 0
- Unit tests: 16 passed

The zero unrecognized count applies only to this filtered evidence file. It does not mean that every possible OpenSSH log format is supported.

The broader SSH journal contains 71 lines, of which 54 are recognized by the current parser and 17 remain unrecognized. The authentication log and journal overlap, so their parser counts must not be added together without deduplication. Classic syslog timestamps are preserved without assuming a year or timezone.

The public honeypot CSV was analysed separately using read-only Python scripts.

## Limitations

- Logs establish recorded events, not the intent behind them.
- A failed password or invalid username does not independently establish a brute-force attack.
- Connection closures are not automatically failed logins.
- October 27 invalid-user activity is likely lab-related, but exact attribution has not been independently established.
- The public dataset represents activity recorded by a honeypot, not evidence from a confirmed compromised production host.
- A recorded SSH login event does not, by itself, prove successful authentication on a real system.
- The September 7 command sequence is consistent with attempted payload delivery, but successful download or execution is not established.
- The public CSV timestamps do not include an explicit timezone offset.
- The investigation covers only the available evidence and collection periods.

## Evidence Integrity

SHA-256 hashes are recorded in [`SHA256SUMS`](SHA256SUMS) for the two lab log files and the downloaded public dataset files.

The authentication log and SSH journal are included in the repository. The extracted public dataset CSV and original compressed archive are retained locally but excluded from Git because of their size.

The hashes allow the local files to be checked for accidental changes. They do not independently establish the authenticity of the original log collection or dataset.

The public dataset source is [Zenodo record 19731615](https://zenodo.org/records/19731615). The source's published checksum should be treated separately from the locally calculated SHA-256 values.
