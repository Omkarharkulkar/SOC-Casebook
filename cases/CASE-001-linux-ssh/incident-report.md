# CASE-001: SSH Authentication and Honeypot Investigation

## 1. Case Information

| Field | Value |
|---|---|
| Case ID | CASE-001 |
| Investigation Title | SSH Authentication and Honeypot Investigation |
| Investigation Date | 2 November 2026 |
| Analyst | SOC Casebook |
| Case Provenance | Lab Evidence + Public Dataset |
| Data Sources | Ubuntu SSH logs and public SSH honeypot dataset |
| Alert Source | Manual retrospective log review |
| Part A Severity | Informational — no confirmed unauthorized access or impact |
| Part B Severity | Medium — suspicious command activity recorded by a public honeypot |
| Confidence | Medium — recorded activity is clear, but payload execution is unconfirmed |

This case contains two separate investigations:

- **Part A:** SSH authentication activity on a controlled Ubuntu lab system.
- **Part B:** SSH activity recorded by a public honeypot dataset.

The two sources represent different environments and time periods. Their events are not treated as directly related.

The Part B severity is rated as if similar activity had occurred on a production host. It does not indicate confirmed compromise.

## 2. Executive Summary

This investigation reviews SSH authentication activity from an Ubuntu 24.04.5 LTS lab system and a public SSH honeypot dataset.

The lab investigation identified:

- One failed password authentication.
- One invalid username attempt.
- Three successful password authentications.
- Seven successful public-key authentications.
- Nine SSH connection closures.

The October 28 failed and successful password events occurred within the same SSH process and connection. A PAM authentication failure was also recorded shortly before the failed-password message. The sequence is consistent with an authentication retry, but the logs do not establish the user's exact intent.

No confirmed brute-force activity or compromise was identified in the examined lab evidence.

The public honeypot dataset contains a separate session from September 7, 2025. In that session, an SSH connection and login event were followed by commands attempting to retrieve a remote file, save it locally, change its permissions, and execute it.

This command sequence is consistent with attempted payload delivery. However, the dataset does not establish whether the remote file was successfully retrieved or executed.

**Part A assessment:** Inconclusive. The available lab records do not independently establish unauthorized activity.

**Part B assessment:** True Positive for suspicious activity recorded by the public honeypot. Successful payload retrieval, execution, and compromise are not established.

## 3. Alert Details

This investigation was initiated through manual retrospective review. No original SIEM alert or automated detection record was available.

| Field | Value |
|---|---|
| Review Name | Manual Retrospective SSH Activity Review |
| Detection Rule | No original alert rule |
| Investigation Trigger | Review of collected SSH authentication and honeypot records |
| Lab Event Period | 27–29 October 2026 |
| Public Dataset Event | 7 September 2025 |
| Primary Lab Source IP | 192.168.50.10 |
| Lab SSH Host IP | 192.168.50.20 |
| Lab Associated Account | Lab Ubuntu account |
| Public Honeypot Source IP | 47[.]251[.]118[.]172 |
| Honeypot Destination | 209[.]38[.]249[.]252:2222 |
| Relevant External Destination | 8[.]210[.]252[.]89:60147 |

The primary lab source IP refers to the Kali system involved in the October 27 and October 28 events. The October 29 self-originating connection used the Ubuntu host's own internal IP.

The public dataset's SSH login event records the submitted username as `root`. The event label alone does not independently prove successful authentication on a production system.

## 4. Investigation Timeline

The lab timestamps were recorded in UTC+05:30. UTC equivalents are included below.

The public dataset timestamps do not contain a timezone offset. They are reproduced as recorded and are not assumed to be UTC or local time.

### Part A — Ubuntu Lab Timeline

| Timestamp (UTC) | Original Time (UTC+05:30) | Event | Evidence |
|---|---|---|---|
| 27 Oct 11:10:22 | 27 Oct 16:40:22 | Invalid username attempt from 192.168.50.10 | E-001, E-002 |
| 28 Oct 11:04:15 | 28 Oct 16:34:15 | PAM authentication failure | E-002 |
| 28 Oct 11:04:17 | 28 Oct 16:34:17 | Failed password authentication | E-001, E-002 |
| 28 Oct 11:04:26 | 28 Oct 16:34:26 | Password authentication accepted | E-001, E-002 |
| 29 Oct 10:42:17 | 29 Oct 16:12:17 | Password authentication accepted | E-001, E-002 |
| 29 Oct 10:42:50–11:44:01 | 29 Oct 16:12:50–17:14:01 | Seven successful public-key authentications | E-001, E-002 |
| 29 Oct 11:22:58 | 29 Oct 16:52:58 | Password authentication accepted from the Ubuntu host's own internal IP | E-001, E-002 |

### Part B — Public Honeypot Timeline

| Dataset Timestamp | Event | Evidence |
|---|---|---|
| 2025-09-07 08:39:05.484958 | SSH connection from 47[.]251[.]118[.]172 | E-003 |
| 2025-09-07 08:39:06.248271 | SSH login event recording submitted username `root` | E-003 |
| 2025-09-07 08:39:07.020032 | Command attempting remote file retrieval and execution | E-003 |
| 2025-09-07 08:39:07.123850 | Additional command attempting to write data to a temporary file | E-003 |

The honeypot command activity began less than one second after the recorded login event.

## 5. Evidence Collected

| Evidence ID | Description | Source | File Reference |
|---|---|---|---|
| E-001 | Filtered Ubuntu SSH authentication events | `/var/log/auth.log` | `evidence/ssh-auth-events.txt` |
| E-002 | SSH service journal records | systemd journal | `evidence/ssh-journal.txt` |
| E-003 | Public SSH honeypot dataset | Zenodo dataset | Local CSV, not committed |
| E-004 | Dataset provenance, collection details and analysis summary | Evidence documentation | `evidence/README.md` |

The original dataset CSV and archive are retained locally and excluded from the Git repository.

### Tools Used

| Tool | Purpose |
|---|---|
| Python dataset analysis scripts | Public honeypot dataset analysis |
| MiniSOC SSH parser | Parsing SSH authentication records |
| Python unit tests | Testing parser behaviour |
| Linux `grep`, `journalctl` and other command-line utilities | Reviewing and filtering lab logs |

Tools are listed separately from evidence because they support the investigation but are not themselves investigation evidence.

## 6. Investigation and Analysis

### Initial Observations

The Ubuntu authentication logs contained a mixture of successful and unsuccessful authentication events.

The public honeypot dataset contained SSH connections, login events, disconnects and a small number of command-execution records.

The investigations were performed separately because the events belong to different systems and dates.

### Part A — Ubuntu Lab Investigation

#### Authentication Event Summary

| Event Type | Count |
|---|---:|
| Failed password | 1 |
| Invalid user | 1 |
| Accepted password | 3 |
| Accepted publickey | 7 |
| Connection closed | 9 |
| **Total** | **21** |

Connection closures were not counted as failed authentication attempts.

#### October 27 — Invalid Username

An invalid username attempt was recorded from 192.168.50.10.

The source address belongs to the Kali system in the controlled lab. However, an exact command record for this particular authentication event is unavailable.

The source and timing are consistent with lab activity, but the available authentication records do not independently confirm the exact action that generated the event.

**Assessment:** Likely lab-related, but exact attribution is unconfirmed.

#### October 28 — Failed and Successful Password Authentication

The journal records the following sequence:

1. 16:34:15 — PAM authentication failure.
2. 16:34:17 — Failed password authentication.
3. 16:34:26 — Password authentication accepted.
4. 16:34:26 — Session opened.
5. 16:34:27 — Session closed.

The failed and successful password events share:

- Source IP: 192.168.50.10
- Source port: 54830
- SSH process ID: 4468

The failed and successful password messages are separated by approximately 9.36 seconds.

The PAM failure occurred approximately two seconds before the failed-password message.

This sequence indicates an authentication retry within the same SSH connection. However, the logs do not establish whether the first failure was caused by a mistyped password or another reason.

The available records do not independently establish the exact command or purpose of the connection.

**Assessment:** Consistent with controlled lab authentication activity. No evidence of repeated password guessing was identified.

#### October 29 — Successful Authentication

The logs contain two successful password authentications and seven successful public-key authentications on October 29.

Across the complete October 27–29 investigation period, three successful password authentications were recorded.

Seven public-key events originated from 192.168.50.10, the Kali lab system.

One successful password authentication originated from 192.168.50.20.

The Ubuntu network configuration confirms that 192.168.50.20 is assigned to the host's own internal interface, `enp0s8`.

The journal shows that the corresponding session opened and closed approximately one second later.

This establishes that the source IP belongs to the Ubuntu host itself. The initiating process and exact purpose of the connection remain unknown.

**Assessment:** No evidence from this event independently establishes unauthorized access.

#### Connection Closures

Nine connection closures were identified.

These included connections ending before authentication and pre-authentication closures involving the lab account.

Connection closures alone do not establish failed authentication or malicious activity.

### Part B — Public SSH Honeypot Investigation

#### Dataset Overview

The public dataset used in this investigation is:

**A 6-Month Dataset of SSH Botnet Interactions and Command Payloads**

Authors: Viktor Boiko and Oleksandr Niiakyi
Platform: Zenodo
Record ID: 19731615

The CSV contains 145,425 records covering the period from 27 July 2025 to 14 November 2025.

Dataset summary:

| Metric | Result |
|---|---:|
| Total records | 145,425 |
| Unique sessions | 137,506 |
| Unique source IP addresses | 13,897 |
| SSH connect events | 137,506 |
| SSH login events | 4,797 |
| SSH disconnect events | 3,094 |
| Command-execution events | 28 |

The dataset was reviewed using Python's built-in CSV module. The analysis scripts read the records without executing recorded commands.

#### Selected Session Review

A session from 7 September 2025 was selected for closer investigation.

| Field | Value |
|---|---|
| Session ID | 9caa7e8b-7378-41b7-9bdd-4ae800e2466e |
| Source IP | 47[.]251[.]118[.]172 |
| Honeypot IP | 209[.]38[.]249[.]252 |
| Honeypot Port | 2222 |
| Recorded Username | root |
| Event Date | 7 September 2025 |

The session contains four correlated records:

1. An SSH connection from the source IP.
2. A login event recording the submitted username `root`.
3. A command attempting to connect to an external IP address on TCP port 60147, request a file, save the response to a temporary location, change its permissions and attempt execution.
4. A second command attempting to write additional data to a temporary file.

The command sequence is consistent with attempted remote payload retrieval and execution.

The timing is notable: the first command was recorded less than one second after the login event, and the next command followed approximately 0.10 seconds later.

This short interval is consistent with automated activity, although timing alone cannot prove that the session was operated by a bot.

#### Sanitized Command-Behavior Summary

The following is an analyst summary of the recorded command activity, not a verbatim command:

> Attempted to contact an external host on TCP port 60147, request a remote file, save the response to a temporary location, change its permissions and attempt to execute it.

The external destination recorded in the dataset is `8[.]210[.]252[.]89:60147`. The command itself is not reproduced here.

#### MITRE ATT&CK Mapping

| Technique | Name | Reason for mapping |
|---|---|---|
| T1059.004 | Unix Shell | The recorded command activity is consistent with shell-based command execution. |
| T1105 | Ingress Tool Transfer | The command attempted to retrieve a file from an external host. |

These mappings describe the observed behavior. They do not confirm that the file transfer or execution succeeded.

#### Analysis

The recorded commands indicate activity beyond ordinary interactive SSH administration.

The attempt to retrieve an external file, modify its permissions and execute it is suspicious and consistent with a payload-delivery attempt.

However, the dataset records commands submitted to the honeypot. It does not independently establish that:

- The external connection succeeded.
- A file was successfully retrieved.
- The resulting file was valid or executable.
- The attempted execution completed successfully.
- A real production system was compromised.

The honeypot dataset is evidence of activity captured by a honeypot, not evidence that the Ubuntu lab system experienced this activity.

**Assessment:** Suspicious SSH activity consistent with attempted payload delivery. Successful payload retrieval or execution is unconfirmed.

### Event Correlation

The two investigations have different timestamps, source systems and evidence origins.

No direct relationship between the October 2026 Ubuntu lab events and the September 2025 honeypot session has been established.

They are compared to demonstrate two different types of SSH activity:

- Authentication activity in a controlled lab.
- Suspicious command activity recorded by a public honeypot.

### Relevant Findings

1. The lab logs contain only one failed password event.
2. The October 28 authentication sequence is consistent with a retry within one SSH connection.
3. The October 29 successful authentication from the Ubuntu host's own IP requires no assumption of an external attacker.
4. The public honeypot contains a command sequence consistent with attempted remote payload retrieval and execution.
5. The sub-second timing between the honeypot login event and command activity is consistent with automation, but does not prove it.
6. Neither evidence source proves successful compromise.

### Indicators of Compromise

The public honeypot session contains the following historical indicators for investigation:

| Indicator | Defanged Value | Context |
|---|---|---|
| Source IP | 47[.]251[.]118[.]172 | Honeypot session source |
| Honeypot IP | 209[.]38[.]249[.]252 | SSH service destination |
| External IP | 8[.]210[.]252[.]89 | Destination in recorded retrieval command |
| External Port | 60147 | TCP destination port in recorded command |
| Session ID | 9caa7e8b-7378-41b7-9bdd-4ae800e2466e | Selected dataset session |

These are historical dataset indicators. They have not been independently checked for current malicious activity and should not be treated as current threat intelligence.

No indicator from this public session was observed in the Ubuntu lab evidence.

## 7. Impact Assessment

### Affected Assets

**Part A:** Ubuntu 24.04.5 LTS lab system.

**Part B:** Public SSH honeypot represented in the dataset.

### Potential Impact

The public honeypot command sequence, if successful on a real system, could lead to the retrieval and execution of an unknown remote file.

The available dataset does not establish that this occurred.

### Confirmed Impact

- No confirmed compromise of the Ubuntu lab system.
- No confirmed payload execution in the honeypot session.
- No evidence connecting the public honeypot activity to the Ubuntu lab system.

## 8. Investigation Verdict

### Part A — Ubuntu Lab

**Severity: Informational.**

**Verdict: Inconclusive — no confirmed attack.**

The October 28 authentication sequence is consistent with a retry within one SSH connection. The October 27 invalid username event is likely lab-related, but exact attribution is unavailable.

The October 29 self-originating connection is attributable to the Ubuntu host's own internal IP, although its initiating process is unknown.

No confirmed unauthorized access or compromise was identified.

### Part B — Public Honeypot

**Severity: Medium.**

**Verdict: True Positive — suspicious activity recorded.**

The selected session contains commands consistent with attempted remote payload retrieval and execution.

The activity is genuinely suspicious, but successful retrieval, execution and compromise are not established.

The Medium severity is an assessment of the potential seriousness of similar activity on a production host, not a statement that compromise was confirmed.

### Overall Case Assessment

- **Part A — Ubuntu Lab:** Inconclusive.
- **Part B — Public Honeypot:** True Positive for suspicious activity recorded.

The two investigations concern separate systems and time periods. The Part B verdict does not establish an attack or compromise of the Ubuntu lab system.

**Overall confidence: Medium.**

Confidence is high that the dataset records the selected connection and command sequence. Confidence is lower regarding the outcome of the attempted retrieval and execution because independent confirmation is unavailable.

## 9. Response and Escalation

### Actions Taken

- Reviewed Ubuntu SSH authentication records.
- Correlated relevant events with the systemd SSH journal.
- Parsed the lab authentication records using the MiniSOC SSH parser.
- Reviewed the public honeypot dataset using Python analysis scripts.
- Reconstructed the selected honeypot session in timestamp order.
- Kept the raw dataset and archive separate from the public Git repository.

No containment or remediation action was required on the Ubuntu lab system based on the examined evidence.

### Recommended Actions

For a production environment showing similar activity:

1. Review SSH authentication failures and successful logins from the same source.
2. Investigate unexpected commands executed after successful authentication.
3. Review outbound network connections associated with suspicious sessions.
4. Check for unexpected files and processes if payload retrieval is suspected.
5. Preserve authentication, process and network evidence.
6. Escalate suspected payload retrieval or execution to the incident response team.

### Escalation Required

**For the lab investigation:** No escalation based on the available evidence.

**For the public honeypot activity:** Escalation would be appropriate if similar command activity were observed on a production system.

This is a retrospective portfolio investigation, not an active incident affecting a production environment.

## 10. Detection Improvements

The investigation highlights several useful SSH monitoring improvements.

### Recommended Detection Changes

- Detect repeated authentication failures from a single source within a defined time window.
- Correlate failed authentication followed by successful authentication.
- Monitor successful logins against unexpected usernames.
- Detect unusual command activity following SSH authentication.
- Investigate outbound connections associated with suspicious SSH sessions.

A possible starting detection is five or more failed authentication events from one source IP within five minutes.

This threshold is a proposed starting point, not a validated detection rule. It should be tested against normal lab activity before being used in production.

### Monitoring Improvements

- Collect complete SSH service journal records, including PAM messages.
- Preserve process IDs, source ports and timestamps for correlation.
- Monitor successful SSH sessions and session termination.
- Include relevant network and process evidence when investigating suspected payload retrieval.

### Additional Data Required

- Complete SSH service records for the relevant time window.
- Shell or command audit records, where available.
- Process execution logs.
- Network connection records.
- Additional honeypot session context confirming retrieval or execution outcomes.

## 11. Lessons Learned

- A failed password event does not automatically indicate brute-force activity.
- A successful login does not independently establish whether access was authorized.
- PAM messages provide useful context that may not appear in filtered authentication records.
- Connection closures should not be counted as failed authentication attempts without supporting evidence.
- Source IP ownership is useful for correlation, but does not always identify the initiating process.
- Honeypot command records can reveal suspicious behavior, but do not prove that a payload executed successfully.
- Evidence from separate systems and time periods should not be combined into one timeline.
- Short command intervals can suggest automation, but timing alone does not prove automated activity.
- A detection should be evaluated using its supporting evidence and limitations before assigning a verdict.

## 12. Limitations

- The Ubuntu investigation covers only the collected log window.
- The authentication evidence file was filtered using grep and does not contain every SSH-related journal event.
- The authentication parser recognized all 21 lines in the filtered authentication evidence file.
- The parser supports ISO-format and classic syslog timestamps. However, successful timestamp parsing does not mean every journal event format is supported.
- When tested against the broader SSH journal, the parser recognized 54 of 71 lines and left 17 unrecognized. Recognized events include PAM authentication failures, PAM session open/close events and SSH server-listening messages. The remaining lines are outside the parser's current event coverage.
- The parser's output from the authentication file and journal should not be combined without deduplication because both sources contain overlapping events.
- Journal timestamps without a year or timezone cannot be reliably converted to UTC without additional context.
- The logs do not establish user intent.
- The October 27 invalid username event has no independently preserved command record.
- The initiating process for the October 29 self-originating connection is unknown.
- No shell-history, login-history, process-accounting or terminal-record results are included in the evidence reviewed for this report. These checks therefore cannot be used to confirm or exclude the source of the lab authentication events.
- The public dataset is honeypot evidence, not a production victim's complete system logs.
- The public dataset timestamps do not specify a timezone offset.
- The honeypot login event does not independently prove successful authentication on a real system.
- The recorded command sequence does not prove successful file retrieval or execution.
- The external IP addresses have not been independently validated as currently malicious.
- No confirmed compromise was identified in either evidence source.

## 13. References

1. Boiko, Viktor and Niiakyi, Oleksandr. *A 6-Month Dataset of SSH Botnet Interactions and Command Payloads*. Zenodo, Record ID 19731615.
2. Ubuntu 24.04.5 LTS SSH authentication logs and systemd journal collected from the controlled lab.
3. OpenSSH server authentication and session records.
4. Python MiniSOC SSH parser and unit tests included in this repository.
5. Python built-in CSV module used for public dataset analysis.

## 14. Evidence That Could Change the Verdict

The following additional evidence could change or strengthen the investigation conclusions.

The checks listed below are not represented by results in the evidence reviewed for this report.

### Ubuntu Lab

- Shell history or audit records confirming the exact command responsible for the October 27 invalid username event.
- Process and terminal records identifying the source of the October 29 self-originating SSH connection.
- Additional records confirming the purpose of successful authentication sessions.
- Complete SSH journal records covering the investigation period.

### Public Honeypot

- Network capture showing whether the external file retrieval connection succeeded.
- Honeypot file-system evidence showing whether the downloaded file was created.
- Process execution records confirming whether the file was launched.
- Additional session records documenting the outcome of the command sequence.

Without this additional evidence, the investigation should not claim confirmed payload execution or system compromise.
