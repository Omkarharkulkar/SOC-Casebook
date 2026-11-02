# CASE-001: SSH Authentication Activity Investigation

## 1. Executive Summary

This investigation reviews SSH authentication activity recorded
on an Ubuntu 24.04.5 LTS lab system.

The investigation identified:
- One failed password authentication.
- One invalid username attempt.
- Three successful password authentications.
- Seven successful public-key authentications.
- Nine SSH connection closures.

The failed password and subsequent successful authentication
on 28 October correlate with documented authorized lab activity.

The invalid username attempt on 27 October is consistent with
the lab environment, but its exact origin has not been
independently confirmed.

No repeated authentication failure pattern sufficient to
establish brute-force activity was identified.

**Preliminary verdict: Inconclusive — no confirmed attack.**

Most observed activity is consistent with authorized lab
operations, but not every event has been independently attributed.

## 2. Investigation Details

| Field | Value |
|---|---|
| Case ID | CASE-001 |
| Title | SSH Authentication Activity Investigation |
| Host | omkarvm |
| Operating system | Ubuntu 24.04.5 LTS |
| Service | OpenSSH |
| Investigation period | 27–29 October 2026 |
| Timezone | UTC+05:30 |
| Analyst | SOC Casebook |

## 3. Evidence Sources

The following sources were examined:

| Evidence | Source | Records |
|---|---|---:|
| ssh-auth-events.txt | /var/log/auth.log | 21 |
| ssh-journal.txt | systemd SSH journal | 71 |

The authentication evidence was filtered using grep.

The SSH service journal was collected using journalctl.

See evidence/README.md for collection details and commands.

## 4. Investigation Methodology

The investigation followed these steps:

1. Collected SSH authentication records from auth.log.
2. Collected supporting SSH service journal entries.
3. Parsed authentication events using the MiniSOC SSH parser.
4. Classified events by authentication type.
5. Correlated timestamps, source IP addresses, usernames,
   source ports and SSH process identifiers.
6. Compared relevant activity with available NetSentry
   lab records.
7. Assessed whether the evidence supported an attack verdict.

The parser's six unit tests passed.

All 21 records in the filtered authentication evidence
were successfully recognized.

## 5. Event Summary

| Event type | Count |
|---|---:|
| Failed password | 1 |
| Invalid user | 1 |
| Accepted password | 3 |
| Accepted publickey | 7 |
| Connection closed | 9 |
| Total | 21 |

Connection closures were treated separately from failed
authentication events.

## 6. Investigation Timeline

All timestamps use UTC+05:30.

| Date and time | Source IP | Event | Assessment |
|---|---|---|---|
| Oct 27 16:40:22 | 192.168.50.10 | Invalid username attempted | Likely lab-related; exact attribution unconfirmed |
| Oct 28 16:34:17 | 192.168.50.10 | Failed password for omkarubuntu | Correlates with lab testing |
| Oct 28 16:34:26 | 192.168.50.10 | Password accepted | Correlates with preceding authentication |
| Oct 29 16:12:17 | 192.168.50.10 | Password accepted | Successful authentication |
| Oct 29 16:12–17:14 | 192.168.50.10 | Seven public-key authentications | Successful key-based authentication |
| Oct 29 16:52:58 | 192.168.50.20 | Password accepted | Source activity requires further attribution |

## 7. Event Correlation

### 7.1 October 27: Invalid Username

An invalid username, invaliduser, was attempted from
192.168.50.10.

The same SSH process recorded a connection closure
immediately afterward.

Previous NetSentry records show authorized Kali-to-Ubuntu
network assessment activity around this period.

The source and timing are consistent with lab activity.
However, an exact command record for this particular
authentication event is unavailable.

Assessment: Likely authorized lab activity, not independently
confirmed.

### 7.2 October 28: Failed and Successful Password

At 16:34:17, SSH recorded a failed password attempt for
omkarubuntu from 192.168.50.10.

At 16:34:26, the same SSH process recorded successful
password authentication.

Both events share:
- Source IP: 192.168.50.10
- Source port: 54830
- SSH process ID: 4468

The events are separated by approximately 9.36 seconds.

Previous NetSentry project records corroborate authorized
SSH testing between the Kali and Ubuntu lab systems.

Assessment: Consistent with a controlled lab authentication
test. No evidence of brute-force activity.

### 7.3 October 29: Successful Authentication

The logs contain successful password and public-key
authentications.

Seven successful public-key events originated from
192.168.50.10, the Kali lab system.

One successful password authentication originated from
192.168.50.20.

The Ubuntu network configuration confirms that
192.168.50.20 is assigned to the host's own internal
interface, enp0s8.

The corresponding SSH journal records show that the
session opened successfully and closed approximately
one second later.

This indicates a connection to the Ubuntu host through
its own internal IP address. However, the initiating
process and exact purpose of the connection are not
established by the available logs.

Assessment: The source is attributable to the Ubuntu
host itself. No evidence from this event independently
establishes unauthorized access.

### 7.4 Connection Closures

Nine connection closures were identified.

These included:
- Connections ending before authentication.
- A closure following the invalid username attempt.
- Pre-authentication closures involving omkarubuntu.

Connection closures alone do not establish failed
authentication or malicious activity.

## 8. Findings

### Finding 1: Limited Failed Authentication

One failed password event was identified.

The available evidence does not demonstrate repeated
password failures or a sustained brute-force pattern.

### Finding 2: Invalid Username Attempt

One invalid username attempt was recorded.

Its source is consistent with the Kali lab system,
but exact attribution remains unconfirmed.

### Finding 3: Successful Authentication

Three password and seven public-key authentication
events were recorded.

Successful authentication does not independently establish
whether an activity was authorized.

### Finding 4: No Confirmed Compromise

The examined evidence does not establish unauthorized
access or account compromise.

## 9. Verdict

**Verdict: Inconclusive — no confirmed attack.**

The October 28 failed-then-successful authentication
correlates with authorized lab testing.

The October 27 invalid username event is likely lab-related,
but exact attribution is unavailable.

The October 29 successful authentication from 192.168.50.20
also requires contextual verification.

No evidence currently establishes a brute-force attack
or confirmed compromise.

## 10. Recommended SOC Actions

1. Correlate repeated authentication failures by source IP,
   username and time window.
2. Review successful logins following suspicious failures.
3. Investigate repeated attempts against invalid usernames.
4. Verify unfamiliar successful authentication sources.
5. Preserve authentication logs for future correlation.
6. Escalate suspicious successful logins when their origin
   cannot be explained.

## 11. Limitations

- The investigation is limited to the collected log window.
- The logs do not establish user intent.
- Not all activity has independently preserved command history.
- Previous project records provide context, not direct proof
  of every individual event.
- No evidence of a confirmed compromise was identified
  in the examined records.

## 12. Conclusion

This investigation demonstrates the importance of correlating
authentication events with system activity and known lab
operations before assigning an incident verdict.

A failed password or invalid username should not automatically
be classified as a brute-force attack.

The available evidence supports further contextual verification,
but does not establish malicious SSH activity.
