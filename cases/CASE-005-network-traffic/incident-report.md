# CASE-005 — Network Traffic Investigation

## 1. Case summary

| Field | Value |
|---|---|
| Case | CASE-005 |
| Type | Network traffic investigation / alert triage |
| Dataset | NM-SAMPLE-002 — Multi-Behavior Scenario |
| Source | NetMetria / Metria Data Systems LLC |
| Capture date | 2026-09-02 |
| Analysis date | 2026-11-23 |
| Status | Complete |
| Assessment | Suspicious remote service execution and lateral movement observed — escalate to L2 |
| Environment | Synthetic multi-behavior scenario |

The investigation identified coordinated SMB administrative-share activity and remote Service Control Manager operations originating from HOST-1. The service definitions include a command-interpreter invocation and an executable located in a Windows temporary directory.

The observed behavior is consistent with lateral movement using SMB and remote service execution. The capture does not independently establish the full endpoint impact or confirm a real-world compromise.

## 2. Alert and investigation objective

The objective was to examine the network capture for suspicious communication, identify relevant hosts and protocols, reconstruct significant activity, and assess whether the observed behavior warranted escalation.

The investigation covered DNS, HTTP, TLS, NTP, SMB2 and DCE/RPC traffic. A short controlled DNS/HTTPS capture from Part A was used as a limited baseline for comparison.

## 3. Evidence and handling

### Evidence IDs

| Evidence ID | Description |
|---|---|
| E-001 | Part A controlled DNS/HTTPS baseline |
| E-002 | Part B NM-SAMPLE-002 network capture |
| E-003 | Part B protocol hierarchy and packet metrics |
| E-004 | Part B DNS, HTTP and TLS analysis |
| E-005 | SMB2 CREATE and WRITE packet analysis |
| E-006 | DCE/RPC and Service Control Manager analysis |
| E-007 | Extracted event timeline and investigation notes |

The original Part B PCAP is retained outside the public repository. Its SHA-256 is:

`ec77f256e309ec7e9eda8dcd3c422b5524119c50d23a7485772838269a0c4d89`

The capture contains 4,134 packets and spans approximately 27 minutes and 59 seconds.

Analysis used TShark and Capinfos 4.2.2. The commands used for reproducibility are maintained in `commands.md`.

### Host references

| Host | Address | Investigation role |
|---|---|---|
| HOST-1 | `10.42.10.21` | Main source of observed SMB and remote SCM activity |
| HOST-2 | `10.42.10.22` | Internal destination involved in SMB and SCM activity |
| HOST-3 | `10.42.20.10` | Internal destination |
| HOST-4 | `10.42.20.15` | Internal destination |
| HOST-5 | `10.42.20.20` | Internal destination |
| HOST-6 | `10.42.20.30` | Internal destination |
| HOST-7 | `10.42.20.40` | Internal destination |

These labels are used to make the report easier to follow. They do not establish the actual system roles or ownership of the hosts.

## 4. Network overview

The capture contains 4,134 frames and approximately 571 KB of captured frame data.

| Protocol | Frames |
|---|---:|
| UDP | 738 |
| DNS | 710 |
| NTP | 28 |
| TCP | 3,396 |
| HTTP | 292 |
| NBSS / SMB2 | 782 |
| DCE/RPC | 292 |
| TLS | 438 |

The protocol hierarchy shows substantial SMB2 and DCE/RPC activity alongside ordinary DNS, HTTP, TLS and NTP traffic.

HTTP and DCE/RPC each account for 292 frames in the protocol hierarchy. This is an observed count, not evidence that the two protocol groups represent the same transactions.

## 5. DNS, HTTP and TLS findings

### DNS

Part B contains 710 DNS frames: 355 queries and 355 responses.

All 355 observed queries used record type A. All 355 responses returned NOERROR. No NXDOMAIN responses were observed.

| DNS name | Query count |
|---|---:|
| `www.msftconnecttest.com` | 113 |
| `download.windowsupdate.com` | 57 |
| `definitionupdates.microsoft.com` | 55 |
| `adl.windows.com` | 55 |
| `updates.arden.local` | 13 |
| `support.arden.local` | 13 |
| `portal.arden.local` | 13 |
| `files.arden.local` | 12 |
| `directory.arden.local` | 12 |
| `config.arden.local` | 12 |

The Windows connectivity and update-related names are consistent with ordinary Windows network activity. The internal `arden.local` names indicate internal service discovery or access, but the DNS results alone do not establish malicious activity.

### Part A and Part B comparison

| Metric | Part A baseline | Part B scenario |
|---|---:|---:|
| DNS queries | 8 | 355 |
| DNS responses | 8 | 355 |
| Query record type | A | A |
| NXDOMAIN responses | 0 | 0 |
| Distinct queried names | 4 | 10 |

Part A was a short controlled capture involving `ubuntu.com`, `github.com`, `example.com` and `debian.org`. Each name was queried twice.

The baseline is useful for demonstrating normal controlled DNS/HTTPS activity, but it is too small to represent an enterprise environment or establish a comprehensive normal-traffic profile.

### HTTP and TLS

Observed HTTP requests included:

- `www.msftconnecttest.com`
- `assets.arden.local`
- `updates.arden.local`
- `support.arden.local`
- `portal.arden.local`
- `files.arden.local`
- `directory.arden.local`
- `config.arden.local`

TLS SNI values included:

- `definitionupdates.microsoft.com`
- `adl.windows.com`
- `download.windowsupdate.com`

The observed Windows connectivity and update-related traffic does not independently establish malicious activity. The internal HTTP requests are relevant to the environment but require application and endpoint context for further attribution.

## 6. SMB2 findings

The capture contains 782 SMB2 frames.

### Administrative-share access

HOST-1 accessed the following administrative share:

`\\files.arden.local\ADMIN$`

The 11 observed CREATE requests for `q4-summary.bin` were mapped to this share using their Tree IDs and Tree Connect frame references.

The requests involved six internal destinations:

- HOST-2
- HOST-3
- HOST-4
- HOST-5
- HOST-6
- HOST-7

### File operation analysis

The 11 CREATE requests used disposition `FILE_OPEN`, indicating requests to open an existing object rather than create a new file.

The corresponding CREATE responses returned success.

The investigation also identified 11 WRITE requests associated with the same file handles. The correlation was verified using both Tree ID and File ID, rather than relying only on TCP stream numbers.

All 11 WRITE responses returned success. Each WRITE operation carried 96 bytes, for a total of 1,056 bytes.

This establishes successful SMB-level write operations against the opened file handles. It does not establish the content of the writes, the purpose of the file, or whether the activity was authorized.

## 7. DCE/RPC and remote service execution findings

The capture contains 292 DCE/RPC frames.

Observed interfaces included:

| Interface | UUID | Frames |
|---|---|---:|
| Service Control Manager (`svcctl`) | `367abb81-9844-35f1-ad32-98f038001003` | 142 |
| Server Service (`srvsvc`) | `4b324fc8-1670-01d3-1278-5a47bf6ee188` | 34 |
| SAM Remote Protocol (`samr`) | `12345778-1234-abcd-ef00-0123456789ac` | 24 |

The investigation identified Service Control Manager operations including:

- `RCloseServiceHandle`
- `RQueryServiceStatus`
- `RCreateServiceW`
- `ROpenSCManagerW`
- `RStartServiceW`

### Service definitions

Two service definitions were particularly significant.

**WinHostSvc**

The observed binary path was:

`C:\Windows\System32\cmd.exe /Q /c whoami > C:\Windows\Temp\svc.out 2>&1`

This is a command-interpreter invocation configured to run `whoami` and redirect its output to a temporary file.

**WinUpdateSvc**

The observed binary path was:

`C:\Windows\Temp\WinUpdateSvc.exe`

This service definition references an executable located in a Windows temporary directory.

Both service definitions warrant endpoint-side investigation.

### Service operation responses

The packet extraction showed successful service-creation responses, including `WERR_OK (0x00000000)`.

Service-start operations returned a mixture of successful results and `WERR_SERVICE_REQUEST_TIMEOUT (0x0000041d)`.

A successful service-creation response confirms that the service creation request succeeded at the protocol level. A successful start response indicates that the start request was accepted. Neither result independently proves that the associated process completed successfully.

Timeout responses must not be treated as confirmed successful execution.

### Host correlation

The clearest request/response sequence involved HOST-1 and HOST-2:

| Frame | Source | Destination | Operation | Result |
|---:|---|---|---|---|
| 3079 | HOST-1 | HOST-2 | CreateServiceW | Request |
| 3085 | HOST-2 | HOST-1 | CreateServiceW | Success |
| 3086 | HOST-1 | HOST-2 | StartServiceW | Request |
| 3088 | HOST-2 | HOST-1 | StartServiceW | Success |

A later sequence involving HOST-1 and HOST-2 also showed service creation and start operations.

Additional service-control activity was observed involving HOST-7 and HOST-5. The extracted frames show requests and responses, but each individual operation must be correlated by its RPC context and TCP stream before assigning a final result to a destination.

The traffic therefore demonstrates remote service-management activity from HOST-1 toward multiple internal systems.

## 8. Timeline highlights

All times below are local capture time (IST, UTC+05:30).

| Time | Event |
|---|---|
| 19:42:41 | First observed burst of `q4-summary.bin` CREATE requests from HOST-1 to five internal destinations |
| 19:57:48 | HOST-1 sends service-creation and service-start operations to HOST-2 |
| 19:57:48 | Service definition for `WinHostSvc` observed, including the `cmd.exe` command |
| 20:00:14 | Second observed burst of `q4-summary.bin` CREATE requests, involving six internal destinations |
| 20:02:07 | Further service-creation and service-start operations involving HOST-2 and other internal destinations |

The two SMB file-operation bursts were approximately 17 minutes and 33 seconds apart.

The repeated destination pattern and identical 96-byte WRITE sizes may indicate automated or scripted activity. This is an inference from the observed pattern, not proof of the tool or operator involved.

## 9. MITRE ATT&CK mapping

The observed behavior is a candidate for:

**T1021.002 — Remote Services: SMB/Windows Admin Shares**

The use of `ADMIN$` and associated SMB file operations supports considering this technique.

Remote Service Control Manager activity is also relevant to lateral-movement and remote-execution investigation. The ATT&CK mapping should remain a behavioral classification rather than a claim that a specific adversary or tool was identified.

## 10. Detection hypotheses

The following detection hypotheses are supported by the observed behavior and can be used for defensive monitoring.

| Detection hypothesis | Supporting evidence | Suggested investigation |
|---|---|---|
| Administrative-share file activity across multiple hosts | HOST-1 accessed `ADMIN$` on six destinations and performed successful writes | Compare with approved administration activity and change records |
| Remote service creation from a workstation or server | `CreateServiceW` requests and successful responses | Review service installation events and the initiating account |
| Service execution using command interpreter | `WinHostSvc` references `cmd.exe` and `whoami` | Review process-creation telemetry and service configuration |
| Service executable launched from a temporary directory | `WinUpdateSvc` references `C:\Windows\Temp\WinUpdateSvc.exe` | Check file creation, hash, signature, and process execution records |
| Repeated remote service operations across internal systems | Similar SCM activity toward multiple destinations | Correlate source host, destination host, account and timestamps |
| SMB file writes followed by remote service operations | Successful writes and SCM activity are both present | Determine whether the file operations and service operations are part of the same activity chain |

These are investigation hypotheses, not detections proven to have fired in a production environment.

## 11. Severity, confidence and escalation

**Assessment:** Suspicious remote service execution and lateral movement observed.

**Recommended severity:** High priority for L2 validation.

**Confidence:**
- High confidence in the observed SMB administrative-share access and successful WRITE responses.
- High confidence that remote Service Control Manager operations occurred.
- High confidence that service definitions included the observed command and executable paths.
- Lower confidence in the identity of the account and the endpoint impact because the capture does not provide the required endpoint context.

### L1 escalation decision

Escalate to L2 for validation.

Recommended follow-up:

1. Identify the account responsible for the remote SMB and SCM sessions.
2. Review Windows service-installation events on the destination systems.
3. Review process-creation events for `cmd.exe`, `whoami` and `WinUpdateSvc.exe`.
4. Verify whether `WinUpdateSvc.exe` existed on the destination systems and examine its hash and signature.
5. Determine the contents and purpose of `q4-summary.bin`.
6. Compare the activity with approved administrative tools, maintenance windows and change records.
7. Establish whether the service operations and SMB file writes were part of one coordinated sequence.

## 12. Limitations

- The dataset is a synthetic multi-behavior scenario. It is not evidence of an actual enterprise compromise.
- Initial access is outside the scope of this scenario.
- No public ground truth or answer key was identified during the investigation.
- The capture does not establish the content of `q4-summary.bin`.
- NTLM username/domain extraction returned no values, so account attribution remains unresolved.
- Successful network-level service responses do not independently prove process completion or resulting endpoint activity.
- The capture alone cannot establish persistence, data exfiltration, or the full impact on destination systems.
- The Part A baseline is short and controlled; it is not representative of normal enterprise traffic.

## 13. Final conclusion

The investigation identified a coordinated pattern of SMB administrative-share access, successful file writes, and remote Service Control Manager operations originating from HOST-1.

The service definitions included a command-interpreter invocation and an executable located in a Windows temporary directory. Successful service-creation and service-start responses provide stronger evidence than a simple service-management request, although endpoint-side execution and impact remain unverified.

The combined behavior is consistent with lateral movement using SMB administrative shares and remote service execution.

**Final verdict: Suspicious remote service execution and lateral movement observed — escalate to L2 for validation.**

No claim of confirmed real-world compromise is made.

## References

- NetMetria — NM-SAMPLE-002 Multi-Behavior Scenario dataset.
- Wireshark / TShark packet analysis.
- Microsoft MS-SCMR — Service Control Manager Remote Protocol.
- MITRE ATT&CK — T1021.002, Remote Services: SMB/Windows Admin Shares.
