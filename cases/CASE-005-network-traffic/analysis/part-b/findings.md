# CASE-005 — Part B Findings

## 1. Network Activity Overview

- Capture duration: 27 minutes 58.992 seconds.
- Total packets: 4,134.
- Primary hosts of interest: HOST-1 and HOST-2.
- Observed protocols include DNS, HTTP, TLS, SMB2, and DCE/RPC.
- HOST-1 communicated repeatedly with multiple internal systems.

## 2. DNS and HTTP Activity

Observed traffic included Windows connectivity-check and update-related domains:

- `www.msftconnecttest.com`
- `download.windowsupdate.com`
- `definitionupdates.microsoft.com`
- `adl.windows.com`

Internal HTTP requests referenced several internal hostnames and API-style paths.

### Assessment

Some observed traffic is consistent with ordinary Windows connectivity-check and update activity. Internal HTTP traffic suggests communication with internal services, although their roles could not be confirmed from the capture alone.

## 3. SMB and DCE/RPC Activity

Repeated SMB2 and DCE/RPC communications were observed between HOST-1 and multiple internal hosts.

RPC metadata included:

- `srvsvc`
- `svcctl`
- `samr`

These identifiers indicate service-related and account-management interfaces were involved in the observed traffic. Their presence alone does not establish malicious activity.

## 4. File-Related Activity

SMB2 CREATE requests involving the filename `q4-summary.bin` were observed in two separate bursts.

| Time (IST) | Destination hosts | Response |
|---|---|---|
| 19:42:41 | Five internal hosts | SUCCESS |
| 20:00:14 | Six internal hosts | SUCCESS |

The corresponding SMB2 responses returned status `0x00000000`.

The repeated filename and multi-host pattern are noteworthy. The successful CREATE responses confirm that the requests succeeded at the SMB protocol level. However, the capture does not establish file contents, successful content transfer, or whether the activity was authorized.

## 5. Final Assessment

**Verdict: Suspicious coordinated internal activity observed — further investigation required.**

The capture contains repeated SMB/RPC activity involving multiple internal systems. Successful SMB2 CREATE operations involving the same filename were observed during two separate bursts.

These observations warrant further investigation. However, the available network evidence does not establish compromise, malicious intent, unauthorized access, or successful execution.

## 6. Recommended Follow-Up

In a real environment, further investigation would include correlating the activity with:

- Endpoint process and security logs from the initiating host.
- File-system records from destination hosts.
- Service-related activity and account usage.
- Approved administrative activity and change records.
- Additional network and endpoint evidence around the observed time windows.

## 7. Limitations

- Analysis was based on the provided network capture.
- The dataset is vendor-provided and synthetic.
- No ground-truth answer key was available during the blind investigation.
- Network evidence alone cannot establish authorization or malicious intent.
- No file contents were extracted or analyzed.
- The capture does not independently establish compromise.
