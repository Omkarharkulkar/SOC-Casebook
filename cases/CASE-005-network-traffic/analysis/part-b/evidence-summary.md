# CASE-005 — Part B Evidence Summary

## Dataset

NM-SAMPLE-002 — Multi-Behavior Scenario

Vendor-provided synthetic network traffic used for a blind defensive investigation.

## Network Overview

- Capture duration: approximately 28 minutes.
- Total packets: 4,134.
- Protocols observed: DNS, HTTP, TLS, SMB2, and DCE/RPC.
- Host-1 was involved in repeated communications with multiple internal systems.
- Host-2 also appeared in the observed internal traffic.

## Observations

| Evidence | Observation | Assessment |
|---|---|---|
| DNS | Repeated connectivity-check and update-related queries | Consistent with some ordinary Windows network activity |
| HTTP | Internal service-related requests and API-style paths | Internal service communication observed |
| TLS | Repeated encrypted connections to external-looking test infrastructure | Encrypted communication observed; contents unavailable |
| SMB2 | Repeated communication involving multiple internal hosts | Warrants investigation |
| DCE/RPC | Service-related and account-management interface identifiers observed | Interface presence alone is not evidence of malicious actions |
| SMB2 CREATE | Requests involving the same filename across multiple hosts | Noteworthy multi-host activity |
| SMB2 responses | Corresponding CREATE responses returned SUCCESS | Requests succeeded at the SMB protocol level |

## File-Related Activity

Two bursts of SMB2 CREATE requests involving `q4-summary.bin` were observed:

- Approximately 19:42:41 IST — five destination hosts.
- Approximately 20:00:14 IST — six destination hosts.

The corresponding responses returned status `0x00000000` (SUCCESS).

The repeated filename and multi-host pattern warrant further investigation. The capture does not establish file contents, successful content transfer, or whether the activity was authorized.

## Assessment

Suspicious coordinated internal activity observed — further investigation required.

The evidence supports repeated SMB/RPC activity and successful SMB2 CREATE operations involving multiple internal systems.

The available network evidence does not independently establish compromise, malicious intent, unauthorized access, or successful execution.

## Limitations

- Vendor-provided synthetic dataset.
- Blind investigation; no ground-truth answer key available.
- Analysis limited to captured network traffic.
- No file contents extracted or analyzed.
- No endpoint telemetry or authorization records available.
- Host identifiers have been anonymized in this summary.
