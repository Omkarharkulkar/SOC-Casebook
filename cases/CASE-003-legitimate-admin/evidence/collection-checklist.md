# CASE-003 Collection Checklist

## Pre-collection baseline

- [x] Record Windows edition, version and build.
- [x] Record PowerShell version and execution elevation.
- [x] Record IST/UTC time zone and Windows Time status.
- [x] Check Process Creation auditing.
- [x] Check command-line logging registry state.
- [x] Review effective Group Policy information.
- [x] Record Security event-log configuration and capacity.
- [x] Record pre-collection Security log boundaries.
- [x] Redact sensitive system identifiers from public documentation.

## Controlled activity collection

- [x] Use one elevated PowerShell session.
- [x] Execute seven planned administrative discovery commands.
- [x] Retain reconstructed command intervals in the ground-truth CSV; their independent source records were not retained.
- [x] Preserve reconstructed timestamps in IST and UTC, clearly labelled as unverified.
- [x] Keep command output out of the public evidence package.
- [x] Reconstruct the ground-truth CSV after finding the original CSV contained only its header; the independent timestamp source was not retained.
- [x] Check that all seven command entries are present; individual timestamp intervals remain unverified.

## Audit configuration

- [x] Confirm Process Creation auditing was already enabled.
- [x] Confirm command-line logging was already enabled.
- [x] Record the original policy and registry state.
- [x] Make no audit-policy or registry changes.
- [x] No policy restoration was required.

## Event export

- [x] Select Security Event ID 4688.
- [x] Define the collection window in UTC.
- [x] Include a five-second margin around command execution.
- [x] Export the selected events using wevtutil.
- [x] Verify the export contains 13 events.
- [x] Calculate and record the EVTX SHA-256 hash.
- [x] Retain the original EVTX locally and exclude it from Git.

## Analysis

- [x] Record Hayabusa version and rules repository commit.
- [x] Preserve the original Hayabusa timeline locally.
- [x] Record the original timeline SHA-256 hash.
- [x] Review informational and non-informational detections.
- [x] Inspect the Possible LOLBIN rule conditions.
- [x] Explain the three low-severity rule matches.
- [x] Complete the separate ground-truth comparison.
- [x] Account for all 13 process-creation events.
- [x] Create and validate a reviewed, sanitized analysis CSV.
- [x] Complete the incident report.
- [x] Complete the final evidence review.

## Evidence handling

- [x] Keep raw EVTX and original timeline outside the public repository.
- [x] Keep ground-truth records separate from event evidence.
- [x] Exclude unnecessary host, account, SID, path and network details.
- [x] Generate final SHA256SUMS for the reviewed public evidence files.
