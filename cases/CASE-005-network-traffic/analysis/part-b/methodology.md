# Part B — Blind Network Investigation Methodology

## Alert prompt
A network sensor flagged unusual traffic involving a host. Review the
available network capture, identify relevant hosts and communication
patterns, assess observations that warrant further investigation, and
document an evidence-supported assessment.

This is a simulated analyst prompt, not an alert produced by the
dataset publisher or a real IDS/SIEM.

## Pre-analysis context
The publisher states the capture is NetMetria-generated and
post-compromise. This investigation characterizes it as synthetic,
vendor-generated data. Initial-access traffic is not included.

The capture is analyzed without supplementary scenario hints or an
answer key. No public ground truth is available.

## Analysis objectives
- Identify hosts, network roles, and communication relationships.
- Review protocol hierarchy and conversation statistics.
- Build a timeline of relevant network activity.
- Examine DNS query volume, response codes, query types, and name patterns.
- Examine HTTP metadata and TLS SNI where available.
- Review SNI, destination, and connection context together.
- Examine SMB session metadata only; do not extract file content.
- Review NTP activity and timing.
- Identify evidence-supported investigation hypotheses.
- Compare applicable DNS and network patterns with the Part A baseline.

Part A was captured in a different lab environment using a DNS64/NAT64
resolver. It is only a partial comparison. Query types and response
characteristics may be compared cautiously; direct timing comparisons
and environment-specific behavior are not treated as equivalent.

## Time and tools
- Report timestamps in UTC.
- Use tshark's UTC display option `-t ud`.
- Record capture first/last packet timestamps and duration.
- Record tshark and capinfos versions.
- Document commands and relevant output in the analysis notes.

## Blind-analysis rules
- Do not consult machine-readable scenario metadata or supplemental
  answers before recording initial findings.
- Use only the PCAP and the limited publisher context documented in
  evidence/part-b/README.md.
- No ground-truth comparison is planned.
- Conclusions are hypotheses with confidence levels and limitations.
- ATT&CK references, if used, are candidate techniques tied to
  specific evidence, not confirmed attribution.

## Handling
- Original PCAP remains outside the Git repository.
- Verify the published and locally calculated SHA-256 values.
- Do not execute extracted files, visit URLs, or export payloads.
- SMB review is metadata-only.
- Publish only derived analysis, defanged indicators, and documentation.
