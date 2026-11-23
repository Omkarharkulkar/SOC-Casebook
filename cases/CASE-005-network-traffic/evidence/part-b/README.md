# Part B Evidence — NM-SAMPLE-002

## Source

- Dataset: NM-SAMPLE-002 — Multi-Behavior Scenario
- Publisher: NetMetria / Metria Data Systems, LLC
- Source page: https://netmetria.com/samples
- Direct download: https://netmetria.com/assets/samples/netmetria-multi-behavior-scenario.pcap
- Acquisition date: 2026-11-23
- Acquisition timestamp (local file timestamp): 2026-11-23 11:08:13 IST (IST)

## Acquisition details

- Local filename: `netmetria-multi-behavior-scenario.pcap`
- Local file size: 637,505 bytes (622.56 KiB)
- Packet count: 4,134
- Capture duration: 1,678.992 seconds (27m 58.992s)
- SHA-256: `ec77f256e309ec7e9eda8dcd3c422b5524119c50d23a7485772838269a0c4d89`
- Verification against publisher checksum file: **PASS**

The local SHA-256 matches the hash currently listed in the publisher's
checksum file:

`ec77f256e309ec7e9eda8dcd3c422b5524119c50d23a7485772838269a0c4d89`

The dataset webpage also displays a different SHA-256:

`e5830a9672261b799cf1a6a259ae6078e976c6e5de06e898f0049a8b7b46db96`

The discrepancy is documented and has not been independently resolved.
Verification was performed against the publisher's checksum file.

## Evidence handling

- Original PCAP retained locally outside the repository.
- Raw PCAP is excluded from Git.
- Offline analysis in the Ubuntu VM.
- No extracted payloads published.
- No extracted files executed.
- No traffic URLs visited.
- SMB analysis limited to metadata.
- Derived observations are documented separately.

## Terms and attribution

The publisher describes the dataset as intended for technical evaluation,
defensive-security research, detection engineering, training, and testing.

The dataset is attributed to its publisher. The original PCAP is not
redistributed in this repository.

Terms reviewed: 2026-11-23.

This is a summary of the publisher's stated terms, not legal advice or
written permission.

## Dataset limitations

- Synthetic dataset.
- Publisher describes it as a post-compromise scenario.
- Initial access is excluded.
- No public ground-truth answer key was identified.
- Findings are analyst observations and hypotheses, not confirmed
  incident conclusions.
