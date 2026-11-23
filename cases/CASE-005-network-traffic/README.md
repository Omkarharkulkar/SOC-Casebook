# CASE-005 — Network Traffic Investigation: Alert Triage

**Status:** In Progress — final review pending.

- **Part A:** Controlled DNS and HTTPS baseline — finalized.
- **Part B:** Blind investigation of a public synthetic network capture — report drafted; final review pending.

Part B uses a simulated analyst alert prompt. The dataset is
NetMetria-generated post-compromise scenario traffic. Conclusions will
be evidence-supported hypotheses; public ground truth is unavailable.

Original PCAP files are stored outside the repository. Only derived
observations, documentation, and defanged indicators will be published.

## Part B — Investigation Status

- Dataset: NM-SAMPLE-002 — Multi-Behavior Scenario
- Assessment: Suspicious coordinated internal activity observed — further investigation required.
- Priority: Medium (provisional analyst assessment)
- Confidence: Moderate in observed activity pattern; low in malicious intent.
- Confirmed compromise: No.
- Report: `analysis/part-b/incident-report.md`
- Raw PCAP: Retained privately; excluded from Git.
- Integrity: Local SHA-256 verified against publisher checksum file.
- Hash discrepancy between the publisher page and checksum file remains unresolved.

See the consolidated incident report for evidence, methodology, limitations,
and recommendations. Case remains **In Progress** pending final review and commit.
