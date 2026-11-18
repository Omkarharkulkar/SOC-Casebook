# SUPP-001 — Synthetic Windows Event Dataset Review

## Overview

This supplementary investigation reviews a synthetic Windows event-log dataset for defensive security analysis and SOC L1 practice.

It is separate from CASE-003, which focuses on controlled administrative activity collected from the local Windows lab.

## Dataset

The supplied dataset contains:

- 443 host events
- 180 directory events
- 623 total event records

The analysis selects events relevant to administrative activity, process creation, account events, and other security-relevant activity.

The review timeline is enriched with account type, department and operating-system context from the supplied lookup tables where available. Account names and email addresses are not included in the analysis output.

## Analysis

- [Findings and assessment](analysis/findings.md)
- [Event summary](analysis/event-summary.csv)
- [Review timeline](analysis/review-timeline.csv)
- [Analysis script](analysis/analyze_public_dataset.py)

## Reproduction

From the repository root:

```bash
python3 supplementary/SUPP-001-synthetic-windows-events/analysis/analyze_public_dataset.py
```

The script reads the host-event, directory-event, account and computer CSVs. It regenerates the event summary and selected review timeline, including account and operating-system context where available.

Verify all six original source files from the evidence directory:

```bash
cd supplementary/SUPP-001-synthetic-windows-events/evidence
sha256sum -c SOURCE-SHA256SUMS
```

## Assessment

The dataset contains events that warrant further review, including audit-log-clearing events, service installations, and group-membership changes. The available records do not establish whether these actions were unauthorized or malicious.

The enriched timeline provides additional account and endpoint context, but this does not independently establish authorization or intent.

This is a training-data investigation, not evidence of activity on a real organizational network.

## Source and licence

- Publisher: Database Sample
- Dataset: Windows Security, System and AD Event Log Test Set
- Version: 1
- Source: https://databasesample.com/datasets/windows-security-system-and-ad-event-log-test-set
- Licence: CC0 1.0 Public Domain, as stated on the publisher's dataset page.
- Dataset contents are generated synthetic records, not collected from a live domain.

The six CSV files are retained with their original source checksums in `evidence/SOURCE-SHA256SUMS`.

## Limitations

- The analysis is based on the supplied event records and does not establish authorization or intent.
- Additional account, endpoint, service, and surrounding-event context would be needed for stronger conclusions.
- Account and computer enrichment depends on the lookup tables supplied with this synthetic dataset; it does not independently verify real-world identities or endpoint ownership.
