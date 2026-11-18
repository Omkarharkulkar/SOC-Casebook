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

## Analysis

- [Findings and assessment](analysis/findings.md)
- [Event summary](analysis/event-summary.csv)
- [Review timeline](analysis/review-timeline.csv)
- [Analysis script](analysis/analyze_public_dataset.py)

## Reproduction

From the repository root:

    python3 supplementary/SUPP-001-synthetic-windows-events/analysis/analyze_public_dataset.py

## Assessment

The dataset contains events that warrant further review, including audit-log-clearing events, service installations, and group-membership changes. The available records do not establish whether these actions were unauthorized or malicious.

This is a training-data investigation, not evidence of activity on a real organizational network.

## Limitations

## Source and licence

- Publisher: Database Sample
- Dataset: Windows Security, System and AD Event Log Test Set
- Version: 1
- Source: https://databasesample.com/datasets/windows-security-system-and-ad-event-log-test-set
- Licence: CC0 1.0 Public Domain, as stated on the publisher's dataset page.
- Dataset contents are generated synthetic records, not collected from a live domain.

The six CSV files are retained with their original source checksums in `evidence/SOURCE-SHA256SUMS`.
- The analysis is based on the supplied event records and does not establish authorization or intent.
- Additional account, endpoint, service, and surrounding-event context would be needed for stronger conclusions.
