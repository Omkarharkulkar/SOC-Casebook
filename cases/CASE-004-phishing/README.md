# CASE-004 — Phishing Email Investigation

**Status:** Complete  
**Case type:** Email security / phishing triage  
**Evidence type:** Synthetic training emails

## Objective

Review email characteristics in a phishing-triage context using a benign control and a suspicious training sample. Compare sender information, authentication indicators, content and links while documenting limitations.

## Case Parts

### Part A — Benign Control
A synthetic newsletter-style email was reviewed offline.

Key observations:
- From and Reply-To domains aligned.
- Simulated SPF, DKIM and DMARC results passed.
- Routine informational content.
- One defanged fictional URL.
- No attachments.

Report: `part-a-report.md`

### Part B — Suspicious Sample
A synthetic account-security themed email was reviewed offline.

Key observations:
- From and Reply-To domains differed.
- Simulated SPF, DKIM and DMARC results failed.
- Account-access review request.
- Defanged fictional URL.
- No attachments.

Report: `part-b-report.md`

## Methodology

- Offline text-based review.
- Python standard-library email parser used for Part A.
- Header and body review.
- Indicator documentation.
- No external links visited.
- No remote content loaded.
- No attachments opened or executed.
- No real IOC reputation enrichment performed.

## Verdict

**Training assessment:** Suspicious characteristics demonstrated in Part B.

This case does not establish a real phishing incident. Both emails are synthetic; their identities, routing, authentication results and content are fictional.

## Evidence and Analysis

- `evidence/` — Synthetic email samples and evidence documentation.
- `analysis/` — Header analysis, indicators, parser and checksums.
- `playbooks/phishing-triage.md` — Basic triage reference.

## Limitations

The synthetic samples demonstrate investigation concepts but do not represent real email delivery or threat infrastructure. Authentication and routing fields are illustrative. No real sender, campaign, recipient exposure, compromise or malicious infrastructure was established.
