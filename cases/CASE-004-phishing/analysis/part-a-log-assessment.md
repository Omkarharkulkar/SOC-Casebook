# CASE-004 — Part A: Stage 1 Technical Working Notes

**Purpose:** Supporting technical notes for the email-only assessment.
**Canonical report:** `../part-a-report.md`
**Evidence:** E-004-A-01 (private original), E-004-A-02 (sanitized derivative)

## Examination method

The original email was reviewed offline using Gmail's message details / Show original view and local analysis.

Reviewed:
- Sender and routing headers
- Provider-added SPF, DKIM and DMARC results
- Message and receiving timestamps
- MIME structure and decoded content
- Link destinations and remote-image references

No links were visited, remote content loaded, attachments executed or reputation lookups performed.

## Header and authentication observations

- From: `no-reply@accounts.google.com`
- Return-Path domain: `gaia.bounces.google.com`
- Message-ID domain: `notifications.google.com`
- Reply-To: Absent
- SPF: PASS — client IP `209.85.220.73`
- DKIM: PASS — `d=accounts.google.com`, selector `20260707`
- DMARC: PASS — policy `p=REJECT`
- Sending host: `mail-sor-f73.google.com`
- Receiving host: `mx.google.com`
- Date header: 19 November 2026, 05:58:50 UTC
- Receiving timestamp: Approximately 05:58:51 UTC

The DKIM signing domain aligns with the From domain. Authentication results were taken from the receiving provider; independent DKIM verification was not performed.

## Content and destination observations

The message reported that Microsoft apps and services had been allowed access to Google Account data.

Observed link hosts:
- `accounts.google.com`
- `myaccount.google.com`

Observed remote-image hosts:
- `www.gstatic.com`
- `lh3.googleusercontent.com`

Original nested `continue=` destinations were checked before sanitization and pointed to Google account domains. URL paths, query parameters and unique identifiers were removed from the published derivative.

## Technical limitations

- The exact local export timestamp was not recorded.
- Earlier Received headers may be forged; the receiving-provider-added hop is the strongest routing evidence.
- The sanitized derivative was modified and reserialized, so its DKIM signature cannot be independently verified.
- No links or remote images were accessed.

## Assessment reference

The Stage 1 authenticity assessment and final case conclusions are documented in `../part-a-report.md`. Account-holder recognition is retrospective user-provided context, not independent forensic verification.
