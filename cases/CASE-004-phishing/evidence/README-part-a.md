# CASE-004 Part A Evidence Notes

## Provenance
- Source: User's Gmail mailbox, original email export.
- Collection date: 19 November 2026.
- Evidence E-004-A-01: Raw original, private and not to be committed.
- Evidence E-004-A-02: Sanitized derivative, intended for public evidence.
- Selected as a real security notification baseline for comparison with suspicious email evidence.

## SHA-256
Raw original:
3a8c614c597672a40f17f7c64f7849f88fbe01261fc8b50c13ab297075983ddb

Sanitized derivative:
4cb90e0244c913d377f11603f664f8891b557a488542ed29dbabe2520aa5e896

## Redactions and transformations
1. Recipient address removed from recipient headers.
2. Email addresses in decoded content redacted.
3. Message-ID redacted.
4. URL query strings and fragments removed.
5. URL schemes and host dots defanged.
6. MIME content re-serialized during sanitization.
7. Original remains unchanged.

The sanitized copy cannot be independently DKIM-verified.

## Authentication results
- SPF: PASS — 209.85.220.73
- DKIM: PASS — accounts.google.com
- Selector: 20260707
- DMARC: PASS — p=REJECT
- DKIM domain aligns with From domain.

## Routing and timing
Sending host reported: mail-sor-f73.google.com (209.85.220.73)
Receiving infrastructure: mx.google.com
Date: 05:58:50 UTC
Receiving timestamp: 21:58:51 PST / 05:58:51 UTC
Approximately one second elapsed.

## Static content review
Link hosts: accounts.google.com, myaccount.google.com
Remote image hosts: www.gstatic.com, lh3.googleusercontent.com
Links were not visited. Remote content was not loaded.

## Ground truth
Pending. Email authenticity does not prove the access event was authorized.

## Retrospective Verification

The user recognized the Microsoft apps/services authorization as legitimate
after reviewing their Google Account security settings directly.

This is user confirmation, not independent forensic verification.
The email was assessed separately before this confirmation.

Final assessment: Authentic notification of a recognized event.
Severity: Informational.
