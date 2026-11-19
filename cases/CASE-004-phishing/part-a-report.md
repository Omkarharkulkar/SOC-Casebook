# CASE-004 Part A — Google Security Alert Investigation

## Scenario

A Google Account security notification reported that Microsoft apps and services had been granted access to some Google Account data.

The investigation assessed whether the notification was authentic and whether the reported authorization was recognized.

## Evidence

- E-004-A-01: Original Google security alert (retained privately).
- E-004-A-02: Sanitized email derivative included in this repository.
- Original email SHA-256: `3a8c614c597672a40f17f7c64f7849f88fbe01261fc8b50c13ab297075983ddb`
- Sanitized email SHA-256: `fffb1e5b7834d8aff0cd92348354dc7d4906657259afa8dca9a87e52fb1b8868`

The original was retained outside the repository. Only the sanitized derivative is published.

## Investigation method

The original email was reviewed offline using its headers, provider authentication results, routing information, MIME structure, message content and URL references.

No links were visited, remote images loaded, attachments executed or reputation lookups performed.

The original message was accessed through Gmail's message details / Show original view. The exact local export timestamp was not recorded. The message Date header was 19 November 2026, 05:58:50 UTC.

## Stage 1 — Email-only assessment

The following authentication results were reported by the receiving Gmail infrastructure:

- SPF: PASS
- DKIM: PASS, domain `accounts.google.com`
- DMARC: PASS, policy `p=REJECT`

The DKIM domain aligned with the From domain. The reported sending infrastructure and receiving timestamps were consistent with Google mail delivery.

The From address was `no-reply@accounts.google.com`. The Return-Path used `gaia.bounces.google.com`, and the Message-ID used `notifications.google.com`.

The message contained no attachment, alternate Reply-To address, payment request or credential-entry form.

The visible link hosts were `accounts.google.com` and `myaccount.google.com`. The original nested `continue=` destinations were also checked before sanitization and pointed to Google account domains. The sanitized derivative does not retain the original URL paths or parameters.

**Stage 1 conclusion:** High confidence that this was an authentic Google security notification. The email alone could not establish whether the reported authorization was legitimate.

## Stage 2 — Retrospective account review

After the email-only assessment, the user directly reviewed Google Account settings, including third-party app connections and recent security activity.

The user recognized the Microsoft apps and services authorization as an activity they had legitimately approved.

The exact review timestamp and displayed authorization date were not recorded in the available investigation notes. No redacted screenshot was retained.

This is user confirmation, not independent forensic verification of the account event.

**Stage 2 conclusion:** The reported authorization was recognized by the account holder. No evidence of unauthorized access was identified during this review.

## Final assessment

- Email authenticity: Authentic Google notification — High confidence.
- Underlying authorization: Recognized by the user.
- Severity: Informational.
- Escalation: Not required based on the available evidence.

## What would make this malicious?

The assessment would change if evidence showed any of the following:

- SPF, DKIM or DMARC failures, or misalignment with the claimed sender.
- A lookalike sender domain.
- An unexpected external Reply-To address.
- Links leading to non-Google or deceptive destinations.
- An unexpected attachment.
- An account authorization the user did not recognize.
- Account activity inconsistent with the user's normal activity.

A passing authentication result alone does not prove that an account action was authorized.

## Limitations

This investigation examined one email and the account holder's subsequent recognition of the reported authorization.

The sanitized derivative has been modified and reserialized; its DKIM signature cannot be independently verified. No independent account audit, provider-side access log or forensic screenshot was available.

The absence of identified unauthorized activity in this review does not prove that the account was never compromised.
