# CASE-004 — Part A: Legitimate Security Notification Baseline

**Evidence:** E-004-A-01 (private original), E-004-A-02 (sanitized derivative)  
**Assessment:** Completed

## Scope and method

The original email was reviewed offline. Analysis covered provider-added authentication results, sender and routing headers, timestamps, MIME structure, decoded content, links and remote-image references.

No links were visited, remote content loaded, attachments executed or reputation lookups performed.

The original message was accessed through Gmail's message details / Show original view. The exact local export timestamp was not recorded.

## Stage 1 — Email-only assessment

### Header analysis

| Header | Observation | Assessment |
|---|---|---|
| From | Google <no-reply@accounts.google.com> | Consistent with Google security notifications |
| To | Redacted | Recipient privacy protected |
| Reply-To | Absent | No alternate reply destination |
| Return-Path | gaia.bounces.google.com | Google-associated bounce domain |
| Sender | Absent | No separate Sender header |
| Message-ID | notifications.google.com domain | Consistent with Google notification infrastructure |
| Date | 19 Nov 2026, 05:58:50 UTC | Consistent with receiving timestamp |
| Subject | Security alert | Consistent with security notification |

The different Google subdomains used for the From, Return-Path and Message-ID fields are not inherently suspicious.

### Authentication

The receiving provider's Authentication-Results reported:

- SPF: PASS — client IP 209.85.220.73
- DKIM: PASS — d=accounts.google.com, selector 20260707
- DMARC: PASS — policy p=REJECT

The DKIM domain aligns with the From domain.

The receiving provider's authentication results were relied upon. No independent DKIM verification was performed.

### Routing and timing

The reported sending host was mail-sor-f73.google.com (209.85.220.73). Gmail receiving infrastructure was identified as mx.google.com.

The Date header was 05:58:50 UTC. The receiving timestamp was approximately 05:58:51 UTC on 19 November 2026.

The receiving-provider-added hop is the most reliable routing evidence. Earlier Received entries can be forged.

### Content and links

The email reported that Microsoft apps and services had been allowed access to Google Account data.

No payment request, attachment, credential-entry form, deadline or alternate Reply-To was observed.

Observed link hosts:
- accounts.google.com
- myaccount.google.com

Observed remote-image hosts:
- www.gstatic.com
- lh3.googleusercontent.com

The original nested continue= destinations were checked before sanitization and pointed to Google account domains. URL paths, query parameters and unique identifiers were removed from the published derivative.

No links were visited and remote images were not loaded.

### Stage 1 assessment

**Email authenticity:** Authentic Google security notification — High confidence.

**Underlying event:** Unverified at this stage. The email cannot establish whether the recipient authorized the reported access.

**Severity:** Informational.

**Escalation:** No escalation based on email evidence alone. An unrecognized authorization would require account-security investigation.

## Stage 2 — Retrospective ground-truth review

After completing the email-only assessment, the account holder directly reviewed Google Account settings, including third-party app connections and recent security activity.

The account holder recognized the Microsoft apps and services authorization as legitimate.

The exact review timestamp and displayed authorization date were not recorded in the available notes. A redacted screenshot was not retained.

This confirmation is based on the user's recognition. It is not independent forensic verification or a provider-side audit.

### Final assessment

**Email:** Authentic Google security notification — High confidence.

**Authorization:** Recognized by the account holder.

**Severity:** Informational.

**Escalation:** Not required based on the available evidence.

## What would change the assessment?

The following findings would require reassessment:

- Failed or misaligned SPF, DKIM or DMARC.
- A lookalike sender domain.
- An unexpected external Reply-To address.
- A non-Google or deceptive link destination.
- An unexpected attachment.
- An authorization the account holder did not recognize.
- Account activity inconsistent with the account holder's activity.

Passing email authentication does not independently prove that the underlying account action was authorized.

## Limitations

One original email and one receiving provider were examined. The published derivative was modified and reserialized, so its DKIM signature cannot be independently verified.

No independent account audit, provider-side access logs or redacted screenshot were available. The user's confirmation is retrospective and should not be represented as independent forensic evidence.
