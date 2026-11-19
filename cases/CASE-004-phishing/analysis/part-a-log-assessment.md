# CASE-004 — Part A: Legitimate Security Notification Baseline

**Evidence:** E-004-A-01 (private original), E-004-A-02 (sanitized derivative)  
**Assessment stage:** Email-only; account ground truth pending

## Scope and method

Reviewed the original email's headers, provider-added authentication results, Received timestamps, MIME structure, decoded text and HTML, and URL/remote-image references. No links were visited and remote content was not loaded. The public sanitized copy was altered and cannot be independently DKIM-verified.

## Header analysis

| Header | Observation | Assessment |
|---|---|---|
| From | Google <no-reply@accounts.google.com> | Consistent with Google security notifications |
| To | Redacted | Personal recipient address withheld |
| Reply-To | Absent | No alternate reply destination |
| Return-Path | gaia.bounces.google.com | Google-associated bounce domain |
| Sender | Absent | No separate Sender header |
| Message-ID | Redacted; notifications.google.com | Google-associated domain |
| Date | 19 Nov 2026, 05:58:50 UTC | Consistent with receiving timestamp |
| Subject | Security alert | Consistent with security notification |

The From, Return-Path and Message-ID use different Google subdomains. This is not inherently suspicious; notification systems may use separate domains for message identity, bounce processing and notifications.

## Authentication

Receiving-provider Authentication-Results reported:

- SPF: PASS — client IP 209.85.220.73
- DKIM: PASS — d=accounts.google.com, selector 20260707
- DMARC: PASS — policy p=REJECT

The DKIM domain matches the From domain, providing DMARC alignment. The receiving provider's Authentication-Results is relied upon; sender-supplied authentication results are not trusted. No independent DKIM verification was performed.

## Routing and timing

The sending host was reported as mail-sor-f73.google.com (209.85.220.73), with Gmail receiving infrastructure identified as mx.google.com.

The Date header is 05:58:50 UTC. The receiving timestamp is 21:58:51 PST, equivalent to 05:58:51 UTC on 19 November. The difference is approximately one second and consistent with delivery.

The receiving-provider-added hop is the most reliable. Earlier Received entries can generally be forged.

## Content and links

The email reports that Microsoft apps and services were granted access to Google Account data. It warns that someone else may be attempting access if the recipient did not authorize it. Such language can occur in both legitimate alerts and phishing.

No payment request, attachment, credential-entry form within the email, deadline, or alternate Reply-To was observed.

Static link hosts observed: accounts.google.com and myaccount.google.com.

Remote image hosts observed: www.gstatic.com and lh3.googleusercontent.com.

The destinations appeared to remain within Google account domains. No links were visited and remote images were not loaded. Unique URL parameters were removed from the sanitized copy.

## Log-based assessment

**Email authenticity:** Authentic Google security notification — high confidence, based on provider SPF, DKIM and DMARC results, DKIM/From alignment, and consistent routing/timing.

**Underlying event:** Unverified. The email reports a Microsoft-app access grant but cannot establish whether the recipient authorized it.

**Severity:** Informational for the email itself.

**Escalation:** None based on email evidence alone. If the access grant is unrecognized, treat it as possible unauthorized account access and escalate for account-security review.

## Limitations

One email and one receiving provider were examined. The sanitized copy cannot be independently DKIM-verified. No links or remote content were accessed, no reputation lookup was performed, and account activity has not yet been reviewed. Ground-truth confirmation is pending.

## Retrospective Ground-Truth Verification

After the email-only assessment, the user reviewed Google Account security
settings directly and recognized the Microsoft apps/services authorization
as a legitimate activity.

This retrospective confirmation supports the legitimacy of the underlying
event. It is based on user recognition and is not independent forensic
verification.

**Final assessment:** Authentic Google security notification concerning
a recognized authorization event. No evidence of unauthorized access was
identified during this review.

**Final severity:** Informational.
**Escalation:** Not required based on the available evidence.
