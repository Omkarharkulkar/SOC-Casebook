# CASE-004 — Phishing Email Investigation

**Status:** In Progress  
**Focus:** Email authenticity, security notification analysis, and phishing triage  
**Severity:** Informational for Part A

## Objective

Investigate a security notification received by an account holder. Assess whether the email is authentic and whether the reported account activity was recognized.

## Investigation

### Part A — Legitimate Security Notification

Analyze a Google Account security alert using its email headers, authentication results, sender infrastructure, URLs, and message content.

The investigation has two stages:

1. **Email-only assessment:** Assess the notification's authenticity without assuming the underlying account activity was legitimate.
2. **Account activity review:** Record the user's subsequent confirmation that the Microsoft apps and services authorization was recognized.

The user's confirmation is not independent forensic verification.

**Part A result:** The available email evidence strongly supports an authentic Google notification. The user recognized the reported authorization. No evidence of unauthorized access was identified during this review.

See `part-a-report.md` and `analysis/part-a-log-assessment.md`.

### Part B — Suspicious Email Investigation

Pending. This part will investigate a suspicious email and compare its indicators and characteristics with the legitimate baseline established in Part A.

## Evidence Handling

The original email is retained outside the repository. Only the sanitized derivative is included in the evidence directory.

See `evidence/README-part-a.md` for sanitization and integrity details.

## Scope and Limitations

This case assesses the available email evidence and the user's account-activity confirmation. It does not establish that the account was independently forensically examined or that every possible account compromise scenario was ruled out.
