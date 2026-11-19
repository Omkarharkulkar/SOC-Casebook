# Phishing Email Triage — Quick Playbook

## 1. Preserve
- Preserve the original email and relevant metadata.
- Record the source, collection time and file hash.
- Avoid modifying the original evidence.

## 2. Review sender details
- Compare From, Reply-To and Return-Path.
- Review the Received chain cautiously; untrusted headers may be forged.
- Use authentication results only from a trusted receiving mail system.

## 3. Review message content
- Identify urgency, account-security lures, payment requests or credential requests.
- Review text without loading remote content.
- Defang URLs before including them in reports.

## 4. Attachments
- Record whether attachments exist and their metadata.
- Do not open or execute suspicious attachments during initial triage.

## 5. Assess
- Record observations separately from assumptions.
- Assign verdict, severity and confidence separately.
- Document limitations and unresolved questions.

## 6. Escalation
For a real suspicious message, follow the organization's incident process. Preserve evidence, identify potentially affected recipients, and escalate for appropriate containment and account-protection actions.

## 7. Document
Record source, tools, collection method, findings, limitations, decisions and hashes.
