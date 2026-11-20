# CASE-004 Part B — Phishing Email Investigation

## Case Overview

**Case:** CASE-004  
**Investigation:** Public phishing email analysis  
**Severity:** Medium  
**Verdict:** Phishing attempt — government/traffic authority impersonation  
**Confidence:** High  
**Analysis method:** Offline email examination

## 1. Source

The email was selected from the Phishing Pot public email dataset.

- Source repository: https://github.com/rf-peixoto/phishing_pot
- Dataset commit: `78be141545ed9e56eefb857808ac78e83eb81b81`
- Sample: `email/sample-1000.eml`
- Email date: 21 September 2026, 06:43:52 UTC
- Dataset recipient: `phishing@pot`

The original sample was retained outside this repository. Analysis was performed on the email content and metadata without visiting the destination or executing any content.

## 2. Email Summary

The email impersonates a Brazilian traffic authority and claims the recipient has an unresolved traffic violation associated with their driver's licence.

It claims that the licence suspension process has started and lists several possible consequences. The recipient is instructed to use a link to regularize the situation before a stated deadline.

## 3. Technical Findings

### Sender

- Display name: Detran - Aviso Urgente
- Sender: `detran@sistemadeinfracao373552`
- Reply-To: Not present
- Return-Path: `detran@sistemadeinfracao373552`

The sender domain does not establish a legitimate connection to the claimed government authority.

### Email Authentication

The recorded authentication results were:

- SPF: None
- DKIM: None
- DMARC: None

The message's authentication results do not establish sender legitimacy.

### Sending Infrastructure

- Source IP: `45[.]32[.]75[.]31`
- Initial sending host: `[127.0.1.1]`
- Receiving infrastructure: Microsoft Outlook protection and mail servers

The email was received through Microsoft's mail infrastructure. This does not establish that the original sender was legitimate.

### Social Engineering

The email uses several pressure tactics:

- Urgent subject line
- Alleged active licence suspension
- Threat of vehicle-related consequences
- Legal and administrative consequences
- Short deadline for regularization
- Request to follow a link to resolve the issue

These elements encourage the recipient to act without independently checking the notice.

### Link Analysis

The message contains a link whose hostname is:

`dete1-489991573399.southamerica-east1.run.app`

The URL includes text resembling Hotmail within its address, but this text is not the actual hostname.

The destination uses a cloud-hosted `run.app` domain rather than an independently established official traffic authority domain.

The link was not visited. Its actual page content and functionality remain unverified.

### Attachments

No attachments were identified.

## 4. Indicators

The observed indicators are documented in `part-b-indicators.csv`.

The sender, source IP and destination hostname are retained as defanged indicators.

## 5. Assessment

The combination of government-authority impersonation, an unverified sender domain, absent email authentication, threatening language, a deadline and a misleading destination hostname strongly supports a phishing assessment.

**Verdict: Phishing attempt — government/traffic authority impersonation.**

**Confidence: High.**

## 6. Limitations

- The destination was not visited.
- No independent domain reputation lookup was performed.
- No website content was collected.
- No recipient interaction or credential submission was established.
- No compromise or successful account access was established.
- Email authentication results alone cannot prove malicious intent.

## 7. Recommended Defensive Actions

- Do not follow the email link.
- Verify traffic or government notices through independently located official channels.
- Report the message as phishing.
- Block or investigate the sender and destination indicators according to organizational procedures.
- If a recipient interacted with the link, investigate browser activity and account activity.

## 8. Conclusion

This sample demonstrates a phishing email using government impersonation, fear of legal consequences and urgency to encourage interaction with a deceptive link.

The available email evidence supports a high-confidence phishing classification. No evidence was collected to establish successful compromise.
