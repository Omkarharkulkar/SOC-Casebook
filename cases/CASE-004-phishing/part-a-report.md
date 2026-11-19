# CASE-004 Part A — Benign Email Control

## Scenario
A routine newsletter-style email is used as a benign control for phishing triage.

## Evidence
`evidence/benign-control.eml` is a synthetic email authored for this case. It was created locally; no email was sent or received. Routing and authentication fields are simulated.

## Analysis method
The raw `.eml` was parsed offline using Python's standard-library `email` parser. Header fields and the plain-text body were reviewed. The email was not opened in a mail client; no links were visited, remote content loaded, attachments executed, or reputation lookups performed.

Reproduce the parsing with:
`python3 analysis/parse_control.py`

## Observations
- From: `news@example.com`; display name is Example Newsletter.
- To: `reader@example.net`; fictional recipient.
- Reply-To: `news@example.com`; matches the From domain.
- Return-Path: `bounce@example.com`; uses the same domain.
- Subject: `November Community Newsletter`; routine informational subject.
- Message-ID: synthetic identifier; not independently verifiable.
- Received: illustrative route using reserved example names and documentation IP `192.0.2.20`; not an actual delivery path.
- SPF, DKIM and DMARC are represented as pass, but simulated and not server-verified.
- Body contains general announcements and no obvious urgent threat, payment demand, or credential request.
- One preference URL is defanged and uses a reserved example domain. It was not visited.
- No attachments were present; parser reported zero attachment filenames.

## Assessment
**Classification:** Benign characteristics observed in a synthetic training email.  
**Severity:** Informational (control sample).  
**Confidence:** High that the constructed sample contains the documented characteristics. This is not a real-world sender or email safety verdict.

## Limitations
The email is synthetic and has no actual mail-server delivery history. Authentication, routing and timestamps are illustrative. This exercise does not verify a real sender or domain.

## Phishing-triage relevance
The control provides comparison points for sender consistency, header structure, routine content, link presentation, and absence of attachments. These characteristics are not proof of legitimacy in real email; phishing messages may also have aligned headers and passing authentication.
