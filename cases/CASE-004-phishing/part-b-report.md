# CASE-004 Part B — Phishing Email Investigation

## Case Summary

| Field | Assessment |
|---|---|
| Case | CASE-004 |
| Trigger | Analyst-initiated public sample triage |
| Severity | Medium (potential production impact) |
| Verdict | Phishing attempt — government/traffic authority impersonation |
| Confidence | High |
| Victim impact | No impact established |
| Escalation | Would warrant investigation in a production environment |

The severity is assessed as if the email reached a production user. The analyzed sample came from a honeypot dataset; no real victim interaction or compromise was established.

## 1. Source and Evidence

The email was selected from the Phishing Pot public dataset.

- Repository: https://github.com/rf-peixoto/phishing_pot
- Dataset commit: `78be141545ed9e56eefb857808ac78e83eb81b81`
- Sample: `email/sample-1000.eml`
- Email date: 21 September 2026, 06:43:52 UTC
- Dataset recipient: `phishing@pot`
- Original SHA-256: `69feb34529b2ea44d90d1b3592935c32e22e968f36829e5f322281641c69450a`

The original sample is retained outside this repository. Analysis was performed offline. No link was visited and no attachment was executed.

### Evidence IDs

| ID | Evidence |
|---|---|
| E-004-B-01 | Original email sample (retained locally, not published) |
| E-004-B-02 | Structured analysis JSON |
| E-004-B-03 | Defanged indicator CSV |
| E-004-B-04 | Offline analyzer script |
| E-004-B-05 | Dataset source and pinned commit |

## 2. Email Summary

The message impersonates a Brazilian traffic authority and claims the recipient has an unresolved traffic violation associated with their driver's licence (CNH).

It claims that suspension proceedings have started and lists consequences including licence suspension, a required course, vehicle-related penalties, and renewal restrictions.

The recipient is urged to regularize the alleged violation before a stated deadline by following an embedded link.

## 3. Sender Analysis

- Display name: `Detran - Aviso Urgente`
- From: `detran@sistemadeinfracao373552`
- Reply-To: Not present
- Return-Path: `detran@sistemadeinfracao373552`

The sender domain is a bare name without a conventional public DNS suffix (TLD). It does not establish a legitimate relationship with the claimed government authority.

The sender uses a domain without a conventional public DNS suffix. SPF, DKIM and DMARC were reported as none in this message. These results do not independently prove maliciousness, but they provide no authentication assurance for the claimed sender.

## 4. Email Authentication

Recorded authentication results:

| Mechanism | Result |
|---|---|
| SPF | None |
| DKIM | None; message unsigned |
| DMARC | None; action none |

DMARC enforcement was not recorded. The message was delivered despite the absence of authentication results.

Authentication alone is not a phishing verdict. The impersonation, deceptive link and threat-based content provide stronger contextual evidence.

## 5. SMTP Routing and Timeline

The recorded Received headers show the message entering Microsoft's mail protection infrastructure and passing through Microsoft mail servers.

| Time (UTC) | Event |
|---|---|
| 06:43:52 | Message date and initial connecting-IP hop recorded |
| 06:43:52 | Received by Microsoft protection infrastructure |
| 06:43:53 | Passed through Microsoft mail server |
| 06:43:55 | Subsequent Microsoft HTTPS transport hop |

Approximately three seconds elapsed between the first recorded hop and the last Received timestamp.

The connecting IP recorded by Microsoft's edge was `45[.]32[.]75[.]31`.

The initial HELO/EHLO value was `[127.0.1.1]`. This is a claimed greeting value, not a verified sending hostname. The observed connecting IP is the stronger network evidence.

The routing headers document delivery through Microsoft's infrastructure. They do not independently establish the sender's identity.

## 6. Social Engineering

The message uses the following pressure tactics:

- Urgent subject line
- Alleged active licence suspension
- Threat of legal and administrative consequences
- Possible vehicle-related penalties
- A deadline for resolution
- A direct link presented as the way to resolve the issue

The email attempts to make the recipient act quickly rather than independently verify the alleged notice.

The Brazil-specific language and government theme, combined with the dataset honeypot recipient, are consistent with broad phishing distribution. Mass-mailing is an inference; campaign targeting was not established.

## 7. Link Analysis

The visible link text is:

`REGULARIZAR SITUAÇÃO DA CNH`

The URL contains user-information text resembling Hotmail. This is not the actual hostname.

Actual hostname (defanged):

`dete1-489991573399[.]southamerica-east1[.]run[.]app`

The hostname uses the `run.app` cloud-hosted service namespace. The hostname itself is not an established official traffic-authority domain.

The URL uses deceptive user-information formatting to make the address appear associated with a familiar service. This is a strong phishing indicator.

The destination was not visited. Its page content, redirects, and functionality remain unverified.

## 8. Passive Enrichment

Lookup date: 20 November 2026.

| Indicator | Result |
|---|---|
| Connecting IP `45[.]32[.]75[.]31` | Exact ASN, registry ownership and PTR not confirmed |
| Exact destination hostname | No exact-match reputation result confirmed |
| Related Cloud Run hostnames | Existing reports describe phishing activity on similar hostnames sharing the numeric identifier and region |
| Attribution | No operator attribution established |

Related infrastructure is context only. Findings for different hostnames are not transferred to the exact indicator.

No new scans were submitted and the URL was not visited.

A missing reputation record is treated as unknown, not clean.

## 9. Indicators

Indicators are documented in `part-b-indicators.csv` in defanged form.

The sender, connecting IP and destination hostname are retained as observable indicators. They should be evaluated in context and are not independently proof of compromise.

## 10. Impact Assessment

- No victim interaction was established.
- No credential submission was established.
- No account compromise was established.
- No attachment delivery was identified.
- No successful redirect or destination-page behavior was observed.

The sample demonstrates a phishing attempt. Actual impact remains unknown.

## 11. Severity and Escalation

**Severity: Medium**

This rating reflects the potential impact if delivered to a production user, considering the government impersonation, threat-based lure and deceptive link.

In a production SOC, this would warrant escalation for email-hunting and recipient-impact assessment. The honeypot sample itself does not establish an affected user or successful compromise.

## 12. MITRE ATT&CK Mapping

- **T1566 — Phishing (parent technique)**
- **T1566.002 — Spearphishing Link (closest link-based sub-technique)**

The link-based delivery behavior is consistent with T1566.002. However, targeting of a specific individual, organization or industry was not established; the sub-technique mapping is therefore contextual rather than a claim of confirmed spearphishing targeting.

Mapping reference: MITRE ATT&CK, version 20.

## 13. Recommended L1 Response

If this email appeared in a production environment:

1. Search mailboxes for the sender, subject and destination hostname.
2. Identify recipients and determine whether anyone interacted with the link.
3. Block or quarantine matching messages and relevant indicators according to organizational policy.
4. Search DNS and proxy logs for destination access.
5. Review browser and endpoint telemetry for affected recipients.
6. Escalate any confirmed credential submission or suspicious activity for incident response.
7. Report the hosting abuse using the appropriate provider channel, with preserved evidence.

## 14. Detection Improvements

Possible defensive detections include:

- Alert on messages claiming government or traffic authority identity while using an unrelated sender domain.
- Flag urgent legal, licence or payment threats paired with external links.
- Detect URL user-information formatting that disguises the actual hostname.
- Identify links to newly observed or unusual cloud-hosted hostnames.
- Correlate email sender, URL and DNS/proxy activity.

These are suggested detection opportunities, not tested production rules.

## 15. What Would Change the Verdict?

The phishing assessment would be strengthened by independently confirming malicious destination behavior, credential harvesting, or matching reports for the exact hostname.

The assessment would be weakened if independently verified evidence established that the message and destination were authorized communications from the claimed authority.

## 16. Limitations

- The destination was not visited.
- No independent exact-hostname reputation match was confirmed.
- IP ownership, ASN and reverse DNS were not confirmed.
- No campaign attribution was established.
- No recipient interaction or compromise was established.
- The dataset is not statistically representative of all phishing emails.

## 17. Conclusion

The message impersonates a Brazilian traffic authority and uses a fabricated traffic violation, licence suspension threats, urgency and a deceptive URL to encourage interaction.

The combined evidence supports a high-confidence phishing classification.

No evidence was collected to establish successful compromise.
