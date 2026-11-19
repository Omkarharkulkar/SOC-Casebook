# CASE-004 — Part B: Suspicious Email Review

## Summary

A synthetic email was reviewed for phishing indicators. It uses an account-security theme and requests that the recipient review account access through a link.

## Observations

- The From domain is `account-alert.example`.
- The Reply-To domain is `different.example`, which differs from the From domain.
- The Return-Path uses `account-alert.example`.
- SPF, DKIM and DMARC are shown as failures in the sample. These results are simulated and cannot establish real authentication failures.
- The message requests an account-access review.
- The URL is defanged and uses fictional example-domain infrastructure.
- No attachment is present.

## Assessment

The sample contains suspicious characteristics, including a Reply-To mismatch, account-access themed request and simulated authentication failures.

**Verdict:** Suspicious characteristics observed — training scenario only.

**Severity:** Medium (scenario assessment).

**Confidence:** High that the synthetic sample contains the documented characteristics; no confidence assessment of a real sender or campaign is possible.

## Limitations

This is a synthetic training email. Sender identities, route, authentication results, content and URL are fictional. No real message source, recipient exposure, delivery, click activity, infrastructure or compromise was established. No external URL was visited and no attachment was opened.

## Conclusion

This exercise demonstrates basic phishing-email triage and indicator documentation. It is not evidence of an actual phishing incident.
