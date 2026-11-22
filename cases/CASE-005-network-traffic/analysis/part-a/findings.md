# Part A Findings — Controlled Network Baseline

## Summary
The scripted baseline completed successfully. Four domain lookups returned DNS responses, and the HTTPS request to example.com returned HTTP 200.

## DNS
A and AAAA responses were observed for all four queried domains. No NXDOMAIN responses appeared in the captured DNS exchanges. Response times are listed in dns-observations.csv. The Debian AAAA response took approximately 1.447 seconds, longer than the other recorded responses. This is a single observation and is not sufficient to diagnose a resolver issue.

## HTTPS
A TCP connection to an address returned for example.com was observed, including the TCP handshake and bidirectional data exchange. The activity log records HTTP status 200 and the content type. HTTPS payloads were not inspected.

## Scope limitation
The capture contains unrelated background HTTPS traffic. It is not included in the controlled-activity findings. The capture was brief and cannot establish that all traffic or host activity was benign.

## Assessment
**Baseline result: expected controlled activity observed; no suspicious activity identified within the scripted DNS and HTTPS actions.** This is a limited baseline observation, not a host-wide security assessment.
