# Part A Findings — Controlled Network Baseline

## Summary
The scripted baseline completed successfully. Four domain lookups returned DNS responses, and the HTTPS request to example.com returned HTTP 200. Packet inspection also identified the TLS ClientHello SNI as `example.com`, matching the scripted request.

## DNS observations
A and AAAA responses were observed for all four queried domains (eight queries and eight corresponding responses). No NXDOMAIN responses or repeated query IDs were observed in the displayed query list. No TXT or NULL queries were part of the scripted activity. Response times are listed in `dns-observations.csv` (IST): seven responses were approximately 54–165 ms; the Debian AAAA response took approximately 1.447 seconds. This is a single observation and is not sufficient to diagnose a resolver issue. No periodic pattern was present in this short scripted sequence; this is not a host-wide conclusion.

The GitHub AAAA response was `64:ff9b::87eb:9590`, within the NAT64 prefix `64:ff9b::/96`, consistent with DNS64 synthesis in this environment. This is an unusual-looking but expected result in a DNS64/NAT64 setup.

## HTTPS
A TCP connection to an address returned for example.com was observed, including the TCP handshake and bidirectional data exchange. The TLS ClientHello SNI was `example.com`. The activity log records HTTP status 200 and the content type. HTTPS payloads were not inspected.

## Baseline profile for Part B comparison
- DNS activity: A and AAAA queries for four scripted domains; eight queries/responses observed.
- Response timing: approximately 54–165 ms for seven responses, with one Debian AAAA response at approximately 1.447 seconds.
- Negative responses: no NXDOMAIN observed.
- Query types: no TXT or NULL queries in the controlled sequence.
- Repetition: no repeated query IDs or periodic domain-query pattern in this short scripted sequence.
- HTTPS: scripted connection to example.com with matching SNI and HTTP 200.
- Addressing: GitHub AAAA answer was consistent with DNS64 synthesis under the NAT64 prefix.

For Part B, compare DNS query volume, NXDOMAIN rate, unusual query types, unusually long or random-looking names, repeated/periodic queries, unexpected ports, and TLS SNI versus destination/context. These are comparison criteria, not assumptions that such activity is malicious.

## Scope limitation
The capture contains unrelated background HTTPS traffic. It is not included in the controlled-activity findings. The capture was brief and cannot establish that all traffic or host activity was benign.

## Assessment
**Baseline result: expected controlled activity observed; no suspicious activity identified within the scripted DNS and HTTPS actions.** This is a limited baseline observation, not a host-wide security assessment.
