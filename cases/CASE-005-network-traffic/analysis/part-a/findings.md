# CASE-005 Part A — Baseline Findings

## Scope
Controlled DNS resolution activity performed on the Ubuntu VM
omkarvm. Capture interface: enp0s3 (VirtualBox NAT).

## Observations
- Four DNS lookups were requested by the activity script.
- The capture contains two complete DNS query/response pairs.
- Queries observed: ubuntu.com and github.com.
- DNS used UDP port 53.
- Both queries received successful A-record responses.
- Observed response times were approximately 243 ms and 44 ms.
- Four packets were captured; zero packets were reported dropped.

## Assessment
The captured activity is consistent with ordinary DNS resolution
during a controlled baseline exercise. No suspicious activity was
identified in this limited DNS capture.

## Limitations
- Only DNS traffic was captured.
- The activity script requested four lookups, but only two query/
  response pairs were observed.
- DNS caching or resolver behavior may explain the missing queries.
- This capture does not establish a complete picture of network
  activity or prove the system is free from suspicious activity.
- Private VM and DNS resolver addresses are omitted from published
  derived evidence.

## Evidence
- evidence/part-a/baseline.pcap
- evidence/part-a/baseline-activity.sh
- evidence/part-a/baseline-activity.txt
- analysis/part-a/dns-observations.csv

## Supplementary TCP/443 Observation

A 20-second background capture recorded 32 TCP packets involving
two external IP addresses on port 443.

The packets show bidirectional data exchange and TCP acknowledgments.
The capture was not tied to a controlled application activity.

This is supplementary observation only. The encrypted traffic's
application and content were not established. The raw capture is
retained locally and excluded from public evidence due to privacy
considerations.

SHA-256:
c8585a3c58eddd01b845762635d9e89167280745703361fcdcac3714e1413cd3

## Local Capture Integrity

DNS PCAP SHA-256:
59704f9a9c704d774aea77b303fe2992f2da392c5f4942365cc2073609dc0c3b

Supplementary TCP PCAP SHA-256:
c8585a3c58eddd01b845762635d9e89167280745703361fcdcac3714e1413cd3
