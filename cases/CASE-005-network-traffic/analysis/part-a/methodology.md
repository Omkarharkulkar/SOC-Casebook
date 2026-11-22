# Part A — Controlled Network Baseline

## Purpose
Record a short, controlled baseline of DNS and HTTPS activity from the Ubuntu lab VM for comparison with later network-traffic investigations.

## Environment and tools
- Ubuntu lab VM
- Capture interface: enp0s3 (NAT)
- tcpdump 4.99.4
- getent and Python standard library urllib
- tshark was not used.

## Procedure
1. Flush the DNS cache using `sudo resolvectl flush-caches`.
2. Start a 30-second capture using:
   `sudo timeout 30s tcpdump -i enp0s3 -s 0 -w evidence/part-a/baseline.pcap 'port 53 or tcp port 443'`
3. Run `evidence/part-a/baseline-activity.sh`, which resolves four domains and makes one HTTPS request to `https://example.com/`.
4. Inspect packets with `tcpdump -nn -tttt -r evidence/part-a/baseline.pcap`. Use `port 53` and `tcp port 443` filters for focused review.

## Results
The activity log shows successful DNS lookups for example.com, ubuntu.com, debian.org, and github.com, with A and AAAA results. The HTTPS request returned HTTP 200 and `text/html; charset=utf-8`.

DNS response timings calculated from captured query and response timestamps are recorded in `dns-observations.csv`. The Debian AAAA response was notably slower (about 1.447 seconds) than the other observed responses.

## Capture scope and limitations
The capture includes unrelated background HTTPS traffic, including connections not attributable to the scripted request. Those connections are excluded from the controlled baseline conclusions. This short capture is not a comprehensive representation of normal host traffic. Encrypted HTTPS payloads were not inspected, and no conclusion is made about the cleanliness of the host.

## Evidence handling
The raw PCAP is local-only and excluded from Git. The case-level checksum manifest includes its hash when present. Public documentation contains derived observations only.
