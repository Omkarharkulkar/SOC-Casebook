# Part A — Controlled Network Baseline

## Purpose
Record a short, controlled baseline of DNS and HTTPS activity from the Ubuntu lab VM for comparison with later network-traffic investigations.

## Environment and tools
- Ubuntu lab VM
- Capture interface: enp0s3 (NAT)
- tcpdump 4.99.4
- getent and Python standard library urllib
- tshark used for final packet-field extraction (SNI, DNS query IDs, and DNS answers); it was not used during the initial capture.

## Procedure
1. Flush the DNS cache using `sudo resolvectl flush-caches`.
2. Start a 30-second capture using:
   `sudo timeout 30s tcpdump -i enp0s3 -s 0 -w evidence/part-a/baseline.pcap 'port 53 or tcp port 443'`
3. Run `evidence/part-a/baseline-activity.sh`, which resolves four domains and makes one HTTPS request to `https://example.com/`.
4. Inspect packets with `tcpdump -nn -tttt -r evidence/part-a/baseline.pcap`. Use `port 53` and `tcp port 443` filters for focused review.
5. Extract DNS query details, response answers, and TLS SNI with tshark. Reusable field selections:
   - DNS queries: `-Y 'dns.flags.response==0' -T fields -e frame.time -e dns.id -e dns.qry.name -e dns.qry.type`
   - DNS answers: `-Y 'dns.flags.response==1' -T fields -e frame.time -e dns.qry.name -e dns.qry.type -e dns.a -e dns.aaaa`
   - TLS SNI: `-Y 'tls.handshake.type==1' -T fields -e frame.time -e ip.dst -e ipv6.dst -e tls.handshake.extensions_server_name`

## Results
The activity log shows successful DNS lookups for example.com, ubuntu.com, debian.org, and github.com, with A and AAAA results. The HTTPS request returned HTTP 200 and `text/html; charset=utf-8`. Packet inspection identified the TLS ClientHello SNI as `example.com`, matching the scripted request.

DNS response timings calculated from captured query and response timestamps are recorded in `dns-observations.csv`; timestamps are in IST (UTC+05:30). Seven responses were approximately 54–165 ms. The Debian AAAA response was approximately 1.447 seconds. The displayed DNS query list contained one query per domain/type with unique transaction IDs; no repeated query was evident in that output. This does not rule out retries or resolver behavior outside the observed packets.

The GitHub AAAA response `64:ff9b::87eb:9590` falls within `64:ff9b::/96`, consistent with DNS64 synthesis in a NAT64 environment.

## Capture scope and limitations
The capture includes unrelated background HTTPS traffic, including connections not attributable to the scripted request. Those connections are excluded from the controlled baseline conclusions. This short capture is not a comprehensive representation of normal host traffic. Encrypted HTTPS payloads were not inspected, and no conclusion is made about the cleanliness of the host. The activity log does not contain a timestamp for each individual lookup; packet timestamps were used to align DNS activity.

## Evidence handling
The raw PCAP is local-only and excluded from Git. The case-level checksum manifest includes its hash when present. The manifest was prepared after the capture; therefore, it verifies the current local evidence and files but does not establish a pre-capture hash or prove the script's exact contents at capture time. Public documentation contains derived observations only.
