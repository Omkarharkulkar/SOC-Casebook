# CASE-005 Part A — Collection and Analysis Methodology

## Environment
- System: Ubuntu VM (omkarvm)
- Interface: enp0s3 (VirtualBox NAT)
- VM address: Redacted in published documentation
- Capture tool: tcpdump 4.99.4
- Snapshot length: 128 bytes

## 1. Controlled DNS Activity

A Bash script was created to record timestamps and perform IPv4
name resolution for four domains using getent:

- example.com
- ubuntu.com
- debian.org
- github.com

The script was hashed before execution.

## 2. DNS Packet Collection

A packet capture was performed on enp0s3 using a UDP port 53
filter with a 15-second maximum duration.

Command:

sudo timeout -s INT 15 tcpdump -i enp0s3 -nn -s 128 \
  -w evidence/part-a/baseline.pcap 'port 53'

The activity script was executed while the capture was running.

## 3. DNS Analysis

The PCAP was inspected using tcpdump's packet-reading and verbose
output options.

Command:

sudo tcpdump -nn -tttt -vvv \
  -r evidence/part-a/baseline.pcap

DNS queries and responses were identified by query names, record
types, response records, source/destination endpoints and timestamps.

Response time was calculated by subtracting the query timestamp
from the corresponding response timestamp.

The capture contained two complete query/response pairs:
ubuntu.com and github.com.

## 4. Supplementary TCP Capture

A separate 20-second capture filtered for TCP port 443 was performed.

Command:

sudo timeout -s INT 20 tcpdump -i enp0s3 -nn -s 128 \
  -w evidence/part-a/tcp-baseline.pcap 'tcp port 443'

The capture was inspected using:

sudo tcpdump -nn -tttt \
  -r evidence/part-a/tcp-baseline.pcap

This traffic was not associated with a controlled application
activity. It was treated as supplementary observation and excluded
from public evidence.

## 5. Integrity

SHA-256 hashes were recorded for the DNS PCAP, activity script,
and activity output.

The raw PCAPs are retained locally. Derived documentation avoids
publishing private VM and resolver addresses.

## 6. Limitations

- Only selected traffic was captured using display-independent
  packet filters.
- The DNS capture does not contain all four requested resolutions.
- TCP/443 traffic was not tied to a controlled application.
- Encrypted payload contents were not inspected.
- This baseline is limited to the observed traffic and does not
  establish that all system activity was benign.
