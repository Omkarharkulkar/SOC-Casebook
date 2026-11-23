# CASE-005 — Analysis Commands

The original Part B PCAP is stored privately outside Git:
`~/case005-private/netmetria-multi-behavior-scenario.pcap`

Analysis tool: TShark 4.2.2.

## Capture metadata
`capinfos ~/case005-private/netmetria-multi-behavior-scenario.pcap`

## Protocol hierarchy
`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -q -z io,phs`

## DNS
`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y dns -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type -e dns.flags.rcode`

## HTTP
`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y http.request -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri`

## TLS SNI
`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y tls.handshake.extensions_server_name -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name`

## SMB
`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y smb2 -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e smb2.cmd -e smb2.tree -e smb2.filename -e smb2.create.disposition -e smb2.create.action -e smb2.write_length -e smb2.nt_status`

## DCE/RPC
`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y dcerpc -T fields -e dcerpc.dg_if_id -e dcerpc.cn_bind_to_uuid -e dcerpc.opnum`

## NTP
`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y ntp -T fields -e frame.number -e frame.time -e ip.src -e ip.dst`

## Key results
- 4,134 packets.
- DNS: 710 frames (355 queries and 355 responses).
- HTTP: 292 frames.
- SMB2: 782 frames.
- DCE/RPC: 292 frames.
- TLS: 438 frames.
- NTP: 28 frames.
- Two q4-summary.bin SMB CREATE bursts.
- Eleven associated WRITE records on the same TCP streams.
- RPC operation-number attribution was not established.

The investigation used traffic metadata. No payload was executed.
