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

## SMB CREATE and WRITE

`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y 'smb2.cmd == 5 || smb2.cmd == 9' -T fields -E header=y -E separator=, -E quote=d -e frame.number -e frame.time -e ip.src -e ip.dst -e smb2.cmd -e smb2.tree -e smb2.tcon_frame -e smb2.fid -e smb2.filename -e smb2.write_length -e smb2.nt_status`

The derived output is stored in `analysis/part-b/smb-create-write.csv`.

CREATE and WRITE correlation was checked using Tree ID and File ID. The 11 observed WRITE requests were associated with the corresponding `q4-summary.bin` file handles.

## DCE/RPC and Service Control Manager

`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y dcerpc -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e dcerpc.dg_if_id -e dcerpc.cn_bind_to_uuid -e dcerpc.opnum -e svcctl.opnum`

Operation numbers observed:

- 0 — RCloseServiceHandle
- 6 — RQueryServiceStatus
- 12 — RCreateServiceW
- 15 — ROpenSCManagerW
- 19 — RStartServiceW

Extract service creation and start operations:

`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y 'svcctl.opnum == 12 || svcctl.opnum == 19 || svcctl.opnum == 15' -T fields -E header=y -E separator=, -E quote=d -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.stream -e dcerpc.cn_call_id -e svcctl.opnum`

The derived output is stored in `analysis/part-b/scm-operations.csv`.

Detailed service names, binary paths and response statuses were examined using verbose packet output:

`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y 'svcctl.opnum == 12 || svcctl.opnum == 19' -V`

The extracted service definitions included `WinHostSvc` and `WinUpdateSvc`. Service creation and start responses included both successful results and `WERR_SERVICE_REQUEST_TIMEOUT`.

## DNS resolution of the SMB server name

`tshark -r ~/case005-private/netmetria-multi-behavior-scenario.pcap -Y 'dns.qry.name == "files.arden.local" && dns.flags.response == 1' -T fields -E header=y -E separator=, -e frame.number -e dns.a -e dns.aaaa`

The observed DNS answers returned `10.42.20.40`. SMB CREATE requests using the same UNC share string were also observed toward other destination IPs. This discrepancy is documented in the incident report.

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
- Two `q4-summary.bin` SMB CREATE bursts.
- Eleven associated WRITE requests, correlated using Tree ID and File ID.
- All 11 WRITE responses returned SMB success.
- Remote Service Control Manager operations included `ROpenSCManagerW`, `RCreateServiceW` and `RStartServiceW`.
- Service definitions included `WinHostSvc` and `WinUpdateSvc`.
- Service-start responses included both `WERR_OK` and `WERR_SERVICE_REQUEST_TIMEOUT`.
- `files.arden.local` DNS answers resolved to `10.42.20.40`, while the same UNC share string appeared in SMB requests toward multiple destination IPs.

The investigation used traffic metadata. No payloads were executed.
