# UDP and QUIC socket traffic measurement

Validated on Windows 11 Pro build 26200 on 2026-08-31, against upstream
d4cc6a25 plus this change. The complete x64 application builds with the
[optional public SDK adapter](public-sdk-build.md).

## Enabling the feature

The Options menu has **Measure UDP/QUIC traffic (experimental, restart required)**.
It sets IsUdpTrafficEnabled, which defaults to FALSE. The network monitor
must also be enabled. Changing this option does not change firewall filters.
Restart Simplewall to apply it, then reopen applications whose UDP sockets you
want to measure. The existing download, upload and total columns are reused.

## Measurement and limitations

- A dedicated real-time ETW session named simplewall-UDP subscribes to
  Microsoft-Windows-Winsock-AFD. Informational DATAGRAM events provide socket
  creation, binding and I/O completion metadata. RIO lifecycle events allow
  rejection of sockets using the unsupported registered-I/O path.
- Successful send/receive completion sizes count UDP payload bytes, including
  QUIC encryption and protocol overhead. IP, UDP and link-layer headers are
  excluded. Pending and failed operations are not counted as successful I/O.
- This is **socket I/O accounting**, not a packet-capture replacement. Unread or
  dropped incoming datagrams, raw sockets and non-Winsock paths are outside the
  measurement. Repeated MSG_PEEK reads may report repeated I/O for one datagram;
  that case is not validated as network usage.
- QUIC is included as UDP traffic, without separate identification or decryption.
- Creation and bind events are required. Sockets opened before capture remain
  unavailable. There is no historical backfill and no need to restart unrelated
  services just to make their rows measurable.
- Totals start when a row is first monitored. Sockets disappearing before the
  existing two-second table refresh are not represented. ETW buffering delayed
  updates by approximately two seconds locally. Speeds describe changes between
  monitor samples, not an instantaneous packet rate.
- Mapping uses the creating PID, bound address, port and IPv6 scope. Owner-table
  creation timestamps reset totals on reuse and reject delayed old events.
  Duplicate/ambiguous endpoint rows are not a supported per-socket breakdown.
- Until a matching event arrives, columns show an em dash with an explanatory
  tooltip. Lost ETW events, unsupported layouts, allocation limits and tracing
  errors invalidate measurement instead of displaying a verified zero.
- Storage is bounded to 8,192 monitored endpoints and 8,192 AFD mappings.
  Successful table refreshes prune stale entries; failed refreshes retain them.
- Only this collector's session may be stopped. A competing instance cannot
  replace it. Orphan reclamation checks the session GUID. Normal shutdown stops
  the session and joins the consumer thread.

The feature remains opt-in. Other Windows versions, ARM64, RIO, multicast
fanout, sockets duplicated across processes and unusual offload configurations
are not claimed as validated. The 32-bit event decoder has synthetic coverage;
a 32-bit application build has not been tested.

## Verification

These checks passed locally:

| Check | Evidence |
|---|---|
| Full x64 Release build | MSVC 14.44, SDK 10.0.26100, /W3 /WX |
| Collector build and static analysis | /W4 /WX /analyze |
| Memory checks | Collector and SDK contract suites under AddressSanitizer |
| AFD decoding | 32/64-bit metadata, IPv4/IPv6, supported completion IDs |
| Attribution fixtures | PID/port isolation, exact/wildcard binds, scopes, reuse |
| Failure fixtures | Pending/cancelled I/O, RIO rejection, truncation and lost events |
| Table lifecycle | Failed versus empty enumeration and collision-chain cleanup |
| Non-administrator | Error 5 propagated as unavailable |
| UDP loopback | IPv4/IPv6, bound/wildcard, connected/unconnected, exact bytes |
| UDP load | 10,000 x 1,200 bytes; 12,000,000 bytes each way per socket |
| Controlled LAN echo | 10,200 IPv4 datagrams total; every case counted exactly |
| Encrypted QUIC | 1 MiB echo, contents verified, exact independent UDP counts |
| Production integration | Live totals and actual column callback match |
| Menu option | Real handler and check state tested with a hidden window |
| TCP regression | Real IPv4/IPv6 connections; EStats counts 120,000 bytes |
| Stop/restart | Repeated stop safe; restarted collector measures new sockets |
| Older socket | A real pre-existing socket remains unavailable, not verified zero |
| Session cleanup | Query returns ERROR_WMI_INSTANCE_NOT_FOUND |

QUIC uses aioquic 1.3.0 with an ephemeral certificate trusted only by the test.
Both endpoints run in a separate Python process. Independent datagram-transport
counters are compared exactly with ETW for each port and direction. The stream
echo is checked byte-for-byte and by SHA-256. Encryption overhead is not confused
with the 1 MiB stream payload.

A final integration run used 140 ms CPU and a 26,411,008-byte peak
working set. The final QUIC observer run used 78 ms CPU and a 16,457,728-byte peak working
set. These measure the whole test process, including fixtures and table polling;
they are not a universal overhead benchmark or full-GUI memory measurement.

Final QUIC counters were 1,083,668 bytes sent / 1,084,617 received at the server,
and the reverse at the client. Both independent counters and both production
row totals matched. The loopback and LAN tests each verified the larger
12,000,000-byte UDP case without discrepancies.

The integration executable uses isolated portable configuration, ordinary hidden
windows, network update functions and the column callback. A separate startup
probe calls the actual WinMain and DlgProc with a test-only WFP object that cannot
open the filtering engine or toggle Windows Firewall. It verified the connections
tab and an exact 120,000-byte UDP loopback total in both directions, with the
option enabled and disabled in separate runs. No installed Simplewall binary,
firewall rule, adapter setting or unrelated ETW session was changed. Filter
workflows are still outside this validation scope.

## Reproduce

Run from the repository root with VS2022 C++ tools and PowerShell 7:

```powershell
.\tools\build-public-sdk.ps1
.\tests\build-public-sdk-tests.cmd
.\tests\build-public-sdk-tests.cmd --asan
.\tests\build-startup-probe.cmd
.\tests\run-startup-probe.ps1
.\tests\run-startup-probe.ps1 -UdpDisabled
.\tests\build-udp-tests.cmd
.\temp\udpstats_test.exe
.\tests\check-udp-memory.cmd
.\tests\build-network-integration.cmd
.\temp\network-integration.exe --denied "$PWD\temp\denied.txt"
```

In an elevated terminal:

```powershell
.\temp\network-integration.exe --live "$PWD\temp\live.txt"
.\temp\network-integration.exe --lifecycle "$PWD\temp\lifecycle.txt"
```

For QUIC, use Python 3.10+ and aioquic 1.3.0 in a virtual environment or local
dependency folder. Simplewall itself has no Python dependency.

```powershell
python -m pip install --target temp/quic-deps aioquic==1.3.0
.\tests\run-quic-test.ps1 -PythonPath (Get-Command python).Source -DependencyPath temp/quic-deps
```

The runner elevates only the observer and checks both process exit codes plus
the independent byte comparison. Fresh reports stay under temp/. Success
requires RESULT: 0 failures and QUIC_ACCOUNTING: PASS.

For a controlled LAN echo server, --live REPORT IPv4 PORT runs two 100-packet
cases and one 10,000-packet case. The peer must echo payloads unchanged. Never
point this test at an unrelated public service.

## Provider choice

Classic kernel UdpIp events did not reach an earlier collector on this host,
despite successful transfers. The current implementation uses AFD and has
removed the unused classic decoder. Existing tracing sessions were not taken over.

References:

- [Winsock tracing details](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-tracing-event-details)
- [AFD creation event](https://learn.microsoft.com/en-us/windows/win32/winsock/afd-event-create)
- [EnableTraceEx2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)
