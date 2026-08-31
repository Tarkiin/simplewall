# Experimental build with the public routine SDK

Verified locally on 2026-08-31 with Visual Studio 2022, MSVC 14.44, Windows SDK
10.0.26100 and the x64 Release configuration, rebased onto upstream d4cc6a25.
This route does not require access
to Henry's private repository. It is an optional compatibility build, not a
claim of identical behavior to the unpublished SDK.

The normal Visual Studio project remains unchanged by these build overrides.
The public SDK clone and the shared `../routine` source are not modified. A
prepared copy and all generated artifacts stay under the ignored `temp/` folder.

## Reproduce

Requires Git, PowerShell 7, and the Visual Studio C++ desktop workload, including
AddressSanitizer for the optional memory check. Start in the repository root.

```powershell
# Only needed when no public SDK checkout has been downloaded yet:
git clone https://github.com/henrypp/routine.git temp/deps/routine
git -C temp/deps/routine checkout 3020ca94007b824c387ce145a6ff22702dc22272

.\tools\build-public-sdk.ps1
.\tests\build-public-sdk-tests.cmd
.\tests\build-public-sdk-tests.cmd --asan
```

`build-public-sdk.ps1` also accepts `-RoutineRoot` and `-MSBuildPath`. It writes
the application to `temp/public-sdk-build/simplewall.exe` and the build log to
`temp/public-sdk-build.log`. It **never installs or launches the application**.

Do not launch this experimental binary against an active firewall installation:
the application can reapply its filters during startup. A successful compilation
does not authorize changing the user's firewall rules for a UI test.

## Compatibility changes

- The adapter translates output-first arguments, renamed configuration and hash
  functions, constant string references, and the changed thread callback type.
- Hashtable enumeration copies the old pointer-sized hash into the application's
  32-bit output without overwriting adjacent memory.
- Temporary owned strings bridge APIs that previously required an owning string
  object, preserving the public library's reference counting.
- Failed file hashing initializes the output to null. Compression decoding grows
  its buffer with a 256 MiB cap and does not accept an exactly filled buffer as
  proof that all compressed chunks were decoded.
- The prepared SDK replaces its unbounded SSE string-length scan with a scalar
  bounded scan. ASan detected a read beyond a string literal in the original
  implementation, whose SSE path also ignored `max_length`. This correction is
  active in both ordinary builds and sanitizer tests, not a warning suppression.
- Preparation checks the exact SHA-256 of the upstream `routine.c` before making
  that substitution. An unexpected upstream version fails instead of being edited.

These local adaptations do not reconstruct the unpublished SDK. UI helpers,
window behavior, resource handling and complete application workflows still
need end-to-end validation before a release.

## Validation

The complete x64 application built with its existing `/W3 /WX` settings. The
adapter's standalone contract suite passed normally and under AddressSanitizer:

- Configuration sections stay separate and 64-bit values round-trip.
- Bounded strings, case-insensitive hashes, file paths, and FILETIME conversion.
- Hashtable enumeration preserves a sentinel immediately after a 32-bit hash.
- File creation, size, seek, SHA-256 of known contents, missing-file failure,
  and hard-link identity, using fixtures next to the test executable only.
- Highly compressed data round-trips without truncation; oversized input fails.
- Current-process and token queries, read-only registry access, service SID
  agreement with Windows, suspended-thread start and completion.
- Hidden test-window context, edit selection/read-only state/margins and checkbox
  state, including the control-helper renames in the August application source.

The tests use a separate application name and portable configuration under
`temp/public-sdk-tests/`. They do not call the firewall APIs or application startup.
UDP/QUIC and production UI callback tests are documented separately in
[UDP measurement](udp-measurement.md). Full application startup and firewall
workflows remain outside this adapter's validation scope.
