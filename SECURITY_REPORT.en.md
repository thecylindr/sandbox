# AI Sandbox security review: current status

[Русский full report](SECURITY_REPORT.md) · [Project overview](README.en.md)

This page describes the **current source revision** reviewed on 25 October 2026.
The Russian report retains earlier audit history; past success on Arch Linux
must not be read as Windows or current-build acceptance.

## Scope and findings

The review read project source files and used purpose-built temporary fixtures.
It did not enumerate host processes, interfaces, VPNs, routes or services, and
did not read credentials outside the project. The latest additions are:

| ID | Risk | Change and remaining limit |
|---|---|---|
| SBX-32 | High if the wrong boundary is chosen | Native Windows account/ACL/WFP limits managed data and direct connections but does not hide host process or adapter lists; the UI and guides direct users who need those hidden to WSL2/Docker. |
| SBX-33 | Medium | The native proxy checks the selected GUID/index before each outbound socket, applies `IP_UNICAST_IF` and a source address, and fails on mismatch. Verified with mocked APIs, not Windows drivers. |
| SBX-34 | Medium | Bundled project skills are installed only in a selected managed copy; changed existing skills and symlink/junction/hardlink paths are refused. Controlled fixture tests passed. |
| SBX-35 | Low, test method | A native-mode unit test previously opened a real host socket to simulate a busy port. It now uses a socket mock so the test does not need host networking. |

The native Windows backend creates a disabled managed local account, prepares
NTFS permissions on one copied workspace, installs persistent per-SID WFP rules,
and uses an authenticated local CONNECT proxy pinned to the selected IPv4
adapter. A controlled preflight under the worker SID runs before the agent. Its
Windows API, WFP, NTFS and PowerShell path **has not been executed on a real
Windows machine here**. Native `user` shares the host desktop and process/network
visibility, and Windows system brokers may send traffic under a different SID.
Even `--offline` is therefore not a total no-network guarantee for hostile code.

The new TUI checks module syntax, policy presence, TOML profiles and unsafe
network options during startup. The Windows ZIP contains a local `SHA256.json`
for accidental-change detection. It is not a signed authenticity proof and
startup is not a live isolation test. TUI preview statuses are illustrative.
The real `check`/`selftest` actions remain separate and use controlled fixtures.

## Verification completed here

`python3 -m unittest discover -s tests -v` ran **183 tests: 180 passed,
3 skipped, 0 failures**. The log is `state/tui-validation-2026-10-25.txt`.
The three live Linux tests were stopped before fixture execution because the
environment rejected bubblewrap namespace setup:

```text
bwrap: loopback: Failed to create NETLINK_ROUTE socket: Operation not permitted
```

There was no fallback to scanning host networks or processes. Python compilation
and shell syntax checks passed. Linux and Windows terminal screen previews ran
locally; the Windows picture was an emulation, not a Windows process run.
No Docker, WSL2 or native Win32 runtime acceptance was possible here.

## Target-machine acceptance

On Linux/WSL2, run `sandbox check` and `sandbox selftest default`, then the
selected Claude/Codex profile. On Windows, run `install.ps1 -Check`, the
backend-specific `windows.py selftest --backend wsl|docker|user`, and a normal
client task. For native `user`, explicitly select an adapter and verify that
disconnecting it fails an active connection instead of using another route.
Do not disable the network or file boundary to turn a failed check into a pass.

The [native Windows guide](WINDOWS_NATIVE.en.md) has its setup and limits. The
[Russian full review](SECURITY_REPORT.md) records earlier Linux/Docker network
findings and older revisions separately.
