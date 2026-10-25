# Native Windows mode: managed user and chosen network adapter

[Русский](WINDOWS_NATIVE.md) · [Compare all modes](WINDOWS.en.md)

`--backend user` works without WSL2 or Docker. It creates a dedicated local
account (default `AIWorker`) without administrator membership, grants that account
read or edit access to the current **copied** project, and starts the agent under
that account. A local authenticated CONNECT proxy sends its own IPv4 TCP and DNS
connections through the adapter you explicitly chose. Global routes and VPN
settings are not changed.

**This is a weaker isolation boundary.** Another Windows user can see host
adapter and process names, access public system files and call system services.
The agent uses the current desktop; account ACLs and WFP rules do not create a
private process, network or IPC namespace. For hiding these host details, use
WSL2/Docker or a separate VM.

## Requirements and current validation status

- Windows 10/11 x64, 64-bit Python 3.11+, Windows PowerShell 5.1 x64 with
  LocalAccounts, NetTCPIP and NetAdapter modules.
- Run setup and launch as Windows administrator. The agent process uses the
  ordinary managed account.
- Select an active adapter with a preferred IPv4 address and IPv4 DNS servers.
  TCP DNS on port 53 via that adapter must work. Agent direct IPv6 is blocked.
- Install the client's `.exe` and dependencies in a directory readable by the
  worker. The launcher does not download clients or copy credentials from your
  personal profile.

The Win32/WFP/NTFS calls and PowerShell scripts **have not been run on Windows**
in this workspace. Linux unit tests cover data flow, structure layouts and
error paths with mocked Windows APIs. The mandatory worker self-test runs before
each real agent launch and refuses to launch after failure. Native acceptance must
be performed on the target machine.

## Setup in the terminal

From an administrator terminal in the unpacked package:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Backend user
py -3 windows.py interfaces --backend user
py -3 windows.py setup-user --username AIWorker --interface "GUID-FROM-LIST"
py -3 windows.py new demo --backend user --copy "C:\Projects\demo"
py -3 windows.py skills demo --backend user
py -3 windows.py selftest --backend user
py -3 windows.py run claude demo --backend user --access edit -- "C:\AI-Tools\claude.exe"
```

Those paths are examples; use the actual installed `.exe`. For an npm-based CLI,
provide the absolute `node.exe` path followed by its JS entrypoint. `.cmd` and
`.bat` files are not executed through a shell. Start `start.cmd` as administrator
for the TUI, choose `user` in item `8`, then explicitly choose the adapter GUID.
Use `start.cmd gui` for the graphical form. The adapter is never auto-selected.
Offline mode does not use the adapter.

## How access is restricted

Data lives in `%ProgramData%\AISandboxNative\AIWorker\`: account identity, the
chosen adapter GUID, proxy port and DPAPI-encrypted password in `account.json`;
managed project copies in `workspaces\`; homes in `homes\`; trusted rules and
self-test in `code\`; rotated proxy logs in `logs\`. Administrators/SYSTEM own
the private files. A selected project gets read or edit ACLs. Other managed
projects and homes lose worker grants before launch. Paths with symlinks,
junctions/reparse points or hardlinks are rejected before privileged ACL work.

The account is disabled between sessions. It is briefly enabled to create a
suspended process, place it in a Job Object and then disabled before the process
resumes. The job limits memory/process counts and ends descendants when closed.
WFP rules tied to the worker SID persist across launcher crashes. They block
direct IPv4 connections except TCP to the fixed proxy port on `127.0.0.1`, direct
IPv6 and incoming connections. Offline mode blocks that proxy port too. The
proxy requires a per-session token, limits CONNECT to profile domains on 443,
rejects non-public destination addresses, and pins every outbound DNS/TCP socket
to the selected interface using `IP_UNICAST_IF` and the selected source address.
An adapter mismatch or bind failure stops the connection; there is no fallback.

## Important limits

The current desktop is shared. Job UI limits do not prevent all synthetic input
or keyboard observation; close windows containing secrets while the worker runs.
The worker's Windows profile and HKCU persist across projects for that username;
use different managed usernames for unrelated projects. System brokers such as
DNS Client and BITS may perform network operations under another SID, outside the
worker's WFP rule. Thus even `--offline` is not a complete no-network guarantee
for hostile code. Existing public directories elsewhere on the computer keep
their own permissions. Very large projects make per-file ACL setup slow.

The self-test checks the worker SID, lack of administrator membership, denial of
a controlled private file, policy protection, project access, direct loopback
denial and proxy responses. It makes no external requests and does not enumerate
host processes or adapters. Run `selftest --backend user` on the target Windows
machine; then validate a normal task and disconnect the chosen adapter to ensure
an active request fails rather than using another interface.

Remove only the managed account and its WFP rules with
`py -3 windows.py remove-user --username AIWorker`; managed project data remains.
The regular `install.ps1 -Uninstall` does not remove that account. See the
[Russian technical review](WINDOWS_NATIVE.md#ревью-режима-25-октября-2026-и-известные-пределы)
for detailed error codes and recovery steps.
