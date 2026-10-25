# AI Sandbox on Windows: choose an isolation backend

[Русский](WINDOWS.md) · [Project overview](README.en.md) · [TUI](TUI.en.md)

The Python launcher offers three backends. Python coordinates setup; the actual
boundaries come from WSL2/Linux, Docker or Windows account/ACL/WFP mechanisms.
The first two can put the agent in a distinct PID and network namespace. Native
`user` mode cannot hide the host's adapter and process lists.

| Mode | Best fit | Project and agent | Main limit |
|---|---|---|---|
| WSL2 + bubblewrap | You can install a Linux distribution and agent CLI | Copy in the selected WSL distribution; Linux namespaces and seccomp | Requires WSL2 and bubblewrap |
| Docker Desktop, Linux containers | You want a prepared image with Node, Python and the agent CLIs | Copy under `windows-data/workspaces`; agent network set to `none`, proxy separate | Requires Docker Desktop; daemon is trusted |
| Native `user` | WSL2/Docker unavailable; you can run setup as administrator | Managed account with NTFS ACLs and a chosen IPv4 proxy interface | Shared desktop, visible host processes/adapters, weaker network boundary |

Use a separate VM for deliberately hostile software or a strict boundary from the
host OS. Backend details and a comparison of remaining exposure are in the
[native user guide](WINDOWS_NATIVE.en.md) and [security status](SECURITY_REPORT.en.md).

## Start the interface

Unpack the Windows ZIP, install widget dependencies from `requirements-tui.txt`
into `.venv` (commands are in [TUI.en.md](TUI.en.md)), then launch `start.cmd` for
the Textual/Rich terminal desktop with its control panel, check table, action log,
and animated seasonal card. Use
`start.cmd gui` for the older graphical form. You can also run:

```powershell
py -3 windows.py tui --backend wsl       # or docker / user
py -3 windows.py tui --preview windows   # visual demo only
```

The launcher copies imported projects. It skips common secret filenames and
rejects protected source directories; this is not a complete secret scanner.
Do not run host commands from an agent-written project directory. The launcher
locates WSL/Docker executables only in absolute PATH directories.

## WSL2 setup

Install WSL2 and a distribution, then Python 3.11+ and bubblewrap inside it.
Install Claude/Codex inside that distribution. From an administrator PowerShell
only if your chosen installation path requires it:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Backend wsl -Distribution Ubuntu
py -3 windows.py selftest --backend wsl --distro Ubuntu
```

Replace `Ubuntu` with your distribution name. `setup-wsl` copies launcher code
into its `~/sandbox` and runs the Linux install checks. For a stronger boundary,
use a dedicated WSL distribution and disable Windows interop and automatic Windows
drive mounts as described in the [Russian full Windows guide](WINDOWS.md).

## Docker setup

Install Docker Desktop and select Linux containers. The package does not reuse
the host home for agent login. Build the agent image, then run the controlled
self-test:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Backend docker -BuildImage
py -3 windows.py check --backend docker
py -3 windows.py selftest --backend docker
py -3 windows.py new demo --backend docker --copy C:\Projects\demo
py -3 windows.py run claude demo --backend docker --access edit
```

The agent container has `--network none`, synthetic hosts/DNS files and a
per-session loopback bridge to a separate proxy container. The proxy allows only
configured public destinations on port 443. Docker homes persist in separate
volumes. Passing an API key makes it available to the agent and trusted daemon.
Use `--offline` for tasks that do not need a remote service.

## Native account setup

`install.ps1 -Backend user` installs the launcher but does not create an account
or change firewall rules. Start the launcher as Windows administrator, explicitly
list adapters and choose the intended GUID:

```powershell
py -3 windows.py interfaces --backend user
py -3 windows.py setup-user --interface "GUID-FROM-LIST" --username AIWorker
py -3 windows.py selftest --backend user --username AIWorker
```

Read [WINDOWS_NATIVE.en.md](WINDOWS_NATIVE.en.md) before using this mode. Its
Windows API and PowerShell path remains unverified on a real Windows machine here.

## Acceptance and limits

Run the selected backend's self-test before using an LLM client. A local Python
unit test or a TUI preview does not prove Windows isolation. Current test counts,
namespace skips and the Windows validation gap are in
[SECURITY_REPORT.en.md](SECURITY_REPORT.en.md). The CONNECT proxy controls
destinations, not TLS content, and cannot hide the public source IP or region.
