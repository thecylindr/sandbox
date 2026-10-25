# AI Sandbox guide

[Русский](MANUAL.md) · [Start here](README.en.md) · [Windows](WINDOWS.en.md)

This is the English operational guide. The [Russian manual](MANUAL.md) carries
additional distribution-specific commands and implementation detail. The current
validation status belongs to [SECURITY_REPORT.en.md](SECURITY_REPORT.en.md), not to
an older test count in archived reviews.

## Purpose and threat model

The user gives a coding agent one managed copy of a project. Agent code may make
mistakes or follow malicious instructions embedded in repository files. AI Sandbox
tries to limit the files, processes and network paths that code can reach, and to
keep agent-written project hooks or IDE tasks from executing on the host. It does
not turn a shared kernel into a separate VM. Behavioral instructions in
`AGENT_POLICY.md` complement, but cannot replace, OS restrictions.

## Choose a platform

| Platform | Boundary | Main prerequisite |
|---|---|
| Linux x86_64/aarch64 | bubblewrap namespaces, seccomp, optional Landlock | Unprivileged user namespace and bubblewrap |
| Windows with WSL2 | The Linux boundary inside WSL2 | WSL2 distribution, Python and bubblewrap inside it |
| Windows with Docker Desktop | Agent `--network none`, separate proxy container | Docker Desktop with Linux containers |
| Native Windows x64 | Managed user, NTFS ACL, WFP, chosen adapter | Administrator for setup/launch; weaker visibility boundary |

Linux needs Python 3.8+, `/usr/bin/python3`, bubblewrap and a regular user account.
The Windows launcher needs Python 3.11+. For native mode, use 64-bit Python and an
active IPv4 adapter with DNS. WSL1, macOS and unsupported CPU architectures are
outside this package. See [WINDOWS.en.md](WINDOWS.en.md) before choosing a Windows
backend.

## Install and use on Linux / WSL2

Run the unpacked `./install.sh`. It installs the `sandbox` command, checks the
environment, and runs an isolation self-test. `--check` only diagnoses;
`--install-deps` explicitly installs dependencies; `--no-selftest` skips the live
check. A failed required check stops installation. An update copies program code
but preserves managed workspaces, homes, logs and edited profiles.

```bash
./install.sh
sandbox                              # Textual desktop (optional requirements-tui.txt)
sandbox new demo --copy ~/code/demo  # copied project; source untouched
sandbox skills demo                  # two local skills for Codex and Claude
sandbox run codex demo --access read
sandbox selftest codex
```

The copied project is under `~/sandbox/workspaces/demo`. `read` is for review;
`edit` allows the agent to change the copy. `sandbox shell default demo` opens
an offline sandbox shell. `sandbox ws` lists copies; `sandbox audit demo` checks
project files that the host may execute, such as Git hooks and IDE tasks.
`sandbox check` checks setup, and `sandbox selftest [profile]` runs controlled
attacks from inside the sandbox. The TUI exposes these actions; see
[TUI.en.md](TUI.en.md).

The widget desktop uses Python 3.10+ and the optional `requirements-tui.txt` packages.
Without them the built-in compact terminal screen remains available.

The import omits common `.env`, key and credential filenames and removes URL
credentials from the copy's `.git/config`. This is only a filename-oriented
filter: review a project before importing sensitive data. The launcher refuses
to copy an entire home directory or protected system area. It never syncs agent
changes back to the original automatically.

## What the agent sees

Linux/WSL agents work in `/workspace` with their own `/home/user`, a restricted
`/proc`, controlled mounts, clean environment and resource limits. The network
namespace has loopback; public outbound connections, when enabled, go through a
CONNECT proxy with a domain allowlist. Direct host network mode and private
destination addresses are rejected. A profile can set `network = "off"` or
`"allowlist"`; its domains and port restrictions matter. The proxy cannot inspect
TLS contents or hide the external source IP. Linux uses a common kernel, so
kernel bugs remain in scope.

The default, Claude and Codex profiles live under `profiles/*.toml`. Project
injection files such as `.git/config`, hooks, `.vscode` and MCP config get
special protection when the host might later execute them. The agent gets the
shared policy as a read-only file. Per-project skills are optional text
instructions and do not grant capabilities.

Some host facts remain visible even with a neutral `/proc`, including the kernel
version, CPU details through direct instructions and disk capacity of the mounted
project. External MCP/SSH services may have separate permissions not controlled
by this sandbox. Disk quotas are not implemented. See the [full Russian threat
table](MANUAL.md#6-защита-угроза--мера) for the detailed boundary.

## Diagnostics and expected failures

- If `bwrap` cannot create user/net namespaces, read `sandbox check` output and
  correct the OS setup. Do not switch to host networking to make a test pass.
- `selftest` checks only known fixture processes, files and sockets. A namespace
  setup rejection or skipped test does not prove protection.
- If the agent cannot read or write a project, verify the selected `read`/`edit`
  mode and the managed copy path. Avoid widening access to personal directories.
- If login requires an unavailable localhost callback, use a supported API-key
  or non-callback authentication flow inside the chosen backend.
- If a project test needs network dependencies, record the failure and explicitly
  update the profile only after understanding its destinations.

The [report template](REPORT_TEMPLATE.en.md) tells agents to record the cause,
changed files, tests, exit codes and limits. [Agent rules](AGENT_POLICY.en.md)
forbid inspecting unrelated host processes, routes, VPNs, services or interfaces.

Developer verification: `python3 -m unittest discover -s tests -v`.
