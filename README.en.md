# AI Sandbox — scoped workspaces for Codex and Claude Code

[Русский](README.md) · [CLI commands](COMMANDS.en.md) · [Terminal desktop](TUI.en.md) · [Windows modes](WINDOWS.en.md)

## Why use it?

AI Sandbox runs a coding CLI over a **copy of one project**. Use it to ask an agent to
fix a bug, inspect unfamiliar code, or run relevant tests while limiting its access
to other projects, your personal files, host processes, and the network. The launcher
prepares a workspace, supplies `AGENT_POLICY.md`, and enforces the selected boundary
with operating-system mechanisms. Edits stay in the copy until you transfer them.

| Your situation | Recommended mode |
|---|---|
| Linux or WSL2; host processes and adapters should be outside the agent's namespace | Linux bubblewrap |
| Windows with Docker Desktop; you want a prepared tool container | Docker, with a separate egress proxy |
| Windows without WSL2 or Docker; you need a selected network adapter and per-project file permissions | Native `user` account; host process and adapter lists remain visible |
| You will run deliberately hostile code or need a stronger boundary | A separate virtual machine |

The optional Textual/Rich widget TUI has a project picker, an animated seasonal card, local
bundle checks, and actions for the existing self-tests. Install its dependencies from
`requirements-tui.txt` as described in [TUI.en.md](TUI.en.md). **A successful startup screen is not a security
test.** The current review status and unverified Windows behavior are in
[SECURITY_REPORT.en.md](SECURITY_REPORT.en.md).

## Quick start

Linux / WSL2, from an extracted package:

```bash
./install.sh
sandbox                       # terminal desktop
sandbox new demo --copy ~/code/demo
sandbox skills demo           # two project skills for each client
sandbox selftest claude       # isolation checks on controlled fixtures
sandbox run claude demo
```

On Windows, install the desired backend with `install.ps1` (details in
[WINDOWS.en.md](WINDOWS.en.md)), then start `start.cmd tui` for the TUI or `start.cmd gui`
for the graphical window. The `user` backend requires administrator rights for
setup and launch; the agent itself uses a non-administrator account.

The [CLI command guide](COMMANDS.en.md) explains the usual workflow, options and the differences among the three Windows backends.

## What each mode enforces

Linux/WSL uses user, PID, network, IPC and UTS namespaces, seccomp, Landlock when
available, a clean environment, resource limits, and a domain-limited CONNECT
proxy. The agent's network namespace contains loopback; the host adapter list is
not mounted into it. Docker starts the agent with `--network none` and provides an
explicit local proxy path. Both modes give the agent a single copied workspace and
a separate home. The native Windows `user` mode uses a local account, NTFS ACLs,
WFP rules and an interface-bound proxy. It has no PID/network namespace.

Instructions and skills guide agent behavior; **the OS boundary controls access**.
None of the modes hides the source IP from an external API, guarantees protection
against a kernel flaw, or turns an untrusted host into a VM. See the
[full English guide](MANUAL.en.md) and the [native Windows limits](WINDOWS_NATIVE.en.md).

## Documentation

| English | Russian | Purpose |
|---|---|---|
| [TUI.en.md](TUI.en.md) | [TUI.md](TUI.md) | Terminal workflow, seasons, project tests and previews |
| [WINDOWS.en.md](WINDOWS.en.md) | [WINDOWS.md](WINDOWS.md) | Choose WSL2, Docker or `user` |
| [WINDOWS_NATIVE.en.md](WINDOWS_NATIVE.en.md) | [WINDOWS_NATIVE.md](WINDOWS_NATIVE.md) | Account setup, selected adapter and limitations |
| [MANUAL.en.md](MANUAL.en.md) | [MANUAL.md](MANUAL.md) | Requirements, commands and threat model |
| [COMMANDS.en.md](COMMANDS.en.md) | [COMMANDS.md](COMMANDS.md) | Practical CLI workflows for Linux, WSL2, Docker and Windows `user` |
| [SECURITY_REPORT.en.md](SECURITY_REPORT.en.md) | [SECURITY_REPORT.md](SECURITY_REPORT.md) | What was changed and actually verified |
| [AGENT_POLICY.en.md](AGENT_POLICY.en.md) | [AGENT_POLICY.md](AGENT_POLICY.md) | Agent behavior rules |
| [REPORT_TEMPLATE.en.md](REPORT_TEMPLATE.en.md) | [REPORT_TEMPLATE.md](REPORT_TEMPLATE.md) | Bug-fix report template |

Developer check: `python3 -m unittest discover -s tests -v`. Live namespace tests
are skipped if the environment forbids namespace creation; a skip is not a pass.
