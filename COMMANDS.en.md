# AI Sandbox commands

[Русский](COMMANDS.md) · [Home](README.en.md) · [Full manual](MANUAL.en.md)

This quick reference answers “what should I run next?” The easiest entry point is usually the desktop: run `sandbox` on Linux/WSL or `start.cmd` on Windows. Use these commands from a terminal or script.

## Linux and WSL2: the usual workflow

Run these in the installed Linux/WSL environment:

```bash
sandbox check                              # check whether the environment is ready
sandbox new demo --copy ~/code/my-project  # create an isolated project copy
sandbox audit demo                         # check for project files the host may execute
sandbox skills demo                        # add skills for Claude Code and Codex
sandbox selftest default                   # probe protections with controlled fixtures
sandbox run claude demo --access edit      # let Claude edit the copy
```

Replace `claude` with `codex` to use Codex. `read` allows the agent to read the project; `edit` lets it change only its workspace copy. The launcher displays the selected settings and normally asks for confirmation. To get an interactive terminal inside the environment, run `sandbox shell default demo`.

When your current directory is already `~/sandbox/workspaces/demo`, you can omit the workspace name: `sandbox run claude`.

## Windows: choose a backend

Open Command Prompt or PowerShell in the extracted project folder. `start.cmd` opens the TUI; `start.cmd gui` opens the graphical window. The examples below call Python directly and specify a backend so the execution environment is clear.

### WSL2

```powershell
py -3 windows.py setup-wsl
py -3 windows.py check --backend wsl
py -3 windows.py new demo --backend wsl --copy 'C:\Projects\my-project'
py -3 windows.py skills demo --backend wsl
py -3 windows.py selftest default --backend wsl
py -3 windows.py run claude demo --backend wsl --access edit
```

`setup-wsl` installs the sandbox files into WSL. Set up WSL2 and a Linux distribution first, as described in the [Windows guide](WINDOWS.en.md). WSL2 is a suitable choice when the agent should not see Windows host processes and network adapters.

### Docker Desktop

```powershell
py -3 windows.py build --backend docker
py -3 windows.py check --backend docker
py -3 windows.py new demo --backend docker --copy 'C:\Projects\my-project'
py -3 windows.py skills demo --backend docker
py -3 windows.py selftest default --backend docker
py -3 windows.py run claude demo --backend docker --access edit
```

Build the image first. Docker Desktop with Linux containers is required. Add `--offline` to disable networking; otherwise access follows the selected profile. Setup may download images and tools.

### Separate Windows account (`user`)

This backend applies ACLs to the selected workspace and routes permitted traffic through the selected network adapter. The agent can still see Windows processes and network adapters. Setup and launch require the launcher to have administrator rights; the CLI agent itself runs under a separate, unprivileged account.

```powershell
py -3 windows.py interfaces --backend user
py -3 windows.py setup-user --backend user --username AIWorker --interface '{ADAPTER-GUID}'
py -3 windows.py new demo --backend user --copy 'C:\Projects\my-project'
py -3 windows.py skills demo --backend user
py -3 windows.py run claude demo --backend user --access edit -- 'C:\Tools\claude.exe'
```

Copy an adapter GUID from the `interfaces` output. After `--`, provide the path to the agent CLI executable. Remove the managed account and its rules with `py -3 windows.py remove-user --backend user --username AIWorker`. See [WINDOWS_NATIVE.en.md](WINDOWS_NATIVE.en.md) for details and limitations.

## Help and maintenance commands

| Command | What it does |
|---|---|
| `sandbox` / `sandbox tui` | Opens the terminal desktop. The widget UI requires `requirements-tui.txt`; `--season spring` selects a theme and `--preview windows` opens a demo with actions disabled. |
| `sandbox new NAME [--copy PATH]` | Creates a workspace and optionally copies a project into it. Common secret files such as `.env`, keys and credentials are skipped. It will not overwrite an existing workspace. |
| `sandbox ws` | Lists project copies. `--json` prints only their names as JSON. |
| `sandbox list` | Lists available launch profiles. |
| `sandbox show PROFILE` | Displays profile settings: project access, network, resource limits and allowed paths. `--json` prints JSON. |
| `sandbox check` | Checks required components and whether the system supports the main isolation mechanisms. This is a readiness check, not a full security-boundary test. |
| `sandbox selftest [PROFILE]` | Runs probes from inside the sandbox against test fixtures. Results reflect the current system; this is not a source-code audit. |
| `sandbox audit [NAME]` | Searches a workspace for files the host may execute or load (for example, Git hooks and IDE settings). Without a name, it checks the current directory if it is a managed workspace. |
| `sandbox skills NAME` | Installs Claude Code and Codex skill files in a workspace. Skills explain the workflow to an agent but do not enforce isolation. |
| `sandbox log [-n 40]` | Shows recent launch log entries from today. Example: `sandbox log -n 100`. |
| `sandbox run PROFILE NAME -- COMMAND [ARGS]` | Runs a program inside the selected profile. Without `-- COMMAND`, it uses the command configured in the profile. |

### Terms and options

- A **profile** (`claude`, `codex`, `default`) defines the command, network access, extra allowed paths and limits. Inspect one with `sandbox show claude`.
- A **workspace** is a separate directory under `~/sandbox/workspaces/`; the launcher does not modify the original project.
- Linux networking is configured in the profile: usually disabled or limited to listed domains. `--net off` forces it off. On Windows, use `--offline`.
- `--ro PATH` mounts an extra path read-only; `--rw PATH` grants write access to an explicitly added path. Use these only when needed.
- `--dry-run` prints the assembled Linux command without starting the agent; Windows supports it for `run` and `shell`.
- `--yes` skips the launch confirmation. Linux `--allow-outside` and `--allow-sensitive` remove protections; they are not needed for normal use.
- On Windows, `--backend` selects `wsl`, `docker` or `user`. This option is not used by the Linux CLI.

If a command fails, inspect its arguments with `sandbox --help`, `sandbox run --help` or `py -3 windows.py --help`. Platform setup and troubleshooting are covered in the [full manual](MANUAL.en.md) and [Windows guide](WINDOWS.en.md).
