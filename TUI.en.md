# AI Sandbox terminal desktop

[Русский](TUI.md) · [Project overview](README.en.md)

The modern screen uses
Textual/Rich widgets: settings and buttons on the left, with a large animated seasonal
card, module status table, events and action log on the right. The pixel-art scene
animates with lightweight frames and no background process. It requires Python 3.10+
and the packages in `requirements-tui.txt` (Textual, Rich, Loguru, openpyxl). Linux/WSL
and Windows use the same subcommands (`tui`, `check`, `new`, and the rest); only the
launcher filename differs. From the project directory:

```bash
# Linux / WSL2: use a stable isolated environment instead of changing system Python
python3 -m venv "$HOME/sandbox/.venv"   # Python 3.10+
"$HOME/sandbox/.venv/bin/python" -m pip install -r requirements-tui.txt
./start.sh tui
```

On Windows, from the extracted folder:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-tui.txt
start.cmd tui
```

If Textual is not installed, the launcher shows an installation hint and starts its
lightweight fallback. Press `0`–`8` to activate actions without Enter; Textual also
supports mouse, Tab and Enter. `Esc` or `q` exits. Select a season from the left
sidebar. “Save XLSX report” writes the bundle checks and current settings to
`state/reports/`.

Existing projects appear in the **Existing project** selector at the top of the
left sidebar. Choose one there; `[1]` refreshes the list. To start a new project, enter
a name under **New project** and press `[2]`. The source folder is optional: leave
it blank for an empty project, or provide a folder to create a managed copy. The source
is left untouched. Creating a project also installs the Claude and Codex skills. The
summary on the right shows the selected copy and the next step.

After choosing a project, set the agent and access mode in the sidebar. The numbered
buttons are:

| Key | Action |
|---|---|
| 1 | Refresh the existing-project list |
| 2 | Create a managed working copy |
| 3 | Install Claude and Codex project skills |
| 4 | Check the sandbox environment |
| 5 | Run the isolation self-test |
| 6 | Launch the agent inside the selected project copy |
| 7 | Run detected project tests inside the sandbox |
| 8 | Save an XLSX report |

On Windows, choose WSL2, Docker or `user` in the isolation selector. User and network
adapter setup controls appear below it.

Startup parses packaged Python modules without executing them, checks the policy
file, reads TOML profiles and rejects unsafe network settings. A packaged Windows
ZIP also supplies `SHA256.json` for a local checksum comparison. The checksum list
is not a signed trust root. These are **bundle health checks**, not a proof that
isolation works. Key `4` checks the environment, while key `5` runs the actual
`selftest` in the selected isolation mode with controlled fixtures. If the current
environment refuses namespace creation, that test fails or skips rather than probing
the host.

The two bundled instruction-only skills are installed in the selected project's
`.agents/skills/` for Codex and `.claude/skills/` for Claude. Existing changed files,
symlinks, junctions and hardlinks are not overwritten. The skills follow the
separately mounted `AGENT_POLICY.md`; they grant no extra filesystem or network
access. TUI offers them immediately after creating a project, and key `3` can install
them later.

On Linux and on Windows WSL2/Docker, key `7` can run a detected Python, Node,
Rust or Go test command through the sandbox with network disabled. In native
Windows `user` mode, use an absolute test `.exe` with the CLI; key `5` still runs
the mode's security self-test. Test output and the exit code appear in the terminal.

With dependencies installed, preview opens the same widget-based screen with actions
disabled. In a non-interactive terminal, the command prints a static mock:

```bash
python3 sandbox.py tui --preview linux --season summer
python3 windows.py tui --preview windows --season summer
```

The Windows preview is an emulation of the screen rendered on Linux; native Windows
process, firewall and console behavior has not been validated by that preview.
