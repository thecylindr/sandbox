# AI Sandbox terminal desktop

[Русский](TUI.md) · [Project overview](README.en.md)

Run `sandbox` or `sandbox tui` in a Linux terminal. On Windows, `start.cmd` starts
the TUI; `start.cmd gui` keeps the graphical window available. The TUI uses only
Python's standard library. It draws a beach umbrella, sand and a deck chair on the
right in summer; spring, autumn and winter have separate scenes. Season follows
the calendar by default and can be changed from menu item `7`. Narrow terminals
show one menu item per row. The startup animation lasts under a second and has no
background worker.

| Menu | Action |
|---|---|
| 1 | Open a managed project copy |
| 2 | Create an empty project or import a copy; the source folder stays untouched |
| 3 | Choose Claude, Codex or default and read/edit access |
| 4 | Install bundled bug-fix and project-test skills for both clients in this copy |
| 5 | Run environment checks or isolation self-tests |
| 6 | Launch the agent through the existing backend |
| 7 | Change the season |
| 8 on Linux | Run a detected project test command inside the sandbox, offline |
| 8 on Windows | Choose WSL2, Docker or `user`; explicitly set up the `user` adapter |

Startup parses packaged Python modules without executing them, checks the policy
file, reads TOML profiles and rejects unsafe network settings. A packaged Windows
ZIP also supplies `SHA256.json` for a local checksum comparison. The checksum list
is not a signed trust root. These are **bundle health checks**, not a proof that
isolation works. Item `5` shows the complete module report and runs the actual
`check` and `selftest` commands on
controlled fixtures. If the current environment refuses namespace creation, that
test fails or skips rather than probing the host.

The two bundled instruction-only skills are installed in the selected project's
`.agents/skills/` for Codex and `.claude/skills/` for Claude. Existing changed files,
symlinks, junctions and hardlinks are not overwritten. The skills follow the
separately mounted `AGENT_POLICY.md`; they grant no extra filesystem or network
access. TUI offers them immediately after creating a project.

On Linux and on Windows WSL2/Docker, item `8` can run a detected Python, Node,
Rust or Go test command through the sandbox with network disabled. In native
Windows `user` mode, use an absolute test `.exe` with the CLI; item `5` still runs
the mode's security self-test. Test output and the exit code appear in the terminal.

Try both visuals without installation or live checks:

```bash
python3 sandbox.py tui --preview linux --season summer
python3 windows.py tui --preview windows --season summer
```

The Windows preview is an emulation of the screen rendered on Linux; native Windows
process, firewall and console behavior has not been validated by that preview.
