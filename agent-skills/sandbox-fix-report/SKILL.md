---
name: sandbox-fix-report
description: Investigate and fix a bug inside the selected sandbox project, then report the cause, change and checks.
---

Use this skill when the user asks to fix a defect in this project.

1. Follow `AGENT_POLICY.md` from `SANDBOX_POLICY` and the project's instructions. Work only in `SANDBOX_WORKSPACE`.
2. Reproduce the relevant error using the project's own files and commands. Do not inspect host processes, interfaces, VPN, routes, services or unrelated files.
3. Fix the cause in the project. Run the smallest meaningful checks in the sandbox.
4. Report the problem, changed files, checks and results, and any check you could not complete. Do not treat an exception as proof of safety.
