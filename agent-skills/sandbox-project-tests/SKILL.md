---
name: sandbox-project-tests
description: Select and run relevant tests for the current sandbox project, and explain failures without changing isolation settings.
---

Use this skill when the user asks to test the selected project.

1. Follow `SANDBOX_POLICY` and project instructions. Find the test command in project documentation or local manifests.
2. Run only project tests inside `SANDBOX_WORKSPACE`. Never run project hooks, IDE tasks or test scripts on the host outside sandbox.
3. Use the test process you started, its exit code and its output. Do not inspect other processes or network interfaces.
4. If a dependency or allowed network request fails, record the error. Do not widen filesystem or network access to make the test pass.
5. Present a concise pass/fail/skip result and the exact command used.
