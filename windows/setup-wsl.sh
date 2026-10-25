#!/usr/bin/env bash
# Called by the Windows launcher with the package location as a positional argument.
set -euo pipefail
package_dir="$1"
target_dir="$HOME/sandbox"
mkdir -p "$target_dir/profiles" "$target_dir/tests"
if [ "$(cd "$package_dir" && pwd -P)" != "$(cd "$target_dir" && pwd -P)" ]; then
  for name in sandbox.py inner.py seccomp.py probe.py tomlmini.py guard.py neutral.py transport.py ui.py tui.py textual_tui.py requirements-tui.txt skills.py install.sh AGENT_POLICY.md AGENT_POLICY.en.md AGENTS.md AGENTS.en.md README.md README.en.md MANUAL.md MANUAL.en.md COMMANDS.md COMMANDS.en.md SECURITY_REPORT.md SECURITY_REPORT.en.md REPORT_TEMPLATE.md REPORT_TEMPLATE.en.md WINDOWS.md WINDOWS.en.md WINDOWS_NATIVE.md WINDOWS_NATIVE.en.md TUI.md TUI.en.md; do
    cp -- "$package_dir/$name" "$target_dir/$name"
  done
  cp -R -- "$package_dir/agent-skills" "$target_dir/"
  for profile in "$package_dir"/profiles/*.toml; do
    if [ ! -e "$target_dir/profiles/$(basename "$profile")" ]; then
      cp -- "$profile" "$target_dir/profiles/"
    fi
  done
  cp -- "$package_dir/tests/test_security.py" "$target_dir/tests/test_security.py"
  cp -- "$package_dir/tests/test_core.py" "$target_dir/tests/test_core.py"
  cp -- "$package_dir/tests/test_network.py" "$target_dir/tests/test_network.py"
  cp -- "$package_dir/tests/isolated.py" "$target_dir/tests/isolated.py"
fi
bash "$target_dir/install.sh"
