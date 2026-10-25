"""Build a source-only Windows ZIP; no recursive inclusion of runtime data."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "windows.py", "sandbox.py", "inner.py", "seccomp.py", "probe.py", "tomlmini.py", "guard.py", "neutral.py", "transport.py", "ui.py", "tui.py", "textual_tui.py", "requirements-tui.txt", "skills.py",
    "install.sh", "install.ps1", "start.cmd",
    ".dockerignore", "AGENT_POLICY.md", "AGENT_POLICY.en.md", "AGENTS.md", "AGENTS.en.md", "README.md", "README.en.md",
    "MANUAL.md", "MANUAL.en.md", "COMMANDS.md", "COMMANDS.en.md", "WINDOWS.md", "WINDOWS.en.md", "WINDOWS_NATIVE.md", "WINDOWS_NATIVE.en.md", "TUI.md", "TUI.en.md",
    "SECURITY_REPORT.md", "SECURITY_REPORT.en.md", "REPORT_TEMPLATE.md", "REPORT_TEMPLATE.en.md",
    "profiles/default.toml", "profiles/claude.toml", "profiles/codex.toml",
    "docker/Dockerfile", "docker/entry.py", "docker/proxy.py", "docker/selftest.py",
    "windows/setup-wsl.sh", "windows/package.py", "tests/test_security.py", "tests/test_core.py", "tests/test_windows.py", "tests/test_windows_hardening.py",
    "tests/test_network.py", "tests/isolated.py",
    "windows/native_user.py", "windows/native_winapi.py", "windows/native_proxy.py",
    "windows/native-control.ps1", "windows/native-selftest.ps1", "tests/test_windows_native.py",
    "tests/test_windows_native_review.py",
    "agent-skills/sandbox-fix-report/SKILL.md", "agent-skills/sandbox-project-tests/SKILL.md", "tests/test_tui.py",
)


def build():
    target = ROOT / "dist/ai-sandbox-windows.zip"
    target.parent.mkdir(exist_ok=True)
    hashes = {}
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in FILES:
            path = ROOT / name
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"invalid source artifact: {name}")
            data = path.read_bytes()
            if path.suffix in (".cmd", ".ps1"):
                data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            hashes[name] = hashlib.sha256(data).hexdigest()
            archive.writestr("ai-sandbox/" + name, data)
        archive.writestr("ai-sandbox/SHA256.json", json.dumps(hashes, indent=2) + "\n")
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("ZIP integrity check failed")
    print(target)


if __name__ == "__main__":
    build()
