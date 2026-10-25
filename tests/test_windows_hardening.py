"""Windows-часть: поиск программ без текущего каталога, источники импорта, согласованность списков файлов пакета.
Docker, WSL и Windows не нужны; проверяется код и текст скриптов."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import windows as launcher

package_spec = importlib.util.spec_from_file_location("windows_package", ROOT / "windows" / "package.py")
package = importlib.util.module_from_spec(package_spec)
package_spec.loader.exec_module(package)

# модули ядра, которые sandbox.py подключает во время работы
CORE_MODULES = ("tomlmini.py", "guard.py", "neutral.py", "seccomp.py", "inner.py", "probe.py", "transport.py")


class ExecutableLookupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sandbox-lookup-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project, self.trusted = self.base / "project", self.base / "trusted"
        for d in (self.project, self.trusted):
            d.mkdir()
        old = os.getcwd()
        os.chdir(self.project)
        self.addCleanup(os.chdir, old)

    def make(self, folder, name="fixture-docker"):
        path = folder / name
        path.write_text("#!/bin/sh\n")
        path.chmod(0o755)
        return str(path)

    def search(self, path_value):
        with patch.dict(os.environ, {"PATH": path_value}):
            return launcher.executable("fixture-docker")

    def test_program_in_current_project_folder_is_never_used(self):
        self.make(self.project)
        trusted = self.make(self.trusted)
        self.assertEqual(self.search(os.pathsep.join(["", str(self.project), ".", str(self.trusted)])), trusted)

    def test_missing_program_is_reported_even_if_planted_in_cwd(self):
        self.make(self.project)
        with self.assertRaises(launcher.LauncherError):
            self.search(os.pathsep.join(["", ".", str(self.project)]))

    def test_relative_path_entries_are_ignored(self):
        os.makedirs("rel")
        self.make(Path("rel"))
        with self.assertRaises(launcher.LauncherError):
            self.search("rel")

    def test_files_inside_launcher_data_are_never_returned(self):
        data = self.base / "package" / "windows-data" / "workspaces" / "demo"
        data.mkdir(parents=True)
        self.make(data)
        with patch.object(launcher, "ROOT", self.base / "package"), patch.object(launcher, "DATA", self.base / "package" / "windows-data"):
            with self.assertRaises(launcher.LauncherError):
                self.search(str(data))


class ImportSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sandbox-import-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        (self.base / "package").mkdir()
        shutil.copyfile(ROOT / "AGENT_POLICY.md", self.base / "package" / "AGENT_POLICY.md")
        for attribute, value in (("ROOT", self.base / "package"), ("DATA", self.base / "package" / "windows-data")):
            p = patch.object(launcher, attribute, value)
            p.start()
            self.addCleanup(p.stop)

    def rejected(self, source):
        with self.assertRaises(launcher.LauncherError):
            launcher.new_project(argparse.Namespace(workspace="demo", copy=str(source)))

    def test_profile_data_and_system_folders_are_not_importable(self):
        for parts in (("AppData", "Roaming", "x"), (".config", "x"), (".azure",), ("Windows", "Temp"), ("Program Files", "Tool")):
            folder = self.base.joinpath(*parts)
            folder.mkdir(parents=True)
            with self.subTest(folder=str(folder)):
                self.rejected(folder)

    def test_filesystem_root_is_not_importable(self):
        self.rejected(Path(self.base.anchor))

    def test_ordinary_project_is_importable(self):
        source = self.base / "code" / "project"
        source.mkdir(parents=True)
        (source / "app.py").write_text("x")
        with patch("sys.stdout"):
            self.assertEqual(launcher.new_project(argparse.Namespace(workspace="demo", copy=str(source))), 0)


class ScriptTextTests(unittest.TestCase):
    def test_start_cmd_leaves_the_current_directory_before_looking_up_programs(self):
        text = (ROOT / "start.cmd").read_text()
        self.assertIn('NoDefaultCurrentDirectoryInExePath=1', text)
        self.assertLess(text.index('cd /d "%~dp0"'), text.index("where py"))

    def test_installer_writes_absolute_interpreter_and_is_ascii(self):
        raw = (ROOT / "install.ps1").read_bytes()
        raw.decode("ascii")                                  # Windows PowerShell 5.1 читает файл без BOM в ANSI
        text = raw.decode()
        self.assertIn("NoDefaultCurrentDirectoryInExePath=1", text)
        self.assertIn("Get-AsciiPath $python", text)
        self.assertNotRegex(text, r'py -3 "%~dp0')           # запуск «py» по имени подхватил бы файл из текущей папки

    def test_docker_proxy_log_is_escaped(self):
        self.assertIn("sandbox.printable(line)", (ROOT / "docker" / "proxy.py").read_text())

    def test_every_runtime_module_is_packaged_and_copied_into_wsl(self):
        setup = (ROOT / "windows" / "setup-wsl.sh").read_text()
        for module in CORE_MODULES:
            self.assertTrue((ROOT / module).is_file(), module)
            self.assertIn(module, package.FILES, f"{module} не попадёт в архив Windows")
            self.assertIn(module, setup, f"{module} не копируется в WSL")

    def test_packaged_files_exist_and_are_not_symlinks(self):
        for name in package.FILES:
            path = ROOT / name
            self.assertTrue(path.is_file() and not path.is_symlink(), name)


if __name__ == "__main__":
    unittest.main()
