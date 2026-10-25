"""Controlled fixtures for the terminal desktop and project-scoped skill installation."""
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import skills
import tui
import windows


class DesktopTests(unittest.TestCase):
    def test_preview_has_both_platforms_without_running_checks_or_agents(self):
        for platform in ("linux", "windows"):
            with self.subTest(platform=platform), patch("sys.stdout", new_callable=io.StringIO) as output, \
                    patch.object(tui, "checks", side_effect=AssertionError("preview touched files")), \
                    patch.object(tui.subprocess, "run", side_effect=AssertionError("preview started process")):
                self.assertEqual(tui.main(platform, ROOT, preview=platform, season="summer"), 0)
            screen = output.getvalue()
            self.assertIn("SAND", screen)
            self.assertIn("ДЕМО:", screen)
            self.assertIn("PIXEL SEASON", screen)
            self.assertIn("РАБОЧИЙ СТОЛ", screen)
            self.assertIn("WINDOWS" if platform == "windows" else "LINUX", screen)

    def test_narrow_seasonal_screen_fits_and_offers_all_actions(self):
        for season in tui.SEASONS:
            screen = tui.render("linux", "bubblewrap", season, "demo", "codex", "edit", tui.preview_checks(), width=60)
            self.assertTrue(all(len(line) == 60 for line in screen.splitlines()))
            self.assertIn("[8] Тесты проекта", screen)
            self.assertIn("[0] Выход", screen)

    def test_season_art_and_numbered_button_labels_are_rendered(self):
        screens = [tui.render("linux", "bubblewrap", season, "demo", "claude", "read",
                              tui.preview_checks(), width=100) for season in tui.SEASONS]
        self.assertEqual(len({tuple(screen.splitlines()[1:]) for screen in screens}), len(tui.SEASONS))
        for screen in screens:
            self.assertIn("[1] Открыть проект", screen)
            self.assertIn("[6] Запустить агента", screen)
            self.assertIn("[7] Сезон", screen)

    def test_fullscreen_game_scene_fills_viewport_and_animates_without_color(self):
        render = lambda frame: tui.render_fullscreen("linux", "bubblewrap", "summer", "demo", "claude", "read",
                                                     tui.preview_checks(), width=80, height=24, frame=frame, color=False)
        first, second = render(0), render(1)
        self.assertEqual(len(first.splitlines()), 23)
        self.assertTrue(all(len(line) == 80 for line in first.splitlines()))
        self.assertNotEqual(first, second)
        self.assertIn("[6]  Запустить агента", first)
        colored = tui.render_fullscreen("linux", "bubblewrap", "winter", "demo", "claude", "read",
                                        tui.preview_checks(), width=80, height=24, color=True)
        self.assertIn("\x1b[38;2;", colored)

    def test_commands_are_argv_and_project_tests_stay_inside_backend(self):
        desktop = tui.Desktop("linux", ROOT, "", "summer")
        self.assertEqual(desktop.argv("run", "default", "demo", extra=["--net", "off", "--", "python3", "-m", "unittest"])[-6:],
                         ["--net", "off", "--", "python3", "-m", "unittest"])
        win = tui.Desktop("windows", ROOT, "user", "winter")
        win.username, win.interface = "AIWorker", "ca951180-7a7e-438e-82c6-f297c39f8c10"
        args = win.argv("setup-user")
        self.assertIn("--backend", args)
        self.assertEqual(args[args.index("--interface") + 1], win.interface)
        self.assertNotIn("shell=True", args)

    def test_health_check_detects_broken_module_and_does_not_execute_it(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / "sandbox.py").write_text("def broken(:\n", encoding="utf-8")
            with patch.object(tui.subprocess, "run", side_effect=AssertionError("checks executed code")):
                results = list(tui.checks(base, "linux"))
        self.assertEqual(results[0][0:2], ("sandbox.py", "bad"))
        self.assertTrue(any(status == "bad" for _, status, _ in results))

    def test_windows_wsl_project_list_comes_from_selected_distribution(self):
        desktop = tui.Desktop("windows", ROOT, "wsl", "summer")
        desktop.distro = "Ubuntu"
        with patch.object(tui.subprocess, "run", return_value=Mock(returncode=0, stdout='["demo"]')) as run:
            self.assertEqual(desktop.names(), ["demo"])
        argv = run.call_args.args[0]
        self.assertIn("--json", argv)
        self.assertEqual(argv[argv.index("--distro") + 1], "Ubuntu")


class SkillTests(unittest.TestCase):
    def test_prepare_installs_both_clients_only_in_selected_copy_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            project = Path(folder) / "copy"
            project.mkdir()
            created = skills.prepare(project)
            self.assertEqual(len(created), 4)
            self.assertEqual(skills.prepare(project), [])
            for path in created:
                self.assertTrue(path.is_relative_to(project))
                self.assertIn("SANDBOX_POLICY", path.read_text("utf-8"))

    def test_changed_skill_or_symlink_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            project = Path(folder) / "copy"
            project.mkdir()
            target = project / ".agents/skills/sandbox-fix-report/SKILL.md"
            target.parent.mkdir(parents=True)
            target.write_text("owner skill", encoding="utf-8")
            with self.assertRaises(OSError):
                skills.prepare(project)
            self.assertEqual(target.read_text("utf-8"), "owner skill")
            target.unlink()
            outside = Path(folder) / "outside"
            outside.mkdir()
            target.parent.rmdir()
            (project / ".agents/skills/sandbox-fix-report").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(OSError):
                skills.prepare(project)
            self.assertEqual(list(outside.iterdir()), [])

    def test_windows_parser_exposes_tui_and_project_skills(self):
        self.assertEqual(windows.parser().parse_args(["tui", "--backend", "user"]).action, "tui")
        self.assertEqual(windows.parser().parse_args(["skills", "demo", "--backend", "docker"]).workspace, "demo")

    def test_widget_ui_and_optional_dependencies_are_packaged(self):
        self.assertIn("textual_tui.py", tui.CORE)
        self.assertTrue((ROOT / "textual_tui.py").is_file())
        requirements = (ROOT / "requirements-tui.txt").read_text("utf-8")
        for package in ("textual>=8.0", "rich>=13", "loguru>=0.7", "openpyxl>=3.1"):
            self.assertIn(package, requirements)


if __name__ == "__main__":
    unittest.main()
