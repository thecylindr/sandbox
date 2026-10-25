"""Windows launcher regressions: no Docker daemon, WSL, host discovery or real network needed."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import windows as launcher

entry_spec = importlib.util.spec_from_file_location("container_entry", ROOT / "docker/entry.py")
entry = importlib.util.module_from_spec(entry_spec)
entry_spec.loader.exec_module(entry)


class WindowsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sandbox-windows-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "package"
        self.root.mkdir()
        shutil.copytree(ROOT / "profiles", self.root / "profiles")
        shutil.copyfile(ROOT / "AGENT_POLICY.md", self.root / "AGENT_POLICY.md")
        for attribute, value in (("ROOT", self.root), ("DATA", self.root / "windows-data")):
            p = patch.object(launcher, attribute, value)
            p.start()
            self.addCleanup(p.stop)
        self.project = launcher.project_path("demo", exists=False)
        self.project.mkdir()

    def args(self, **changes):
        values = dict(action="run", backend="docker", distro=None, profile="claude", workspace="demo",
                      access="read", offline=False, dry_run=False, command=[])
        return argparse.Namespace(**(values | changes))

    def plan(self, **changes):
        return launcher.docker_plan(self.args(**changes), self.project, self.base / "proxy.json", "fixture123", False)

    def test_docker_has_no_host_namespace_or_docker_socket(self):
        plan = self.plan()
        args = plan["agent"]
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--user") + 1], "1000:1000")
        self.assertIn("--read-only", args)
        self.assertEqual(args[args.index("--pull") + 1], "never")
        self.assertIn("no-new-privileges=true", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--pid", args)
        self.assertNotIn("--device", args)
        mounts = [args[i + 1] for i, v in enumerate(args) if v == "--mount"]
        self.assertFalse(any("docker.sock" in v or "docker_engine" in v for v in mounts))
        binds = [v for v in mounts if v.startswith("type=bind")]
        self.assertEqual(len(binds), 6)  # project, three policies and two synthetic network files
        self.assertTrue(all(str(self.project) in v or "AGENT_POLICY.md" in v
                            or "target=/etc/hosts," in v or "target=/etc/resolv.conf," in v for v in binds))
        self.assertIn("--memory", args)
        self.assertIn("--pids-limit", args)

    def test_read_access_mounts_project_and_proxy_socket_readonly(self):
        args = self.plan()["agent"]
        mounts = [args[i + 1] for i, v in enumerate(args) if v == "--mount"]
        self.assertTrue(next(m for m in mounts if "target=/workspace" in m).endswith(",readonly"))
        self.assertTrue(next(m for m in mounts if "target=/run/sandbox-proxy" in m).endswith(",readonly"))

    def test_edit_changes_only_project_mount_access(self):
        before, after = self.plan(), self.plan(access="edit")
        read = next(v for v in before["agent"] if "target=/workspace" in v)
        edit = next(v for v in after["agent"] if "target=/workspace" in v)
        self.assertEqual(read, edit + ",readonly")
        self.assertEqual(before["home"], after["home"])

    def test_offline_has_no_proxy_volume_or_sidecar(self):
        plan = self.plan(offline=True)
        self.assertIsNone(plan["proxy"])
        self.assertIsNone(plan["socket_volume"])
        self.assertNotIn("SANDBOX_NET=allowlist", plan["agent"])

    def test_proxy_cannot_read_project_home_or_credentials(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fixture-secret"}):
            plan = self.plan()
        text = " ".join(plan["proxy"])
        self.assertNotIn(str(self.project), text)
        self.assertNotIn(plan["home"], text)
        self.assertNotIn("ANTHROPIC_API_KEY", text)
        self.assertNotIn("fixture-secret", json.dumps(plan))
        self.assertIn("ANTHROPIC_API_KEY", plan["agent"])
        self.assertNotIn("--publish", plan["proxy"])
        self.assertNotIn("--privileged", plan["proxy"])

    def test_home_is_separate_for_each_project(self):
        args = self.args()
        other = launcher.docker_plan(args, self.project.parent / "other", self.base / "proxy.json", "fixture456", False)
        self.assertNotEqual(self.plan()["home"], other["home"])

    def test_synthetic_dns_and_hosts_are_readonly_agent_mounts(self):
        plan = self.plan()
        mounts = [plan["agent"][i + 1] for i, value in enumerate(plan["agent"]) if value == "--mount"]
        for name in ("hosts", "resolv.conf"):
            entry = next(m for m in mounts if f"target=/etc/{name}," in m)
            self.assertTrue(entry.endswith(",readonly"))
            self.assertIn(str(self.base / name), entry)
            self.assertNotIn(entry, plan["proxy"])

    def test_proxy_network_is_unique_and_agent_has_no_egress_interface(self):
        plan = self.plan()
        self.assertTrue(plan["network"].startswith("sbx-egress-"))
        self.assertEqual(plan["proxy"][plan["proxy"].index("--network") + 1], plan["network"])
        self.assertNotIn(plan["network"], plan["agent"])
        self.assertIsNone(self.plan(offline=True)["network"])

    def test_csv_mount_injection_is_rejected(self):
        with self.assertRaises(launcher.LauncherError):
            launcher.mount("bind", "C:\\project,readonly=false", "/workspace", True)

    def test_names_reject_traversal_and_windows_devices(self):
        for name in ("../outside", "C:\\test", "CON", "NUL.txt", "COM1", "demo.", "a/b"):
            with self.subTest(name=name), self.assertRaises(launcher.LauncherError):
                launcher.validate_name(name)

    def test_project_symlink_is_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        alias = self.project.parent / "alias"
        try:
            alias.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("creating a symlink is unavailable for this Windows account")
        with self.assertRaises(launcher.LauncherError):
            launcher.project_path("alias")

    def test_import_creates_independent_copy_and_skips_env(self):
        source = self.base / "source with spaces"
        source.mkdir()
        (source / "app.py").write_text("original")
        (source / ".env.production").write_text("fixture-secret")
        with patch("sys.stdout", new=io.StringIO()):
            launcher.new_project(argparse.Namespace(workspace="imported", copy=str(source)))
        project = launcher.project_path("imported")
        self.assertFalse((project / ".env.production").exists())
        (project / "app.py").write_text("edited")
        self.assertEqual((source / "app.py").read_text(), "original")
        self.assertIn("VPN", (project / "AGENTS.md").read_text(encoding="utf-8"))

    def test_import_rejects_existing_destination(self):
        (self.project / "keep").write_text("original")
        with self.assertRaises(launcher.LauncherError):
            launcher.new_project(argparse.Namespace(workspace="demo", copy=None))
        self.assertEqual((self.project / "keep").read_text(), "original")

    def test_python311_detects_windows_reparse_points_without_is_junction(self):
        with patch.object(Path, "lstat", return_value=Mock(st_mode=0o40755, st_file_attributes=0x400)):
            self.assertTrue(launcher.redirect(self.base / "junction"))

    def test_wsl_argument_data_never_becomes_shell_code(self):
        args = self.args(backend="wsl", command=["python3", "a script.py", "$(fixture); ' quoted"])
        with patch.object(launcher, "wsl_prefix", return_value=["wsl.exe"]), patch.object(launcher, "call", return_value=Mock(returncode=0)) as call:
            self.assertEqual(launcher.run_wsl(args), 0)
        argv = call.call_args.args[0]
        script = argv[argv.index("-c") + 1]
        self.assertNotIn("fixture", script)
        self.assertEqual(argv[-3:], args.command)
        self.assertIn("--access", argv)
        self.assertIn("read", argv)

    def test_wsl_import_uses_argument_not_interpolation(self):
        args = self.args(action="new", copy="C:\\user's project; $fixture")
        with patch.object(launcher, "wsl_prefix", return_value=["wsl.exe"]), patch.object(launcher, "call", return_value=Mock(returncode=0)) as call:
            launcher.run_wsl(args)
        argv = call.call_args.args[0]
        self.assertNotIn("fixture", argv[argv.index("-c") + 1])
        self.assertIn("--copy", argv)

    def test_remote_docker_endpoint_is_rejected(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://fixture.invalid:2375", "DOCKER_CONTEXT": ""}), patch.object(launcher, "executable", return_value="docker"), patch.object(launcher, "call") as call:
            with self.assertRaises(launcher.LauncherError):
                launcher.require_local_docker()
            call.assert_not_called()

    def test_docker_cleanup_only_targets_own_resources_after_failure(self):
        calls = []

        def fake(argv, **kwargs):
            calls.append(argv)
            if len(argv) > 2 and argv[1] == "run" and "--detach" not in argv:
                return Mock(returncode=17)
            return Mock(returncode=0, stdout="fixture", stderr="")

        with patch.object(launcher, "require_local_docker", return_value="docker"), patch.object(launcher, "call", side_effect=fake), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(launcher.run_docker(self.args()), 17)
        removed = [c for c in calls if c[1:3] == ["rm", "--force"]]
        self.assertEqual(len(removed), 2)
        self.assertTrue(any(c[-1].startswith("sbx-agent-") for c in removed))
        self.assertTrue(any(c[-1].startswith("sbx-proxy-") for c in removed))
        self.assertTrue(any(c[1:3] == ["volume", "rm"] and c[-1].startswith("sbx-socket-") for c in calls))
        self.assertFalse(any("prune" in c or "ps" in c for c in calls))
        self.assertFalse(any(c[1:3] == ["volume", "rm"] and c[-1].startswith("sbx-home-") for c in calls))

    def test_failed_proxy_start_is_also_cleaned_up(self):
        calls = []

        def fake(argv, **kwargs):
            calls.append(argv)
            if argv[1] == "run" and "--detach" in argv:
                raise launcher.LauncherError("fixture startup failure")
            return Mock(returncode=0, stdout="", stderr="")

        with patch.object(launcher, "require_local_docker", return_value="docker"), patch.object(launcher, "call", side_effect=fake):
            with self.assertRaises(launcher.LauncherError):
                launcher.run_docker(self.args())
        self.assertTrue(any(c[1:3] == ["rm", "--force"] and c[-1].startswith("sbx-proxy-") for c in calls))
        self.assertTrue(any(c[1:3] == ["volume", "rm"] and c[-1].startswith("sbx-socket-") for c in calls))

    def test_log_failure_does_not_leave_proxy_volume_or_network(self):
        calls = []
        real_directory = launcher.directory

        def directory(path):
            if Path(path).name == "logs":
                raise PermissionError("fixture log permission failure")
            return real_directory(path)

        def fake(argv, **kwargs):
            calls.append(argv)
            return Mock(returncode=0, stdout="fixture", stderr="")

        with patch.object(launcher, "require_local_docker", return_value="docker"), patch.object(launcher, "directory", side_effect=directory), patch.object(launcher, "call", side_effect=fake), patch("sys.stdout"), patch("sys.stderr"):
            self.assertEqual(launcher.run_docker(self.args()), 1)
        self.assertTrue(any(c[1:3] == ["rm", "--force"] and c[-1].startswith("sbx-proxy-") for c in calls))
        self.assertTrue(any(c[1:3] == ["volume", "rm"] for c in calls))
        self.assertTrue(any(c[1:3] == ["network", "rm"] for c in calls))

    def test_cleanup_exception_does_not_prevent_other_cleanup(self):
        calls = []

        def fake(argv, **kwargs):
            calls.append(argv)
            if argv[1:3] == ["rm", "--force"] and argv[-1].startswith("sbx-proxy-"):
                raise launcher.LauncherError("fixture engine timeout")
            return Mock(returncode=0, stdout="", stderr="")

        with patch.object(launcher, "require_local_docker", return_value="docker"), patch.object(launcher, "call", side_effect=fake), patch("sys.stdout"), patch("sys.stderr"):
            self.assertEqual(launcher.run_docker(self.args()), 1)
        self.assertTrue(any(c[1:3] == ["volume", "rm"] for c in calls))
        self.assertTrue(any(c[1:3] == ["network", "rm"] for c in calls))

    def test_selftest_exercises_offline_and_proxy_without_credentials(self):
        calls = []

        def run(args, **kwargs):
            calls.append((vars(args).copy(), kwargs))
            return 0

        with patch.object(launcher, "run_docker", side_effect=run):
            self.assertEqual(launcher.selftest_docker(self.args()), 0)
        self.assertEqual([item[0]["access"] for item in calls], ["read", "edit", "read"])
        self.assertEqual([item[0]["offline"] for item in calls], [True, True, False])
        self.assertTrue(calls[-1][1]["test_network"])
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fixture"}):
            plan = launcher.docker_plan(self.args(), self.project, self.base / "proxy.json", "fixture", False, True)
        self.assertNotIn("ANTHROPIC_API_KEY", plan["agent"])
        self.assertEqual(plan["config"], {"domains": ["fixture.invalid"]})

    def test_container_job_filters_host_environment(self):
        spec = entry.job(["bash"], {"SECRET_HOST_FIXTURE": "secret", "HOME": "/host", "HTTP_PROXY": "http://host:1", "SANDBOX_ACCESS": "read", "SANDBOX_NET": "off"})
        self.assertNotIn("SECRET_HOST_FIXTURE", spec["env"])
        self.assertNotIn("HTTP_PROXY", spec["env"])
        self.assertEqual(spec["env"]["HOME"], "/home/node")
        self.assertNotIn("/workspace", spec["rw"])
        self.assertIsNone(spec["bridge"])

    def test_container_job_proxy_only_uses_local_loopback_bridge(self):
        spec = entry.job(["claude"], {"SANDBOX_ACCESS": "edit", "SANDBOX_NET": "allowlist"})
        self.assertEqual(spec["env"]["HTTPS_PROXY"], "http://127.0.0.1:3128")
        self.assertEqual(spec["bridge"][0], "/run/sandbox-proxy/proxy.sock")
        self.assertIn("/workspace", spec["rw"])


@unittest.skipIf(os.name == "nt", "requires Linux prctl; affects only a test child process")
class FilterTests(unittest.TestCase):
    def test_seccomp_install_in_own_child_fails_closed(self):
        code = '''
import ctypes, errno, os, platform, seccomp
seccomp.install()
libc=ctypes.CDLL(None, use_errno=True)
libc.syscall.restype=ctypes.c_long
nr=seccomp.DENY[platform.machine()]["unshare"]
result=libc.syscall(ctypes.c_long(nr), ctypes.c_long(0))
assert result == -1 and ctypes.get_errno() == errno.EPERM
assert libc.prctl(39, 0, 0, 0, 0) == 1
print("filter OK")
'''
        result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("filter OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
