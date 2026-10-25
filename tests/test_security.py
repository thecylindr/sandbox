"""Регрессии изоляции; только временные файлы, собственные команды и имитация сокетов."""
import argparse
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("sandbox_under_test", ROOT / "sandbox.py")
sandbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sandbox)


@unittest.skipIf(os.name == "nt", "Linux/bubblewrap tests; Windows launcher tests are in test_windows.py")
class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sandbox-regression-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "sandbox"
        self.root.mkdir()
        for name in ("WORKSPACES", "HOMES", "STATE", "PROFILES", "LOGS"):
            value = self.root / name.lower()
            value.mkdir()
            p = patch.object(sandbox, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(sandbox, "ROOT", self.root)
        p.start()
        self.addCleanup(p.stop)
        self.ws = sandbox.WORKSPACES / "project"
        self.ws.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()

    def build(self, cfg=None, name="test"):
        cfg = copy.deepcopy(sandbox.DEFAULTS) if cfg is None else cfg
        with patch.object(sandbox.subprocess, "run", return_value=Mock(stdout="--disable-userns")):
            argv, binds, fds = sandbox.build(cfg, str(self.ws), ["/usr/bin/true"], self.base, False, name)
        for fd in fds:
            self.addCleanup(os.close, fd)
        with os.fdopen(os.dup(fds[-1]), "rb") as stream:
            job = json.loads(stream.read())
        return argv, binds, job

    def test_workspace_symlink_cannot_select_external_directory(self):
        (sandbox.WORKSPACES / "escape").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(SystemExit):
            sandbox.resolve_workspace("escape")

    def test_workspace_symlink_to_other_project_is_also_rejected(self):
        (sandbox.WORKSPACES / "alias").symlink_to(self.ws, target_is_directory=True)
        with self.assertRaises(SystemExit):
            sandbox.resolve_workspace("alias")

    def test_new_does_not_follow_existing_destination_links(self):
        sentinel = self.outside / "keep.txt"
        sentinel.write_text("original")
        (self.ws / "keep.txt").symlink_to(sentinel)
        src = self.base / "source"
        src.mkdir()
        (src / "keep.txt").write_text("replacement")
        with self.assertRaises(SystemExit):
            sandbox.cmd_new(argparse.Namespace(name="project", copy=str(src)))
        self.assertEqual(sentinel.read_text(), "original")

    def test_new_creates_instructions_and_excludes_env_variants(self):
        src = self.base / "source"
        src.mkdir()
        (src / ".env.production").write_text("fixture-secret")
        (src / "app.py").write_text("print('ok')")
        sandbox.cmd_new(argparse.Namespace(name="new-project", copy=str(src)))
        new = sandbox.WORKSPACES / "new-project"
        self.assertFalse((new / ".env.production").exists())
        self.assertTrue((new / "app.py").is_file())
        self.assertIn("VPN", (new / "AGENTS.md").read_text())
        self.assertIn("VPN", (new / "CLAUDE.md").read_text())

    def test_new_preserves_project_instruction_files(self):
        src = self.base / "source"
        src.mkdir()
        (src / "AGENTS.md").write_text("Project test command")
        sandbox.cmd_new(argparse.Namespace(name="new-project", copy=str(src)))
        self.assertEqual((sandbox.WORKSPACES / "new-project" / "AGENTS.md").read_text(), "Project test command")

    def test_profile_traversal_rejected_and_external_id_stays_a_name(self):
        for name in ("../escape", "/tmp/escape", "a/b", ".", ".."):
            with self.subTest(name=name), self.assertRaises(SystemExit):
                sandbox.profile_id(name)
        safe = sandbox.profile_id("/tmp/external/profile.toml")
        self.assertEqual(Path(safe).name, safe)
        self.assertTrue(safe.startswith("profile-"))
        with self.assertRaises(SystemExit):
            self.build(name="../../outside")

    def test_home_symlink_is_rejected(self):
        (sandbox.HOMES / "test").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(SystemExit):
            self.build()

    def test_profile_overrides_do_not_mutate_defaults(self):
        (sandbox.PROFILES / "one.toml").write_text('command = ["true"]\n')
        (sandbox.PROFILES / "two.toml").write_text('command = ["true"]\n')
        one = sandbox.load_profile("one")
        one["ro"].append("/fixture")
        one["env_set"]["FIXTURE"] = "value"
        two = sandbox.load_profile("two")
        self.assertNotIn("/fixture", two["ro"])
        self.assertNotIn("FIXTURE", two["env_set"])

    def test_large_launch_spec_and_policy_bindings(self):
        cfg = copy.deepcopy(sandbox.DEFAULTS)
        cfg["env_set"] = {"LARGE_FIXTURE": "x" * 262144, "SANDBOX": "0", "CODEX_HOME": "/escape"}
        argv, _, job = self.build(cfg)
        self.assertEqual(len(job["env"]["LARGE_FIXTURE"]), 262144)
        self.assertEqual(job["env"]["SANDBOX"], "1")
        self.assertEqual(job["env"]["CODEX_HOME"], str(Path.home() / ".codex"))
        self.assertIn("--unshare-all", argv)
        self.assertNotIn("--share-net", argv)
        destinations = [argv[i + 2] for i, value in enumerate(argv) if value == "--ro-bind"]
        self.assertIn("/run/sandbox/AGENT_POLICY.md", destinations)
        self.assertIn(str(Path.home() / ".codex/AGENTS.override.md"), destinations)
        self.assertIn(str(Path.home() / ".claude/CLAUDE.md"), destinations)
        self.assertNotIn("LARGE_FIXTURE", " ".join(argv))

    def test_bind_source_and_destination_use_canonical_path(self):
        alias = self.base / "alias"
        alias.symlink_to(self.outside, target_is_directory=True)
        cfg = copy.deepcopy(sandbox.DEFAULTS)
        cfg["ro"] = [str(alias)]
        argv, binds, _ = self.build(cfg)
        self.assertIn(str(self.outside), binds)
        self.assertNotIn(str(alias), binds)
        index = argv.index(str(self.outside))
        self.assertEqual(argv[index + 1], str(self.outside))

    def test_explicit_read_access_refuses_nested_rw_override(self):
        child = self.ws / "child"
        child.mkdir()
        cfg = copy.deepcopy(sandbox.DEFAULTS)
        cfg["rw"] = [str(child)]
        args = argparse.Namespace(profile="default", workspace="project", rw=[], ro=[], domain=[], env=[],
                                  net=None, unsafe_host_net=False, command=["true"], access="read")
        with patch.object(sandbox, "load_profile", return_value=cfg), self.assertRaises(SystemExit):
            sandbox.cmd_run(args)

    def test_explicit_read_access_reaches_mount_builder(self):
        cfg = copy.deepcopy(sandbox.DEFAULTS)
        args = argparse.Namespace(profile="default", workspace="project", rw=[], ro=[], domain=[], env=[],
                                  net=None, unsafe_host_net=False, command=["true"], access="read", allow_sensitive=False,
                                  allow_outside=False, dry_run=True)
        with (patch.object(sandbox, "load_profile", return_value=cfg),
              patch.object(sandbox, "build", return_value=(["fixture-bwrap"], {}, [])) as build,
              patch.object(sandbox, "limits_wrap") as limits):
            sandbox.cmd_run(args)
        self.assertFalse(build.call_args.args[0]["workdir_rw"])
        limits.assert_not_called()

    def test_unexpected_probe_exception_is_failed_check(self):
        tree = ast.parse((ROOT / "probe.py").read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "check")
        namespace = {"results": []}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "probe-check", "exec"), namespace)

        def broken_fixture():
            raise RuntimeError("fixture bug")

        namespace["check"]("broken")(broken_fixture)
        self.assertFalse(namespace["results"][0][1])
        self.assertIn("ОШИБКА ПРОВЕРКИ", namespace["results"][0][2])

    def test_standalone_probe_stops_before_any_checks(self):
        env = dict(os.environ)
        env.pop("SANDBOX", None)
        result = subprocess.run([sys.executable, "-I", "-S", str(ROOT / "probe.py")],
                                env=env, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("только через sandbox selftest", result.stderr)
        self.assertNotIn("[защищено]", result.stdout)

    def test_probe_rejects_same_namespaces_before_running_checks(self):
        env = dict(os.environ, SANDBOX="1", SANDBOX_NET="off")
        args = ["fixture", "12345", "fixture-socket", "12345", str(self.base),
                os.readlink("/proc/self/ns/pid"), os.readlink("/proc/self/ns/net")]
        result = subprocess.run([sys.executable, "-I", "-S", str(ROOT / "probe.py"), *args],
                                env=env, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("нет изоляции PID/сети", result.stderr)
        self.assertNotIn("[защищено]", result.stdout)

    def test_selftest_preserves_preexisting_directories_and_reaps_own_child(self):
        old_ws = sandbox.WORKSPACES / ".selftest"
        old_home = sandbox.HOMES / "selftest-default"
        for path in (old_ws, old_home):
            path.mkdir()
            (path / "sentinel").write_text("keep")
        child = Mock(pid=12345)
        child.poll.return_value = None
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        sock.getsockname.return_value = ("127.0.0.1", 23456)
        with (patch.object(sandbox, "load_profile", return_value=copy.deepcopy(sandbox.DEFAULTS)),
              patch.object(sandbox.subprocess, "Popen", return_value=child),
              patch.object(sandbox.subprocess, "run", return_value=Mock(returncode=0)),
              patch.object(sandbox.socket, "socket", return_value=sock),
              patch.object(sandbox, "build", return_value=(["fixture-command"], {}, [])) as build,
              patch.object(sandbox, "limits_wrap", return_value=[])):
            with self.assertRaises(SystemExit) as result:
                sandbox.cmd_selftest(argparse.Namespace(profile="default"))
            self.assertEqual(result.exception.code, 0)
            self.assertNotEqual(Path(build.call_args.args[1]), old_ws)
        for path in (old_ws, old_home):
            self.assertEqual((path / "sentinel").read_text(), "keep")
        self.assertEqual(sorted(p.name for p in sandbox.WORKSPACES.iterdir()), [".selftest", "project"])
        self.assertEqual([p.name for p in sandbox.HOMES.iterdir()], ["selftest-default"])
        child.kill.assert_called_once()
        child.wait.assert_called_once()

    def test_proxy_denies_private_dns_answer_before_connecting(self):
        server = Mock()
        server.recv.return_value = b"CONNECT fixture.invalid:443 HTTP/1.1\r\n\r\n"
        with (patch.object(sandbox.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]),
              patch.object(sandbox, "connect_resolved") as connect):
            sandbox.proxy_conn(server, {"domains": ["fixture.invalid"], "ports": [443], "allow_private_net": False})
            self.assertIn(b"403 Private address", server.sendall.call_args.args[0])
            connect.assert_not_called()

    def test_proxy_rejects_oversized_headers_without_dns(self):
        server = Mock()
        request = b"CONNECT fixture.invalid:443 HTTP/1.1\r\nX: " + b"a" * 17000
        server.recv.side_effect = [request[i:i + 4096] for i in range(0, len(request), 4096)]
        with patch.object(sandbox.socket, "getaddrinfo") as dns:
            sandbox.proxy_conn(server, {"domains": ["*"]})
            self.assertIn(b"431", server.sendall.call_args.args[0])
        timeouts = [call.args[0] for call in server.settimeout.call_args_list]
        self.assertTrue(timeouts and all(0 < value <= 10 for value in timeouts))
        self.assertEqual(timeouts, sorted(timeouts, reverse=True))
        server.close.assert_called_once()
        dns.assert_not_called()


if __name__ == "__main__":
    unittest.main()
