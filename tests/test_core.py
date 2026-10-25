"""Регрессии ядра: разбор TOML, защита файлов проекта, нейтральная среда, прокси, пути, seccomp.
Только временные файлы, имитация сокетов и собственные дочерние процессы; сведения о хосте не собираются."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("sandbox_core_under_test", ROOT / "sandbox.py")
sandbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sandbox)
import guard
import neutral
import tomlmini

LINUX = sys.platform.startswith("linux")
FEATURES = Mock(stdout="--disable-userns --ro-bind-data --size")


class TomlMiniTests(unittest.TestCase):
    CASES = [
        'a = "x"\nb = 1\nc = true\nd = 1.5\ne = -3\nf = 1_000\n',
        'ro = [\n  "a", # комментарий\n  "b",\n]\nenv_set = { FOO = "bar", N = 2 }\n',
        '[t]\nk = "v"\n[a.b]\nc = [1, 2]\n',
        'a.b.c = 1\n"quoted key" = \'literal \\n\'\nu = "\\u00e9 \\"q\\" \\\\"\n',
        'crlf = 1\r\nlist = [\r\n 1,\r\n 2\r\n]\r\n',
    ]

    def test_matches_tomllib_on_profile_subset(self):
        try:
            import tomllib
        except ModuleNotFoundError:
            self.skipTest("нет tomllib: сравнивать не с чем")
        texts = self.CASES + [p.read_text("utf-8") for p in (ROOT / "profiles").glob("*.toml")]
        for text in texts:
            with self.subTest(text=text[:40]):
                self.assertEqual(tomlmini.loads(text), tomllib.loads(text))

    def test_unsupported_constructs_fail_with_line_number(self):
        for text in ("a = 1979-05-27\n", 'a = """x"""\n', "[[a]]\n", "a = 0xFF\n", "a = 1\na = 2\n", 'a = "x\n', "a = 1 2\n"):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "строка"):
                tomlmini.loads(text)

    def test_profile_loader_falls_back_without_tomllib(self):
        with patch.dict(sys.modules, {"tomllib": None, "tomli": None}):
            self.assertEqual(sandbox.toml_loads('a = ["x", "y"]\n'), {"a": ["x", "y"]})


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sandbox-guard-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "ws"
        (self.root / ".git" / "hooks").mkdir(parents=True)
        (self.root / ".git" / "hooks" / "pre-commit.sample").write_text("#!/bin/sh\n")
        (self.root / ".git" / "config").write_text("[core]\n\tbare = false\n")
        (self.root / "vendor" / "lib" / ".git" / "hooks").mkdir(parents=True)
        (self.root / "vendor" / "lib" / ".git" / "config").write_text("[core]\n")

    def test_scan_protects_configs_and_pins_parent_directories(self):
        mounts, _ = guard.scan(self.root)
        modes = {os.path.relpath(p, self.root): m for p, m in mounts}
        self.assertEqual(modes[".git/config"], "ro")
        self.assertEqual(modes[".git/hooks"], "ro")
        self.assertEqual(modes["vendor/lib/.git/config"], "ro")
        for parent in (".git", "vendor", "vendor/lib", "vendor/lib/.git"):    # иначе .git можно переименовать и подменить
            self.assertEqual(modes[parent], "rw", parent)
        order = [os.path.relpath(p, self.root) for p, _ in mounts]
        self.assertLess(order.index("vendor"), order.index("vendor/lib"))     # родители раньше вложенных путей

    def test_audit_reports_only_new_or_changed_risky_files(self):
        _, before = guard.scan(self.root)
        self.assertEqual(guard.audit(self.root, before), [])
        (self.root / ".git" / "config").write_text('[core]\n\tfsmonitor = "touch /x"\n')
        (self.root / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
        (self.root / ".envrc").write_text("export A=1\n")
        notes = dict(guard.audit(self.root, before))
        self.assertIn("core.fsmonitor", notes[".git/config"])
        self.assertIn("хук git", notes[".git/hooks/pre-commit"])
        self.assertIn("direnv", notes[".envrc"])
        self.assertNotIn(".git/hooks/pre-commit.sample", notes)

    def test_harmless_new_git_configuration_is_not_reported(self):
        _, before = guard.scan(self.root)
        (self.root / "app" / ".git" / "hooks").mkdir(parents=True)
        (self.root / "app" / ".git" / "config").write_text("[core]\n\tbare = false\n[remote \"o\"]\n\turl = https://example.invalid/r.git\n")
        (self.root / "app" / ".git" / "hooks" / "pre-push.sample").write_text("#!/bin/sh\n")
        self.assertEqual(guard.audit(self.root, before), [])

    def test_audit_without_baseline_lists_only_dangerous_present_files(self):
        (self.root / ".vscode").mkdir()
        (self.root / ".vscode" / "tasks.json").write_text('{"runOptions": {"runOn": "folderOpen"}}')
        (self.root / "link").mkdir()
        (self.root / "link" / ".git").write_text("gitdir: ../vendor/lib/.git\n")
        names = {n for n, _ in guard.audit(self.root)}
        self.assertEqual(names, {".vscode/tasks.json", "link/.git"})

    def test_risky_config_keys(self):
        text = ('[core]\n\tfsmonitor = x\n\teditor = vim\n\tbare = false\n[credential "https://h"]\n\thelper = store\n'
                '[alias]\n\tst = status\n\tx = !echo\n[url "https://e/"]\n\tinsteadOf = https://g/\n[pager]\n\tlog = less\n\tdiff = false\n'
                '[remote "origin"]\n\turl = https://example.invalid/r.git\n')
        self.assertEqual(guard.risky_config(text), [("core", "fsmonitor"), ("core", "editor"), ("credential", "helper"),
                                                    ("alias", "x"), ("url", "insteadof"), ("pager", "log")])

    def test_symlinks_are_not_followed(self):
        outside = self.root.parent / "outside"
        outside.mkdir()
        (outside / "config").write_text("[core]\n")
        (self.root / "evil").symlink_to(outside, target_is_directory=True)
        mounts, snap = guard.scan(self.root)
        self.assertFalse(any("evil" in p for p, _ in mounts))
        self.assertFalse(any(k.startswith("evil") for k in snap))


class NeutralTests(unittest.TestCase):
    def test_synthetic_proc_files_hide_hardware_and_use_profile_limit(self):
        files = neutral.proc_files(8 << 30)
        cpus = len(os.sched_getaffinity(0)) or 1
        self.assertEqual(files["cpuinfo"].count("model name\t: Virtual CPU"), cpus)
        self.assertTrue(files["meminfo"].startswith("MemTotal:") and "8388608 kB" in files["meminfo"].splitlines()[0])
        self.assertIn("sandbox@sandbox", files["version"])
        self.assertEqual(files["stat"].count("\ncpu"), cpus)
        self.assertNotEqual(neutral.proc_files(1 << 30)["sys/kernel/random/boot_id"], files["sys/kernel/random/boot_id"])

    def test_size_parser(self):
        for text, value in (("8G", 8 << 30), ("512m", 512 << 20), ("1048576", 1048576), ("2GB", 2 << 30)):
            self.assertEqual(sandbox.size_bytes(text), value)
        for text in ("lots", "", "infinity", "nan"):
            with self.assertRaises(ValueError):
                sandbox.size_bytes(text)
        self.assertEqual(sandbox.memory_limit("50%"), 8 << 30)


class SandboxCase(unittest.TestCase):
    """Каталоги состояния песочницы заменяются временными; код (ROOT) остаётся настоящим."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sandbox-core-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        for name in ("WORKSPACES", "HOMES", "STATE", "LOGS"):
            value = self.base / name.lower()
            value.mkdir()
            p = patch.object(sandbox, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.ws = sandbox.WORKSPACES / "project"
        self.ws.mkdir()

    def build(self, cfg=None, features=FEATURES, **kw):
        cfg = copy.deepcopy(sandbox.DEFAULTS) if cfg is None else cfg
        with patch.object(sandbox.subprocess, "run", return_value=features):
            argv, binds, fds = sandbox.build(cfg, str(self.ws), ["/usr/bin/true"], self.base, False, "test", **kw)
        for fd in fds:
            self.addCleanup(os.close, fd)
        with os.fdopen(os.dup(fds[-1]), "rb") as stream:
            job = json.loads(stream.read())
        return argv, binds, job

    @staticmethod
    def pairs(argv, flag, width=2):
        return [tuple(argv[i + 1:i + 1 + width]) for i, v in enumerate(argv) if v == flag]


@unittest.skipUnless(LINUX, "ядро песочницы работает только на Linux")
class BuildTests(SandboxCase):
    def test_synthetic_files_use_data_descriptors_and_hosts_always_exists(self):
        argv, _, _ = self.build()
        data = {dest for _, dest in self.pairs(argv, "--ro-bind-data")}
        for dest in ("/etc/passwd", "/etc/group", "/etc/hosts", "/run/sandbox/AGENT_POLICY.md", "/run/sandbox/inner.py"):
            self.assertIn(dest, data)
        self.assertIn(("/etc/localtime", "/etc/localtime"), self.pairs(argv, "--ro-bind-try"))          # обычная среда: часовой пояс хоста

    def test_without_data_binds_files_fall_back_to_host_copies(self):
        argv, _, _ = self.build(features=Mock(stdout="--disable-userns"))
        self.assertEqual(self.pairs(argv, "--ro-bind-data"), [])
        self.assertIn("/etc/hosts", [d for _, d in self.pairs(argv, "--ro-bind")])
        self.assertNotIn("--size", argv)

    def test_tmp_size_is_limited_when_bwrap_supports_it(self):
        argv, _, _ = self.build()
        i = argv.index("--size")
        self.assertEqual((argv[i + 1], argv[i + 2], argv[i + 3]), (str(1 << 30), "--tmpfs", "/tmp"))

    def test_neutral_environment_hides_identity_paths_and_locale(self):
        cfg = copy.deepcopy(sandbox.DEFAULTS)
        cfg["neutral"] = True
        cfg["env_set"] = {"X": "~/tools"}
        with patch.dict(os.environ, {"LANG": "ru_RU.UTF-8", "PATH": "/usr/lib/jvm/default/bin:/usr/bin", "USER": "realname"}):
            argv, binds, job = self.build(cfg)
        env = job["env"]
        self.assertEqual((env["HOME"], env["USER"], env["TZ"], env["LANG"]), ("/home/user", "user", "UTC", "C.UTF-8"))
        self.assertEqual((env["SANDBOX_WORKSPACE"], job["chdir"]), ("/workspace", "/workspace"))
        self.assertEqual(env["PATH"], "/usr/local/bin:/usr/bin:/bin")
        self.assertEqual(env["X"], "/home/user/tools")
        self.assertIn((str(self.ws), "/workspace"), self.pairs(argv, "--bind"))
        self.assertIn("/workspace", job["rw"])
        self.assertNotIn(str(self.ws), job["rw"])
        proc = {dest for _, dest in self.pairs(argv, "--ro-bind-data")}
        self.assertTrue({"/proc/cpuinfo", "/proc/meminfo", "/proc/stat", "/proc/uptime", "/proc/loadavg"} <= proc)
        self.assertNotIn(("/etc/localtime", "/etc/localtime"), self.pairs(argv, "--ro-bind-try"))
        self.assertIn(("/dev/null", "/proc/interrupts"), self.pairs(argv, "--ro-bind"))

    def test_protected_paths_are_bound_after_workspace_and_parents_first(self):
        protect = [(str(self.ws / ".git"), "rw"), (str(self.ws / ".git" / "config"), "ro")]
        argv, _, _ = self.build(protect=protect)
        self.assertEqual(self.pairs(argv, "--bind-try"), [(protect[0][0],) * 2])
        self.assertEqual(self.pairs(argv, "--ro-bind-try")[-1], (protect[1][0],) * 2)
        self.assertLess(argv.index("--bind-try"), len(argv) - argv[::-1].index("--ro-bind-try") - 1)

    def test_seccomp_off_forces_new_session(self):
        cfg = copy.deepcopy(sandbox.DEFAULTS)
        cfg.update(seccomp=False, new_session=False)
        argv, _, _ = self.build(cfg)
        self.assertIn("--new-session", argv)

    def test_home_key_selects_per_workspace_home(self):
        _, _, _ = self.build(home_key="test+project")
        self.assertTrue((sandbox.HOMES / "test+project").is_dir())
        with self.assertRaises(SystemExit):
            self.build(home_key="test+../x")

    def test_nproc_limit_is_passed_to_inner(self):
        self.assertEqual(self.build(nproc=777)[2]["nproc"], 777)
        self.assertIsNone(self.build()[2]["nproc"])

    def test_nproc_fallback_only_on_kernels_with_namespaced_counters(self):
        cfg = {"tasks_max": 2048}
        for release, want in (("5.10.0-generic", None), ("5.14.0", 2048), ("6.12.3-arch1", 2048), ("7.2.10-arch1-1", 2048)):
            with patch.object(sandbox.os, "uname", return_value=Mock(release=release)):
                self.assertEqual(sandbox.nproc_fallback(cfg), want, release)

    def test_tool_path_in_neutral_mode_keeps_only_bound_user_directories(self):
        tools = self.base / "tools" / "bin"
        tools.mkdir(parents=True)
        with patch.dict(os.environ, {"PATH": f"/usr/lib/jvm/default/bin:{tools}:/usr/bin"}):
            neutral_path = sandbox.tool_path({str(tools.parent): "ro"}, True)
        self.assertEqual(neutral_path, [str(tools), "/usr/local/bin", "/usr/bin", "/bin"])


class ProfileTests(SandboxCase):
    def write(self, text):
        path = self.base / "p.toml"
        path.write_text(text)
        return str(path)

    def test_new_keys_are_validated(self):
        for text in ('home_scope = "everyone"\n', 'tmp_size = "lots"\n', 'tmp_size = "infinity"\n', 'memory_max = "x"\n'):
            with self.subTest(text=text), self.assertRaises(SystemExit):
                sandbox.load_profile(self.write(text))
        for ok in ('memory_max = "infinity"\n', 'memory_max = "50%"\n', 'memory_max = "512M"\n'):
            sandbox.load_profile(self.write(ok))
        cfg = sandbox.load_profile(self.write('home_scope = "workspace"\nneutral = true\nprotect_extra = [".github"]\n'))
        self.assertTrue(cfg["neutral"])
        self.assertEqual((cfg["home_scope"], cfg["protect_extra"], cfg["protect"]), ("workspace", [".github"], True))

    def test_builtin_profiles_enable_neutral_environment(self):
        for name in ("default", "codex", "claude"):
            self.assertTrue(sandbox.load_profile(name)["neutral"], name)


class PathTests(SandboxCase):
    def test_symlinked_home_does_not_disable_the_sensitive_path_guard(self):
        real = self.base / "real-home"
        (real / ".ssh").mkdir(parents=True)
        (real / "proj").mkdir()
        link = self.base / "link-home"
        link.symlink_to(real, target_is_directory=True)
        with patch.dict(os.environ, {"HOME": str(link)}):
            for bad in (link, link / ".ssh", real, real / ".ssh"):
                with self.subTest(path=str(bad)), self.assertRaises(SystemExit):
                    sandbox.check_path(str(bad), False)
            sandbox.check_path(str(real / "proj"), False)

    def test_home_below_forbidden_prefix_is_not_a_system_directory(self):
        var = self.base / "var"
        (var / "home" / "u" / "code" / "proj").mkdir(parents=True)
        (self.base / "home").symlink_to("var/home", target_is_directory=True)     # как /home -> /var/home в Fedora Atomic
        with patch.dict(os.environ, {"HOME": str(self.base / "home" / "u")}), patch.object(sandbox, "FORBIDDEN_ABS", [str(var)]):
            sandbox.check_path(str(self.base / "home" / "u" / "code" / "proj"), False)
            with self.assertRaises(SystemExit):
                sandbox.check_path(str(var / "lib"), False)

    def test_windows_drives_in_wsl(self):
        problem = sandbox.windows_problem
        for bad in ("/mnt", "/mnt/c", "/mnt/c/Users", "/mnt/c/Users/me", "/mnt/c/Users/me/AppData/Roaming", "/mnt/d/Users/me/.ssh",
                    "/mnt/c/Windows/System32", "/mnt/c/Program Files", "/mnt/wsl", "/mnt/wslg/runtime-dir"):
            self.assertTrue(problem(Path(bad)), bad)
        for good in ("/mnt/c/Users/me/code/proj", "/mnt/d/work/proj", "/opt/tool", "/home/u/proj"):
            self.assertIsNone(problem(Path(good)), good)

    def test_new_skips_secret_like_files_and_scrubs_git_credentials(self):
        src = self.base / "source"
        (src / ".git").mkdir(parents=True)
        (src / ".git" / "config").write_text('[remote "o"]\n\turl = https://user:tok3n@example.invalid/r.git\n\turl2 = git@example.invalid:r.git\n')
        for name in (".npmrc", "credentials.json", "app.p12", "terraform.tfstate.backup", "keep.txt"):
            (src / name).write_text("x")
        with patch("sys.stderr"):
            sandbox.cmd_new(argparse.Namespace(name="copy", copy=str(src)))
        new = sandbox.WORKSPACES / "copy"
        self.assertEqual({p.name for p in new.iterdir()} - {"AGENTS.md", "CLAUDE.md"}, {".git", "keep.txt"})
        text = (new / ".git" / "config").read_text()
        self.assertNotIn("tok3n", text)
        self.assertIn("git@example.invalid:r.git", text)


class ProxyTests(unittest.TestCase):
    def test_target_syntax_is_strict(self):
        parse = sandbox.parse_target
        self.assertEqual(parse("EXAMPLE.com.:443"), ("example.com", 443))
        self.assertEqual(parse("example.com"), ("example.com", 443))
        self.assertEqual(parse("[2606:4700::1111]:443"), ("2606:4700::1111", 443))
        for bad in ("evil.com#.openai.com:443", "a b:443", "x:99999", "x:abc", "::1:443", "[bad]:443", "a..b:443", "-a.com:443", ":443"):
            self.assertIsNone(parse(bad), bad)

    def test_embedded_ipv4_is_checked_as_ipv4(self):
        public = sandbox.public_address
        for good in ("8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"):
            self.assertTrue(public(good), good)
        for bad in ("::ffff:127.0.0.1", "::ffff:192.168.1.1", "64:ff9b::7f00:1", "64:ff9b::c0a8:101", "2002:c0a8:101::1", "100.64.0.1",
                    "10.0.0.1", "fe80::1%eth0", "::1"):
            self.assertFalse(public(bad), bad)

    def test_malformed_target_is_rejected_before_dns(self):
        server = Mock()
        server.recv.return_value = b"CONNECT evil.com#.openai.com:443 HTTP/1.1\r\n\r\n"
        with patch.object(sandbox.socket, "getaddrinfo") as dns, patch.object(sandbox, "log"):
            sandbox.proxy_conn(server, {"domains": ["*.openai.com"], "ports": [443], "allow_private_net": False})
        self.assertIn(b"400", server.sendall.call_args.args[0])
        dns.assert_not_called()

    def test_log_escapes_terminal_control_sequences(self):
        with tempfile.TemporaryDirectory() as d, patch.object(sandbox, "LOGS", Path(d)):
            sandbox.log("DENY \x1b]0;TITLE\x07host \u202e")
            raw = next(Path(d).glob("*.log")).read_bytes()
        self.assertNotIn(b"\x1b", raw)
        self.assertNotIn(b"\x07", raw)
        self.assertIn(b"\\x1b]0;TITLE\\x07host \\x202e", raw)

    @unittest.skipUnless(LINUX, "AF_UNIX с /proc/self/fd")
    def test_unix_socket_path_longer_than_sun_path_is_bound(self):
        from isolated import run
        result = run('''
import sandbox, socket, stat, tempfile
from pathlib import Path
with tempfile.TemporaryDirectory() as d:
    deep = Path(d)
    while len(str(deep / "proxy.sock")) < 130:
        deep = deep / ("d" * 40)
    deep.mkdir(parents=True)
    with socket.socket(socket.AF_UNIX) as srv:
        sandbox.bind_unix(srv, str(deep / "proxy.sock"))
        assert stat.S_ISSOCK((deep / "proxy.sock").lstat().st_mode)
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_proxy_socket_directory_is_short_private_and_without_user_name(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp, patch.dict(os.environ, {"XDG_RUNTIME_DIR": ""}):
            path = sandbox.proxy_sock(tmp)
            self.addCleanup(lambda: __import__("shutil").rmtree(Path(path).parent, ignore_errors=True))
            self.assertLess(len(path), 90)
            self.assertEqual(stat.S_IMODE(Path(path).parent.stat().st_mode), 0o700)


class RunTests(SandboxCase):
    def test_ctrl_c_terminates_then_kills_the_sandbox(self):
        proc = Mock()
        proc.wait.side_effect = [KeyboardInterrupt, sandbox.subprocess.TimeoutExpired("x", 5), 137]
        self.assertEqual(sandbox.wait_child(proc), 137)
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()
        proc = Mock()
        proc.wait.side_effect = [KeyboardInterrupt, KeyboardInterrupt, 130]
        self.assertEqual(sandbox.wait_child(proc), 130)
        proc.kill.assert_called_once()

    def test_shared_terminal_ctrl_c_is_left_to_the_sandbox(self):
        proc = Mock()
        proc.wait.side_effect = [KeyboardInterrupt, KeyboardInterrupt, 0]
        self.assertEqual(sandbox.wait_child(proc, forward=False), 0)
        proc.terminate.assert_not_called()
        proc.kill.assert_not_called()

    def test_log_command_escapes_lines_written_before_escaping_existed(self):
        (sandbox.LOGS / "2000-01-01.log").write_text("12:00:00 [-] DENY \x1b]0;T\x07evil\n")
        with patch.object(sandbox.time, "strftime", return_value="2000-01-01"), patch("sys.stdout") as out:
            sandbox.cmd_log(argparse.Namespace(n=5))
        printed = "".join(c.args[0] for c in out.write.call_args_list)
        self.assertNotIn("\x1b", printed)
        self.assertIn("\\x1b]0;T\\x07evil", printed)

    def test_stale_mountpoints_in_persistent_home_are_pruned_but_content_is_kept(self):
        ph = self.base / "ph"
        (ph / "sandbox" / "workspaces" / "other").mkdir(parents=True)
        (ph / "sandbox" / "workspaces" / "kept").mkdir()
        (ph / "sandbox" / "workspaces" / "kept" / "note").write_text("agent data")
        paths = ["/h/sandbox/workspaces/other", "/h/sandbox/workspaces/kept", "/h/sandbox/workspaces", "/h/sandbox", "/elsewhere/x"]
        sandbox.prune_mountpoints(ph, "/h", paths)
        self.assertFalse((ph / "sandbox" / "workspaces" / "other").exists())
        self.assertEqual((ph / "sandbox" / "workspaces" / "kept" / "note").read_text(), "agent data")
        self.assertTrue(ph.is_dir())

    def test_audit_command_exit_code_reflects_findings(self):
        with self.assertRaises(SystemExit) as clean, patch("sys.stdout"):
            sandbox.cmd_audit(argparse.Namespace(name="project"))
        self.assertEqual(clean.exception.code, 0)
        (self.ws / ".git").mkdir()
        (self.ws / ".git" / "config").write_text("[core]\n\tfsmonitor = x\n")
        with self.assertRaises(SystemExit) as dirty, patch("sys.stdout"):
            sandbox.cmd_audit(argparse.Namespace(name="project"))
        self.assertEqual(dirty.exception.code, 1)

    def test_run_requires_non_root_linux_with_bwrap(self):
        with patch.object(sandbox.shutil, "which", return_value=None), self.assertRaises(SystemExit):
            sandbox.require_host()
        with patch.object(sandbox.os, "geteuid", return_value=0), self.assertRaises(SystemExit):
            sandbox.require_host()


@unittest.skipUnless(LINUX, "seccomp только на Linux")
class SeccompBehaviourTests(unittest.TestCase):
    def test_socket_allowlist_and_unknown_syscalls_in_own_child(self):
        code = '''
import ctypes, errno, os, socket, seccomp
seccomp.install()
def err(fn):
    try:
        fn(); return 0
    except OSError as e:
        return e.errno
S = socket
assert err(lambda: S.socket(S.AF_UNIX).close()) == 0
assert err(lambda: S.socket(S.AF_INET).close()) == 0
assert err(lambda: S.socketpair()) == 0
assert err(lambda: S.socket(16, S.SOCK_RAW, 0).close()) == 0
assert err(lambda: S.socket(16, S.SOCK_RAW, 9).close()) == errno.EPROTONOSUPPORT
for fam in (17, 15, 38, 40, 31, 21, 30):
    assert err(lambda: S.socket(fam, S.SOCK_RAW if fam in (17, 15) else S.SOCK_STREAM).close()) == errno.EAFNOSUPPORT, fam
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
assert libc.syscall(ctypes.c_long(5000)) == -1 and ctypes.get_errno() == errno.ENOSYS
assert libc.syscall(ctypes.c_long(seccomp.DENY[__import__("platform").machine()]["open_tree_attr"])) == -1 and ctypes.get_errno() == errno.EPERM
print("socket filter OK")
'''
        from isolated import run
        result = run(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("socket filter OK", result.stdout)

    def test_program_fits_in_conditional_jump_offsets(self):
        program = sandbox_seccomp_build()
        self.assertEqual(len(program) % 8, 0)
        self.assertLess(len(program) // 8, 4096)


def sandbox_seccomp_build():
    import seccomp
    return seccomp.build()


if __name__ == "__main__":
    unittest.main()
