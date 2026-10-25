"""Регрессии ревью режима user: чистые функции и порядок операций; вызовы Windows и PowerShell подменены."""
import argparse
import contextlib
import ctypes
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "windows"))
import windows as launcher
import native_proxy as proxy
import native_user as native
import native_winapi as win

GUID = "ca951180-7a7e-438e-82c6-f297c39f8c10"
SID = "S-1-5-21-123-456-789-1005"
INTERFACE = {"guid": GUID, "index": 19, "address": "192.0.2.5", "dns": ["192.0.2.53"], "alias": "Fixture adapter"}


class ProcessInputTests(unittest.TestCase):
    def test_environment_block_is_sorted_case_insensitively_and_double_terminated(self):
        block = win.environment_block({"b": "2", "Z": "3", "A": "1"})
        self.assertEqual(block, "A=1\0b=2\0Z=3\0\0")

    def test_environment_block_rejects_separators_in_names_and_values(self):
        for env in ({"A=B": "1"}, {"": "1"}, {"A": "x\0y"}, {"A\0": "1"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                win.environment_block(env)

    def test_command_line_is_quoted_and_limited_to_documented_length(self):
        self.assertEqual(win.command_line(["C:\\Program Files\\x.exe", "a b", "c"]), '"C:\\Program Files\\x.exe" "a b" c')
        with self.assertRaises(ValueError):
            win.command_line(["C:\\x.exe", "a" * 1024])

    def test_logon_errors_carry_actionable_hints(self):
        self.assertIn("локальный вход", str(win.logon_error(1385)))
        self.assertIn("seclogon", str(win.logon_error(1058)))
        self.assertIn("не в профиле владельца", str(win.logon_error(5)))
        self.assertNotIn(". ", str(win.logon_error(987654)).split("987654")[-1])

    def test_desktop_dacl_is_edited_through_a_handle_opened_with_dacl_rights(self):
        self.assertEqual(win.DesktopAccess.EDIT_DACL, 0x20000 | 0x40000)

    def test_win64_field_offsets_match_the_c_headers(self):
        """Смещения по заголовкам Windows SDK (x64): одного размера структуры мало, поле могло бы сместиться внутри неё."""
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            self.skipTest("64-bit ABI")
        expected = {
            "Filter": {"flags": 32, "provider": 40, "providerData": 48, "layer": 64, "sublayer": 80, "weight": 96, "count": 112,
                       "conditions": 120, "action": 128, "context": 152, "reserved": 168, "id": 176, "effectiveWeight": 184},
            "Sublayer": {"flags": 32, "provider": 40, "providerData": 48, "weight": 64},
            "Condition": {"match": 16, "value": 24},
            "Startup": {"desktop": 16, "title": 24, "flags": 60, "show": 64, "reservedData": 72, "stdin": 80, "stdout": 88, "stderr": 96},
            "BasicLimits": {"flags": 16, "processes": 40, "affinity": 48, "priority": 56, "scheduling": 60},
            "ExtendedLimits": {"io": 64, "processMemory": 112, "jobMemory": 120, "peakJob": 136},
            "Trustee": {"operation": 8, "form": 12, "type": 16, "name": 24},
            "ExplicitAccess": {"mode": 4, "inheritance": 8, "trustee": 16},
            "ProcessInfo": {"thread": 8, "pid": 16, "tid": 20},
        }
        for name, fields in expected.items():
            for field, offset in fields.items():
                with self.subTest(structure=name, field=field):
                    self.assertEqual(getattr(getattr(win, name), field).offset, offset)


class ControlAndAclTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sandbox-native-review-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_powershell_timeout_is_an_oserror_without_request_data(self):
        with patch.object(native, "powershell", return_value="powershell.exe"), \
                patch.object(native.subprocess, "run", side_effect=subprocess.TimeoutExpired("powershell.exe", 5)):
            with self.assertRaises(OSError) as raised:
                native.control("acl", timeout=5, entries=[{"path": "secret-path"}])
        self.assertIn("5", str(raised.exception))
        self.assertNotIn("secret-path", str(raised.exception))

    def test_large_trees_are_sent_in_bounded_batches_with_scaled_timeouts(self):
        tree = self.base / "project"
        tree.mkdir()
        for index in range(950):
            (tree / f"f{index}.txt").write_text("x")
        calls = []
        with patch.object(native, "control", side_effect=lambda action, **kw: calls.append(kw)), \
                contextlib.redirect_stderr(io.StringIO()) as notice:
            native.acl([(tree, "edit", True)], SID)
        self.assertEqual([len(kw["entries"]) for kw in calls], [400, 400, 151])
        self.assertTrue(all(kw["sid"] == SID and kw["timeout"] >= 120 + 3 * len(kw["entries"]) for kw in calls))
        self.assertIn("951", notice.getvalue())

    def test_small_requests_stay_single_and_silent(self):
        calls = []
        with patch.object(native, "control", side_effect=lambda action, **kw: calls.append(kw)), \
                contextlib.redirect_stderr(io.StringIO()) as notice:
            native.acl([(self.base, "none", False)])
        self.assertEqual(len(calls), 1)
        self.assertEqual(notice.getvalue(), "")

    def test_prepare_resets_other_projects_only_and_grants_selected_ones_once(self):
        base = self.base
        for name in ("workspaces/a", "workspaces/b", "homes/a", "homes/b", "code"):
            (base / name).mkdir(parents=True)
        (base / "workspaces/stray.txt").write_text("x")
        (base / "code/AGENT_POLICY.md").write_text("policy")
        fake = types.SimpleNamespace(project_path=lambda name: base / "workspaces" / name)
        with patch.object(native, "acl") as acl:
            project, home = native.prepare(fake, argparse.Namespace(workspace="a", access="edit"), base, {"sid": SID})
        reset = {(str(path.relative_to(base)), rights, recursive) for path, rights, recursive in acl.call_args_list[0].args[0]}
        self.assertEqual(reset, {("workspaces", "none", False), ("homes", "none", False), ("workspaces/b", "none", True),
                                 ("workspaces/stray.txt", "none", True), ("homes/b", "none", True)})
        self.assertEqual(acl.call_args_list[1].args, ([(project, "edit", True), (home, "edit", True)], SID))
        for relative in (".codex/AGENTS.override.md", ".claude/CLAUDE.md"):
            self.assertEqual((home / relative).read_text(), "policy")


class EnvironmentTests(unittest.TestCase):
    def fixture(self, profile="claude", **extra):
        environ = {"SystemRoot": "C:\\Windows", "ProgramFiles": "C:\\Program Files", "PATHEXT": ".EXE;.CMD",
                   "HOST_SECRET": "secret", "USERPROFILE": "C:\\Users\\owner", **extra}
        with patch.dict(os.environ, environ), patch.object(native, "machine_path", return_value=["C:\\Program Files\\Git\\cmd", "c:\\windows"]):
            return native.environment(["C:/Tools/agent.exe"], "H", "P", "POL", "AIWorker", profile)

    def test_only_listed_system_variables_are_copied(self):
        env = self.fixture()
        self.assertEqual((env["ProgramFiles"], env["PATHEXT"]), ("C:\\Program Files", ".EXE;.CMD"))
        self.assertNotIn("HOST_SECRET", env)
        self.assertNotEqual(env["USERPROFILE"], "C:\\Users\\owner")

    def test_git_does_not_reject_files_owned_by_administrators(self):
        env = self.fixture()
        self.assertEqual((env["GIT_CONFIG_COUNT"], env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"]), ("1", "safe.directory", "*"))

    def test_path_starts_with_program_dir_and_has_no_case_duplicates(self):
        parts = self.fixture()["PATH"].split(";")
        self.assertEqual(parts[0], "C:/Tools")
        self.assertEqual([part.lower() for part in parts].count("c:\\windows"), 1)
        self.assertIn("C:\\Program Files\\Git\\cmd", parts)

    def test_bash_path_is_passed_only_to_claude(self):
        self.assertEqual(self.fixture(CLAUDE_CODE_GIT_BASH_PATH="C:\\Git\\bin\\bash.exe")["CLAUDE_CODE_GIT_BASH_PATH"], "C:\\Git\\bin\\bash.exe")
        self.assertNotIn("CLAUDE_CODE_GIT_BASH_PATH", self.fixture("codex", CLAUDE_CODE_GIT_BASH_PATH="C:\\Git\\bin\\bash.exe"))

    def test_machine_path_comes_from_registry_without_owner_or_relative_entries(self):
        key = Mock()
        key.__enter__ = Mock(return_value=key)
        key.__exit__ = Mock(return_value=False)
        value = ('%SystemRoot%\\system32;C:\\Program Files\\Git\\cmd;C:\\Users\\owner\\bin;relative\\bin;'
                 '%UNKNOWN%\\x;;"C:\\Tools";C:\\Program Files\\Git\\cmd')
        registry = types.SimpleNamespace(HKEY_LOCAL_MACHINE=2, OpenKey=Mock(return_value=key),
                                         QueryValueEx=Mock(return_value=(value, 2)))
        with patch.dict(sys.modules, {"winreg": registry}), \
                patch.dict(os.environ, {"SystemRoot": "C:\\Windows", "USERPROFILE": "C:\\Users\\owner"}):
            self.assertEqual(native.machine_path(), ["C:\\Windows\\system32", "C:\\Program Files\\Git\\cmd", "C:\\Tools"])

    def test_machine_path_is_empty_when_registry_is_unavailable(self):
        with patch.dict(sys.modules, {"winreg": None}):
            self.assertEqual(native.machine_path(), [])


class ProxyPortTests(unittest.TestCase):
    def test_busy_preferred_port_is_replaced_and_free_one_is_kept(self):
        # Simulated loopback listener: this unit test must never open a host socket.
        seen = []
        def fake_socket():
            probe = Mock()
            probe.__enter__ = Mock(return_value=probe)
            probe.__exit__ = Mock(return_value=False)
            def bind(address):
                seen.append(address)
                if address[1] == 41000:
                    raise OSError("controlled busy-port fixture")
                probe.getsockname.return_value = ("127.0.0.1", 42000 if address[1] == 0 else address[1])
            probe.bind.side_effect = bind
            return probe
        with patch.object(socket, "SO_EXCLUSIVEADDRUSE", socket.SO_REUSEADDR, create=True), \
                patch.object(native.socket, "socket", side_effect=fake_socket):
            self.assertEqual(native.reserve_port(41000), 42000)
            self.assertEqual(native.reserve_port(43000), 43000)
        self.assertEqual(seen, [("127.0.0.1", 41000), ("127.0.0.1", 0), ("127.0.0.1", 43000)])

    def test_bind_failure_names_the_port_and_keeps_the_account_blocked(self):
        with tempfile.TemporaryDirectory(prefix="sandbox-native-port-") as name:
            base = Path(name)
            (base / "logs").mkdir()
            state = {"version": 1, "username": "AIWorker", "sid": SID, "port": 54321, "password": "", "interface": GUID}
            args = argparse.Namespace(profile="claude", offline=False, interface=GUID, dry_run=False, access="read")
            with patch.object(native, "selected", return_value=INTERFACE), patch.object(native, "command_for", return_value=["fixture.exe"]), \
                    patch.object(native, "control"), patch.object(win, "filters") as filters, \
                    patch.object(native, "prepare", return_value=(base, base)), \
                    patch.object(proxy, "start", side_effect=OSError("address in use")), \
                    patch.object(native, "preflight") as preflight, patch.object(native, "start_child") as start:
                with self.assertRaises(OSError) as raised:
                    native.run(launcher, args, base, state)
            self.assertIn("54321", str(raised.exception))
            self.assertIn("setup-user", str(raised.exception))
            preflight.assert_not_called()
            start.assert_not_called()
            self.assertEqual(filters.call_args.kwargs, {"offline": True})


if __name__ == "__main__":
    unittest.main()
