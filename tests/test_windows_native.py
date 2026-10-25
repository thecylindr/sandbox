"""Native account backend regressions; all Windows calls and network I/O are mocked here."""
import argparse
import base64
import ctypes
import io
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "windows"))
import windows as launcher
import native_user as native
import native_proxy as proxy
import native_winapi as win
import sandbox

GUID = "ca951180-7a7e-438e-82c6-f297c39f8c10"
SID = "S-1-5-21-123-456-789-1005"
INTERFACE = {"guid": GUID, "index": 19, "address": "192.0.2.5", "dns": ["192.0.2.53"], "alias": "Fixture adapter"}


def question(host):
    return b"".join(bytes([len(x)]) + x for x in host.encode().split(b".")) + b"\0\0\1\0\1"


class NativeProxyTests(unittest.TestCase):
    def test_socket_pins_interface_and_source_before_connect(self):
        connector = proxy.InterfaceConnector(INTERFACE)
        with patch.object(win, "interface_index", return_value=19), patch.object(proxy.socket, "socket") as factory:
            conn = connector.connect([(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))])
        self.assertIs(conn, factory.return_value)
        self.assertEqual([c[0] for c in conn.method_calls], ["setsockopt", "bind", "settimeout", "connect"])
        conn.setsockopt.assert_called_once_with(socket.IPPROTO_IP, 31, b"\0\0\0\x13")
        conn.bind.assert_called_once_with(("192.0.2.5", 0))

    def test_changed_interface_never_falls_back(self):
        with patch.object(win, "interface_index", return_value=20), patch.object(proxy.socket, "socket") as factory:
            with self.assertRaises(OSError):
                proxy.InterfaceConnector(INTERFACE).socket()
        factory.assert_not_called()

    def test_bind_failure_closes_socket_without_connect(self):
        with patch.object(win, "interface_index", return_value=19), patch.object(proxy.socket, "socket") as factory:
            factory.return_value.bind.side_effect = OSError("fixture adapter lost")
            with self.assertRaises(OSError):
                proxy.InterfaceConnector(INTERFACE).socket()
        factory.return_value.close.assert_called_once()
        factory.return_value.connect.assert_not_called()

    def test_connector_close_aborts_existing_sockets_and_rejects_new_ones(self):
        connector = proxy.InterfaceConnector(INTERFACE)
        with patch.object(win, "interface_index", return_value=19), patch.object(proxy.socket, "socket") as factory:
            connector.socket()
            connector.close()
            with self.assertRaises(OSError):
                connector.socket()
        self.assertEqual(factory.call_count, 1)
        factory.return_value.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        factory.return_value.close.assert_called_once()

    def test_dns_is_sent_to_selected_resolver_on_pinned_socket(self):
        ident, host = 42, "api.fixture.invalid"
        packet = struct.pack("!6H", ident, 0x8180, 1, 1, 0, 0) + question(host)
        packet += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + b"\x08\x08\x08\x08"
        connector, conn = proxy.InterfaceConnector(INTERFACE), Mock()
        manager = Mock()
        manager.__enter__ = Mock(return_value=conn)
        manager.__exit__ = Mock(return_value=False)
        conn.recv.side_effect = [struct.pack("!H", len(packet)), packet]
        with patch.object(connector, "socket", return_value=manager), patch.object(proxy.secrets, "randbelow", return_value=42), patch.object(socket, "getaddrinfo") as system_dns:
            result = connector.resolve(host, 443)
        conn.connect.assert_called_once_with(("192.0.2.53", 53))
        self.assertEqual(result[0][4], ("8.8.8.8", 443))
        system_dns.assert_not_called()

    def test_dns_validates_transaction_question_and_address_owner(self):
        host = "api.fixture.invalid"
        packet = struct.pack("!6H", 42, 0x8180, 1, 1, 0, 0) + question(host)
        record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + b"\x08\x08\x08\x08"
        self.assertEqual(proxy.dns_answer(packet + record, 42, host), ["8.8.8.8"])
        for data, ident, name in ((packet + record, 43, host), (packet + record, 42, "other.invalid"),
                                  (packet + record[:-1], 42, host), (packet, 42, host)):
            with self.subTest(data=data), self.assertRaises(OSError):
                proxy.dns_answer(data, ident, name)
        wrong_owner = b"\x05other\x07invalid\0" + record[2:]
        with self.assertRaises(OSError):
            proxy.dns_answer(packet + wrong_owner, 42, host)

    def test_dns_pointer_cycles_and_invalid_names_fail(self):
        for data in (b"\xc0\x00", b"\xc0", b"\xc0\xff", b"\x01\xff\0", b"\x40" + b"a" * 64):
            with self.subTest(data=data), self.assertRaises(OSError):
                proxy.dns_name(data, 0)

    def test_ipv6_literal_is_not_sent_via_another_interface(self):
        with patch.object(socket, "getaddrinfo") as dns, self.assertRaises(OSError):
            proxy.InterfaceConnector(INTERFACE).resolve("2606:4700::1111", 443)
        dns.assert_not_called()

    def test_proxy_authentication_rejects_missing_wrong_and_duplicate_headers(self):
        auth = proxy.authenticator("fixture-token")
        value = base64.b64encode(b"sandbox:fixture-token")
        line = b"Proxy-Authorization: Basic " + value
        self.assertTrue(auth(b"CONNECT fixture:443 HTTP/1.1\r\n" + line))
        for header in (b"CONNECT fixture:443 HTTP/1.1", b"CONNECT fixture:443 HTTP/1.1\r\n" + line + b"wrong",
                       b"CONNECT fixture:443 HTTP/1.1\r\n" + line + b"\r\n" + line):
            self.assertFalse(auth(header))

    def test_missing_auth_is_rejected_before_dns(self):
        conn, resolve, connect = Mock(), Mock(), Mock()
        conn.recv.return_value = b"CONNECT fixture.invalid:443 HTTP/1.1\r\n\r\n"
        sandbox.proxy_conn(conn, {}, resolve, connect, proxy.authenticator("fixture"))
        self.assertIn(b"407", conn.sendall.call_args.args[0])
        resolve.assert_not_called()
        connect.assert_not_called()

    def test_private_dns_answer_is_rejected_even_with_native_connector(self):
        conn, connect = Mock(), Mock()
        conn.recv.return_value = b"CONNECT fixture.invalid:443 HTTP/1.1\r\n\r\n"
        resolve = Mock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
        with patch.object(sandbox, "log"):
            sandbox.proxy_conn(conn, {"domains": ["fixture.invalid"], "ports": [443]}, resolve, connect)
        connect.assert_not_called()
        self.assertIn(b"403", conn.sendall.call_args.args[0])


class WfpModelTests(unittest.TestCase):
    def test_win64_abi_layouts(self):
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            self.skipTest("64-bit ABI")
        for name, expected in {"GUID": 16, "Blob": 16, "Value": 16, "Condition": 40, "Filter": 200,
                               "Sublayer": 72, "Startup": 104, "ProcessInfo": 24, "ExtendedLimits": 144,
                               "Trustee": 32, "ExplicitAccess": 48}.items():
            self.assertEqual(ctypes.sizeof(getattr(win, name)), expected, name)
        self.assertEqual(bytes(win.GUID.parse(GUID)), uuid.UUID(GUID).bytes_le)

    def test_rules_cover_ipv6_inbound_non_tcp_and_every_other_endpoint(self):
        rules = win.filter_specs(54321)

        def blocked(layer, ip, port, proto):
            values = {win.REMOTE_IP: ip, win.REMOTE_PORT: port, win.PROTOCOL: proto}
            return any(rule_layer == layer and (field is None or values[field] != value)
                       for _, rule_layer, field, _, value in rules)

        self.assertFalse(blocked(win.CONNECT4, 0x7F000001, 54321, 6))
        for case in ((win.CONNECT4, 0x7F000001, 54322, 6), (win.CONNECT4, 0x08080808, 443, 6),
                     (win.CONNECT4, 0x7F000001, 54321, 17), (win.CONNECT6, 0, 54321, 6),
                     (win.RECEIVE4, 0x7F000001, 54321, 6), (win.RECEIVE6, 0, 54321, 6)):
            self.assertTrue(blocked(*case), case)
        rules = win.filter_specs(54321, offline=True)
        self.assertTrue(blocked(win.CONNECT4, 0x7F000001, 54321, 6))

    def test_invalid_sid_cannot_reach_windows_api(self):
        with patch.object(win, "dll") as api, self.assertRaises(ValueError):
            win.filters("S-1-1-0", 54321)
        api.assert_not_called()


class NativeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sandbox-native-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = {"version": 1, "username": "AIWorker", "sid": SID, "port": 54321,
                      "password": base64.b64encode(b"encrypted").decode(), "interface": GUID}

    def test_names_reject_paths_and_shell_metacharacters(self):
        for bad in ("../user", "a b", "x;whoami", "x$()", "x\\y", "9user", "x" * 21):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                native.account_name(bad)
        self.assertEqual(native.account_name("AIWorker"), "AIWorker")

    def test_symlink_and_hardlink_refused_before_acl_call(self):
        target = self.base / "original"
        target.write_text("fixture")
        link = self.base / "hardlink"
        os.link(target, link)
        with patch.object(native, "control") as control, self.assertRaises(OSError):
            native.acl([(link, "edit", False)], SID)
        control.assert_not_called()
        self.assertEqual(target.read_text(), "fixture")

    def test_account_is_disabled_before_resume_and_after_exit(self):
        events = []
        child = Mock()
        child.resume.side_effect = lambda: events.append("resume")
        child.wait.return_value = 17
        child.close.side_effect = lambda: events.append("close")
        with patch.object(native, "control", side_effect=lambda action, **kw: events.append(action)), patch.object(win, "protect", return_value=b"password"), patch.object(win, "Child", return_value=child):
            self.assertEqual(native.start_child(self.state, ["fixture.exe"], self.base, {}), 17)
        self.assertEqual(events, ["enable", "disable", "resume", "close", "disable"])

    def test_job_assignment_failure_never_resumes_and_disables_user(self):
        with patch.object(native, "control") as control, patch.object(win, "protect", return_value=b"password"), patch.object(win, "Child", side_effect=OSError("job failure")):
            with self.assertRaises(OSError):
                native.start_child(self.state, ["fixture.exe"], self.base, {})
        self.assertEqual([call.args[0] for call in control.call_args_list], ["enable", "disable"])

    def test_failed_disable_before_resume_closes_job(self):
        child = Mock()
        with patch.object(native, "control", side_effect=[{}, OSError("fixture disable failure"), {}]), patch.object(win, "protect", return_value=b"password"), patch.object(win, "Child", return_value=child):
            with self.assertRaises(OSError):
                native.start_child(self.state, ["fixture.exe"], self.base, {})
        child.resume.assert_not_called()
        child.close.assert_called_once()

    def test_environment_does_not_inherit_owner_profile_or_other_keys(self):
        with patch.dict(os.environ, {"SystemRoot": "C:\\Windows", "HOME": "owner-home", "HOST_SECRET": "secret",
                                    "OPENAI_API_KEY": "openai", "ANTHROPIC_API_KEY": "anthropic", "HTTP_PROXY": "owner-proxy"}):
            env = native.environment(["C:/Tools/claude.exe"], self.base / "home", self.base / "project", self.base / "policy", "AIWorker", "claude", "http://sandbox:fixture@127.0.0.1:54321")
        self.assertNotIn("HOST_SECRET", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotEqual(env["HOME"], "owner-home")
        self.assertEqual(env["ANTHROPIC_API_KEY"], "anthropic")
        self.assertEqual(env["NO_PROXY"], "")
        self.assertNotEqual(env["HTTP_PROXY"], "owner-proxy")

    def test_selected_interface_guid_must_match_exactly(self):
        with patch.object(native, "control", return_value={**INTERFACE, "guid": str(uuid.uuid4())}), self.assertRaises(OSError):
            native.selected(GUID)

    def test_failed_preflight_cannot_launch_agent_and_restores_block(self):
        (self.base / "logs").mkdir()
        args = argparse.Namespace(profile="claude", offline=False, interface=GUID, dry_run=False, access="read")
        with patch.object(native, "selected", return_value=INTERFACE), patch.object(native, "command_for", return_value=["fixture.exe"]), patch.object(native, "control"), patch.object(win, "filters") as filters, patch.object(native, "prepare", return_value=(self.base, self.base)), patch.object(proxy, "start") as server, patch.object(native, "preflight", side_effect=OSError("fixture fail")), patch.object(native, "start_child") as start:
            with self.assertRaises(OSError):
                native.run(launcher, args, self.base, self.state)
        start.assert_not_called()
        server.return_value.close.assert_called_once()
        self.assertEqual(filters.call_args.kwargs, {"offline": True})

    def test_power_shell_input_is_data_not_command_interpolation(self):
        with patch.object(native, "powershell", return_value="powershell.exe"), patch.object(native.subprocess, "run", return_value=Mock(returncode=0, stdout="{}")) as call:
            native.control("create", username="AIWorker", password="secret & ` $()")
        argv = call.call_args.args[0]
        self.assertNotIn("secret", " ".join(argv))
        self.assertNotIn("-Command", argv)
        self.assertEqual(json.loads(call.call_args.kwargs["input"])["password"], "secret & ` $()")

    def test_cli_exposes_third_backend_and_passes_guid_as_data(self):
        args = launcher.parser().parse_args(["setup-user", "--username", "AIWorker", "--interface", GUID])
        self.assertEqual((args.backend, args.username, args.interface), ("user", "AIWorker", GUID))
        fake = Mock()
        fake.handle.return_value = 0
        with patch.object(launcher, "native_module", return_value=fake):
            self.assertEqual(launcher.main(["run", "claude", "demo", "--backend", "user", "--interface", GUID, "--", "C:\\Tools\\claude.exe"]), 0)
        self.assertEqual(fake.handle.call_args.args[1].command, ["C:\\Tools\\claude.exe"])

    def test_powershell_sources_are_ascii_for_windows_51(self):
        for filename in ("native-control.ps1", "native-selftest.ps1"):
            (ROOT / "windows" / filename).read_bytes().decode("ascii")


if __name__ == "__main__":
    unittest.main()
