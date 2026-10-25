"""Network regressions: mocks, or fixtures strictly inside fresh namespaces."""
import copy
import errno
import io
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import sandbox
import transport


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {"domains": ["fixture.invalid"], "ports": [443], "allow_private_net": False}
        self.address = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        self.logger = patch.object(sandbox, "log")
        self.logger.start()
        self.addCleanup(self.logger.stop)

    def test_malformed_request_never_resolves_or_connects(self):
        for request in (b"CONNECT fixture.invalid:443\r\n\r\n", b"CONNECT fixture.invalid:443 HTTP/9\r\n\r\n",
                        b"CONNECT [::1 HTTP/1.1\r\n\r\n", b"CONNECT [2606:4700::1111%lo]:443 HTTP/1.1\r\n\r\n",
                        b"CONNECT fixture.invalid:443 HTTP/1.1 extra\r\n\r\n",
                        b"CONNECT fixture.invalid:" + b"9" * 5000 + b" HTTP/1.1\r\n\r\n"):
            client = Mock()
            client.recv.return_value = request
            with self.subTest(request=request), patch.object(sandbox.socket, "getaddrinfo") as dns, patch.object(sandbox, "connect_resolved") as connect:
                sandbox.proxy_conn(client, self.cfg)
                self.assertIn(b"400", client.sendall.call_args.args[0])
                dns.assert_not_called()
                connect.assert_not_called()

    def test_private_mixed_empty_and_multicast_dns_answers_fail_closed(self):
        for addresses in ([], [self.address, (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
                          [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("224.0.0.1", 443))]):
            client = Mock()
            client.recv.return_value = b"CONNECT fixture.invalid:443 HTTP/1.1\r\n\r\n"
            with self.subTest(addresses=addresses), patch.object(sandbox.socket, "getaddrinfo", return_value=addresses), patch.object(sandbox, "connect_resolved") as connect:
                sandbox.proxy_conn(client, self.cfg)
                self.assertIn(b"403", client.sendall.call_args.args[0])
                connect.assert_not_called()

    def test_nonpublic_ipv6_scopes_are_rejected(self):
        for address in ("fec0::1", "ff0e::1", "2606:4700::1111%fixture", "224.0.0.1", "240.0.0.1"):
            self.assertFalse(sandbox.public_address(address), address)

    def test_proxy_start_failure_closes_listener(self):
        with patch.object(sandbox.socket, "socket") as factory, patch.object(sandbox, "bind_unix", side_effect=PermissionError("fixture")):
            with self.assertRaises(PermissionError):
                sandbox.start_proxy("fixture.sock", self.cfg)
        factory.return_value.close.assert_called_once()

    def test_private_address_cannot_be_enabled_via_proxy_config(self):
        client = Mock()
        client.recv.return_value = b"CONNECT fixture.invalid:443 HTTP/1.1\r\n\r\n"
        address = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 443))
        with patch.object(sandbox.socket, "getaddrinfo", return_value=[address]), patch.object(sandbox, "connect_resolved") as connect:
            sandbox.proxy_conn(client, {**self.cfg, "allow_private_net": True})
        self.assertIn(b"403", client.sendall.call_args.args[0])
        connect.assert_not_called()

    def test_connect_preserves_pipelined_tls_data(self):
        client, upstream = Mock(), Mock()
        client.recv.side_effect = [b"CONNECT fixture.invalid:443 HTTP/1.1\r\n", b"\r\n\x16\x03\x01fixture"]
        with patch.object(sandbox.socket, "getaddrinfo", return_value=[self.address]) as dns, patch.object(sandbox, "connect_resolved", return_value=upstream), patch.object(sandbox, "pipe") as relay:
            sandbox.proxy_conn(client, self.cfg)
        dns.assert_called_once()
        self.assertIn(b"200", client.sendall.call_args.args[0])
        relay.assert_called_once_with(client, upstream, b"\x16\x03\x01fixture")
        upstream.close.assert_called_once()
        client.close.assert_called_once()

    def test_resolved_addresses_are_tried_without_second_dns_lookup(self):
        first, second = Mock(), Mock()
        first.connect.side_effect = OSError(errno.ENETUNREACH, "fixture IPv6 unavailable")
        v6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1111", 443, 0, 0))
        with patch.object(sandbox.socket, "socket", side_effect=[first, second]), patch.object(sandbox.socket, "getaddrinfo") as dns:
            self.assertIs(sandbox.connect_resolved([v6, self.address]), second)
        first.close.assert_called_once()
        first.connect.assert_called_once_with(v6[4])
        second.connect.assert_called_once_with(self.address[4])
        self.assertLessEqual(first.settimeout.call_args.args[0], 5)
        dns.assert_not_called()

    def test_dns_error_sends_bad_gateway_and_closes(self):
        client = Mock()
        client.recv.return_value = b"CONNECT fixture.invalid:443 HTTP/1.1\r\n\r\n"
        with patch.object(sandbox.socket, "getaddrinfo", side_effect=socket.gaierror("fixture DNS failure")):
            sandbox.proxy_conn(client, self.cfg)
        self.assertIn(b"502", client.sendall.call_args.args[0])
        client.close.assert_called_once()

    def test_slow_header_has_total_deadline(self):
        client = Mock()
        client.recv.return_value = b"C"
        with patch.object(sandbox.time, "monotonic", side_effect=[0, 1, 11]), patch.object(sandbox.socket, "getaddrinfo") as dns:
            sandbox.proxy_conn(client, self.cfg)
        self.assertEqual(client.recv.call_count, 1)
        dns.assert_not_called()
        client.close.assert_called_once()

    def test_network_escape_modes_are_rejected_before_build(self):
        for changes in ({"network": "on"}, {"allow_private_net": True}, {"allow_private_net": "false"}):
            cfg = {**copy.deepcopy(sandbox.DEFAULTS), **changes}
            with self.subTest(changes=changes), patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
                sandbox.build(cfg, "/unused", ["true"], "/unused", False)


class Stream:
    def __init__(self, data):
        self.data, self.written, self.closed, self.shutdowns = bytearray(data), bytearray(), False, []

    def setblocking(self, value):
        assert value is False

    def recv(self, count):
        result = bytes(self.data[:count])
        del self.data[:count]
        return result

    def send(self, data):
        count = min(3, len(data))  # Simulate partial writes.
        self.written.extend(data[:count])
        return count

    def shutdown(self, how):
        self.shutdowns.append(how)

    def close(self):
        self.closed = True


class TransportTests(unittest.TestCase):
    def test_partial_writes_and_half_closes_preserve_both_directions(self):
        a, b = Stream(b"request" * 20), Stream(b"response" * 20)
        with patch.object(transport.select, "select", side_effect=lambda r, w, x, t: (r, w, [])):
            transport.relay(a, b, initial=b"early", buffer_size=16)
        self.assertEqual(a.written, b"response" * 20)
        self.assertEqual(b.written, b"early" + b"request" * 20)
        for stream in (a, b):
            self.assertTrue(stream.closed)
            self.assertEqual(stream.shutdowns, [socket.SHUT_WR])

    def test_stalled_writer_expires_with_bounded_buffer(self):
        a, b = Stream(b"x" * 100000), Stream(b"")
        calls = []

        def ready(readers, writers, _, timeout):
            calls.append((list(readers), list(writers)))
            return ([a] if len(calls) == 1 else [], [], [])

        with patch.object(transport.select, "select", side_effect=ready):
            transport.relay(a, b, buffer_size=16)
        self.assertEqual(len(a.data), 100000 - 16)
        self.assertNotIn(a, calls[1][0])
        self.assertTrue(a.closed and b.closed)

    def test_worker_limit_rejects_excess_and_closes_listener_on_start_failure(self):
        listener, first, second = Mock(), Mock(), Mock()
        listener.accept.side_effect = [(first, None), (second, None), OSError("closed")]
        threads = []

        class Thread:
            def __init__(self, target, args=(), **kwargs):
                self.target, self.args = target, args
                threads.append(self)

            def start(self):
                if len(threads) == 1:
                    self.target()

        with patch.object(transport.threading, "Thread", Thread):
            transport.serve(listener, Mock(), max_connections=1)
        self.assertEqual(len(threads), 2)
        second.close.assert_called_once()
        first.close.assert_not_called()
        threads[1].target(*threads[1].args)
        first.close.assert_called_once()
        with patch.object(transport.threading, "Thread") as thread:
            thread.return_value.start.side_effect = RuntimeError("thread limit")
            with self.assertRaises(RuntimeError):
                transport.serve(listener, Mock())
        listener.close.assert_called_once()

    def test_worker_start_failure_releases_capacity_and_closes_connection(self):
        listener, first, second = Mock(), Mock(), Mock()
        listener.accept.side_effect = [(first, None), (second, None), OSError("closed")]
        calls = []

        class Thread:
            def __init__(self, target, args=(), **kwargs):
                self.target, self.args = target, args
                calls.append(self)

            def start(self):
                if len(calls) == 1:
                    self.target()
                else:
                    raise RuntimeError("thread limit")

        with patch.object(transport.threading, "Thread", Thread):
            transport.serve(listener, Mock(), max_connections=1)
        self.assertEqual(len(calls), 3)
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_network_guard_rejects_extra_interfaces(self):
        for interfaces in ([], [(1, "lo"), (2, "fixture")]):
            with patch.object(transport.socket, "if_nameindex", return_value=interfaces), self.assertRaises(RuntimeError):
                transport.require_loopback()
        with patch.object(transport.socket, "if_nameindex", return_value=[(1, "lo")]):
            transport.require_loopback()

    def test_existing_but_unresponsive_proxy_does_not_pass_readiness(self):
        with patch.object(transport.time, "monotonic", side_effect=[0, 0, 0, 21]), patch.object(transport.time, "sleep"), patch.object(transport.socket, "socket") as factory:
            factory.return_value.__enter__.return_value.recv.return_value = b""
            with self.assertRaises(RuntimeError):
                transport.wait_proxy("fixture.sock")

    def test_readiness_accepts_fragmented_response(self):
        with patch.object(transport.socket, "socket") as factory:
            factory.return_value.__enter__.return_value.recv.side_effect = [b"HTTP/1.1 4", b"05 Only CONNECT\r\n"]
            transport.wait_proxy("fixture.sock")


@unittest.skipUnless(sys.platform.startswith("linux"), "isolated Linux network fixtures")
class IntegrationTests(unittest.TestCase):
    def test_connect_tunnel_in_fresh_namespace(self):
        from isolated import run
        result = run('''
import socket, threading, tempfile
from pathlib import Path
from unittest.mock import patch
import sandbox, transport
transport.require_loopback()
sandbox.log = lambda message: None
payload = b"fixture request" * 10000
reply = b"fixture response" * 10000
with tempfile.TemporaryDirectory() as tmp, socket.socket() as upstream:
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    def answer():
        with upstream.accept()[0] as conn:
            conn.settimeout(5)
            received = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                received += chunk
            assert received == payload
            conn.sendall(reply)
    worker = threading.Thread(target=answer, daemon=True)
    worker.start()
    addr = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
    connect = sandbox.connect_resolved
    def local_fixture(addresses):
        assert addresses == [addr]
        return connect([(socket.AF_INET, socket.SOCK_STREAM, 6, "", upstream.getsockname())])
    server = sandbox.start_proxy(str(Path(tmp) / "proxy.sock"), {"domains": ["fixture.invalid"], "ports": [443]})
    try:
        transport.wait_proxy(str(Path(tmp) / "proxy.sock"))
        with patch.object(sandbox.socket, "getaddrinfo", return_value=[addr]), patch.object(sandbox, "connect_resolved", side_effect=local_fixture):
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(5)
                client.connect(str(Path(tmp) / "proxy.sock"))
                client.sendall(b"CONNECT fixture.invalid:443 HTTP/1.1\\r\\n\\r\\n" + payload)
                client.shutdown(socket.SHUT_WR)
                received = b""
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    received += chunk
                assert received == b"HTTP/1.1 200 Connection established\\r\\n\\r\\n" + reply
    finally:
        server.close()
    worker.join(5)
    assert not worker.is_alive()
print("isolated CONNECT transfer OK")
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("isolated CONNECT transfer OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
