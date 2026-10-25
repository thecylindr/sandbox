"""Windows IPv4 CONNECT broker: every DNS/TCP socket is pinned to one interface."""
import base64
import hmac
import ipaddress
import secrets
import socket
import struct
import threading
import time
import weakref

IP_UNICAST_IF = 31


def read_exact(conn, count, deadline):
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("DNS deadline exceeded")
        conn.settimeout(remaining)
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise OSError("short DNS response")
        data.extend(chunk)
    return bytes(data)


def dns_name(packet, offset):
    labels, visited, end = [], set(), None
    for _ in range(128):
        if offset >= len(packet) or offset in visited:
            raise OSError("invalid DNS name")
        visited.add(offset)
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise OSError("truncated DNS pointer")
            if end is None:
                end = offset + 2
            offset = ((size & 63) << 8) | packet[offset + 1]
            continue
        if size > 63 or offset + size + 1 > len(packet):
            raise OSError("invalid DNS label")
        offset += 1
        if size == 0:
            try:
                return b".".join(labels).decode("ascii").lower(), end or offset
            except UnicodeError as exc:
                raise OSError("non-ASCII DNS name") from exc
        labels.append(packet[offset:offset + size])
        offset += size
    raise OSError("DNS name too long")


def dns_answer(packet, ident, host):
    if len(packet) < 12:
        raise OSError("short DNS header")
    tx, flags, questions, answers, _, _ = struct.unpack("!6H", packet[:12])
    if tx != ident or flags & 0xFA0F != 0x8000 or questions != 1 or answers > 128:
        raise OSError("invalid or unsuccessful DNS response")
    name, offset = dns_name(packet, 12)
    if name != host or packet[offset:offset + 4] != b"\x00\x01\x00\x01":
        raise OSError("DNS question mismatch")
    offset += 4
    records, aliases = {}, {}
    for _ in range(answers):
        owner, offset = dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise OSError("truncated DNS record")
        kind, cls, ttl, length = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if offset + length > len(packet):
            raise OSError("truncated DNS data")
        if cls == 1 and kind == 1 and length == 4:
            records.setdefault(owner, []).append(str(ipaddress.IPv4Address(packet[offset:offset + 4])))
        if cls == 1 and kind == 5:
            target, end = dns_name(packet, offset)
            if end != offset + length:
                raise OSError("invalid CNAME length")
            aliases[owner] = target
        offset += length
    for _ in range(16):
        if name in records:
            return list(dict.fromkeys(records[name]))
        name = aliases.get(name)
        if name is None:
            break
    raise OSError("DNS returned no IPv4 address for the requested name")


class InterfaceConnector:
    def __init__(self, interface):
        self.index = int(interface["index"])
        self.guid = interface["guid"]
        self.source = str(ipaddress.IPv4Address(interface["address"]))
        self.dns = [str(ipaddress.IPv4Address(address)) for address in interface["dns"]]
        self._lock, self._sockets, self._closed = threading.Lock(), weakref.WeakSet(), False
        if not 0 < self.index < 1 << 24 or not self.dns:
            raise ValueError("selected interface needs IPv4 and IPv4 DNS servers")

    def socket(self, timeout=5):
        import native_winapi
        if native_winapi.interface_index(self.guid) != self.index:
            raise OSError("selected adapter changed; restart with an explicit interface selection")
        with self._lock:
            if self._closed:
                raise OSError("proxy session has ended")
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sockets.add(conn)
        try:
            # Winsock expects a DWORD in network byte order for IP_UNICAST_IF.
            conn.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", self.index))
            conn.bind((self.source, 0))
            conn.settimeout(timeout)
            return conn
        except BaseException:
            conn.close()
            raise

    def close(self):
        with self._lock:
            self._closed = True
            sockets = list(self._sockets)
            self._sockets.clear()
        for conn in sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def resolve(self, host, port):
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            ident = secrets.randbelow(65536)
            labels = host.encode("ascii").split(b".")
            if any(not 0 < len(label) <= 63 for label in labels):
                raise OSError("invalid DNS name")
            question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0\0\1\0\1"
            packet = struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + question
            error = OSError("selected DNS servers did not respond")
            deadline = time.monotonic() + 15
            for server in self.dns[:3]:
                try:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("DNS deadline exceeded")
                    with self.socket(min(5, remaining)) as conn:
                        conn.connect((server, 53))
                        conn.sendall(struct.pack("!H", len(packet)) + packet)
                        length = struct.unpack("!H", read_exact(conn, 2, deadline))[0]
                        addresses = dns_answer(read_exact(conn, length, deadline), ident, host)
                    break
                except OSError as exc:
                    error = exc
            else:
                raise error
        else:
            if literal.version != 4:
                raise OSError("native-user backend supports IPv4 egress only")
            addresses = [str(literal)]
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)) for ip in addresses]

    def connect(self, addresses):
        deadline = time.monotonic() + 15
        error = OSError("no validated address")
        for index, (family, _, _, _, address) in enumerate(addresses):
            remaining = deadline - time.monotonic()
            if family != socket.AF_INET or remaining <= 0:
                raise OSError("selected IPv4 interface unavailable")
            conn = self.socket(min(5, remaining / (len(addresses) - index)))
            try:
                conn.connect(address)
                return conn
            except OSError as exc:
                conn.close()
                error = exc
        raise error


def authenticator(token):
    expected = b"Basic " + base64.b64encode(("sandbox:" + token).encode("ascii"))

    def check(header):
        values = [line.split(b":", 1)[1].strip() for line in header.split(b"\r\n")[1:]
                  if line.partition(b":")[0].lower() == b"proxy-authorization"]
        return len(values) == 1 and hmac.compare_digest(values[0], expected)
    return check


def start(port, token, interface, domains):
    import sandbox
    import transport
    connector = InterfaceConnector(interface)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lock, active = threading.Lock(), set()
    stopped = False
    thread = None

    def serve(conn):
        with lock:
            if stopped:
                conn.close()
                return
            active.add(conn)
        try:
            sandbox.proxy_conn(conn, {"domains": domains, "ports": [443]},
                               connector.resolve, connector.connect, authenticator(token))
        finally:
            with lock:
                active.discard(conn)

    class Server:
        def close(self):
            nonlocal stopped
            with lock:
                stopped = True
                clients = list(active)
            listener.close()
            connector.close()
            for conn in clients:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()
            if thread is not None:
                thread.join(1)

    server = Server()
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(64)
        thread = transport.serve(listener, serve)
    except BaseException:
        server.close()
        raise
    return server
