"""Bounded TCP/Unix transport used only by the trusted proxy and sandbox bridge."""
import select
import socket
import threading
import time


def relay(a, b, initial=b"", idle_timeout=300, buffer_size=65536):
    """Bound memory, expire stalled writers, and preserve data after a half-close."""
    peers = {a: b, b: a}
    pending = {a: bytearray(), b: bytearray(initial)}
    ended, shut = set(), set()
    deadline = time.monotonic() + idle_timeout
    try:
        if len(initial) > buffer_size:
            raise ValueError("initial tunnel data exceeds buffer limit")
        for s in peers:
            s.setblocking(False)
        while True:
            for s in peers:
                if peers[s] in ended and not pending[s] and s not in shut:
                    s.shutdown(socket.SHUT_WR)
                    shut.add(s)
            readers = [s for s in peers if s not in ended and len(pending[peers[s]]) < buffer_size]
            writers = [s for s in peers if pending[s]]
            if not readers and not writers:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                readable, writable, _ = select.select(readers, writers, [], remaining)
            except ValueError:
                if a.fileno() < 0 or b.fileno() < 0:  # Broker shutdown closed a socket in another thread.
                    return
                raise
            if not readable and not writable:
                return
            for s in readable:
                try:
                    data = s.recv(buffer_size - len(pending[peers[s]]))
                except (BlockingIOError, InterruptedError):
                    continue
                if data:
                    pending[peers[s]].extend(data)
                    deadline = time.monotonic() + idle_timeout
                else:
                    ended.add(s)
            for s in writable:
                try:
                    count = s.send(pending[s])
                except (BlockingIOError, InterruptedError):
                    continue
                if count == 0:
                    return
                del pending[s][:count]
                deadline = time.monotonic() + idle_timeout
    except OSError:
        pass
    finally:
        a.close()
        b.close()


def serve(srv, handler, max_connections=64):
    """Start bounded workers; closing the listener stops accept within 0.5 seconds."""
    slots = threading.BoundedSemaphore(max_connections)
    srv.settimeout(0.5)

    def worker(conn):
        try:
            handler(conn)
        finally:
            conn.close()
            slots.release()

    def accept():
        while True:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not slots.acquire(blocking=False):
                conn.close()
                continue
            try:
                threading.Thread(target=worker, args=(conn,), daemon=True).start()
            except RuntimeError:
                conn.close()
                slots.release()

    thread = threading.Thread(target=accept, daemon=True)
    try:
        thread.start()
    except RuntimeError:
        srv.close()
        raise
    return thread


def wait_proxy(path, timeout=20):
    """Readiness requires a response from the Unix proxy, not just a socket inode."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX) as conn:
                conn.settimeout(min(1, max(0.01, deadline - time.monotonic())))
                conn.connect(path)
                conn.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
                response = b""
                while b"\r\n" not in response and len(response) < 128:
                    chunk = conn.recv(128 - len(response))
                    if not chunk:
                        break
                    response += chunk
                if response.startswith(b"HTTP/1.1 405 "):
                    return
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("прокси не отвечает за отведённое время; запуск остановлен")


def require_loopback():
    """Called inside the new network namespace, before untrusted code runs."""
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError("ожидалась изолированная сеть только с loopback; запуск остановлен")
