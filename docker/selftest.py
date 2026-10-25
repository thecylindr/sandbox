"""Own-container checks only; never enumerates host processes, interfaces or services."""
import os
from pathlib import Path
import secrets
import socket
import sys


def main():
    if os.environ.get("SANDBOX") != "1" or os.environ.get("SANDBOX_WORKSPACE") != "/workspace":
        sys.exit("selftest: запускайте только через windows.py selftest --backend docker")
    checks = []
    # The entrypoint has already verified the isolated namespace, before running this script.
    checks.append(("only sandbox loopback", {name for _, name in socket.if_nameindex()} == {"lo"}))
    checks.append(("synthetic DNS", Path("/etc/resolv.conf").read_text() ==
                   "nameserver 127.0.0.1\noptions attempts:1 timeout:1\n"))
    checks.append(("synthetic hosts", Path("/etc/hosts").read_text() ==
                   "127.0.0.1 localhost sandbox\n::1 localhost\n"))
    if os.environ.get("SANDBOX_NET") == "allowlist":
        # Only the sandbox's own bridge; no DNS lookup or request to an external service.
        for request, expected in ((b"HEAD / HTTP/1.1\r\n\r\n", b"405"),
                                  (b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n", b"403")):
            with socket.create_connection(("127.0.0.1", 3128), timeout=5) as conn:
                conn.sendall(request)
                response = b""
                while b"\r\n" not in response and len(response) < 128:
                    chunk = conn.recv(128 - len(response))
                    if not chunk:
                        break
                    response += chunk
            checks.append(("proxy response " + expected.decode(), response.startswith(b"HTTP/1.1 " + expected + b" ")))
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    checks.append(("non-root", os.getuid() != 0))
    checks.append(("no_new_privs", status["NoNewPrivs"].strip() == "1"))
    checks.append(("capabilities", int(status["CapEff"].strip(), 16) == 0))
    checks.append(("seccomp", status["Seccomp"].strip() == "2"))
    for name in ("/run/sandbox/AGENT_POLICY.md", "/home/node/.codex/AGENTS.override.md", "/home/node/.claude/CLAUDE.md"):
        try:
            fd = os.open(name, os.O_WRONLY)  # No data is modified if a mount was unexpectedly writable.
        except PermissionError:
            safe = True
        except OSError as exc:
            if exc.errno == 30:  # EROFS
                safe = True
            else:
                raise
        else:
            os.close(fd)
            safe = False
        checks.append((f"read-only {name}", safe))
    target = Path("/workspace") / (".sandbox-selftest-" + secrets.token_hex(8))
    try:
        with target.open("x") as stream:
            stream.write("fixture")
    except OSError as exc:
        if exc.errno not in (13, 30):
            raise
        writable = False
    else:
        target.unlink()
        writable = True
    checks.append(("project access", writable == (os.environ["SANDBOX_ACCESS"] == "edit")))
    for label, safe in checks:
        print(f"{'[ok]' if safe else '[FAIL]'} {label}")
    return 0 if all(safe for _, safe in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
