"""Run fixtures in fresh PID/net/mount namespaces; never fall back to host networking."""
import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import sandbox


def run(code):
    if os.name != "posix" or not shutil.which("bwrap"):
        raise unittest.SkipTest("isolated fixture requires Linux/bubblewrap")
    parent_net = os.readlink("/proc/self/ns/net")
    parent_pid = os.readlink("/proc/self/ns/pid")
    guard = ("import os, sys\n"
             f"assert os.readlink('/proc/self/ns/net') != {parent_net!r}\n"
             f"assert os.readlink('/proc/self/ns/pid') != {parent_pid!r}\n"
             "sys.path.insert(0, '/run/sandbox')\n")
    with tempfile.TemporaryDirectory(prefix="sandbox-isolated-") as tmp:
        project = Path(tmp) / "project"
        project.mkdir()
        cfg = {**copy.deepcopy(sandbox.DEFAULTS), "persist_home": False}
        argv, _, fds = sandbox.build(cfg, str(project), ["/usr/bin/python3", "-I", "-S", "-c", guard + code], tmp, False)
        index = argv.index("--")
        extra = []
        for name in ("sandbox.py", "seccomp.py"):
            extra += ["--ro-bind", str(sandbox.ROOT / name), "/run/sandbox/" + name]
        argv[index:index] = extra
        try:
            result = subprocess.run(argv, pass_fds=fds, capture_output=True, text=True, timeout=30)
        finally:
            for fd in fds:
                os.close(fd)
    # This specific launcher failure precedes all fixture code. Never skip Python/test errors.
    if result.returncode and result.stderr.startswith("bwrap:") and any(
            reason in result.stderr for reason in (
                "loopback: Failed to create NETLINK_ROUTE socket: Operation not permitted",
                "Creating new namespace failed: Operation not permitted", "No permissions to create new namespace")):
        raise unittest.SkipTest("external sandbox blocks namespaces: " + result.stderr.strip())
    return result
