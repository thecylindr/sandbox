"""Trusted Docker entrypoint: seccomp -> clean job -> existing inner.py."""
import json
import os
from pathlib import Path
import sys
import tempfile

def job(command, source):
    access = source.get("SANDBOX_ACCESS", "read")
    network = source.get("SANDBOX_NET", "off")
    if access not in ("read", "edit") or network not in ("off", "allowlist"):
        raise ValueError("недопустимые параметры изоляции")
    env = {"HOME": "/home/node", "USER": "node", "LOGNAME": "node", "PATH": "/usr/local/bin:/usr/bin:/bin",
           "LANG": "C.UTF-8", "TERM": source.get("TERM", "xterm-256color"), "SANDBOX": "1",
           "SANDBOX_NET": network, "SANDBOX_ACCESS": access, "SANDBOX_WORKSPACE": "/workspace",
           "SANDBOX_POLICY": "/run/sandbox/AGENT_POLICY.md", "CODEX_HOME": "/home/node/.codex",
           "CLAUDE_CONFIG_DIR": "/home/node/.claude", "DISABLE_AUTOUPDATER": "1", "DISABLE_UPDATES": "1"}
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        if key in source:
            env[key] = source[key]
    bridge = None
    if network == "allowlist":
        proxy = "http://127.0.0.1:3128"
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env[key] = proxy
        env.update({"NO_PROXY": "127.0.0.1,localhost", "NODE_USE_ENV_PROXY": "1"})
        bridge = ["/run/sandbox-proxy/proxy.sock", 3128]
    return {"env": env, "cmd": command, "chdir": "/workspace",
            "rw": (["/workspace"] if access == "edit" else []) + ["/home/node", "/tmp", "/dev/shm"],
            "devw": ["/dev"], "bridge": bridge, "landlock": True, "landlock_required": False}


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import inner
    import seccomp
    seccomp.install()  # A failure stops launch; the Docker default filter also remains active.
    spec = job(sys.argv[1:] or ["bash"], os.environ)
    with tempfile.TemporaryFile() as stream:
        stream.write(json.dumps(spec).encode())
        stream.flush()
        stream.seek(0)
        fd = os.dup(stream.fileno())
    sys.argv = ["inner.py", str(fd)]
    inner.main()


if __name__ == "__main__":
    main()
