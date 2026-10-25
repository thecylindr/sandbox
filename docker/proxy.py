"""Trusted sidecar: only a Unix listener; no project, credentials or host service mounts."""
import json
from pathlib import Path
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sandbox
import seccomp


def main():
    seccomp.install()
    data = json.loads(Path(sys.argv[1]).read_text("utf-8"))
    if (not isinstance(data.get("domains"), list) or not data["domains"]
            or not all(isinstance(d, str) and d != "*" for d in data["domains"])):
        raise ValueError("прокси требует явный список доменов")
    cfg = {"domains": data["domains"], "ports": [443], "allow_private_net": False}
    sandbox.log = lambda line: print(sandbox.printable(line), flush=True)
    server = sandbox.start_proxy("/run/sandbox-proxy/proxy.sock", cfg)
    try:
        threading.Event().wait()
    finally:
        server.close()


if __name__ == "__main__":
    main()
