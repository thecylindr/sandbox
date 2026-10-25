# inner — первый процесс внутри песочницы (запускается bwrap как /usr/bin/python3 -I /run/sandbox/inner.py FD).
# Структура: задание из анонимного FD -> мост к прокси -> Landlock -> чистое окружение -> exec агента.
# Задание не передаётся аргументами: в cmdline не остаётся ни ключей, ни переменных.
import ctypes, json, os, resource, signal, socket, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import transport

PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS = 4, 38
SYS_CREATE, SYS_ADD, SYS_RESTRICT = 444, 445, 446      # landlock_* — одинаковы на x86_64 и aarch64

# права Landlock на запись (чтение уже ограничено набором смонтированных путей)
FS_WRITE_FILE, FS_TRUNCATE, FS_REFER = 1 << 1, 1 << 14, 1 << 13
FS_WRITE_V1 = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12)
SCOPE_ABSTRACT_UNIX, SCOPE_SIGNAL = 1 << 0, 1 << 1

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def fail(msg):
    print(f"sandbox(inner): {msg}", file=sys.stderr)
    os._exit(126)


def sc(*a):
    return libc.syscall(*[x if isinstance(x, ctypes.Array) else ctypes.c_long(x) for x in a])


def landlock(rw, devw):
    """Запись — только в rw (полностью) и devw (запись в устройства). Плюс запрет сигналов и абстрактных
    unix-сокетов за пределами песочницы. Действует на все потомки и не снимается. Возвращает версию ABI."""
    abi = sc(SYS_CREATE, 0, 0, 1)
    if abi < 1:
        return 0
    w = FS_WRITE_V1 | (FS_REFER if abi >= 2 else 0) | (FS_TRUNCATE if abi >= 3 else 0)
    if abi >= 6:
        attr = struct.pack("QQQ", w, 0, SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL)
    elif abi >= 4:
        attr = struct.pack("QQ", w, 0)
    else:
        attr = struct.pack("Q", w)
    buf = ctypes.create_string_buffer(attr, len(attr))
    fd = sc(SYS_CREATE, buf, len(attr), 0)
    if fd < 0:
        fail(f"landlock_create_ruleset: errno {ctypes.get_errno()}")

    def rule(path, access):
        try:
            pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError:
            return
        if not os.path.isdir(path):
            access &= FS_WRITE_FILE | (FS_TRUNCATE if abi >= 3 else 0)   # для файла допустимы только файловые права
        b = ctypes.create_string_buffer(struct.pack("=Qi", access, pfd), 12)
        r = sc(SYS_ADD, fd, 1, b, 0)
        os.close(pfd)
        if r < 0:
            fail(f"landlock_add_rule {path}: errno {ctypes.get_errno()}")

    for p in rw:
        rule(p, w)
    for p in devw:
        rule(p, FS_WRITE_FILE | (FS_TRUNCATE if abi >= 3 else 0))
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 or sc(SYS_RESTRICT, fd, 0) != 0:
        fail(f"landlock_restrict_self: errno {ctypes.get_errno()}")
    os.close(fd)
    return abi


def pipe(a, b):
    transport.relay(a, b)


def bridge(srv, sock_path):
    # мост 127.0.0.1:порт -> unix-сокет прокси хоста; память моста закрыта от чтения (не dumpable)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        fail("не удалось закрыть память моста")

    def forward(c):
        u = None
        try:
            u = socket.socket(socket.AF_UNIX)
            u.settimeout(10)
            u.connect(sock_path)
            pipe(c, u)
        except OSError:
            pass
        finally:
            if u is not None:
                u.close()

    transport.serve(srv, forward).join()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    fd = int(sys.argv[1])
    with os.fdopen(fd, "rb") as f:
        spec = json.loads(f.read())
    if spec.get("parent_netns") == os.readlink("/proc/self/ns/net"):
        fail("пространство сети не отделено от вызывающего процесса")
    transport.require_loopback()
    if spec.get("nproc"):                       # запасной предел числа задач, когда нет cgroup (systemd --user)
        resource.setrlimit(resource.RLIMIT_NPROC, (spec["nproc"], spec["nproc"]))
    srv = None
    if spec.get("bridge"):
        sock_path, port = spec["bridge"]
        transport.wait_proxy(sock_path)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(64)
    abi = landlock(spec["rw"], spec["devw"]) if spec["landlock"] else 0
    if spec["landlock"] and abi < 1 and spec["landlock_required"]:
        fail("ядро без Landlock, а профиль его требует (landlock_required)")
    bridge_pid = 0
    if srv:
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            fail("не удалось закрыть память моста")
        parent = os.getpid()
        bridge_pid = os.fork()
        if bridge_pid == 0:
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
                fail("не удалось привязать завершение моста к агенту")
            if os.getppid() != parent:
                os._exit(126)
            os.closerange(3, srv.fileno())
            os.closerange(srv.fileno() + 1, 65536)
            bridge(srv, sock_path)
    if srv:
        srv.close()
    os.closerange(3, 65536)                    # агенту не достаётся ни одного лишнего дескриптора
    env = spec["env"]
    env["SANDBOX_LANDLOCK"] = str(abi)
    env["SANDBOX_BRIDGE_PID"] = str(bridge_pid)
    os.chdir(spec["chdir"])
    try:
        os.execvpe(spec["cmd"][0], spec["cmd"], env)
    except OSError as e:
        fail(f"не удалось запустить {spec['cmd'][0]}: {e}")


if __name__ == "__main__":
    main()
