# seccomp — фильтр системных вызовов для песочницы (классический BPF, без libseccomp).
# Запрещены вызовы для побега и доступа к чужим процессам: ptrace, process_vm_*, mount, bpf, io_uring,
# новые пространства имён, модули ядра, TIOCSTI и т.п. Сокеты — белый список семейств (UNIX, IPv4, IPv6,
# netlink только маршрутизации); вызовы новее проверенной таблицы получают ENOSYS.
# Таблицы номеров получены из заголовков ядра (x86_64, aarch64).
import platform, struct

ARCH_ID = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
EPERM, ENOSYS, EPROTONOSUPPORT, EAFNOSUPPORT = 1, 38, 93, 97
RET_ALLOW, RET_KILL = 0x7FFF0000, 0x80000000
RET_ERRNO = 0x00050000
NS_FLAGS = 0x7E020000   # CLONE_NEWNS|CGROUP|UTS|IPC|USER|PID|NET

DENY = {
    "x86_64": {
        "ptrace": 101, "syslog": 103, "uselib": 134, "personality": 135, "vhangup": 153,
        "modify_ldt": 154, "pivot_root": 155, "_sysctl": 156, "adjtimex": 159, "chroot": 161,
        "acct": 163, "settimeofday": 164, "mount": 165, "umount2": 166, "swapon": 167,
        "swapoff": 168, "reboot": 169, "sethostname": 170, "setdomainname": 171, "iopl": 172,
        "ioperm": 173, "create_module": 174, "init_module": 175, "delete_module": 176, "get_kernel_syms": 177,
        "query_module": 178, "quotactl": 179, "nfsservctl": 180, "lookup_dcookie": 212, "clock_settime": 227,
        "mbind": 237, "set_mempolicy": 238, "kexec_load": 246, "add_key": 248, "request_key": 249,
        "keyctl": 250, "migrate_pages": 256, "unshare": 272, "move_pages": 279, "perf_event_open": 298,
        "name_to_handle_at": 303, "open_by_handle_at": 304, "clock_adjtime": 305, "setns": 308, "process_vm_readv": 310,
        "process_vm_writev": 311, "kcmp": 312, "finit_module": 313, "kexec_file_load": 320, "bpf": 321,
        "userfaultfd": 323, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427, "open_tree": 428,
        "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
        "pidfd_getfd": 438, "mount_setattr": 442, "open_tree_attr": 467,
    },
    "aarch64": {
        "lookup_dcookie": 18, "umount2": 39, "mount": 40, "pivot_root": 41, "nfsservctl": 42,
        "chroot": 51, "vhangup": 58, "quotactl": 60, "acct": 89, "personality": 92,
        "unshare": 97, "kexec_load": 104, "init_module": 105, "delete_module": 106, "clock_settime": 112,
        "syslog": 116, "ptrace": 117, "reboot": 142, "sethostname": 161, "setdomainname": 162,
        "settimeofday": 170, "adjtimex": 171, "add_key": 217, "request_key": 218, "keyctl": 219,
        "swapon": 224, "swapoff": 225, "mbind": 235, "set_mempolicy": 237, "migrate_pages": 238,
        "move_pages": 239, "perf_event_open": 241, "name_to_handle_at": 264, "open_by_handle_at": 265, "clock_adjtime": 266,
        "setns": 268, "process_vm_readv": 270, "process_vm_writev": 271, "kcmp": 272, "finit_module": 273,
        "bpf": 280, "userfaultfd": 282, "kexec_file_load": 294, "io_uring_setup": 425, "io_uring_enter": 426,
        "io_uring_register": 427, "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431,
        "fsmount": 432, "fspick": 433, "pidfd_getfd": 438, "mount_setattr": 442, "open_tree_attr": 467,
    },
}
CLONE = {"x86_64": 56, "aarch64": 220}
CLONE3 = {"x86_64": 435, "aarch64": 435}
IOCTL = {"x86_64": 16, "aarch64": 29}
SOCKET = {"x86_64": 41, "aarch64": 198}
SOCKETPAIR = {"x86_64": 53, "aarch64": 199}
EXTRA = {"process_madvise": 440, "process_mrelease": 448}      # одинаковы на обеих архитектурах
# ioctl ввода в чужой терминал: TIOCSTI (подстановка нажатий), TIOCLINUX (консоль)
BAD_IOCTL = [0x5412, 0x541C]
# разрешённые семейства сокетов: AF_UNIX, AF_INET, AF_INET6; AF_NETLINK — только NETLINK_ROUTE и NETLINK_SOCK_DIAG.
# Остальные (AF_PACKET, AF_VSOCK, AF_ALG, AF_BLUETOOTH, AF_RDS, AF_KEY и др.) недоступны программам в песочнице.
SOCK_OK = [1, 2, 10]
AF_NETLINK, NETLINK_OK = 16, [0, 4]
KNOWN_MAX = 471     # наибольший номер вызова в заголовках ядра 7.2 (x86_64 и aarch64 совпадают выше 425)


def _ins(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


def build():
    """Возвращает байты программы BPF для текущей архитектуры (или None, если архитектура неизвестна)."""
    m = platform.machine()
    if m not in ARCH_ID:
        return None
    LD, JEQ, JGE, JSET, RET = 0x20, 0x15, 0x35, 0x45, 0x06
    prog, labels = [], {}

    def add(code, k, jt=0, jf=0):             # jt/jf — число или имя метки (переходы только вперёд)
        prog.append([code, jt, jf, k])

    def label(name):
        labels[name] = len(prog)

    add(LD, 4)                                # arch
    add(JEQ, ARCH_ID[m], 1, 0)
    add(RET, RET_KILL)                        # чужая архитектура (32-бит режим) — убить процесс
    add(LD, 0)                                # номер вызова
    if m == "x86_64":
        add(JGE, 0x40000000, "deny", 0)       # x32 ABI обходит таблицу — запретить
    add(JGE, KNOWN_MAX + 1, "enosys", 0)      # вызов новее проверенной таблицы: программы откатываются на старое поведение
    for nr in sorted(set(DENY[m].values()) | set(EXTRA.values())):
        add(JEQ, nr, "deny", 0)
    add(JEQ, CLONE[m], "clone", 0)
    add(JEQ, IOCTL[m], "ioctl", 0)
    add(JEQ, SOCKET[m], "socket", 0)
    add(JEQ, SOCKETPAIR[m], "socketpair", 0)
    add(JEQ, CLONE3[m], "enosys", 0)          # glibc сам откатится на clone, где флаги проверяются
    add(RET, RET_ALLOW)
    label("enosys")
    add(RET, RET_ERRNO | ENOSYS)
    label("clone")                            # clone: флаги — первый аргумент
    add(LD, 16)
    add(JSET, NS_FLAGS, "deny", 0)
    add(RET, RET_ALLOW)
    label("ioctl")                            # ioctl: команда — второй аргумент
    add(LD, 24)
    for c in BAD_IOCTL:
        add(JEQ, c, "deny", 0)
    add(RET, RET_ALLOW)
    label("socket")                           # socket: семейство — первый аргумент
    add(LD, 16)
    for f in SOCK_OK:
        add(JEQ, f, "allow", 0)
    add(JEQ, AF_NETLINK, "netlink", 0)
    add(RET, RET_ERRNO | EAFNOSUPPORT)
    label("netlink")                          # netlink: протокол — третий аргумент
    add(LD, 32)
    for p in NETLINK_OK:
        add(JEQ, p, "allow", 0)
    add(RET, RET_ERRNO | EPROTONOSUPPORT)
    label("socketpair")                       # socketpair: только AF_UNIX
    add(LD, 16)
    add(JEQ, 1, "allow", 0)
    add(RET, RET_ERRNO | EAFNOSUPPORT)
    label("allow")
    add(RET, RET_ALLOW)
    label("deny")
    add(RET, RET_ERRNO | EPERM)

    out = []
    for i, (code, jt, jf, k) in enumerate(prog):
        jt = labels[jt] - (i + 1) if isinstance(jt, str) else jt
        jf = labels[jf] - (i + 1) if isinstance(jf, str) else jf
        assert 0 <= jt < 256 and 0 <= jf < 256
        out.append(_ins(code, jt, jf, k))
    return b"".join(out)


def install():
    """Добавить фильтр текущему процессу и его потомкам; используется entrypoint Docker."""
    import ctypes
    bpf = build()
    if bpf is None:
        raise RuntimeError("seccomp: неподдерживаемая архитектура")
    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    code = ctypes.create_string_buffer(bpf)
    program = Program(len(bpf) // 8, ctypes.cast(code, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP")
