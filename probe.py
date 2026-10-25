# probe — атаки изнутри песочницы для `sandbox selftest`: попытки увидеть, прочитать или затронуть процессы
# и данные хоста. Каждая проверка: (что пробуем, защищено ли, подробность). Код выхода 1 — найдена уязвимость.
# Аргументы: МАРКЕР PID_ЖЕРТВЫ АБСТРАКТНЫЙ_СОКЕТ TCP_ПОРТ HOME PID_NS_ВЫЗЫВАЮЩЕГО NET_NS_ВЫЗЫВАЮЩЕГО
import ctypes, errno, fcntl, os, platform, pty, socket, struct, sys, termios

# До любой проверки: только отдельные PID/net namespaces. Прямой запуск на хосте
# должен завершиться без чтения чужих процессов и сетевой диагностики.
if len(sys.argv) != 8 or os.environ.get("SANDBOX") != "1":
    sys.exit("probe: запускайте только через sandbox selftest")
if (os.readlink("/proc/self/ns/pid") == sys.argv[6]
        or os.readlink("/proc/self/ns/net") == sys.argv[7]
        or os.environ.get("SANDBOX_NET") == "on"):
    sys.exit("probe: нет изоляции PID/сети; проверки не запускались")

MARK, VICTIM, ABSTRACT, PORT, REAL_HOME = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5]
NR = {
    "x86_64": dict(unshare=272, mount=165, bpf=321, perf_event_open=298, userfaultfd=323, io_uring_setup=425,
                   keyctl=250, open_by_handle_at=304, ptrace=101, process_vm_readv=310, init_module=175, setns=308),
    "aarch64": dict(unshare=97, mount=40, bpf=280, perf_event_open=241, userfaultfd=282, io_uring_setup=425,
                    keyctl=219, open_by_handle_at=265, ptrace=117, process_vm_readv=270, init_module=105, setns=268),
}[platform.machine()]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
results = []
me = os.getpid()


def check(name):
    def wrap(fn):
        try:
            safe, detail = fn()
        except Exception as e:
            safe, detail = False, f"ОШИБКА ПРОВЕРКИ: {type(e).__name__}: {e}"
        results.append((name, safe, detail))
        return fn
    return wrap


sections = []                               # (номер первой проверки раздела, название): для заголовков в отчёте


def part(title):
    sections.append((len(results), title))


def sys_call(name, *args):
    r = libc.syscall(ctypes.c_long(NR[name]), *[ctypes.c_long(a) for a in args])
    return r, errno.errorcode.get(ctypes.get_errno(), "?")


def others():
    # Только PID 1 и собственный мост, без перечисления /proc.
    return [p for p in (1, int(os.environ.get("SANDBOX_BRIDGE_PID", "0"))) if p > 0 and p != me]


def read(path, n=4096):
    with open(path, "rb") as f:
        return f.read(n)


# ---------- процессы ----------
part("Процессы")
@check("Маркер хоста отсутствует у контрольных процессов песочницы")
def _():
    found = []
    for p in others():
        for f in ("cmdline", "environ"):
            try:
                if MARK.encode() in read(f"/proc/{p}/{f}", 1 << 20):
                    found.append(f"{p}/{f}")
            except OSError:
                pass
    return not found, f"контрольных PID: {len(others())}" + (f"; МАРКЕР НАЙДЕН: {found}" if found else "")


@check("Окружение хоста не утекает через /proc/1/environ")
def _():
    try:
        data = read("/proc/1/environ", 1 << 20)
    except OSError as e:
        return True, f"закрыто ({e.strerror})"
    bad = [k for k in (MARK.encode(), b"DBUS_SESSION", b"WAYLAND_DISPLAY", b"XDG_RUNTIME_DIR", b"SSH_AUTH_SOCK") if k in data]
    n = data.count(b"\0")
    return not bad, f"{n} переменных" + (f"; утечка: {bad}" if bad else "")


@check("Сигнал процессу хоста (kill по его PID)")
def _():
    try:
        os.kill(VICTIM, 0)
    except ProcessLookupError:
        return True, "такого процесса нет в песочнице"
    except PermissionError:
        return True, "EPERM"
    try:
        ours = MARK.encode() not in read(f"/proc/{VICTIM}/cmdline")
    except OSError:
        ours = True
    return ours, "PID занят процессом самой песочницы" if ours else "СИГНАЛ ДОШЁЛ ДО ХОСТА"


@check("ptrace(ATTACH) к другому процессу")
def _():
    for p in others():
        r, e = sys_call("ptrace", 16, p, 0, 0)
        if r == 0:
            return False, f"присоединился к {p}"
    return True, "отказ (seccomp)"


@check("process_vm_readv: чтение памяти другого процесса")
def _():
    buf = ctypes.create_string_buffer(8)
    iov = struct.pack("PN", ctypes.addressof(buf), 8)
    liov = ctypes.create_string_buffer(iov)
    for p in others():
        r = libc.syscall(ctypes.c_long(NR["process_vm_readv"]), ctypes.c_long(p), liov, ctypes.c_long(1), liov, ctypes.c_long(1), ctypes.c_long(0))
        if r > 0:
            return False, f"прочитана память {p}"
    return True, "отказ (seccomp)"


@check("/proc/PID/mem, maps, fd, root, cwd других процессов (открытие)")
def _():
    opened = []
    for p in others():
        for f in ("mem", "maps", "root", "cwd"):
            try:
                if f in ("root", "cwd"):
                    os.listdir(f"/proc/{p}/{f}")
                else:
                    if not read(f"/proc/{p}/{f}", 64) and f == "maps":
                        continue
                opened.append(f"{p}/{f}")
            except OSError:
                pass
        try:
            fds = os.listdir(f"/proc/{p}/fd")        # номера видны владельцу; опасно, если дескриптор можно открыть
        except OSError:
            fds = []
        for f in fds:
            try:
                os.readlink(f"/proc/{p}/fd/{f}")
                os.close(os.open(f"/proc/{p}/fd/{f}", os.O_RDONLY))
                opened.append(f"{p}/fd/{f}")
            except OSError:
                pass
    return not opened, "все закрыты" if not opened else f"ОТКРЫТО: {opened}"


# ---------- каналы к процессам хоста ----------
part("Каналы к процессам хоста")
@check("Абстрактный unix-сокет процесса хоста")
def _():
    s = socket.socket(socket.AF_UNIX)
    try:
        s.connect("\0" + ABSTRACT)
    except OSError as e:
        return True, f"недоступен ({e.strerror})"
    return False, "ПОДКЛЮЧИЛСЯ к сокету хоста"


@check("TCP к службе хоста на 127.0.0.1")
def _():
    try:
        socket.create_connection(("127.0.0.1", PORT), timeout=2).close()
    except OSError as e:
        return True, f"недоступна ({e.strerror or e})"
    return False, "ПОДКЛЮЧИЛСЯ к службе хоста"


@check("TIOCSTI: подстановка нажатий в терминал")
def _():
    m, s = pty.openpty()
    try:
        fcntl.ioctl(s, termios.TIOCSTI, b"x")
    except OSError as e:
        return True, f"отказ ({errno.errorcode.get(e.errno)})"
    return False, "ВВОД В ТЕРМИНАЛ РАБОТАЕТ"


@check("Сокеты вне сетевого пространства: AF_VSOCK, AF_ALG, AF_BLUETOOTH")
def _():
    opened = []
    for fam, n in ((40, "VSOCK"), (38, "ALG"), (31, "BLUETOOTH")):
        try:
            socket.socket(fam, socket.SOCK_STREAM if fam == 40 else socket.SOCK_SEQPACKET).close()
            opened.append(n)
        except OSError:
            pass
    return not opened, "все запрещены" if not opened else f"ОТКРЫТЫ: {opened}"


# ---------- побег и ядро ----------
part("Побег и ядро")
for name, args in (("unshare", (0x10000000,)), ("setns", (0, 0)), ("mount", (0, 0, 0, 0, 0)), ("bpf", (0, 0, 0)),
                   ("perf_event_open", (0, 0, -1, -1, 0)), ("userfaultfd", (0,)), ("io_uring_setup", (1, 0)),
                   ("keyctl", (0, 0)), ("open_by_handle_at", (0, 0, 0)), ("init_module", (0, 0, 0))):
    def make(n=name, a=args):
        r, e = sys_call(n, *a)
        return r == -1 and e in ("EPERM", "ENOSYS"), f"{'отказ' if r == -1 else 'ВЫПОЛНЕНО'} ({e})"
    check(f"Системный вызов {name}")(make)


@check("Ограничения процесса: seccomp, no_new_privs, ноль capabilities")
def _():
    st = dict(l.split(":\t", 1) for l in read("/proc/self/status", 1 << 16).decode().splitlines() if ":\t" in l)
    ok = st.get("Seccomp", "").strip() == "2" and st.get("NoNewPrivs", "").strip() == "1" and int(st.get("CapEff", "1"), 16) == 0
    return ok, f"Seccomp={st.get('Seccomp','?').strip()} NoNewPrivs={st.get('NoNewPrivs','?').strip()} CapEff={st.get('CapEff','?').strip()}"


# ---------- файлы ----------
part("Файлы")
@check("Запись вне рабочей папки (/, /usr, /etc, /run/sandbox)")
def _():
    written = []
    for d in ("/", "/usr", "/etc", "/run/sandbox"):
        try:
            p = os.path.join(d, ".sandbox-probe")
            with open(p, "w") as f:
                f.write("x")
            os.unlink(p)
            written.append(d)
        except OSError:
            pass
    return not written, f"Landlock ABI {os.environ.get('SANDBOX_LANDLOCK', '?')}" + (f"; ЗАПИСАНО: {written}" if written else ", запись запрещена")


@check("Секреты и данные хоста не видны (~/.ssh, ~/.config, /run/user, /sys, /var, /dev/mem)")
def _():
    seen = [p for p in (f"{REAL_HOME}/.ssh", f"{REAL_HOME}/.config", f"{REAL_HOME}/.gnupg", "/run/user", "/sys",
                        "/var", "/root", "/dev/mem", "/dev/kmsg", "/etc/shadow", "/etc/machine-id") if os.path.exists(p)]
    homes = os.listdir("/home") if os.path.isdir("/home") else []
    real = os.path.basename(REAL_HOME)
    # в нейтральной среде своя папка /home/user; каталог с именем пользователя хоста допустим только как путь к инструментам профиля из ~
    allowed = {"user"} | ({real} if os.environ.get("SANDBOX_PROBE_TOOLS_HOME") == "1" else set()) if os.environ.get("SANDBOX_NEUTRAL") == "1" else {real}
    return not seen and set(homes) <= allowed, (f"ВИДНО: {seen}" if seen else "не видны") + f"; /home: {homes}"


@check("Чувствительные файлы /proc скрыты (kcore, kallsyms, keys, sched_debug, timer_list, cmdline)")
def _():
    open_ = []
    for f in ("kcore", "kallsyms", "keys", "key-users", "sched_debug", "timer_list", "cmdline", "locks", "modules"):
        try:
            if read(f"/proc/{f}", 64):
                open_.append(f)
        except OSError:
            pass
    return not open_, "скрыты" if not open_ else f"ЧИТАЮТСЯ: {open_}"


@check("Сеть отделена от пространства имён вызывающего процесса")
def _():
    return os.readlink("/proc/self/ns/net") != sys.argv[7], "отдельный net namespace; интерфейсы не перечислялись"


@check("Имя хоста скрыто")
def _():
    h = socket.gethostname()
    return h == "sandbox", h


# ---------- рабочая папка, сеть и среда ----------
part("Рабочая папка, сеть и среда")
def need_env(*names):
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        raise RuntimeError(f"не заданы контрольные значения {missing}")


@check("Соседние проекты и каталоги самой песочницы (state, profiles, logs, home) не видны")
def _():
    need_env("SANDBOX_PROBE_SIBLING", "SANDBOX_PROBE_ROOT")
    root = os.environ["SANDBOX_PROBE_ROOT"]
    seen = [p for p in (os.environ["SANDBOX_PROBE_SIBLING"], root + "/state", root + "/profiles", root + "/logs", root + "/home")
            if os.path.exists(p)]
    return not seen, "не видны" if not seen else f"ВИДНО: {seen}"


@check("Файлы, которые хост выполнит сам (.git/config, .git/hooks), доступны только для чтения")
def _():
    rels = [r for r in os.environ.get("SANDBOX_PROBE_PROTECTED", "").split(",") if r]
    if not rels:
        return True, "защита выключена профилем (protect = false)"
    writable = []
    for rel in rels:
        path = os.path.join(os.environ["SANDBOX_WORKSPACE"], rel)
        try:
            if os.path.isdir(path):
                marker = os.path.join(path, ".sandbox-probe")
                open(marker, "w").close()
                os.unlink(marker)
            else:
                os.close(os.open(path, os.O_WRONLY | os.O_APPEND))
            writable.append(rel)
        except OSError:
            pass
    base = os.environ["SANDBOX_WORKSPACE"]
    for parent in sorted({os.path.dirname(r) for r in rels if os.path.dirname(r)}):      # каталог-предок нельзя переименовать
        try:
            os.rename(os.path.join(base, parent), os.path.join(base, parent) + ".moved")
            os.rename(os.path.join(base, parent) + ".moved", os.path.join(base, parent))
            writable.append(f"{parent} (перенос)")
        except OSError:
            pass
    return not writable, "только чтение, перенос каталога невозможен" if not writable else f"ОБХОД ВОЗМОЖЕН: {writable}"


@check("/etc/hosts задан и localhost разрешается")
def _():
    ok = "localhost" in read("/etc/hosts", 4096).decode() and any(a[4][0] in ("127.0.0.1", "::1") for a in socket.getaddrinfo("localhost", None))
    return ok, "есть"


@check("Сокеты вне белого списка (AF_PACKET, AF_KEY, netlink аудита и netfilter) запрещены; UNIX и IPv4 работают")
def _():
    opened = []
    for fam, typ, proto, label in ((17, socket.SOCK_RAW, 0, "PACKET"), (15, socket.SOCK_RAW, 2, "KEY"),
                                   (16, socket.SOCK_RAW, 9, "NETLINK_AUDIT"), (16, socket.SOCK_RAW, 12, "NETLINK_NETFILTER")):
        try:
            socket.socket(fam, typ, proto).close()
            opened.append(label)
        except OSError:
            pass
    broken = []
    for fam in (socket.AF_UNIX, socket.AF_INET):
        try:
            socket.socket(fam).close()
        except OSError as e:
            broken.append(f"{fam}: {e.strerror}")
    return not opened and not broken, ("запрещены" if not opened else f"ОТКРЫТЫ: {opened}") + (f"; НЕ РАБОТАЮТ: {broken}" if broken else "")


if os.environ.get("SANDBOX_NEUTRAL") == "1":
    part("Нейтральная среда")
    @check("Нейтральная среда: /proc не раскрывает процессор, диски, загрузку и сборку ядра хоста")
    def _():
        models = {l.split(":", 1)[1].strip() for l in read("/proc/cpuinfo", 1 << 20).decode().splitlines() if l.startswith("model name")}
        units = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}
        limit = os.environ.get("SANDBOX_MEMORY_MAX", "").lower().rstrip("b")
        try:
            want = int(float(limit[:-1]) * units[limit[-1]] if limit and limit[-1] in units else float(limit)) >> 10
        except (ValueError, OverflowError):
            want = 8 << 20                              # infinity и проценты: показывается 8 ГиБ
        total = int(read("/proc/meminfo", 256).split()[1])
        filled = []
        for f in ("interrupts", "softirqs", "diskstats", "partitions", "swaps", "devices", "misc", "vmstat"):
            try:
                if read(f"/proc/{f}", 16):
                    filled.append(f)
            except OSError:
                pass
        version = read("/proc/version", 512).decode()
        ok = models == {"Virtual CPU"} and total == want and not filled and "sandbox@sandbox" in version
        return ok, f"процессор {sorted(models)}, MemTotal {total} кБ (лимит {want}), непустые скрытые файлы: {filled}"

    @check("Нейтральная среда: имя пользователя хоста, HOME, рабочий каталог и часовой пояс не раскрыты")
    def _():
        real = os.path.basename(REAL_HOME)
        env = os.environ
        exposed = [k for k in ("HOME", "SANDBOX_WORKSPACE") if REAL_HOME != "/home/user" and REAL_HOME in env.get(k, "")]
        exposed += [k for k in ("USER", "LOGNAME") if real != "user" and env.get(k) == real]
        names = [l.split(":", 1)[0] for l in read("/etc/passwd", 4096).decode().splitlines()]
        if real != "user" and real in names:
            exposed.append("passwd")
        ok = not exposed and env.get("HOME") == "/home/user" and env.get("SANDBOX_WORKSPACE") == "/workspace" and env.get("TZ") == "UTC"
        return ok, f"HOME={env.get('HOME')} рабочая папка={env.get('SANDBOX_WORKSPACE')} TZ={env.get('TZ')}" + (f"; ВИДНО В: {exposed}" if exposed else "")

    @check("Нейтральная среда: инструкции, passwd и служебные скрипты не оставляют путей хоста в mountinfo")
    def _():
        if os.environ.get("SANDBOX_DATA_BIND") != "1":
            return True, "bwrap без --ro-bind-data: пути хоста видны в mountinfo (обновите bubblewrap)"
        root = os.environ.get("SANDBOX_PROBE_ROOT", "")
        sources = [l.split()[3] for l in read("/proc/self/mountinfo", 1 << 20).decode().splitlines() if len(l.split()) > 3]
        leaked = sorted({n for src in sources for n in ("inner.py", "probe.py", "AGENT_POLICY.md", "passwd", "group", "hosts", "/state/run/")
                         if n in src or (root and src.startswith(root + "/state"))})
        return not leaked, "пути не видны" if not leaked else f"ВИДНО в источниках монтирования: {leaked}"


bad = [r for r in results if not r[1]]
errors = [r for r in bad if r[2].startswith("ОШИБКА ПРОВЕРКИ:")]
w = max(len(r[0]) for r in results)
for name, safe, detail in results:
    label = "[защищено]" if safe else "[ОШИБКА]  " if detail.startswith("ОШИБКА ПРОВЕРКИ:") else "[УЯЗВИМО] "
    print(f"  {label} {name:{w}}  {detail}")
print(f"\nИтог: успешно {len(results) - len(bad)} из {len(results)}; ошибок проверки: {len(errors)}."
      + (" ЗАЩИТА НЕ ПОДТВЕРЖДЕНА." if bad else " Проверенные сценарии пройдены; это не доказательство отсутствия всех уязвимостей."))
sys.exit(1 if bad else 0)
