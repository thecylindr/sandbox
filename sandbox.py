#!/usr/bin/env python3
# sandbox — запуск ИИ-помощников (codex, claude и др.) в изоляции.
# Структура: профили -> проверка путей -> подтверждение -> bwrap (Linux/WSL) + прокси с белым списком доменов.
# Слои: пространства имён, сброс прав, seccomp (seccomp.py), Landlock и чистое окружение (inner.py), маски /proc и
# нейтральная среда (neutral.py), защита исполняемых на хосте файлов (guard.py), лимиты cgroup/RLIMIT.
# Самопроверка атаками изнутри — `sandbox selftest` (probe.py).
import argparse, contextlib, copy, hashlib, ipaddress, json, os, re, shutil, signal, socket, subprocess, sys, tempfile, threading, time
import transport
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROFILES, LOGS, STATE = ROOT / "profiles", ROOT / "logs", ROOT / "state"
WORKSPACES, HOMES = ROOT / "workspaces", ROOT / "home"   # единственное место, где LLM может писать / постоянный $HOME агента
BRIDGE_PORT = 3128
IN_DIR = "/run/sandbox"
IN_SOCK = IN_DIR + "/proxy.sock"
POLICY = ROOT / "AGENT_POLICY.md"
SAFE_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*"
# файлы /proc, раскрывающие ядро и чужие процессы: подменяются пустыми
PROC_MASK = ["kcore", "kallsyms", "keys", "key-users", "sched_debug", "timer_list", "timer_stats", "latency_stats",
             "sysrq-trigger", "kmsg", "cmdline", "locks", "modules", "iomem", "ioports", "vmallocinfo", "slabinfo",
             "pagetypeinfo", "zoneinfo", "buddyinfo", "kpagecount", "kpageflags", "kpagecgroup", "config.gz"]
PROC_HIDE_DIRS = ["acpi", "asound", "scsi", "irq", "bus", "fs", "tty", "driver", "dynamic_debug", "pressure"]

DEFAULTS = {
    "description": "", "command": [], "workdir_rw": True, "ro": [], "rw": [],
    "network": "off",            # off — сети нет; allowlist — только домены из списка
    "domains": [], "ports": [443], "allow_private_net": False,
    "env_pass": [], "env_set": {}, "new_session": True,
    "persist_home": True,        # свой постоянный $HOME в ~/sandbox/home/<профиль> (настоящий домашний каталог не виден)
    "memory_max": "8G", "tasks_max": 2048,   # лимиты cgroup (systemd-run --user), если доступны
    "seccomp": True,
    "landlock": True,            # запись только в рабочую папку и $HOME, запрет сигналов/сокетов наружу (ядро 5.13+/6.12+)
    "landlock_required": False,  # true — не запускать, если ядро без Landlock
    "neutral": False,            # нейтральная среда: /proc без оборудования хоста, имя user, /home/user, /workspace, UTC, C.UTF-8
    "home_scope": "profile",     # profile — один $HOME на профиль; workspace — свой $HOME на каждую рабочую папку
    "protect": True,             # .git/config, .git/hooks, .vscode и т. п. внутри только для чтения + проверка после запуска
    "protect_extra": [],         # дополнительные пути (от корня рабочей папки) только для чтения
    "tmp_size": "1G",            # размер /tmp (tmpfs); пусто — без ограничения (нужен bwrap с --size)
}
SIZE_UNITS = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}
BASE_ENV = ["TERM", "LANG", "LC_ALL", "COLORTERM"]
# пути, которые нельзя открывать агенту (ключи, токены, браузерные профили)
SENSITIVE = [".ssh", ".gnupg", ".aws", ".kube", ".docker", ".netrc", ".git-credentials", ".password-store",
             ".config/gcloud", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware",
             ".mozilla", ".local/share/keyrings", ".local/share/kwalletd", ".config/sops", ".pki"]
FORBIDDEN_ABS = ["/etc", "/proc", "/sys", "/dev", "/run", "/var", "/boot", "/root", "/usr", "/bin", "/sbin", "/lib", "/lib64"]
# диски Windows в WSL: корень диска, системные каталоги, профили пользователей и их секреты
WIN_DRIVE = re.compile(r"^/mnt/[a-z](?:/(.*))?$")
WIN_SYSTEM = {"windows", "program files", "program files (x86)", "programdata", "$recycle.bin", "system volume information", "recovery"}
WIN_SECRETS = {"appdata", ".ssh", ".aws", ".gnupg", ".kube", ".azure", ".docker", ".config", "ntuser.dat", ".gitconfig",
               ".git-credentials", ".npmrc", ".codex", ".claude"}


def die(msg):
    print(f"sandbox: {msg}", file=sys.stderr)
    sys.exit(2)


def platform_machine():
    import platform
    return platform.machine()


def need(module):
    """Подключение соседнего модуля (neutral, guard, tomlmini); без него песочница не запускается вхолостую."""
    try:
        return __import__(module)
    except ImportError:
        die(f"не найден {module}.py рядом с sandbox.py: переустановите песочницу (install.sh)")


def size_bytes(text):
    """'8G', '512m', '1048576' -> байты (формат MemoryMax systemd без суффикса B); ValueError при другом формате."""
    t = str(text).strip().lower().rstrip("b")
    unit = t[-1] if t and t[-1] in "kmgt" else ""
    value = float(t[:-1] if unit else t) * SIZE_UNITS[unit]
    if not 0 <= value < 1 << 60:                      # inf, nan и нелепо большие значения
        raise ValueError(text)
    return int(value)


def memory_limit(text):
    """Лимит памяти в байтах для сведений /proc; infinity и проценты (их понимает systemd) заменяются на 8 ГиБ."""
    try:
        return size_bytes(text)
    except ValueError:
        return 8 << 30


# ---------- журнал ----------
_log_lock = threading.Lock()
_log_tag = "-"


def printable(text):
    """Управляющие и невидимые символы -> \\xNN: в журнал попадают строки, которые задаёт агент (адрес CONNECT и т. п.)."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(text))


def log(line):
    LOGS.mkdir(parents=True, exist_ok=True)
    with _log_lock, open(LOGS / (time.strftime("%Y-%m-%d") + ".log"), "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%H:%M:%S')} [{_log_tag}] {printable(line)}\n")


# ---------- пути ----------
def tilde(path):
    """Путь для человека: домашний каталог записан как ~."""
    home, text = str(Path.home()), str(path)
    return "~" + text[len(home):] if text == home or text.startswith(home + os.sep) else text


def expand(p):
    p = os.path.expandvars(os.path.expanduser(str(p)))
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", p)          # путь Windows -> /mnt/<диск>/... (внутри WSL)
    if m:
        p = f"/mnt/{m[1].lower()}/" + m[2].replace("\\", "/")
    return os.path.abspath(p)


def windows_problem(rp):
    """Диски Windows в WSL (/mnt/<диск>/...): диск целиком, системные каталоги, профиль и его секреты."""
    rp = str(rp)
    if rp == "/mnt" or rp.startswith(("/mnt/wsl", "/mnt/docker")):
        return "служебный каталог WSL"
    m = WIN_DRIVE.match(rp)
    if not m:
        return None
    parts = [x for x in (m[1] or "").split("/") if x]
    low = [x.lower() for x in parts]
    if not parts:
        return "диск Windows целиком"
    if low[0] in WIN_SYSTEM:
        return "системный каталог Windows"
    if low[0] == "users" and len(parts) <= 2:
        return "профиль Windows целиком"
    if low[0] == "users" and low[2] in WIN_SECRETS:
        return f"секреты профиля Windows ({parts[2]})"
    return None


def check_path(p, allow_sensitive):
    rp = Path(os.path.realpath(p))
    home = Path(os.path.realpath(Path.home()))       # сравнение с разрешёнными путями: $HOME может быть ссылкой (/home -> /var/home)
    if allow_sensitive:
        return
    bad = None
    if rp == Path("/") or rp == home or rp in home.parents:
        bad = "корень или домашняя папка целиком"
    elif any(rp == Path(a) or Path(a) in rp.parents for a in FORBIDDEN_ABS) and not (home == rp or home in rp.parents):
        bad = "системный каталог"
    elif rp == WORKSPACES or rp in ROOT.parents or (rp == ROOT or ROOT in rp.parents) and WORKSPACES not in rp.parents:
        bad = "каталог самой песочницы (разрешены только рабочие папки workspaces/<имя>)"
    elif windows_problem(rp):
        bad = windows_problem(rp)
    else:
        for s in SENSITIVE:
            sp = Path(os.path.realpath(home / s))
            if rp == sp or sp in rp.parents or rp in sp.parents:
                bad = f"секреты (~/{s})"
    if bad:
        die(f"путь {p} отклонён: {bad}. Если это точно нужно — --allow-sensitive")


def reachable(p, bound):
    rp = os.path.realpath(p)
    return rp.startswith("/usr/") or any(rp == b or rp.startswith(b.rstrip("/") + "/") for b in bound)


def checked_directory(path):
    """Не позволять постоянным каталогам состояния перенаправлять запись через symlink."""
    path = Path(path)
    if path.resolve() != path.absolute():
        die(f"каталог не должен проходить через символическую ссылку: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def workspace_path(name):
    if not re.fullmatch(SAFE_NAME, name):
        die("имя рабочей папки: буквы, цифры, . _ - (без путей)")
    checked_directory(WORKSPACES)
    path = WORKSPACES / name
    if path.is_symlink() or path.resolve() != path.absolute():
        die(f"рабочая папка не должна быть символической ссылкой: {path}")
    return path


def profile_id(name):
    """Путь к внешнему TOML никогда не используется как путь постоянного $HOME."""
    if name.endswith(".toml"):
        stem = Path(name).stem
        if not re.fullmatch(SAFE_NAME, stem):
            die("недопустимое имя профиля")
        return stem + "-" + hashlib.sha256(str(Path(name).resolve()).encode()).hexdigest()[:12]
    if not re.fullmatch(SAFE_NAME, name):
        die("имя профиля должно быть без путей; для внешнего файла укажите путь .toml")
    return name


# ---------- профили ----------
def toml_loads(text):
    """tomllib (Python 3.11+), иначе tomli, иначе встроенный разбор подмножества TOML (tomlmini.py)."""
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            tomllib = need("tomlmini")
    return tomllib.loads(text)


def load_profile(name):
    profile_id(name)
    p = Path(name) if name.endswith(".toml") else PROFILES / f"{name}.toml"
    if not p.is_file():
        die(f"профиль не найден: {p}")
    try:
        data = toml_loads(p.read_text("utf-8"))
    except ValueError as e:                       # tomllib.TOMLDecodeError и ошибки tomlmini — подклассы ValueError
        die(f"профиль {p}: {e}")
    bad = set(data) - set(DEFAULTS)
    if bad:
        die(f"неизвестные ключи в профиле: {', '.join(sorted(bad))}")
    cfg = {**copy.deepcopy(DEFAULTS), **data}
    validate_network(cfg)
    if cfg["home_scope"] not in ("profile", "workspace"):
        die("home_scope должен быть profile или workspace")
    for key, extra in (("memory_max", r"infinity|\d{1,3}%"), ("tmp_size", None)):
        try:
            if cfg[key] and not (extra and re.fullmatch(extra, str(cfg[key]).strip().lower())):
                size_bytes(cfg[key])
        except ValueError:
            die(f"{key}: ожидается размер вида 512M или 8G" + (", infinity или проценты" if extra else ""))
    return cfg


def validate_network(cfg):
    if cfg["network"] not in ("off", "allowlist"):
        die("сеть хоста запрещена; допустимы только off и allowlist")
    if cfg.get("allow_private_net", False) is not False:
        die("allow_private_net должен быть false: службы хоста и локальной сети закрыты")


# ---------- прокси с белым списком доменов (на стороне хоста, через unix-сокет) ----------
def domain_ok(host, patterns):
    host = host.lower().rstrip(".")
    for p in patterns:
        p = p.lower()
        if p == "*":                               # весь интернет, но локальная сеть всё равно закрыта
            return True
        if p.startswith("*."):
            if host.endswith(p[1:]) or host == p[2:]:
                return True
        elif host == p:
            return True
    return False


HOST_NAME = re.compile(r"(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
NAT64 = ipaddress.ip_network("64:ff9b::/96")


def parse_target(text):
    """Адрес из CONNECT: host:port, [IPv6]:port или host -> (host, порт); None, если запись недопустима."""
    if text.startswith("["):
        host, closing, rest = text[1:].partition("]")
        if not closing:
            return None
        port = rest[1:] if rest.startswith(":") else ("443" if not rest else "")
        if ":" not in host:
            return None
    else:
        host, sep, port = text.partition(":")
        port = port if sep else "443"
    host = host.lower().rstrip(".")
    if "%" in host:
        return None
    if not (len(port) <= 5 and port.isascii() and port.isdigit() and 0 < int(port) < 65536):
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_NAME.fullmatch(host):
            return None
    return host, int(port)


def public_address(text):
    """Глобальный адрес; встроенные IPv4 (::ffff:a.b.c.d, 6to4, Teredo, NAT64) проверяются как обычные IPv4."""
    ip = ipaddress.ip_address(text.partition("%")[0])
    embedded = []
    if ip.version == 6:
        embedded = [e for e in (ip.ipv4_mapped, ip.sixtofour) if e] + list(ip.teredo or ())
        if ip in NAT64:
            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    def unicast(address):
        return (address.is_global and not address.is_multicast and not address.is_unspecified
                and not (address.is_reserved if address.version == 4 else address.is_site_local))
    return "%" not in text and unicast(ip) and all(unicast(e) for e in embedded)


def pipe(a, b, initial=b""):
    transport.relay(a, b, initial)


def connect_resolved(addrs, timeout=15):
    """Use validated numeric sockaddrs, try IPv4/IPv6 within one deadline; no second DNS lookup."""
    deadline = time.monotonic() + timeout
    last = OSError("DNS не вернул адресов")
    for index, (family, kind, protocol, _, address) in enumerate(addrs):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("время соединения истекло")
        up = socket.socket(family, kind, protocol)
        try:
            up.settimeout(min(5, remaining / (len(addrs) - index)))
            up.connect(address)
            return up
        except OSError as exc:
            last = exc
            up.close()
    raise last


def proxy_conn(conn, cfg, resolve=None, connect=None, authenticate=None):
    up = None
    try:
        deadline = time.monotonic() + 10       # общий предел, включая медленную отправку заголовков
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("CONNECT header timeout")
            conn.settimeout(remaining)
            d = conn.recv(min(4096, 16384 - len(buf)))
            if not d:
                return
            buf += d
        if b"\r\n\r\n" not in buf or len(buf.split(b"\r\n\r\n", 1)[0]) > 16384:
            conn.sendall(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
            return
        header, initial = buf.split(b"\r\n\r\n", 1)
        if authenticate is not None and not authenticate(header):
            conn.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="sandbox"\r\n\r\n')
            return
        parts = header.split(b"\r\n", 1)[0].decode("latin1").split(" ")
        if len(parts) != 3 or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        if len(parts) < 2 or parts[0] != "CONNECT":
            log("DENY не-CONNECT запрос")
            conn.sendall(b"HTTP/1.1 405 Only CONNECT\r\n\r\n")
            return
        target = parse_target(parts[1])
        if target is None:
            log(f"DENY некорректный адрес {parts[1]}")
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        host, port = target
        if not domain_ok(host, cfg["domains"]) or port not in cfg["ports"]:
            log(f"DENY {host}:{port}")
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        addrs = resolve(host, port) if resolve else socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        # защита от сканирования локальной сети: только публичные адреса
        if not addrs or not all(a[0] in (socket.AF_INET, socket.AF_INET6) and public_address(a[4][0]) for a in addrs):
            log(f"DENY {host}:{port} -> непубличный адрес")
            conn.sendall(b"HTTP/1.1 403 Private address\r\n\r\n")
            return
        up = connect(addrs) if connect else connect_resolved(addrs)
        conn.settimeout(10)
        log(f"ALLOW {host}:{port}")
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        pipe(conn, up, initial)
    except OSError as e:
        log(f"ERR {e}")
        if up is None:
            with contextlib.suppress(OSError):
                conn.settimeout(1)
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
    finally:
        conn.close()
        if up is not None:
            up.close()


def proxy_sock(tmp):
    """Путь сокета прокси в коротком закрытом каталоге (XDG_RUNTIME_DIR или /tmp): без имени пользователя и корня
    песочницы, поэтому он не раскрывается в mountinfo и укладывается в предел sun_path."""
    run = os.environ.get("XDG_RUNTIME_DIR", "")
    d = Path(run if run.startswith("/") and os.path.isdir(run) else "/tmp") / ("sbx-" + Path(tmp).name)
    d.mkdir(mode=0o700, exist_ok=True)
    return str(d / "proxy.sock")


def bind_unix(srv, path):
    """bind для AF_UNIX; путь длиннее предела sun_path (107 байт) задаётся через /proc/self/fd/<каталог>/<имя>."""
    if len(os.fsencode(path)) < 104:
        srv.bind(path)
        return
    dfd = os.open(os.path.dirname(path), os.O_PATH | os.O_DIRECTORY)
    try:
        srv.bind(f"/proc/self/fd/{dfd}/{os.path.basename(path)}")
    finally:
        os.close(dfd)


def start_proxy(sock_path, cfg):
    srv = socket.socket(socket.AF_UNIX)
    try:
        bind_unix(srv, sock_path)
        os.chmod(sock_path, 0o600)
        srv.listen(64)
        transport.serve(srv, lambda c: proxy_conn(c, cfg))
    except Exception:
        srv.close()
        raise
    return srv


# ---------- сборка команды bwrap ----------
def bwrap_features(bwrap):
    """Текст справки bwrap: по нему определяются поддерживаемые ключи (--disable-userns, --ro-bind-data, --size)."""
    try:
        return subprocess.run([bwrap, "--help"], capture_output=True, text=True).stdout
    except OSError:
        return ""


def anon_fd(tmp, data):
    """Анонимный файл с данными -> дескриптор с позицией 0, готовый к pass_fds."""
    with tempfile.TemporaryFile(dir=tmp) as f:
        f.write(data)
        f.flush()
        f.seek(0)
        return os.dup(f.fileno())


def tool_path(binds, neutral_env):
    """PATH внутри: каталоги из PATH хоста, лежащие в смонтированных путях, и стандартные системные."""
    host = [d for d in os.environ.get("PATH", "").split(":") if d and os.path.isdir(d)]
    if neutral_env:           # без каталогов /usr из PATH хоста (jvm, perl и т. п.): они раскрывают набор установленного ПО
        inside = [os.path.realpath(d) for d in host]
        keep = [d for d, r in zip(host, inside) if any(r == b or r.startswith(b.rstrip("/") + "/") for b in binds)]
        return list(dict.fromkeys(keep + need("neutral").PATH))
    return list(dict.fromkeys([d for d in host if reachable(d, binds)] + ["/usr/local/bin", "/usr/bin", "/bin"]))


def build(cfg, cwd, command, tmp, allow_sensitive, name="check", allow_outside=False, chdir=None, home_key=None,
          nproc=None, protect=()):
    validate_network(cfg)
    if not re.fullmatch(SAFE_NAME, name):
        die("недопустимое имя постоянного $HOME профиля")
    home_key = home_key or name
    if not re.fullmatch(SAFE_NAME + r"(\+" + SAFE_NAME + ")?", home_key):
        die("недопустимое имя постоянного $HOME")
    host_home = str(Path.home())
    binds = {}
    nl = need("neutral") if cfg["neutral"] else None

    def add(path, mode, must_exist):
        if not os.path.exists(path):
            if must_exist:
                print(f"sandbox: пропущено (нет такого пути): {path}", file=sys.stderr)
            return
        check_path(path, allow_sensitive)
        path = os.path.realpath(path)          # проверяем и монтируем один канонический путь
        if binds.get(path) != "rw":
            binds[path] = mode

    for p in cfg["ro"]:
        add(expand(p), "ro", False)
    for p in cfg["rw"]:
        p = expand(p)
        # запись разрешена только в workspaces/ — иначе нужен явный --allow-outside
        if not allow_outside and WORKSPACES not in Path(os.path.realpath(p)).parents:
            die(f"запись вне {WORKSPACES} запрещена: {p} (--allow-outside, если это осознанно)")
        add(p, "rw", True)
    add(cwd, "rw" if cfg["workdir_rw"] else "ro", True)
    check_path(cwd, allow_sensitive)
    cwd_real = os.path.realpath(cwd)

    def inside(path):
        """Путь хоста -> путь внутри песочницы (в нейтральной среде рабочая папка видна как /workspace)."""
        path = os.path.realpath(path)
        if nl and (path == cwd_real or path.startswith(cwd_real + "/")):
            return nl.WORKSPACE + path[len(cwd_real):]
        return path

    exe = shutil.which(command[0])
    if not exe:
        die(f"команда не найдена на хосте: {command[0]}")
    if not (reachable(exe, binds) and reachable(os.path.dirname(exe), binds)):
        die(f"{exe} вне песочницы: добавьте его каталог в ro профиля (например ~/.local или ~/.nvm)")
    bwrap = shutil.which("bwrap") or "bwrap"
    help_text = bwrap_features(bwrap)
    data_ok = "--ro-bind-data" in help_text
    home = nl.HOME if nl else host_home
    user = nl.USER if nl else os.environ.get("USER", "user")

    # env -i: bwrap становится PID 1 внутри, и его окружение читается через /proc/1/environ — оно должно быть пустым
    a = ["/usr/bin/env", "-i", bwrap, "--die-with-parent", "--unshare-all", "--clearenv",
         "--cap-drop", "ALL", "--hostname", "sandbox"]
    if "--disable-userns" in help_text:
        a += ["--unshare-user", "--disable-userns"]        # запрет создавать вложенные user namespace
    if cfg["new_session"] or not cfg["seccomp"]:           # без seccomp TIOCSTI не запрещён — сессия обязательна
        a.append("--new-session")
    a += ["--ro-bind", "/usr", "/usr"]
    for d in ("bin", "sbin", "lib", "lib64"):
        h = f"/{d}"
        if os.path.islink(h):
            a += ["--symlink", os.readlink(h), h]
        elif os.path.isdir(h):
            a += ["--ro-bind", h, h]
    # сертификаты и политики TLS; localtime — только в обычной среде (в нейтральной время UTC через TZ)
    for e in ("ssl", "ca-certificates", "pki", "crypto-policies", "ld.so.cache", "alternatives", "nsswitch.conf") + (() if nl else ("localtime",)):
        a += ["--ro-bind-try", f"/etc/{e}", f"/etc/{e}"]
    a += ["--ro-bind-try", "/var/lib/ca-certificates", "/var/lib/ca-certificates"]      # openSUSE: пакет сертификатов лежит в /var

    fds = []

    def text_mount(dest, text=None, source=None):
        """Файл только для чтения с содержимым text или из файла source. Через дескриптор путь хоста не попадает в mountinfo."""
        if data_ok:
            fd = anon_fd(tmp, text.encode() if text is not None else Path(source).read_bytes())
            fds.append(fd)
            return ["--ro-bind-data", str(fd), dest]
        if source is None:
            fd, source = tempfile.mkstemp(dir=tmp)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
        return ["--ro-bind", str(source), dest]

    # синтетические passwd/group/hosts: имена других пользователей хоста не видны, localhost разрешается всегда
    uid, gid = os.getuid(), os.getgid()
    files = {"passwd": f"{user}:x:{uid}:{gid}::{home}:/bin/sh\n", "group": f"{user}:x:{gid}:\n",
             "hosts": "127.0.0.1 localhost\n::1 localhost\n"}
    files["resolv.conf"] = "nameserver 127.0.0.1\noptions attempts:1 timeout:1\n"
    for n, text in files.items():
        a += text_mount(f"/etc/{n}", text)

    a += ["--proc", "/proc", "--dev", "/dev"]
    if cfg["tmp_size"] and "--size" in help_text:
        a += ["--size", str(size_bytes(cfg["tmp_size"]))]
    a += ["--tmpfs", "/tmp"]
    for f in PROC_MASK + (nl.MASK if nl else []):
        if os.path.exists(f"/proc/{f}"):
            a += ["--ro-bind", "/dev/null", f"/proc/{f}"]
    for d in PROC_HIDE_DIRS:
        if os.path.isdir(f"/proc/{d}"):
            a += ["--tmpfs", f"/proc/{d}", "--remount-ro", f"/proc/{d}"]
    if nl:
        for rel, text in nl.proc_files(memory_limit(cfg["memory_max"])).items():
            if os.path.exists(f"/proc/{rel}"):
                a += text_mount(f"/proc/{rel}", text)
    if cfg["persist_home"] and name != "check":
        checked_directory(HOMES)
        ph = checked_directory(HOMES / home_key)  # токены агента хранятся отдельно от настоящего ~
        a += ["--bind", str(ph), home]
    else:
        a += ["--tmpfs", home]
    for p in sorted(binds, key=len):                      # родители раньше вложенных путей
        a += ["--bind" if binds[p] == "rw" else "--ro-bind", p, inside(p)]
    for p, mode in protect:                               # файлы, которые хост выполнит сам: внутри только для чтения
        a += ["--bind-try" if mode == "rw" else "--ro-bind-try", p, inside(p)]

    env = {"HOME": home, "USER": user, "LOGNAME": user, "PATH": ":".join(tool_path(binds, bool(nl)))}
    if nl:
        env.update(nl.ENV)
    for n in [x for x in BASE_ENV if not (nl and x in ("LANG", "LC_ALL"))] + cfg["env_pass"]:
        if n in os.environ:
            env[n] = os.environ[n]
    for k, v in cfg["env_set"].items():
        v = os.path.expandvars(os.path.expanduser(str(v)))
        env[k] = home + v[len(host_home):] if nl and (v == host_home or v.startswith(host_home + "/")) else v

    # Правила читаются из доверенного файла и монтируются только для чтения.
    # Глобальные инструкции дополняют инструкции проекта, но не являются границей безопасности.
    env.update({"SANDBOX": "1", "SANDBOX_POLICY": f"{IN_DIR}/AGENT_POLICY.md", "SANDBOX_WORKSPACE": inside(cwd),
                "CODEX_HOME": f"{home}/.codex", "CLAUDE_CONFIG_DIR": f"{home}/.claude",
                "SANDBOX_NEUTRAL": "1" if nl else "0", "SANDBOX_MEMORY_MAX": str(cfg["memory_max"]),
                "SANDBOX_DATA_BIND": "1" if data_ok else "0"})
    for dest in (f"{IN_DIR}/AGENT_POLICY.md", f"{home}/.codex/AGENTS.override.md", f"{home}/.claude/CLAUDE.md"):
        a += text_mount(dest, source=POLICY)

    bridge = None
    if cfg["network"] == "allowlist":
        sock = proxy_sock(tmp)
        Path(sock).touch()                     # точка монтирования; сам сокет создаётся перед запуском
        px = f"http://127.0.0.1:{BRIDGE_PORT}"
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env[k] = px
        env.update({"NO_PROXY": "127.0.0.1,localhost", "NODE_USE_ENV_PROXY": "1"})
        a += ["--bind", sock, IN_SOCK]
        bridge = [IN_SOCK, BRIDGE_PORT]
    env["SANDBOX_NET"] = cfg["network"]
    for f in ("inner.py", "probe.py", "transport.py"):
        a += text_mount(f"{IN_DIR}/{f}", source=ROOT / f)

    if cfg["seccomp"]:
        import seccomp
        bpf = seccomp.build()
        if bpf is None:
            die("seccomp: архитектура не поддерживается (отключите seccomp=false в профиле на свой риск)")
        f = Path(tmp) / "filter.bpf"
        f.write_bytes(bpf)
        fd = os.open(f, os.O_RDONLY)
        fds.append(fd)
        a += ["--seccomp", str(fd)]

    # Анонимный файл: большие задания не блокируются на ёмкости pipe.
    rw = [inside(p) for p, m in binds.items() if m == "rw"] + [home, "/tmp", "/dev/shm"]
    spec = {"env": env, "cmd": list(command), "chdir": inside(chdir or cwd), "rw": rw, "devw": ["/dev"], "bridge": bridge,
            "landlock": cfg["landlock"], "landlock_required": cfg["landlock_required"], "nproc": nproc,
            "parent_netns": os.readlink("/proc/self/ns/net")}
    with tempfile.TemporaryFile(dir=tmp) as spec_file:
        spec_file.write(json.dumps(spec).encode())
        spec_file.flush()
        spec_file.seek(0)
        r = os.dup(spec_file.fileno())
    fds.append(r)
    inner = ["/usr/bin/python3", "-I", "-S", f"{IN_DIR}/inner.py", str(r)]
    return a + ["--chdir", "/", "--"] + inner, binds, fds



# ---------- подтверждение ----------
def confirm(name, cfg, cwd, binds, yes):
    key = json.dumps({"p": name, "cwd": cwd, "cfg": cfg}, sort_keys=True)
    h = hashlib.sha256(key.encode()).hexdigest()
    st = STATE / "approved.json"
    ok = json.loads(st.read_text()) if st.exists() else {}
    if ok.get(f"{name}:{cwd}") == h:
        return
    out = need("ui").Out()
    out.say(f"\n=== Песочница: профиль «{name}» ===", "head")
    for p, m in sorted(binds.items()):
        mode = f"{'ЧТЕНИЕ+ЗАПИСЬ' if m == 'rw' else 'только чтение ':14}"
        print(f"  {out.paint(mode, 'warn' if m == 'rw' else 'ok')} {p}")
    online = cfg["network"] == "allowlist"
    net = {"off": "ВЫКЛЮЧЕНА", "allowlist": "только: " + ", ".join(cfg["domains"])}[cfg["network"]]
    print(f"  сеть: {out.paint(net, 'warn' if online else 'ok')}")
    if cfg["neutral"]:
        print("  среда: нейтральная (проект виден как /workspace, HOME /home/user, время UTC)")
    if cfg["protect"] and cfg["workdir_rw"]:
        print("  .git/config, .git/hooks и подобные файлы внутри — только для чтения; после запуска проверка")
    print(f"  переменные окружения: {', '.join(cfg['env_pass']) or 'нет'}\n  всё остальное скрыто.")
    if not yes:
        if not sys.stdin.isatty() or input("Запустить? [y/N] ").strip().lower() not in ("y", "д", "yes"):
            die("отменено")
    ok[f"{name}:{cwd}"] = h
    STATE.mkdir(exist_ok=True)
    st.write_text(json.dumps(ok, indent=1))


# ---------- команды ----------
def resolve_workspace(ws):
    """Рабочая папка LLM — только workspaces/<имя>. Возвращает (корень проекта, текущий каталог внутри него)."""
    if ws:
        root = workspace_path(ws)
        if not root.is_dir():
            die(f"нет рабочей папки «{ws}». Создайте: sandbox new {ws}")
        return str(root.resolve()), str(root.resolve())
    checked_directory(WORKSPACES)
    cur = Path(os.path.realpath(os.getcwd()))
    if WORKSPACES.resolve() in cur.parents:
        root = workspace_path(cur.relative_to(WORKSPACES.resolve()).parts[0])
        return str(root), str(cur)
    have = ", ".join(p.name for p in sorted(WORKSPACES.glob("*")) if p.is_dir()) or "пока нет"
    die(f"укажите рабочую папку (sandbox run ПРОФИЛЬ ИМЯ) или зайдите в {WORKSPACES}/<имя>. Есть: {have}")


def require_host():
    """Запуск возможен только на Linux (в том числе WSL2) от обычного пользователя и при наличии bwrap."""
    if not sys.platform.startswith("linux"):
        die(f"платформа {sys.platform} не поддерживается: нужен Linux или WSL2 (Windows: windows.py)")
    if os.geteuid() == 0:
        die("не запускайте песочницу от root: агент получил бы права суперпользователя в своём пространстве имён. "
            "Запустите от обычного пользователя")
    if not shutil.which("bwrap"):
        die("bubblewrap (bwrap) не найден. Установите пакет bubblewrap (подсказка для дистрибутива: sandbox check)")


def have_scope():
    """Есть ли systemd --user для запуска в cgroup-области с лимитами."""
    return bool(shutil.which("systemd-run")) and subprocess.run(
        ["systemd-run", "--user", "--scope", "-q", "true"], capture_output=True).returncode == 0


def nproc_fallback(cfg):
    """Запасной RLIMIT_NPROC без systemd: с ядра 5.14 он считается внутри пространства имён, раньше — по всему пользователю."""
    m = re.match(r"(\d+)\.(\d+)", os.uname().release)
    return cfg["tasks_max"] if m and (int(m[1]), int(m[2])) >= (5, 14) else None


def limits_wrap(cfg, scoped=None):
    """Лимиты памяти и числа процессов через cgroup пользователя; если systemd недоступен — предупреждение."""
    if have_scope() if scoped is None else scoped:
        return ["systemd-run", "--user", "--scope", "--quiet", "--collect", "-p", f"MemoryMax={cfg['memory_max']}",
                "-p", f"TasksMax={cfg['tasks_max']}", "--"]
    print("sandbox: лимиты памяти не применены (нет systemd --user); число процессов ограничено только RLIMIT_NPROC", file=sys.stderr)
    return []


def wait_child(proc, forward=True):
    """Ожидание песочницы. В её новую сессию Ctrl-C не доходит: первый завершает её, через 5 с или второй — принудительно.
    Без новой сессии (forward=False) SIGINT получает сама песочница, лаунчер только ждёт."""
    stopping = False
    while True:
        try:
            return proc.wait(timeout=5 if stopping else None)
        except KeyboardInterrupt:
            if not forward:
                continue
            if stopping:
                proc.kill()
            else:
                stopping = True
                proc.terminate()
        except subprocess.TimeoutExpired:
            proc.kill()


def prune_mountpoints(ph, host_home, paths):
    """Пустые каталоги — следы точек монтирования внутри постоянного $HOME: удаляются от листа к корню."""
    ph, base = Path(ph), host_home.rstrip("/") + "/"
    for p in paths:
        if p.startswith(base):
            cur = ph / p[len(base):]
            while cur != ph and ph in cur.parents:
                try:
                    cur.rmdir()
                except OSError:
                    break
                cur = cur.parent


SECRET_FILES = (".env*", "*.pem", "*.key", "id_*", ".npmrc", ".pypirc", ".netrc", ".git-credentials", "*.p12", "*.pfx",
                "*.jks", "*.keystore", "*.kdbx", "credentials.json", "service-account*.json", "terraform.tfstate*")
URL_CREDS = re.compile(r"(https?://)[^/@\s:]+(?::[^/@\s]*)?@")


def scrub_git_credentials(project):
    """Учётные данные в URL удалённых репозиториев (https://user:token@host) не должны попадать в копию проекта."""
    cfg = Path(project) / ".git" / "config"
    if cfg.is_file() and not cfg.is_symlink():
        text = cfg.read_text("utf-8", errors="replace")
        clean = URL_CREDS.sub(r"\1", text)
        if clean != text:
            cfg.write_text(clean, "utf-8")
            print("sandbox: из .git/config копии удалены учётные данные в URL", file=sys.stderr)


def cmd_new(args):
    p = workspace_path(args.name)
    if p.exists():
        die(f"рабочая папка уже существует: {p}; копирование поверх существующих файлов запрещено")
    src = None
    if args.copy:
        src = Path(expand(args.copy))
        if not src.is_dir():
            die(f"не папка: {src}")
        check_path(src, False)                    # секреты и домашнюю папку копировать нельзя
    p.mkdir(mode=0o700)
    if src is not None:
        skipped = []

        def ignore(folder, names):
            hit = shutil.ignore_patterns(*SECRET_FILES)(folder, names)
            skipped.extend(os.path.join(folder, n) for n in hit)
            return hit

        shutil.copytree(src, p, dirs_exist_ok=True, symlinks=True, ignore=ignore)
        scrub_git_credentials(p)
        if skipped:
            print(f"sandbox: пропущено файлов, похожих на секреты: {len(skipped)} (например {os.path.relpath(skipped[0], src)})",
                  file=sys.stderr)
    for filename in ("AGENTS.md", "CLAUDE.md"):
        target = p / filename
        if not os.path.lexists(target):
            target.write_text(POLICY.read_text("utf-8"), encoding="utf-8")
    print(p)
    hint = need("ui").Out(sys.stderr)                # подсказка только человеку: stdout остаётся одним путём
    if hint.pretty:
        hint.say(f"Дальше: sandbox run claude {args.name}  (или codex; sandbox shell default {args.name} — просто оболочка внутри)", "dim")


def last_change(folder):
    """Время последнего изменения папки или её верхнего уровня (для списка рабочих папок)."""
    try:
        return max([folder.stat().st_mtime] + [c.stat().st_mtime for c in list(folder.iterdir())[:500]])
    except OSError:
        return 0


def cmd_ws(args):
    out = need("ui").Out()
    folders = [p for p in sorted(WORKSPACES.glob("*")) if p.is_dir() and not p.is_symlink()]
    if getattr(args, "json", False):
        print(json.dumps([p.name for p in folders], ensure_ascii=False))
        return
    if not out.pretty:
        for p in folders:
            print(f"{p.name:20} {p}")
        return
    if not folders:
        out.say("Рабочих папок пока нет.")
        out.say("Пустая: sandbox new ИМЯ   ·   копия проекта: sandbox new ИМЯ --copy ПУТЬ", "dim")
        return
    out.say("Рабочие папки", "head")
    out.table([((p.name, "bold"), time.strftime("%d.%m.%Y %H:%M", time.localtime(last_change(p))), tilde(p)) for p in folders],
              header=("имя", "изменена", "путь"))
    out.say("Запуск: sandbox run ПРОФИЛЬ ИМЯ   ·   проверка файлов: sandbox audit ИМЯ", "dim")


def cmd_skills(args):
    project = workspace_path(args.name)
    if not project.is_dir():
        die(f"рабочая папка не найдена: {project}")
    created = need("skills").prepare(project)
    out = need("ui").Out()
    out.say(f"Навыки Claude и Codex в {project}: добавлено {len(created)}, всего 4 файла.", "ok")
    out.say("Правила AGENT_POLICY.md действуют отдельно; навыки не расширяют доступ агента.", "dim")


def cmd_run(args, shell=False):
    global _log_tag
    name = profile_id(args.profile)
    cfg = load_profile(args.profile)
    cfg["rw"] += args.rw
    cfg["ro"] += args.ro
    cfg["domains"] += args.domain
    cfg["env_pass"] += args.env
    if args.net:
        cfg["network"] = args.net
    if getattr(args, "access", None):
        cfg["workdir_rw"] = args.access == "edit"
    validate_network(cfg)
    command = ["bash"] if shell else (args.command or cfg["command"])
    if not command:
        die("не задана команда: укажите её после -- или поле command в профиле")
    if cfg["network"] == "allowlist" and not cfg["domains"]:
        cfg["network"] = "off"
    dry = getattr(args, "dry_run", False)
    if not dry:
        require_host()
    cwd, workdir = resolve_workspace(args.workspace)
    if getattr(args, "access", None) == "read":
        root = Path(cwd)
        for path in cfg["rw"]:
            target = Path(expand(path)).resolve()
            if target == root or root in target.parents or target in root.parents:
                die("режим чтения несовместим с rw-монтированием внутри или над проектом")
    _log_tag = name
    key = name if cfg["home_scope"] == "profile" else f"{name}+{Path(cwd).name}"
    host_home, persist = str(Path.home()), cfg["persist_home"]
    guarded = cfg["protect"] and cfg["workdir_rw"]
    guard = need("guard") if guarded else None
    mounts, before = guard.scan(cwd, cfg["protect_extra"]) if guarded else ([], {})
    scoped = dry or have_scope()
    checked_directory(STATE / "run")
    if persist and not dry:                          # следы монтирования прошлых запусков (имена чужих проектов)
        prune_mountpoints(HOMES / key, host_home, [str(WORKSPACES)] + [str(d) for d in WORKSPACES.iterdir() if d.is_dir()])
    with tempfile.TemporaryDirectory(dir=STATE / "run") as tmp:
        argv, binds, fds = build(cfg, cwd, command, tmp, args.allow_sensitive, name, args.allow_outside, workdir, key,
                                 None if scoped else nproc_fallback(cfg), mounts)
        proxy = None
        try:
            if dry:
                print(" ".join(argv))
                return 0
            confirm(name, cfg, cwd, binds, args.yes)
            argv = limits_wrap(cfg, scoped) + argv
            if cfg["network"] == "allowlist":
                os.unlink(proxy_sock(tmp))
                proxy = start_proxy(proxy_sock(tmp), cfg)
            log(f"START {command} cwd={cwd} net={cfg['network']} rw={[p for p, m in binds.items() if m == 'rw']}")
            proc = subprocess.Popen(argv, pass_fds=fds)
        except BaseException:
            if proxy is not None:
                proxy.close()
            raise
        finally:
            for fd in fds:
                os.close(fd)
        try:
            signal.signal(signal.SIGTERM, lambda *_: proc.terminate())
            rc = wait_child(proc, cfg["new_session"] or not cfg["seccomp"])
        finally:
            if proxy is not None:
                proxy.close()
            shutil.rmtree(Path(proxy_sock(tmp)).parent, ignore_errors=True)
            if persist:
                prune_mountpoints(HOMES / key, host_home, list(binds) + [m for m, _ in mounts])
            if guarded:
                notes = guard.audit(cwd, before, cfg["protect_extra"])
                if notes:
                    print(guard.report(notes), file=sys.stderr)
                    log("AUDIT " + "; ".join(f"{path}: {why}" for path, why in notes))
        log(f"EXIT {rc}")
        return rc


def network_summary(cfg):
    """Сеть профиля одной фразой: (текст, стиль)."""
    if cfg["network"] == "allowlist" and cfg["domains"]:
        return f"домены: {len(cfg['domains'])}", "warn"
    return "без сети", "ok"


def cmd_list(_):
    out = need("ui").Out()
    profiles = [(p.stem, load_profile(str(p))) for p in sorted(PROFILES.glob("*.toml"))]
    if not out.pretty:
        for name, cfg in profiles:
            print(f"{name:12} {cfg['description']}")
        return
    out.say("Профили", "head")
    out.table([((name, "bold"), network_summary(cfg), cfg["description"]) for name, cfg in profiles],
              header=("профиль", "сеть", "описание"))
    out.say("Запуск: sandbox run ПРОФИЛЬ ИМЯ   ·   настройки: sandbox show ПРОФИЛЬ", "dim")


def profile_rows(cfg):
    """Настройки профиля для чтения человеком: (название с ключом TOML, значение)."""
    yes = lambda value: "да" if value else "нет"
    listed = lambda items: ", ".join(items) or "—"
    online = cfg["network"] == "allowlist" and bool(cfg["domains"])
    scope = {"profile": "один на профиль", "workspace": "свой на каждый проект"}[cfg["home_scope"]]
    return [
        ("Команда (command)", " ".join(cfg["command"]) or "— (укажите после --)"),
        ("Запись в проект (workdir_rw)", "да" if cfg["workdir_rw"] else "нет, только чтение"),
        ("Сеть (network)", f"только домены {listed(cfg['domains'])}; порты {listed(map(str, cfg['ports']))}" if online else "выключена"),
        ("Только чтение (ro)", listed(cfg["ro"])),
        ("Запись вне проекта (rw)", listed(cfg["rw"])),
        ("Переменные (env_pass, env_set)", listed(list(cfg["env_pass"]) + [f"{k}={v}" for k, v in cfg["env_set"].items()])),
        ("Свой $HOME (persist_home)", f"постоянный, {scope}" if cfg["persist_home"] else "временный"),
        ("Нейтральная среда (neutral)", yes(cfg["neutral"])),
        ("Защита git и IDE (protect)", yes(cfg["protect"]) + (f"; дополнительно {listed(cfg['protect_extra'])}" if cfg["protect_extra"] else "")),
        ("Фильтр вызовов (seccomp)", yes(cfg["seccomp"])),
        ("Landlock (landlock)", yes(cfg["landlock"]) + ("; обязателен" if cfg["landlock_required"] else "")),
        ("Новый сеанс терминала (new_session)", yes(cfg["new_session"])),
        ("Лимиты (memory_max, tasks_max, tmp_size)", f"память {cfg['memory_max']}, процессов {cfg['tasks_max']}, /tmp {cfg['tmp_size'] or 'без ограничения'}"),
    ]


def cmd_show(args):
    cfg = load_profile(args.profile)
    out = need("ui").Out()
    if getattr(args, "json", False) or not out.pretty:
        print(json.dumps(cfg, ensure_ascii=False, indent=1))
        return
    out.say(f"Профиль {profile_id(args.profile)}", "head")
    out.say(cfg["description"])
    out.say()
    out.table(profile_rows(cfg))
    out.say()
    out.say("Файл: " + tilde(Path(args.profile) if args.profile.endswith(".toml") else PROFILES / f"{args.profile}.toml")
            + "   ·   те же данные в JSON: sandbox show ПРОФИЛЬ --json", "dim")


LOG_EVENTS = {"ALLOW": "ok", "DENY": "bad", "ERR": "bad", "START": "info", "AUDIT": "warn"}


def style_log(line, out):
    """Строка журнала «ЧЧ:ММ:СС [профиль] СОБЫТИЕ …»: событие цветом, время и профиль приглушены; без цвета — как есть."""
    m = re.match(r"^(\S+) (\[[^\]]*\]) (\S+)(.*)$", line)
    if not out.color or not m:
        return line
    stamp, tag, event, rest = m.groups()
    style = ("ok" if rest.strip() == "0" else "bad") if event == "EXIT" else LOG_EVENTS.get(event)
    return f"{out.paint(stamp, 'dim')} {out.paint(tag, 'dim')} {out.paint(event, style)}{rest}"


def cmd_log(args):
    out = need("ui").Out()
    f = LOGS / (time.strftime("%Y-%m-%d") + ".log")
    if not f.exists():
        out.say("Журнал за сегодня пуст." if out.pretty else "журнал пуст", end="\n" if out.pretty else "")
        return
    lines = [printable(l.rstrip("\n")) for l in f.read_text(encoding="utf-8", errors="replace").splitlines(True)[-args.n:]]
    for line in lines:
        out.say(style_log(line, out))
    if out.pretty and lines:
        count = lambda word: sum(1 for l in lines if re.search(rf"\] {word}\b", l))
        out.say(f"В показанных строках: запусков {count('START')}, разрешено {count('ALLOW')}, отклонено {count('DENY')}", "dim")


def kernel_features():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(ctypes.c_long(444), None, ctypes.c_long(0), ctypes.c_long(1))
    rd = lambda p: Path(p).read_text().strip() if os.path.exists(p) else None
    return {"landlock": max(abi, 0), "yama": rd("/proc/sys/kernel/yama/ptrace_scope"),
            "tiocsti": rd("/proc/sys/dev/tty/legacy_tiocsti")}


def detect_platform():
    """Среда запуска: wsl1, wsl2, container или linux."""
    rd = lambda path: Path(path).read_text(errors="replace").strip().lower() if os.path.exists(path) else ""
    rel = rd("/proc/sys/kernel/osrelease")
    if "microsoft" in rel or "wsl" in rel or os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return "wsl2" if "wsl2" in rel or "microsoft-standard" in rel else "wsl1"
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return "container"
    return "linux"


def userns_hints(kind):
    """Возможные причины, по которым bwrap не создаёт пространства имён, и что с ними делать."""
    rd = lambda path: Path(path).read_text().strip() if os.path.exists(path) else None
    hints = []
    if kind == "wsl1":
        hints.append("WSL1 не поддерживает пространства имён: wsl --set-version ДИСТРИБУТИВ 2 (в PowerShell)")
    if kind == "container":
        hints.append("внутри контейнера bwrap нужны разрешённые user namespace (docker: --security-opt seccomp=unconfined "
                     "--security-opt apparmor=unconfined или podman rootless); надёжнее — отдельный хост или ВМ")
    if rd("/proc/sys/kernel/unprivileged_userns_clone") == "0":
        hints.append("kernel.unprivileged_userns_clone=0: sudo sysctl kernel.unprivileged_userns_clone=1 (Debian и производные)")
    if rd("/proc/sys/user/max_user_namespaces") == "0":
        hints.append("user.max_user_namespaces=0: sudo sysctl user.max_user_namespaces=15000")
    if rd("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1":
        hints.append("AppArmor (Ubuntu 23.10+/24.04) ограничивает user namespace: разрешите их только для bwrap профилем "
                     "AppArmor (MANUAL.md, «Частые проблемы»), не отключайте ограничение для всей системы")
    return hints


def cmd_check(_):
    out = need("ui").Out()
    ok = True
    counts = {"ok": 0, "bad": 0, "warn": 0}

    def line(good, text, hard=True):
        nonlocal ok
        status = "ok" if good else "bad" if hard else "warn"
        counts[status] += 1
        if hard:
            ok &= good
        out.item(({"ok": "[ok]", "bad": "[!!]", "warn": "[..]"}[status], status), text)
    if out.pretty:
        out.say("Проверка окружения", "head")
        out.say()
    kind = detect_platform()
    line(sys.platform.startswith("linux"), f"система: {sys.platform}, среда: {kind} (нужен Linux или WSL2)")
    line(sys.version_info >= (3, 8), f"python {sys.version.split()[0]} (нужен 3.8+)")
    try:
        import tomllib                                # noqa: F401
        toml = "tomllib"
    except ModuleNotFoundError:
        toml = "tomli" if __import__("importlib.util").util.find_spec("tomli") else "встроенный tomlmini.py"
    line(True, f"разбор профилей: {toml}", hard=False)
    line(hasattr(os, "geteuid") and os.geteuid() != 0, "запуск от обычного пользователя (не root)")
    import seccomp
    line(platform_machine() in seccomp.ARCH_ID, f"архитектура {platform_machine()} поддерживается фильтром seccomp (x86_64, aarch64)")
    bwrap = shutil.which("bwrap")
    line(bool(bwrap), "bubblewrap (bwrap) установлен")
    line(os.path.exists("/usr/bin/python3"), "/usr/bin/python3 есть (первый процесс песочницы)")
    k = kernel_features()
    line(k["landlock"] >= 1, f"Landlock ABI {k['landlock']} (запись только в рабочую папку)", hard=False)
    line(k["landlock"] >= 6, "Landlock ABI 6+: запрет сигналов и абстрактных сокетов наружу (ядро 6.12+)", hard=False)
    line(k["yama"] in ("1", "2", "3"), f"Yama ptrace_scope={k['yama']} (доп. защита памяти процессов)", hard=False)
    line(k["tiocsti"] in ("0", None), f"legacy_tiocsti={k['tiocsti']} (в песочнице TIOCSTI всё равно запрещён seccomp)", hard=False)
    line(have_scope(), "systemd --user для лимитов памяти/процессов (иначе только RLIMIT_NPROC)", hard=False)
    if bwrap:
        h = bwrap_features(bwrap)
        feats = {f: f in h for f in ("--disable-userns", "--ro-bind-data", "--size")}
        line(all(feats.values()), "возможности bwrap: " + ", ".join(f"{f} {'есть' if v else 'нет'}" for f, v in feats.items())
             + ("" if all(feats.values()) else " — обновите bubblewrap (0.8+): часть защит работает слабее"), hard=False)
        with tempfile.TemporaryDirectory() as tmp:
            try:
                cfg = {**load_profile("default"), "workdir_rw": False}
            except SystemExit:
                cfg = {**copy.deepcopy(DEFAULTS), "workdir_rw": False}
            fds = []
            try:
                argv, _, fds = build(cfg, tmp, ["true"], tmp, False)
                r = subprocess.run(argv, capture_output=True, text=True, pass_fds=fds)
                line(r.returncode == 0, "тестовый запуск в песочнице" + ("" if r.returncode == 0 else f": {r.stderr.strip()}"))
                if r.returncode != 0:
                    for hint in userns_hints(kind):
                        out.item(("     подсказка:", "warn"), hint)
            except SystemExit:
                line(False, "тестовый запуск не удался")
            finally:
                for fd in fds:
                    os.close(fd)
    if kind.startswith("wsl"):
        interop = os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop") or os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop-late")
        line(not interop, "WSL: запуск программ Windows (interop) выключен [interop] enabled=false в /etc/wsl.conf", hard=False)
        line(not os.path.isdir("/mnt/c"), "WSL: диски Windows не смонтированы [automount] enabled=false (песочница их и так не показывает)", hard=False)
    total = sum(counts.values())
    if out.pretty:
        out.say()
    if counts["bad"]:
        out.say(f"Итог: проблем {counts['bad']}, предупреждений {counts['warn']} из {total} проверок. Исправьте пункты [!!]: без них запуск невозможен или ненадёжен.", "bad")
    elif counts["warn"]:
        out.say(f"Итог: работать можно; предупреждений {counts['warn']} из {total} проверок ([..] — часть защит слабее, см. MANUAL.md, «Частые проблемы»).", "warn")
    else:
        out.say(f"Итог: всё в порядке ({total} из {total} проверок).", "ok")
    out.say("Полная проверка атаками изнутри: sandbox selftest [ПРОФИЛЬ]", "dim")
    sys.exit(0 if ok else 1)


def cmd_selftest(args):
    """Проверки только своих фикстур; никаких списков процессов или интерфейсов хоста."""
    import secrets
    require_host()
    cfg = load_profile(args.profile)
    if cfg["network"] == "allowlist" and not cfg["domains"]:
        cfg["network"] = "off"
    for path in (WORKSPACES, HOMES, STATE / "run"):
        checked_directory(path)
    out = need("ui").Out()

    def stop_child(proc):
        if proc.poll() is None:
            proc.kill()
        proc.wait()

    with contextlib.ExitStack() as stack:
        ws = stack.enter_context(tempfile.TemporaryDirectory(prefix="selftest-", dir=WORKSPACES))
        sibling = stack.enter_context(tempfile.TemporaryDirectory(prefix="selftest-sibling-", dir=WORKSPACES))
        ph = stack.enter_context(tempfile.TemporaryDirectory(prefix="selftest-", dir=HOMES))
        tmp = stack.enter_context(tempfile.TemporaryDirectory(dir=STATE / "run"))
        # фикстуры защиты: git-конфигурация и каталог хуков внутри рабочей папки
        (Path(ws) / ".git" / "hooks").mkdir(parents=True)
        (Path(ws) / ".git" / "config").write_text("[core]\n")
        mounts = need("guard").scan(ws)[0] if cfg["protect"] else []
        home = os.path.realpath(Path.home())
        tools = any(os.path.realpath(expand(x)).startswith(home + "/") for x in cfg["ro"] + cfg["rw"] if os.path.exists(expand(x)))
        cfg["env_set"] = {**cfg["env_set"], "SANDBOX_PROBE_SIBLING": sibling, "SANDBOX_PROBE_ROOT": str(ROOT),
                          "SANDBOX_PROBE_TOOLS_HOME": "1" if tools else "0",
                          "SANDBOX_PROBE_PROTECTED": ".git/config,.git/hooks" if mounts else "",
                          "SANDBOX_PROBE_UI": f"pretty={int(out.pretty)},color={int(out.color)},width={out.width}"}
        mark = "SANDBOX-SECRET-" + secrets.token_hex(8)
        victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)", mark])
        stack.callback(stop_child, victim)
        abstract = "sandbox-selftest-" + secrets.token_hex(8)
        au = stack.enter_context(socket.socket(socket.AF_UNIX))
        au.bind("\0" + abstract)
        au.listen(1)
        tcp = stack.enter_context(socket.socket())
        tcp.bind(("127.0.0.1", 0))
        tcp.listen(1)
        cmd = ["/usr/bin/python3", "-I", "-S", f"{IN_DIR}/probe.py", mark, str(victim.pid), abstract,
               str(tcp.getsockname()[1]), str(Path.home()), os.readlink("/proc/self/ns/pid"), os.readlink("/proc/self/ns/net")]
        scoped = have_scope()
        argv, _, fds = build(cfg, ws, cmd, tmp, False, Path(ph).name, nproc=None if scoped else nproc_fallback(cfg), protect=mounts)
        out.say(f"Самопроверка «{args.profile}»: только изолированная среда и собственные контрольные фикстуры\n", "bold")
        out.stream.flush()
        try:
            if cfg["network"] == "allowlist":
                os.unlink(proxy_sock(tmp))
                proxy = start_proxy(proxy_sock(tmp), cfg)
                stack.callback(proxy.close)
                stack.callback(shutil.rmtree, Path(proxy_sock(tmp)).parent, ignore_errors=True)
            rc = subprocess.run(limits_wrap(cfg, scoped) + argv, pass_fds=fds, timeout=60).returncode
        finally:
            for fd in fds:
                os.close(fd)
    sys.exit(rc)


def cmd_audit(args):
    """Файлы рабочей папки, которые хост выполнит сам: хуки и конфигурация git, настройки IDE, direnv, MCP."""
    root, _ = resolve_workspace(args.name)
    notes = need("guard").audit(root)
    out = need("ui").Out()
    if notes:
        out.say(need("guard").report(notes).strip(), "warn")
    else:
        out.say(f"В {root} опасных для хоста файлов не найдено.", "ok")
    sys.exit(1 if notes else 0)


def run_in_wsl(argv):
    # на Windows весь запуск идёт внутри WSL2, где стоит bubblewrap
    if not shutil.which("wsl"):
        die("нужен WSL2: wsl --install, затем install.ps1")
    cwd = subprocess.check_output(["wsl", "wslpath", "-a", os.getcwd()], encoding="utf-8").strip()
    cmd = ["wsl", "--cd", cwd, "-e", "bash", "-lc", 'exec python3 "$HOME/sandbox/sandbox.py" "$@"', "sandbox"] + argv
    sys.exit(subprocess.call(cmd))


def main():
    argv = sys.argv[1:]
    if os.name == "nt":
        run_in_wsl(argv)
    if not argv and sys.stdin.isatty() and sys.stdout.isatty():
        argv = ["tui"]
    cmd = []
    if "--" in argv:
        i = argv.index("--")
        argv, cmd = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(prog="sandbox", description="Изоляция ИИ-помощников: видно только разрешённое.")
    sub = ap.add_subparsers(dest="c", required=True)
    for n in ("run", "shell"):
        p = sub.add_parser(n, help="запустить профиль" if n == "run" else "оболочка внутри песочницы")
        p.add_argument("profile", nargs="?", default="default")
        p.add_argument("workspace", nargs="?", help="имя папки в ~/sandbox/workspaces (по умолчанию — текущая, если она там)")
        p.add_argument("--allow-outside", action="store_true", help="разрешить запись вне workspaces (опасно)")
        p.add_argument("--rw", action="append", default=[], metavar="ПУТЬ", help="дать запись")
        p.add_argument("--ro", action="append", default=[], metavar="ПУТЬ", help="дать чтение")
        p.add_argument("--net", choices=["off", "allowlist"])
        p.add_argument("--access", choices=["read", "edit"], help="доступ к проекту: только чтение или редактирование")
        p.add_argument("--domain", action="append", default=[], help="разрешить домен (*.example.com)")
        p.add_argument("--env", action="append", default=[], metavar="ИМЯ", help="передать переменную окружения")
        p.add_argument("-y", "--yes", action="store_true", help="не спрашивать подтверждение")
        p.add_argument("--dry-run", action="store_true", help="показать команду bwrap")
        p.add_argument("--allow-sensitive", action="store_true", help="снять защиту ~/.ssh, ~ и т.п. (опасно)")
    sub.add_parser("list", help="список профилей")
    p = sub.add_parser("new", help="создать рабочую папку")
    p.add_argument("name")
    p.add_argument("--copy", metavar="ПУТЬ", help="скопировать в неё проект (без .env, ключей)")
    p = sub.add_parser("ws", help="список рабочих папок")
    p.add_argument("--json", action="store_true", help="имена рабочих папок в JSON")
    sub.add_parser("check", help="проверить окружение")
    p = sub.add_parser("audit", help="найти в рабочей папке файлы, которые хост выполнит сам (хуки git и т. п.)")
    p.add_argument("name", nargs="?", help="имя рабочей папки (по умолчанию — текущая)")
    p = sub.add_parser("skills", help="подготовить навыки Claude/Codex в выбранной копии проекта")
    p.add_argument("name")
    p = sub.add_parser("tui", help="интерактивный рабочий стол в терминале")
    p.add_argument("--preview", choices=["linux", "windows"], help="показать демонстрацию без запуска агента")
    p.add_argument("--season", choices=["auto", "spring", "summer", "autumn", "winter"], default="auto")
    p = sub.add_parser("selftest", help="атаковать песочницу изнутри и показать, что защищено")
    p.add_argument("profile", nargs="?", default="default")
    p = sub.add_parser("show", help="показать профиль")
    p.add_argument("profile")
    p.add_argument("--json", action="store_true", help="вывести профиль в виде JSON (в канал и файл он выводится так всегда)")
    p = sub.add_parser("log", help="журнал за сегодня")
    p.add_argument("-n", type=int, default=40)
    args = ap.parse_args(argv)
    args.command = cmd
    if args.c == "tui":
        sys.exit(need("tui").main("linux", ROOT, preview=args.preview, season=args.season))
    if args.c in ("run", "shell"):
        sys.exit(cmd_run(args, shell=args.c == "shell"))
    {"list": cmd_list, "show": cmd_show, "log": cmd_log, "check": cmd_check, "new": cmd_new, "ws": cmd_ws, "selftest": cmd_selftest,
     "audit": cmd_audit, "skills": cmd_skills}[args.c](args)


if __name__ == "__main__":
    main()
