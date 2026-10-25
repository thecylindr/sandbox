"""Native Windows account backend. This is an ACL/WFP boundary, not a container."""
import base64
import ctypes
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import ntpath
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import uuid

import native_proxy
import native_winapi as win

SCRIPT = Path(__file__).resolve().parent / "native-control.ps1"


def account_name(value):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,19}", value):
        raise ValueError("Имя учётной записи: 1–20 латинских букв, цифр, _ или -; первая — буква.")
    return value


def require_windows(admin=True):
    if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise OSError("Режим user требует 64-битные Windows и Python.")
    if admin and not ctypes.windll.shell32.IsUserAnAdmin():
        raise OSError("Для режима user запустите start.cmd или терминал от администратора Windows.")


def powershell():
    return str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")


def control(action, *, timeout=60, **data):
    try:
        result = subprocess.run([powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                 "-File", str(SCRIPT), "-Action", action], input=json.dumps(data), text=True,
                                encoding="utf-8", errors="replace", capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise OSError(f"Windows {action}: PowerShell не завершился за {timeout} с; операция прервана.") from exc
    if result.returncode:
        # PowerShell can echo source lines in errors. Never include the request/password in diagnostics.
        raise OSError(f"Windows {action}: " + result.stderr.strip())
    return json.loads(result.stdout.strip().lstrip("\ufeff") or "{}")


def no_redirect(path, hardlinks=True):
    path = Path(path).absolute()
    for current in (path, *path.parents):
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if current.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise OSError(f"Ссылка/junction запрещена в управляемом пути: {current}")
        if hardlinks and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink > 1:
            raise OSError(f"Hardlink запрещён перед привилегированными операциями: {current}")
    return path


def tree(path):
    path = no_redirect(path)
    result = [path]
    if path.is_dir():
        for child in path.iterdir():
            result.extend(tree(child))
    return result


ACL_CHUNK = 400  # записей на один запуск PowerShell: ConvertFrom-Json 5.1 ограничен ~2 МБ входа, Set-Acl идёт по одному файлу


def acl(entries, sid=""):
    # Enumerate/validate before handing any paths to privileged ACL operations. Never recurse in PowerShell.
    prepared = []
    for path, rights, recursive in entries:
        for item in tree(path) if recursive else [no_redirect(path)]:
            prepared.append({"path": str(item), "rights": rights})
    if len(prepared) > ACL_CHUNK:
        print(f"Права доступа NTFS: {len(prepared)} объектов, это может занять несколько минут…", file=sys.stderr, flush=True)
    for start in range(0, len(prepared), ACL_CHUNK):
        chunk = prepared[start:start + ACL_CHUNK]
        control("acl", sid=sid, entries=chunk, timeout=120 + 3 * len(chunk))


def base_path(username):
    return no_redirect(Path(os.environ["ProgramData"]) / "AISandboxNative" / account_name(username))


def save(base, state):
    target = no_redirect(base / "account.json")
    staging = no_redirect(base / "account.new")
    staging.write_text(json.dumps(state, indent=2), encoding="utf-8")
    staging.replace(target)


def load(base, username, verify=True):
    state = json.loads(no_redirect(base / "account.json").read_text("utf-8"))
    if state.get("version") != 1 or state.get("username") != username:
        raise ValueError("Некорректная запись управляемого пользователя.")
    if verify:
        control("verify", username=username, sid=state["sid"])
    return state


def selected(guid):
    value = str(uuid.UUID(str(guid).strip("{}")))
    interface = control("interface", guid=value)
    if uuid.UUID(interface["guid"].strip("{}")) != uuid.UUID(value):
        raise OSError("Windows вернула другой интерфейс; запуск остановлен.")
    native_proxy.InterfaceConnector(interface)  # Validate IPv4/index/DNS before any account or process change.
    return interface


def reserve_port(preferred=None):
    """Свободный порт loopback: прежний, если он ещё доступен, иначе случайный. Проверка тем же исключительным bind, что у прокси."""
    for candidate in ((preferred,) if preferred else ()) + (0,):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                probe.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            return probe.getsockname()[1]
    raise OSError("Не удалось выбрать свободный порт на 127.0.0.1.")


def setup(launcher, args, base):
    interface = selected(args.interface) if args.interface else None
    if interface is None:
        raise ValueError("Выберите интерфейс: interfaces --backend user, затем setup-user --interface GUID.")
    root = base.parent
    root.mkdir(exist_ok=True)
    acl([(root, "none", False)])
    if (base / "account.json").exists():
        state = load(base, args.username)
        control("disable", username=args.username, sid=state["sid"])
        state["port"] = reserve_port(state["port"])  # порт мог стать занятым или попасть в исключённый диапазон Windows
    else:
        if base.exists():
            raise ValueError("Каталог пользователя существует без account.json; требуется ручная проверка владельцем.")
        base.mkdir()
        acl([(base, "none", False)])
        password = "Aa9!" + secrets.token_urlsafe(40)
        encrypted = base64.b64encode(win.protect(password.encode())).decode("ascii")
        port = reserve_port()
        user = control("create", username=args.username, password=password)
        state = {"version": 1, "username": args.username, "sid": user["sid"], "password": encrypted, "port": port}
        save(base, state)  # Account stays disabled; a later setup can repair an interrupted WFP installation.
    state["interface"] = str(uuid.UUID(interface["guid"].strip("{}")))
    save(base, state)
    win.filters(state["sid"], state["port"], offline=True)
    for name in ("workspaces", "homes", "code", "logs"):
        no_redirect(base / name).mkdir(exist_ok=True)
    for source, dest in ((launcher.ROOT / "AGENT_POLICY.md", base / "code/AGENT_POLICY.md"),
                         (SCRIPT.parent / "native-selftest.ps1", base / "code/native-selftest.ps1")):
        no_redirect(dest)
        shutil.copyfile(source, dest)
    acl([(base / "code", "read", True)], state["sid"])
    print(f"Создан/обновлён {args.username} без прав администратора. Интерфейс: {interface['alias']} ({state['interface']}).")
    print("Учётная запись отключена вне запуска. Проверка: sandbox selftest --backend user")
    return 0


# Несекретные общесистемные переменные Windows: без них многие CLI не находят Program Files и расширения программ.
SYSTEM_ENV = ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "CommonProgramFiles(x86)",
              "CommonProgramW6432", "ProgramData", "ALLUSERSPROFILE", "PUBLIC", "OS", "PROCESSOR_ARCHITECTURE",
              "NUMBER_OF_PROCESSORS", "PATHEXT")
# Переменные профиля, которые разрешено передать агенту, если они заданы в окружении запустившего лаунчер терминала.
PASSTHROUGH = {"claude": ("ANTHROPIC_API_KEY", "CLAUDE_CODE_GIT_BASH_PATH"), "codex": ("OPENAI_API_KEY",)}


def machine_path():
    """Системный PATH из реестра (общий для всех пользователей: Git, Node, Python); PATH и профиль владельца не берутся."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as key:
            value = winreg.QueryValueEx(key, "Path")[0]
    except (ImportError, OSError):
        return []
    owner = [ntpath.normcase(os.environ[name]) for name in ("USERPROFILE", "APPDATA", "LOCALAPPDATA") if os.environ.get(name)]
    result = []
    for entry in ntpath.expandvars(str(value)).split(";"):
        entry = entry.strip().strip('"')
        if (entry and ntpath.isabs(entry) and "%" not in entry and entry not in result
                and not any(ntpath.normcase(entry).startswith(prefix) for prefix in owner)):
            result.append(entry)
    return result[:64]


def environment(command, home, project, policy, username, profile, proxy_url=None):
    system = Path(os.environ["SystemRoot"])
    home = str(home)
    path = []
    for entry in [str(Path(command[0]).parent), str(system / "System32"), str(system)] + machine_path():
        if ntpath.normcase(entry) not in [ntpath.normcase(known) for known in path]:
            path.append(entry)
    env = {"SystemRoot": str(system), "WINDIR": str(system), "SystemDrive": system.drive,
           "COMSPEC": str(system / "System32/cmd.exe"), "USERNAME": username,
           "USERPROFILE": home, "HOME": home, "APPDATA": home + "\\AppData\\Roaming",
           "LOCALAPPDATA": home + "\\AppData\\Local", "TEMP": home + "\\tmp", "TMP": home + "\\tmp",
           "PATH": ";".join(path),
           "SANDBOX": "1", "SANDBOX_BACKEND": "user", "SANDBOX_WORKSPACE": str(project),
           "SANDBOX_POLICY": str(policy), "CODEX_HOME": home + "\\.codex", "CLAUDE_CONFIG_DIR": home + "\\.claude",
           "DISABLE_AUTOUPDATER": "1", "DISABLE_UPDATES": "1", "NODE_USE_ENV_PROXY": "1",
           # файлы проекта принадлежат Administrators: без этого Git отвечает «dubious ownership» пользователю worker
           "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"}
    for name in SYSTEM_ENV:
        if name in os.environ:
            env[name] = os.environ[name]
    for key in PASSTHROUGH.get(profile, ()):
        if key in os.environ:
            env[key] = os.environ[key]
    if proxy_url:
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env[name] = proxy_url
        env["NO_PROXY"] = ""
        env["no_proxy"] = ""
    return env


def command_for(launcher, args, base):
    command = args.command or ([powershell(), "-NoLogo", "-NoProfile"] if args.action == "shell"
                               else [launcher.executable(args.profile + ".exe")])
    if not isinstance(command, list) or not command or not all(isinstance(x, str) and "\0" not in x for x in command):
        raise ValueError("Некорректная команда.")
    path = Path(command[0])
    if not path.is_absolute() or path.suffix.lower() != ".exe" or not path.is_file():
        raise ValueError("Укажите абсолютный путь к .exe после -- (для npm используйте node.exe и путь к JS CLI).")
    real = no_redirect(path, hardlinks=False).resolve()
    if base == real or base in real.parents or launcher.DATA in real.parents:
        raise ValueError("Исполняемый файл должен быть установлен вне данных агента.")
    return [str(real)] + command[1:]


def start_child(state, command, project, env, timeout=None):
    child = None
    try:
        control("enable", username=state["username"], sid=state["sid"])
        password = win.protect(base64.b64decode(state["password"], validate=True), decrypt=True).decode()
        child = win.Child(state["username"], password, command, project, env, state["sid"])
        del password
        # Disable new logons before untrusted code can execute; the existing token remains usable.
        control("disable", username=state["username"], sid=state["sid"])
        child.resume()
        return child.wait(timeout)
    finally:
        try:
            if child is not None:
                child.close()
        finally:
            control("disable", username=state["username"], sid=state["sid"])


def prepare(launcher, args, base, state):
    project = launcher.project_path(args.workspace)
    home = no_redirect(base / "homes" / args.workspace)
    home.mkdir(exist_ok=True)
    for relative in ("tmp", "AppData/Roaming", "AppData/Local", ".codex", ".claude"):
        no_redirect(home / relative).mkdir(parents=True, exist_ok=True)
    # Other projects/homes lose all worker grants, including explicit grants on previously created files.
    # Выбранные проект и HOME здесь пропускаются: следующей строкой каждый их объект получает свежий защищённый DACL.
    others = [(base / "workspaces", "none", False), (base / "homes", "none", False)]
    for parent, current in ((base / "workspaces", project), (base / "homes", home)):
        others += [(path, "none", True) for path in sorted(parent.iterdir())
                   if os.path.normcase(str(path)) != os.path.normcase(str(current))]
    acl(others)
    acl([(project, args.access, True), (home, "edit", True)], state["sid"])
    for relative in (".codex/AGENTS.override.md", ".claude/CLAUDE.md"):
        target = no_redirect(home / relative)
        shutil.copyfile(base / "code/AGENT_POLICY.md", target)
        acl([(target, "read", False)], state["sid"])
    return project, home


def preflight(state, base, project, home, token, access, offline):
    # Controlled fixtures only: a private file and a fresh listening localhost socket owned by this invocation.
    secret = base / ("fixture-" + uuid.uuid4().hex)
    secret.write_text("sandbox fixture", encoding="ascii")
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            command = [powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                       "-File", str(base / "code/native-selftest.ps1")]
            env = environment(command, home, project, base / "code/AGENT_POLICY.md", state["username"], "default")
            env.update({"SBX_EXPECT_SID": state["sid"], "SBX_PRIVATE_FIXTURE": str(secret),
                        "SBX_BLOCKED_PORT": str(listener.getsockname()[1]), "SBX_PROXY_PORT": str(state["port"]),
                        "SBX_PROXY_TOKEN": token, "SBX_ACCESS": access, "SBX_OFFLINE": str(int(offline))})
            result = start_child(state, command, project, env, timeout=120)  # первый вход создаёт профиль Windows: это медленно
            if result:
                raise OSError(f"Проверка отдельного пользователя не пройдена (код {result}); агент не запущен. См. WINDOWS_NATIVE.md.")
    finally:
        secret.unlink(missing_ok=True)


def run(launcher, args, base, state, selftest=False):
    cfg = launcher.profile(args.profile)
    offline = args.offline or cfg.get("network", "off") == "off" or not cfg.get("domains")
    interface = selected(args.interface or state.get("interface")) if not offline else None
    command = None if selftest else command_for(launcher, args, base)
    if args.dry_run:
        print(json.dumps({"username": state["username"], "project": str(launcher.project_path(args.workspace)),
                          "access": args.access, "interface": interface, "offline": offline, "command": command},
                         ensure_ascii=False, indent=2))
        return 0
    control("disable", username=state["username"], sid=state["sid"])
    win.filters(state["sid"], state["port"], offline)
    project, home = prepare(launcher, args, base, state)
    token, server = secrets.token_hex(32), None
    import sandbox
    logger = logging.getLogger("sandbox-native-" + state["username"])
    handler = RotatingFileHandler(base / "logs/proxy.log", maxBytes=1 << 20, backupCount=3, encoding="utf-8")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    old_log = sandbox.log
    sandbox.log = lambda line: logger.info("%s", sandbox.printable(line))
    try:
        if not offline:
            try:
                server = native_proxy.start(state["port"], token, interface, cfg["domains"])
            except OSError as exc:
                raise OSError(f"Порт прокси {state['port']} недоступен ({exc}); выполните setup-user ещё раз, чтобы выбрать другой.") from exc
        preflight(state, base, project, home, token, args.access, offline)
        print("Проверки SID, прав проекта, прямых соединений и прокси пройдены.", flush=True)
        if selftest:
            return 0
        url = f"http://sandbox:{token}@127.0.0.1:{state['port']}" if not offline else None
        env = environment(command, home, project, base / "code/AGENT_POLICY.md", state["username"], args.profile, url)
        print(f"{state['username']}: {args.access}, сеть {'off' if offline else interface['alias']}; отдельное окно агента.", flush=True)
        return start_child(state, command, project, env)
    finally:
        if server is not None:
            server.close()
        sandbox.log = old_log
        logger.removeHandler(handler)
        handler.close()
        # Leave a blocked, disabled account even after an exception; never remove protection on normal exit.
        try:
            control("disable", username=state["username"], sid=state["sid"])
        finally:
            win.filters(state["sid"], state["port"], offline=True)


def handle(launcher, args):
    if args.action not in ("interfaces", "setup-user", "remove-user", "new", "ws", "check", "skills", "selftest", "run", "shell"):
        raise ValueError("Команда недоступна для режима user.")
    require_windows(admin=args.action != "interfaces")
    if args.action == "interfaces":
        print(json.dumps(control("interfaces"), ensure_ascii=False, indent=2))
        return 0
    username = account_name(args.username)
    base = base_path(username)
    lock = win.Lock(username)
    old_data = launcher.DATA
    try:
        if args.action == "setup-user":
            return setup(launcher, args, base)
        state = load(base, username, verify=args.action != "remove-user")
        launcher.DATA = base
        if args.action == "remove-user":
            control("remove", username=username, sid=state["sid"])
            win.filters(state["sid"], state["port"], remove=True)
            (base / "account.json").rename(base / ("removed-account-" + uuid.uuid4().hex + ".json"))
            print(f"Удалена только управляемая учётная запись {username} и её WFP-фильтры. Данные сохранены: {base}")
            return 0
        if args.action == "new":
            return launcher.new_project(args)
        if args.action == "skills":
            import skills
            project = launcher.project_path(args.workspace)
            created = skills.prepare(project)
            print(f"Навыки Claude и Codex: добавлено {len(created)}, всего 4 файла в копии проекта.")
            return 0
        if args.action == "ws":
            projects = [path for path in sorted((base / "workspaces").iterdir()) if path.is_dir() and not launcher.redirect(path)]
            if args.json:
                print(json.dumps([path.name for path in projects], ensure_ascii=False))
            else:
                for path in projects:
                    print(path.name, path)
            return 0
        if args.action == "check":
            interface = selected(args.interface or state["interface"])
            print(f"{username}, SID проверен; интерфейс {interface['alias']}. Приёмка: selftest --backend user")
            return 0
        if args.action == "selftest":
            import argparse
            name = "selftest-" + uuid.uuid4().hex[:12]
            launcher.new_project(argparse.Namespace(workspace=name, copy=None))
            try:
                for access, offline in (("read", True), ("edit", True), ("read", False)):
                    check = argparse.Namespace(**vars(args))
                    check.workspace, check.access, check.offline, check.dry_run = name, access, offline, False
                    check.profile = "claude"  # Explicit domains, but probe never contacts an external service.
                    run(launcher, check, base, state, selftest=True)
                return 0
            finally:
                for path in (base / "workspaces" / name, base / "homes" / name):
                    if path.exists():
                        tree(path)
                        shutil.rmtree(path)
        if args.action in ("run", "shell"):
            return run(launcher, args, base, state)
        raise ValueError("Команда недоступна для режима user.")
    finally:
        launcher.DATA = old_data
        lock.close()
