#!/usr/bin/env python3
"""Windows launcher: WSL/bubblewrap, Docker, or a native account with interface-bound proxy."""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "windows-data"
IMAGE = "ai-sandbox-agent:local"
NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
ENV_KEYS = {"claude": ["ANTHROPIC_API_KEY"], "codex": ["OPENAI_API_KEY"], "default": []}
# части пути, при которых папку нельзя импортировать как проект: секреты профиля, данные клиентов, системные каталоги Windows
BLOCKED_SOURCE = {".ssh", ".aws", ".gnupg", ".codex", ".claude", ".kube", ".azure", ".docker", ".config", "appdata", "windows",
                  "program files", "program files (x86)", "programdata", "$recycle.bin", "system volume information"}


class LauncherError(Exception):
    pass


def validate_name(value):
    if not re.fullmatch(NAME, value) or value.endswith("."):
        raise LauncherError("Имя проекта: 1–64 латинские буквы, цифры, . _ -; без точки в конце.")
    if value.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)], *[f"LPT{i}" for i in range(1, 10)]}:
        raise LauncherError("Это имя зарезервировано Windows.")
    return value


def redirect(path):
    path = Path(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISLNK(metadata.st_mode)
            or bool(getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def directory(path):
    path = Path(path).absolute()
    if redirect(path) or path.resolve() != path:
        raise LauncherError(f"Каталог не должен проходить через ссылку или junction: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def project_path(name, exists=True):
    path = directory(DATA / "workspaces") / validate_name(name)
    if redirect(path) or path.resolve() != path.absolute():
        raise LauncherError("Рабочая папка не должна быть ссылкой или junction.")
    if exists and not path.is_dir():
        raise LauncherError(f"Нет проекта {name}; создайте его командой new.")
    return path


def call(argv, capture=False, check=True, env=None, timeout=None):
    try:
        result = subprocess.run(argv, capture_output=capture, text=True, encoding="utf-8", errors="replace", env=env, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise LauncherError(f"Команда {argv[0]} не завершилась за {timeout} секунд.") from exc
    if check and result.returncode:
        raise LauncherError((result.stderr or "").strip() or f"Команда {argv[0]} завершилась с кодом {result.returncode}.")
    return result


def executable(name):
    """Команда из каталогов PATH. Текущий каталог не просматривается: Windows ищет в нём первым, а рабочая папка
    проекта принадлежит агенту, который мог положить туда docker.exe или wsl.exe. Файлы внутри ROOT/DATA пропускаются."""
    exts = [""] if os.path.splitext(name)[1] or os.name != "nt" else os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").lower().split(";")
    cwd = os.path.normcase(os.path.abspath(os.getcwd()))
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if not folder or not os.path.isabs(folder) or os.path.normcase(os.path.abspath(folder)) == cwd:
            continue
        for ext in exts:
            candidate = os.path.join(folder, name + ext)
            real = Path(candidate).resolve()
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and ROOT not in real.parents and DATA not in real.parents:
                return candidate
    raise LauncherError(f"Не найдена команда {name} в PATH. См. WINDOWS.md.")


def wsl_prefix(distro=None):
    result = [executable("wsl.exe" if os.name == "nt" else "wsl")]
    if distro:
        result += ["--distribution", distro]
    return result


def wsl_args(args, command):
    # All user data is passed as positional arguments, never interpolated into shell code.
    return wsl_prefix(args.distro) + ["--exec", "bash", "-c", 'exec python3 "$HOME/sandbox/sandbox.py" "$@"', "sandbox"] + command


def run_wsl(args):
    command = args.action
    if command == "new":
        forwarded = ["new", validate_name(args.workspace)]
        if args.copy:
            forwarded += ["--copy", str(Path(args.copy).expanduser().absolute())]
    elif command in ("run", "shell"):
        forwarded = [command, args.profile, validate_name(args.workspace), "--access", args.access, "--yes"]
        if args.offline:
            forwarded += ["--net", "off"]
        if args.command:
            forwarded += ["--"] + args.command
    elif command == "selftest":
        forwarded = [command, args.profile]
    elif command == "skills":
        forwarded = ["skills", validate_name(args.workspace)]
    elif command == "ws":
        forwarded = ["ws"] + (["--json"] if args.json else [])
    else:
        forwarded = [command]
    argv = wsl_args(args, forwarded)
    if getattr(args, "dry_run", False):
        print(json.dumps(argv, ensure_ascii=False, indent=2))
        return 0
    env = dict(os.environ)
    keys = [k for k in ENV_KEYS.get(getattr(args, "profile", "default"), []) if k in env]
    existing = [x for x in env.get("WSLENV", "").split(":") if x]
    env["WSLENV"] = ":".join(existing + [k for k in keys if k not in [x.split("/")[0] for x in existing]])
    return call(argv, check=False, env=env).returncode


def setup_wsl(args):
    prefix = wsl_prefix(args.distro)
    converted = call(prefix + ["--exec", "wslpath", "-a", str(ROOT)], capture=True).stdout.strip()
    return call(prefix + ["--exec", "bash", "-c", 'exec bash "$1/windows/setup-wsl.sh" "$1"', "sandbox-setup", converted], check=False).returncode


def profile(name):
    import tomllib
    data = tomllib.loads((ROOT / "profiles" / f"{name}.toml").read_text("utf-8"))
    domains = data.get("domains", [])
    if (not isinstance(domains, list) or not all(isinstance(d, str) and d != "*" for d in domains)
            or data.get("allow_private_net", False) or data.get("network", "off") not in ("off", "allowlist")
            or data.get("ports", [443]) != [443]):
        raise LauncherError("Docker допускает только off/allowlist, явные домены, порт 443 и запрет private net.")
    return data


def require_local_docker():
    docker = executable("docker")
    if os.environ.get("DOCKER_HOST") and not os.environ.get("DOCKER_CONTEXT"):
        endpoint = os.environ["DOCKER_HOST"]
    else:
        endpoint = json.loads(call([docker, "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"], capture=True).stdout)
    if not endpoint.startswith(("npipe://", "unix://")):
        raise LauncherError("Нужен локальный Docker Desktop/Engine; удалённый DOCKER_HOST запрещён.")
    kind = call([docker, "info", "--format", "{{.OSType}}"], capture=True).stdout.strip()
    if kind != "linux":
        raise LauncherError("Переключите Docker Desktop в режим Linux containers.")
    return docker


def mount(kind, source, target, readonly=False):
    # Docker --mount has its own CSV parser. Reject commas rather than permit extra options.
    if any("," in str(p) or "\n" in str(p) or "\r" in str(p) for p in (source, target)):
        raise LauncherError("Пути с запятой или переводом строки не поддерживаются Docker --mount.")
    return f"type={kind},source={source},target={target}" + (",readonly" if readonly else "")


def limits(name, memory="8g", pids="512", cpus="2"):
    return ["--name", name, "--init", "--read-only", "--user", "1000:1000", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges=true", "--pids-limit", pids, "--memory", memory,
            "--memory-swap", memory, "--cpus", cpus, "--ulimit", "core=0", "--hostname", "sandbox",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,mode=1777", "--log-opt", "max-size=10m", "--log-opt", "max-file=2"]


def docker_plan(args, project, config_path, run_id, interactive, test_network=False):
    cfg = profile(args.profile)
    if test_network:
        cfg = {**cfg, "network": "allowlist", "domains": ["fixture.invalid"]}
    online = not args.offline and cfg.get("network") == "allowlist" and bool(cfg.get("domains"))
    install = hashlib.sha256(str(ROOT).encode()).hexdigest()[:10]
    home = f"sbx-home-{install}-{args.profile}-{hashlib.sha256(str(project).encode()).hexdigest()[:12]}"
    sockvol, proxyname, agentname = f"sbx-socket-{run_id}", f"sbx-proxy-{run_id}", f"sbx-agent-{run_id}"
    base = ["run", "--rm", "--pull", "never"] + limits(agentname) + ["--network", "none", "--workdir", "/workspace"]
    if interactive:
        base += ["--interactive", "--tty"]
    base += ["--mount", mount("bind", project, "/workspace", args.access == "read"),
             "--mount", mount("volume", home, "/home/node")]
    for name in ("hosts", "resolv.conf"):
        base += ["--mount", mount("bind", config_path.parent / name, "/etc/" + name, True)]
    for target in ("/run/sandbox/AGENT_POLICY.md", "/home/node/.codex/AGENTS.override.md", "/home/node/.claude/CLAUDE.md"):
        base += ["--mount", mount("bind", ROOT / "AGENT_POLICY.md", target, True)]
    base += ["--env", "SANDBOX_ACCESS=" + args.access, "--env", "SANDBOX_NET=" + ("allowlist" if online else "off")]
    for key in ENV_KEYS[args.profile]:
        if key in os.environ and not test_network:
            base += ["--env", key]  # Value is taken by Docker from the environment, absent from argv/logs.
    proxy = None
    if online:
        base += ["--mount", mount("volume", sockvol, "/run/sandbox-proxy", True)]
        proxy = (["run", "--detach", "--pull", "never"] + limits(proxyname, "256m", "160", "1")
                 + ["--network", f"sbx-egress-{run_id}", "--mount", mount("volume", sockvol, "/run/sandbox-proxy"),
                    "--mount", mount("bind", config_path, "/run/proxy-config.json", True),
                    "--entrypoint", "python3", IMAGE, "-I", "-S", "/opt/sandbox/proxy.py", "/run/proxy-config.json"])
    command = args.command or (["bash"] if args.action == "shell" else cfg.get("command", ["bash"]))
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        raise LauncherError("Некорректная команда профиля.")
    return {"agent": base + [IMAGE] + command, "proxy": proxy, "socket_volume": sockvol if online else None,
            "home": home, "agent_name": agentname, "proxy_name": proxyname,
            "network": f"sbx-egress-{run_id}" if online else None,
            "config": {"domains": cfg.get("domains", [])}}


def new_project(args):
    path = project_path(args.workspace, exists=False)
    if path.exists():
        raise LauncherError("Проект уже существует; копирование поверх запрещено.")
    source = Path(args.copy).expanduser().resolve() if args.copy else None
    if source is not None:
        home = Path.home().resolve()
        if (not source.is_dir() or source == home or source in home.parents or source == ROOT or ROOT in source.parents
                or source.parent == source or any(p.lower() in BLOCKED_SOURCE for p in source.parts)):
            raise LauncherError("Выберите отдельную папку проекта без ключей, данных клиента, системных каталогов и файлов launcher.")

    def ignore(folder, names):
        return [name for name in names if redirect(Path(folder) / name)
                or any(fnmatch.fnmatch(name, pattern) for pattern in (".env*", "*.pem", "*.key", "id_*"))]

    with tempfile.TemporaryDirectory(prefix="import-", dir=path.parent) as tmp:
        staging = Path(tmp) / "project"
        if source is None:
            staging.mkdir()
        else:
            shutil.copytree(source, staging, symlinks=True, ignore=ignore)
        for name in ("AGENTS.md", "CLAUDE.md"):
            if not (staging / name).exists():
                shutil.copyfile(ROOT / "AGENT_POLICY.md", staging / name)
        staging.rename(path)
    print(path)
    return 0


def run_docker(args, temporary_home=False, test_network=False):
    project = project_path(args.workspace)
    run_id = uuid.uuid4().hex[:16]
    state = directory(DATA / "run")
    with tempfile.TemporaryDirectory(prefix="run-", dir=state) as tmp:
        cfgpath = Path(tmp) / "proxy.json"
        plan = docker_plan(args, project, cfgpath, run_id, sys.stdin.isatty() and sys.stdout.isatty(), test_network)
        cfgpath.write_text(json.dumps(plan["config"]), encoding="utf-8")
        (Path(tmp) / "hosts").write_text("127.0.0.1 localhost sandbox\n::1 localhost\n", encoding="ascii")
        (Path(tmp) / "resolv.conf").write_text("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", encoding="ascii")
        if args.dry_run:
            print(json.dumps(plan, ensure_ascii=False, indent=2))
            return 0
        docker = require_local_docker()
        created_socket = False
        created_network = False
        proxy_started = False
        cleanup_errors = []

        def clean(argv, strict=True):
            try:
                result = call([docker] + argv, capture=True, check=False, timeout=20)
                if strict and result.returncode:
                    cleanup_errors.append(" ".join(argv))
                return result
            except (OSError, LauncherError) as exc:
                cleanup_errors.append(f"{' '.join(argv)}: {exc}")
                return None

        try:
            if plan["proxy"]:
                created_network = True  # Cleanup also covers a client error after daemon creation.
                call([docker, "network", "create", "--driver", "bridge", "--opt",
                      "com.docker.network.bridge.enable_icc=false", plan["network"]], capture=True, timeout=30)
                created_socket = True
                call([docker, "volume", "create", plan["socket_volume"]], capture=True)
                proxy_started = True  # A failed docker run may still have created its named container.
                call([docker] + plan["proxy"], capture=True)
            print(f"Docker: {args.profile}, проект {project}, доступ {args.access}; сеть {'allowlist' if plan['proxy'] else 'off'}.", flush=True)
            rc = call([docker] + plan["agent"], check=False).returncode
        finally:
            # Only names created by this invocation are addressed, never docker ps/prune or other sessions.
            clean(["rm", "--force", plan["agent_name"]], strict=False)  # --rm may have removed it already.
            if proxy_started:
                log = clean(["logs", "--tail", "2000", plan["proxy_name"]], strict=False)
                clean(["rm", "--force", plan["proxy_name"]])
                if log is not None:
                    try:
                        logs = directory(DATA / "logs")
                        (logs / f"{run_id}.log").write_text(log.stdout + log.stderr, encoding="utf-8")
                    except (OSError, LauncherError) as exc:
                        cleanup_errors.append(f"сохранение журнала: {exc}")
            if created_socket:
                clean(["volume", "rm", plan["socket_volume"]])
            if created_network:
                clean(["network", "rm", plan["network"]])
            if temporary_home:
                clean(["volume", "rm", plan["home"]])
            for error in cleanup_errors:
                print(f"sandbox: ошибка завершения: {error}", file=sys.stderr)
        return rc or (1 if cleanup_errors else 0)


def selftest_docker(args):
    name = "selftest-" + uuid.uuid4().hex[:12]
    path = project_path(name, exists=False)
    path.mkdir()
    try:
        for access in ("read", "edit"):
            run = argparse.Namespace(**vars(args))
            run.action, run.workspace, run.access, run.offline = "run", name, access, True
            run.profile, run.command, run.dry_run = "default", ["python3", "-I", "-S", "/opt/sandbox/selftest.py"], False
            if run_docker(run, temporary_home=True):
                return 1
        run.access, run.offline = "read", False
        return run_docker(run, temporary_home=True, test_network=True)
    finally:
        shutil.rmtree(path)


def native_module():
    sys.path.insert(0, str(ROOT / "windows"))
    import native_user
    return native_user


def parser():
    ap = argparse.ArgumentParser(description="AI Sandbox: WSL2, Docker или отдельный пользователь Windows.")
    ap.add_argument("--keep-open", action="store_true", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="action", required=True)
    native_actions = ("interfaces", "setup-user", "remove-user")
    for action in ("run", "shell", "new", "ws", "check", "selftest", "skills", "build", "setup-wsl") + native_actions:
        p = sub.add_parser(action)
        p.add_argument("--backend", choices=["wsl", "docker", "user"],
                       default="user" if action in native_actions else "docker" if action == "build" else "wsl")
        p.add_argument("--distro", help="имя установленного дистрибутива WSL")
        p.add_argument("--username", default="AIWorker", help="управляемая учётная запись для --backend user")
        p.add_argument("--interface", help="GUID адаптера для --backend user; список: interfaces")
        if action in ("run", "shell"):
            p.add_argument("profile", choices=list(ENV_KEYS))
            p.add_argument("workspace")
            p.add_argument("--access", choices=["read", "edit"], default="read")
            p.add_argument("--offline", action="store_true")
            p.add_argument("--dry-run", action="store_true")
        if action == "new":
            p.add_argument("workspace")
            p.add_argument("--copy", help="импортировать копию проекта, оригинал не изменяется")
        if action == "skills":
            p.add_argument("workspace")
        if action == "ws":
            p.add_argument("--json", action="store_true")
        if action == "selftest":
            p.add_argument("profile", choices=list(ENV_KEYS), nargs="?", default="default")
        if action == "build":
            p.add_argument("--claude-version", default="latest")
            p.add_argument("--codex-version", default="latest")
    sub.add_parser("gui")
    p = sub.add_parser("tui", help="терминальный рабочий стол")
    p.add_argument("--backend", choices=["wsl", "docker", "user"], default="wsl")
    p.add_argument("--preview", choices=["linux", "windows"])
    p.add_argument("--season", choices=["auto", "spring", "summer", "autumn", "winter"], default="auto")
    return ap


def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    window = tk.Tk()
    window.title("AI Sandbox — Windows")
    window.minsize(800, 670)
    frame = ttk.Frame(window, padding=22)
    frame.pack(fill="both", expand=True)
    backend, agent, workspace, access, distro = (tk.StringVar(value=v) for v in ("docker", "claude", "myproj", "read", ""))
    username, interface_choice, native_exe = tk.StringVar(value="AIWorker"), tk.StringVar(), tk.StringVar()
    interface_map = {}
    offline = tk.BooleanVar(value=False)
    for row, (label, variable, values) in enumerate((("Изоляция", backend, ["wsl", "docker", "user"]),
            ("Агент", agent, list(ENV_KEYS)), ("Проект", workspace, None), ("Доступ", access, ["read", "edit"]),
            ("Дистрибутив WSL (необязательно)", distro, None))):
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=6)
        widget = ttk.Combobox(frame, textvariable=variable, values=values, state="readonly") if values else ttk.Entry(frame, textvariable=variable)
        widget.grid(row=row, column=1, sticky="ew", pady=6)
    frame.columnconfigure(1, weight=1)
    ttk.Checkbutton(frame, text="Без сети (локальная работа)", variable=offline).grid(row=5, column=0, columnspan=2, sticky="w")
    ttk.Label(frame, text="Windows-пользователь (user)").grid(row=6, column=0, sticky="w", pady=6)
    ttk.Entry(frame, textvariable=username).grid(row=6, column=1, sticky="ew")
    ttk.Label(frame, text="Интерфейс (user, IPv4)").grid(row=7, column=0, sticky="w", pady=6)
    interfaces = ttk.Combobox(frame, textvariable=interface_choice, state="readonly")
    interfaces.grid(row=7, column=1, sticky="ew")

    def refresh_interfaces():
        try:
            native = native_module()
            native.require_windows(admin=False)
            rows = native.control("interfaces")
            interface_map.clear()
            for item in rows:
                label = f"{item['alias']} — {item['address']} — {item['guid']}"
                interface_map[label] = item["guid"]
            interfaces["values"] = list(interface_map)
            interface_choice.set("")  # Owner chooses; never auto-pick another adapter.
            if not rows:
                messagebox.showinfo("Интерфейсы", "Нет активных адаптеров с IPv4 и IPv4 DNS.")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Ошибка", str(exc))

    ttk.Button(frame, text="Обновить список", command=refresh_interfaces).grid(row=7, column=2, padx=5)
    ttk.Label(frame, text="Программа Windows (.exe, user)").grid(row=8, column=0, sticky="w", pady=6)
    ttk.Entry(frame, textvariable=native_exe).grid(row=8, column=1, sticky="ew")

    def select_exe():
        filename = filedialog.askopenfilename(title="CLI, доступный отдельному пользователю", filetypes=[("Windows executable", "*.exe")])
        if filename:
            native_exe.set(filename)

    ttk.Button(frame, text="Выбрать…", command=select_exe).grid(row=8, column=2, padx=5)

    def launch(action, extra=()):
        try:
            argv = [sys.executable, str(ROOT / "windows.py"), "--keep-open", action, "--backend", backend.get()]
            if distro.get():
                argv += ["--distro", distro.get()]
            if backend.get() == "user":
                argv += ["--username", native_module().account_name(username.get())]
                if interface_choice.get():
                    argv += ["--interface", interface_map[interface_choice.get()]]
            if action in ("run", "shell"):
                argv += [agent.get(), validate_name(workspace.get()), "--access", access.get()]
                if offline.get():
                    argv += ["--offline"]
            argv += list(extra)
            if backend.get() == "user" and action == "run" and native_exe.get():
                argv += ["--", native_exe.get()]
            if os.name == "nt":
                subprocess.Popen(argv, creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:
                messagebox.showinfo("Команда", " ".join(argv))
        except (LauncherError, OSError, ValueError) as exc:
            messagebox.showerror("Ошибка", str(exc))

    def import_project():
        folder = filedialog.askdirectory(title="Выберите проект для копирования в sandbox")
        if folder:
            launch("new", [workspace.get(), "--copy", folder])

    buttons = ttk.Frame(frame)
    buttons.grid(row=9, column=0, columnspan=3, sticky="w", pady=16)
    for label, callback in (("Создать проект", lambda: launch("new", [workspace.get()])),
                            ("Импорт копии…", import_project), ("Запустить", lambda: launch("run"))):
        ttk.Button(buttons, text=label, command=callback).pack(side="left", padx=3)
    ttk.Button(frame, text="Список проектов", command=lambda: launch("ws")).grid(row=10, column=0, sticky="w")
    ttk.Button(frame, text="Настроить пользователя (user)", command=lambda: launch("setup-user")).grid(row=10, column=1, sticky="w")
    ttk.Button(frame, text="Самопроверка", command=lambda: launch("selftest")).grid(row=10, column=2, sticky="w")
    ttk.Label(frame, text="read — чтение; edit — редактирование копии. Docker: сначала sandbox build.\nuser: запустите лаунчер от администратора, выберите адаптер и настройте пользователя.\nuser ограничивает права и прямые соединения, но не скрывает адаптеры/процессы хоста.\nДля изоляции их видимости используйте WSL/Docker. Подробнее: WINDOWS_NATIVE.md.",
              wraplength=740).grid(row=11, column=0, columnspan=3, sticky="w", pady=14)
    window.mainloop()
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = []
    if "--" in argv:
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    args = parser().parse_args(argv or (["tui"] if sys.stdin.isatty() and sys.stdout.isatty() else ["gui"]))
    args.command = command
    try:
        if args.action == "gui":
            return gui()
        if args.action == "tui":
            import tui
            return tui.main("windows", ROOT, backend=args.backend, preview=args.preview, season=args.season)
        if command and args.action not in ("run", "shell"):
            raise LauncherError("Команда после -- разрешена только для run/shell.")
        if args.action in ("interfaces", "setup-user", "remove-user") and args.backend != "user":
            raise LauncherError("Эта команда относится к --backend user.")
        if args.backend == "user":
            return native_module().handle(sys.modules[__name__], args)
        if args.action == "setup-wsl":
            return setup_wsl(args)
        if args.action == "build":
            if args.backend != "docker":
                raise LauncherError("Сборка образа относится к Docker.")
            docker = require_local_docker()
            return call([docker, "build", "--file", str(ROOT / "docker/Dockerfile"), "--tag", IMAGE,
                         "--build-arg", "CLAUDE_VERSION=" + args.claude_version,
                         "--build-arg", "CODEX_VERSION=" + args.codex_version, str(ROOT)], check=False).returncode
        if args.backend == "wsl":
            return run_wsl(args)
        if args.action == "skills":
            import skills
            created = skills.prepare(project_path(args.workspace))
            print(f"Навыки Claude и Codex: добавлено {len(created)}, всего 4 файла в копии проекта.")
            return 0
        if args.action == "new":
            return new_project(args)
        if args.action in ("run", "shell"):
            return run_docker(args)
        if args.action == "selftest":
            return selftest_docker(args)
        if args.action == "ws":
            projects = [p for p in sorted(directory(DATA / "workspaces").iterdir()) if p.is_dir() and not redirect(p)]
            if args.json:
                print(json.dumps([p.name for p in projects], ensure_ascii=False))
            else:
                for p in projects:
                    print(p.name, p)
            return 0
        if args.action == "check":
            require_local_docker()
            print("Локальный Docker Linux доступен. Проверка контейнерной защиты: sandbox selftest --backend docker")
            return 0
        raise LauncherError("Неизвестная команда.")
    except (LauncherError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"sandbox: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if args.keep_open and sys.stdin.isatty():
            input("Нажмите Enter, чтобы закрыть окно…")


if __name__ == "__main__":
    sys.exit(main())
