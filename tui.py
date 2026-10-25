"""Small line-driven terminal desktop shared by Linux and Windows launchers.

Only the selected project and packaged source files are read. Live isolation tests
are explicit actions delegated to the existing launchers.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

SEASONS = {"spring": "Весна", "summer": "Лето", "autumn": "Осень", "winter": "Зима"}
SCENES = {
    "summer": (
        "       .--.        ", "    .-(    )-.     ", "      `----'       ",
        "       .-^-.       ", "    .-'  |  '-.    ", "   /_____|_____\\   ",
        "         |         ", "    __/|____       ", "   /__/____/_/     ",
        " ~~~~~~ SAND ~~~~~ ",
    ),
    "spring": (
        "    .  .   .  .    ", "     \\ | /  .     ", "   .--(*)--.       ",
        "      / | \\       ", "       |           ", "   .-.-|-.  .-.-.   ",
        "  (  bloom  )      ", "   `-.__.-'        ", "     / \\  / \\      ",
        "  ~~~  SPRING ~~~   ",
    ),
    "autumn": (
        "   .  *    .  *    ", "     \\  |  /       ", "  * --\\ | /-- .    ",
        "       \\|/         ", "        |          ", "    *   |   .      ",
        "      __|__        ", "  .  * /___\\  .    ", "    ~~~  ~~~       ",
        "  ~~~ AUTUMN ~~~   ",
    ),
    "winter": (
        "    *    .    *    ", "  .   *   .     .  ", "      /\\          ",
        "     /  \\   *      ", "    /____\\         ", "      ||   .        ",
        "   ___||___        ", "  /________\\   *   ", "  .   *     .      ",
        "  ~~~ WINTER ~~~   ",
    ),
}
CORE = ("sandbox.py", "inner.py", "seccomp.py", "probe.py", "transport.py", "guard.py", "neutral.py", "tomlmini.py", "ui.py", "tui.py", "skills.py")
WIN = ("windows.py", "windows/native_user.py", "windows/native_winapi.py", "windows/native_proxy.py")
DOCKER = ("docker/entry.py", "docker/proxy.py", "docker/selftest.py")


def season_name(value):
    if value == "auto":
        month = time.localtime().tm_mon
        return ("winter", "spring", "summer", "autumn")[((month % 12) // 3)]
    if value not in SEASONS:
        raise ValueError("Неизвестный сезон")
    return value


def checks(root, platform):
    """Local package health checks, not a security attestation or host inspection."""
    root = Path(root)
    files = CORE + (WIN + DOCKER if platform == "windows" else ())
    for name in files:
        path = root / name
        try:
            if path.is_symlink() or not path.is_file():
                raise OSError("нет обычного файла")
            ast.parse(path.read_text("utf-8"), filename=name)
            yield (name, "ok", "синтаксис")
        except (OSError, SyntaxError, UnicodeError) as exc:
            yield (name, "bad", type(exc).__name__)
    policy = root / "AGENT_POLICY.md"
    try:
        if policy.is_symlink() or not policy.read_text("utf-8").strip():
            raise OSError("нет правил")
        yield ("Правила агента", "ok", "файл доступен")
    except (OSError, UnicodeError) as exc:
        yield ("Правила агента", "bad", type(exc).__name__)
    try:
        from tomlmini import loads
    except ImportError:
        loads = None
    for name in ("default", "claude", "codex"):
        path = root / "profiles" / (name + ".toml")
        try:
            if loads is None:
                raise OSError("отсутствует tomlmini.py")
            if path.is_symlink():
                raise OSError("ссылка")
            profile = loads(path.read_text("utf-8"))
            if profile.get("network", "off") not in ("off", "allowlist") or profile.get("allow_private_net", False) is not False:
                raise ValueError("опасные сетевые параметры")
            yield ("Профиль " + name, "ok", "TOML / сеть")
        except (OSError, UnicodeError, ValueError) as exc:
            yield ("Профиль " + name, "bad", type(exc).__name__)
    for name in ("sandbox-fix-report", "sandbox-project-tests"):
        path = root / "agent-skills" / name / "SKILL.md"
        try:
            data = path.read_text("utf-8")
            if path.is_symlink() or not data.startswith("---\nname: "):
                raise ValueError("отсутствует описание")
            yield ("Навык " + name, "ok", "SKILL.md")
        except (OSError, UnicodeError, ValueError) as exc:
            yield ("Навык " + name, "bad", type(exc).__name__)
    manifest = root / "SHA256.json"
    if manifest.is_symlink():
        yield ("Контрольные суммы", "bad", "ссылка на список запрещена")
    elif manifest.is_file():
        try:
            expected = json.loads(manifest.read_text("utf-8"))
            skill_files = tuple("agent-skills/" + name + "/SKILL.md" for name in
                                ("sandbox-fix-report", "sandbox-project-tests"))
            for name in files + ("AGENT_POLICY.md",) + skill_files:
                if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected[name]:
                    raise ValueError(name)
            yield ("Контрольные суммы", "ok", "совпадают с локальным списком")
        except (OSError, ValueError, KeyError, UnicodeError) as exc:
            yield ("Контрольные суммы", "bad", str(exc)[:32])
    else:
        yield ("Контрольные суммы", "warn", "локального списка нет")


def preview_checks():
    return [("sandbox.py", "ok", "синтаксис"), ("AGENT_POLICY.md", "ok", "правила"),
            ("Профили", "ok", "3 из 3"), ("Навыки", "ok", "2 из 2"),
            ("Изоляция", "warn", "запустите самопроверку")]


def render(platform, backend, season, project, profile, access, items, progress=1.0, note="", width=86):
    width = max(60, min(int(width), 120))
    scene_width = 20 if width >= 70 else 17
    left_width = width - scene_width - 5
    scene = SCENES[season]
    def clip(value):
        value = str(value).replace("\n", " ")
        return value if len(value) <= left_width else value[:left_width - 1] + "…"
    rows = [
        "AI SANDBOX   /   " + ("Windows" if platform == "windows" else "Linux") + "   /   " + SEASONS[season],
        "", "РАБОЧИЙ СТОЛ", f"Проект: {project or 'не выбран'}", f"Агент: {profile}   Доступ: {access}",
        f"Изоляция: {backend}", "", "Загрузка и проверка комплекта",
        "[" + "#" * round(18 * progress) + "." * (18 - round(18 * progress)) + f"] {round(progress * 100):3d}%",
    ]
    for name, status, detail in list(items)[-5 if width >= 80 else -2:]:
        rows.append(f"{ {'ok': '+', 'bad': '!', 'warn': '?'}[status] } {name}: {detail}")
    while len(rows) < len(scene):
        rows.append("")
    options = [("1", "Открыть проект"), ("2", "Создать / импортировать"),
               ("3", "Агент и доступ"), ("4", "Навыки Claude/Codex"),
               ("5", "Проверки"), ("6", "Запустить агента"),
               ("7", "Сезон"), ("8", "Настройка Windows" if platform == "windows" else "Тесты проекта")]
    if width >= 80:
        rows.append("")
        rows += [f"{a} {label_a:<20} {b} {label_b}" for (a, label_a), (b, label_b) in zip(options[::2], options[1::2])]
        rows += ["0 Выход", "", clip(note or "Правила агента действуют в выбранной копии проекта.")]
    else:
        rows += [f"{number} {label}" for number, label in options]
        rows += ["0 Выход", clip(note or "Правила агента действуют в выбранной копии проекта.")]
    border = "=" * width
    lines = [border]
    for index, row in enumerate(rows):
        art = scene[index][:scene_width].ljust(scene_width) if index < len(scene) else " " * scene_width
        lines.append("  " + clip(row).ljust(left_width) + " | " + art)
    lines.append(border)
    return "\n".join(lines)


def terminal_width():
    try:
        return shutil.get_terminal_size((86, 24)).columns
    except OSError:
        return 86


class Desktop:
    def __init__(self, platform, root, backend, season):
        self.platform, self.root, self.backend = platform, Path(root), backend
        self.season, self.project, self.profile, self.access = season_name(season), "", "claude", "read"
        self.username, self.interface, self.distro = "AIWorker", "", ""
        self.items, self.note, self.healthy = [], "", False

    def draw(self, progress=1.0):
        import ui
        if sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and (os.name != "nt" or ui.windows_ansi()):
            print("\x1b[2J\x1b[H", end="")
        screen = render(self.platform, self.backend, self.season, self.project, self.profile,
                        self.access, self.items, progress, self.note, terminal_width())
        if ui.color_on():
            screen = screen.replace("AI SANDBOX", "\x1b[1;36mAI SANDBOX\x1b[0m")
            screen = screen.replace("РАБОЧИЙ СТОЛ", "\x1b[1;33mРАБОЧИЙ СТОЛ\x1b[0m")
        print(screen, flush=True)

    def boot(self):
        try:
            names = list(checks(self.root, self.platform))
        except (OSError, ValueError, ImportError) as exc:
            names = [("Проверка комплекта", "bad", type(exc).__name__)]
        import ui
        animate = (sys.stdout.isatty() and os.environ.get("TERM") not in (None, "", "dumb")
                   and (os.name != "nt" or ui.windows_ansi()))
        for index, item in enumerate(names, 1):
            self.items.append(item)
            self.note = f"Проверено {index} из {len(names)}: {item[0]}"
            if animate:
                self.draw(index / len(names))
                time.sleep(0.045)
        bad = sum(state == "bad" for _, state, _ in self.items)
        self.healthy = bad == 0
        self.note = (f"Ошибок комплекта: {bad}. Запуск отключён до исправления." if bad else
                     "Комплект загружен. Проверка защиты запускается в меню 5.")

    def workspace_root(self):
        if self.platform == "linux":
            return self.root / "workspaces"
        if self.backend == "user":
            from windows import native_module
            return native_module().base_path(self.username) / "workspaces"
        from windows import DATA
        return DATA / "workspaces"

    def names(self):
        if self.platform == "windows" and self.backend == "wsl":
            result = subprocess.run(self.argv("ws", extra=["--json"]), capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=30, check=False)
            if result.returncode:
                raise OSError(result.stderr.strip() or "Не удалось получить список проектов WSL.")
            names = json.loads(result.stdout)
            if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
                raise ValueError("Некорректный список проектов WSL.")
            return names
        from skills import safe_path
        base = safe_path(self.workspace_root())
        if not base.is_dir():
            return []
        return [path.name for path in sorted(base.iterdir()) if not path.is_symlink() and path.is_dir()
                and not getattr(path.lstat(), "st_file_attributes", 0) & 0x400]

    def argv(self, action, *positional, extra=()):
        script = self.root / ("windows.py" if self.platform == "windows" else "sandbox.py")
        args = [sys.executable, str(script), action]
        if self.platform == "windows":
            args += ["--backend", self.backend]
            if self.backend == "user":
                args += ["--username", self.username]
                if self.interface:
                    args += ["--interface", self.interface]
            elif self.backend == "wsl" and self.distro:
                args += ["--distro", self.distro]
        args += list(positional) + list(extra)
        return args

    def execute(self, action, *positional, extra=()):
        print("\n" + "─" * min(terminal_width(), 86))
        result = subprocess.run(self.argv(action, *positional, extra=extra), check=False)
        self.note = f"{action}: " + ("готово" if result.returncode == 0 else f"ошибка, код {result.returncode}")
        input("\nEnter — вернуться на рабочий стол…")
        return result.returncode

    def select_project(self):
        names = self.names()
        if not names:
            self.note = "Копий проектов пока нет. Создайте новую через пункт 2."
            return
        print("\nКопии проектов:")
        for number, name in enumerate(names, 1):
            print(f"  {number:2d}  {name}")
        value = input("Номер проекта (Enter — назад): ").strip()
        if value.isdecimal() and 1 <= int(value) <= len(names):
            self.project = names[int(value) - 1]
            self.note = f"Выбрана копия проекта: {self.project}"

    def create_project(self):
        name = input("Имя новой копии проекта (Enter — назад): ").strip()
        if not name:
            return
        source = input("Исходная папка для копии (Enter — пустой проект): ").strip()
        extra = ["--copy", source] if source else []
        if self.execute("new", name, extra=extra) == 0:
            self.project = name
            self.execute("skills", name)

    def choose_profile(self):
        value = input("Агент: 1 Claude / 2 Codex / 3 default: ").strip()
        self.profile = {"1": "claude", "2": "codex", "3": "default"}.get(value, self.profile)
        value = input("Доступ: 1 чтение / 2 редактирование: ").strip()
        self.access = {"1": "read", "2": "edit"}.get(value, self.access)
        self.note = f"Профиль {self.profile}, доступ {self.access}"

    def require_project(self):
        if self.project and self.project in self.names():
            return True
        self.note = "Выберите существующую копию проекта через пункт 1."
        return False

    def tests(self):
        print("\n0 Отчёт загрузки по всем модулям\n1 Проверка среды\n2 Самопроверка защиты выбранного профиля\n3 Самопроверка Claude и Codex")
        value = input("Проверка: ").strip()
        if value == "0":
            print("\nНаличие, синтаксис и локальные контрольные суммы; не оценка безопасности кода.")
            for name, status, detail in self.items:
                print(f"[{status.upper():4}] {name}: {detail}")
            input("\nEnter — вернуться на рабочий стол…")
        elif value == "1":
            self.execute("check")
        elif value == "2":
            self.execute("selftest", self.profile)
        elif value == "3":
            for profile in ("claude", "codex"):
                if self.execute("selftest", profile):
                    break

    def project_tests(self):
        if not self.require_project():
            return
        if self.platform == "windows" and self.backend == "user":
            self.note = "Для user задайте абсолютный .exe теста через CLI; защита проверяется пунктом 5."
            return
        folder = None if self.platform == "windows" and self.backend == "wsl" else self.workspace_root() / self.project
        presets = []
        for marker, label, command in (("tests", "Python unittest", ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]),
                ("package.json", "Node npm test", ["npm", "test"]), ("Cargo.toml", "Rust cargo test", ["cargo", "test"]),
                ("go.mod", "Go test", ["go", "test", "./..."])):
            if folder is None or ((folder / marker).exists() and not (folder / marker).is_symlink()):
                presets.append((label, command))
        if not presets:
            self.note = "Команда тестов не определена. Добавьте её в проект или запустите через CLI в песочнице."
            return
        for number, (label, command) in enumerate(presets, 1):
            print(f"{number} {label}: {' '.join(command)}")
        value = input("Номер команды: ").strip()
        if value.isdecimal() and 1 <= int(value) <= len(presets):
            command = presets[int(value) - 1][1]
            extra = (["--offline"] if self.platform == "windows" else ["--net", "off"])
            self.execute("run", "default", self.project, extra=extra + ["--"] + command)

    def windows_settings(self):
        print("\n1 WSL2  2 Docker  3 отдельный пользователь  4 настроить режим user")
        value = input("Режим: ").strip()
        if value in ("1", "2", "3"):
            self.backend = {"1": "wsl", "2": "docker", "3": "user"}[value]
            self.project = ""
            if self.backend == "wsl":
                self.distro = input("Дистрибутив WSL (Enter — по умолчанию): ").strip()
            self.note = f"Выбран режим {self.backend}; выберите его копию проекта."
        elif value == "4":
            if self.backend != "user":
                self.note = "Сначала выберите режим user."
                return
            self.username = input(f"Имя пользователя [{self.username}]: ").strip() or self.username
            self.execute("interfaces")  # Explicit owner action; never during boot or preview.
            self.interface = input("GUID выбранного адаптера: ").strip()
            if self.interface:
                self.execute("setup-user")

    def cycle_season(self):
        names = list(SEASONS)
        self.season = names[(names.index(self.season) + 1) % len(names)]
        self.note = "Оформление: " + SEASONS[self.season]

    def loop(self):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("TUI нужен терминал. Для демонстрации: tui --preview linux|windows", file=sys.stderr)
            return 2
        self.boot()
        try:
            while True:
                self.draw()
                value = input("Выберите пункт: ").strip()
                if value == "0":
                    return 0
                if not self.healthy and value in ("2", "4", "5", "6", "8"):
                    self.note = "Сначала восстановите файлы комплекта: проверка загрузки не пройдена."
                    continue
                try:
                    if value == "1":
                        self.select_project()
                    elif value == "2":
                        self.create_project()
                    elif value == "3":
                        self.choose_profile()
                    elif value == "4" and self.require_project():
                        self.execute("skills", self.project)
                    elif value == "5":
                        self.tests()
                    elif value == "6" and self.require_project():
                        extra = ["--access", self.access]
                        if self.platform == "windows" and self.backend == "user":
                            path = input("Абсолютный путь к .exe клиента: ").strip()
                            if not path:
                                self.note = "Укажите .exe клиента для отдельного пользователя."
                                continue
                            extra += ["--", path]
                        self.execute("run", self.profile, self.project, extra=extra)
                    elif value == "7":
                        self.cycle_season()
                    elif value == "8":
                        self.windows_settings() if self.platform == "windows" else self.project_tests()
                except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                    self.note = "Ошибка: " + str(exc)[:70]
        except (KeyboardInterrupt, EOFError):
            print()
            return 130


def main(platform, root, backend="bubblewrap", preview=None, season="auto"):
    desktop = Desktop(platform, root, backend, season)
    if preview:
        desktop.platform = preview
        desktop.backend = "Docker / WSL2 / user" if preview == "windows" else "bubblewrap"
        desktop.project, desktop.items = "demo", preview_checks()
        print(render(desktop.platform, desktop.backend, desktop.season, desktop.project,
                     desktop.profile, desktop.access, desktop.items,
                     note="ДЕМО ЭКРАНА: проверки и запуск не выполнялись.", width=86))
        return 0
    return desktop.loop()
