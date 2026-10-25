"""Small line-driven terminal desktop shared by Linux and Windows launchers.

Only the selected project and packaged source files are read. Live isolation tests
are explicit actions delegated to the existing launchers.
"""
import ast
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import select
import subprocess
import sys
import time

SEASONS = {"spring": "Весна", "summer": "Лето", "autumn": "Осень", "winter": "Зима"}
SCENES = {
    "summer": (
        "      \\  |  /      ", "       .-*- .       ", "     .'  |  `.      ",
        "    /____|____\\     ", "       / | \\        ", "   ___/  |  \\___    ",
        "  /  _  / \\  _  \\   ", "  | | |/___\\| | |   ", "  |_|  BEACH  |_|   ",
        "  ~~~ ~~~ ~~~ ~~~   ",
    ),
    "spring": (
        "  .  *  .  *  .     ", "     \\ | /          ", "   --- (*) ---       ",
        "     /  |  \\         ", "        |            ", "   .-.-.|.-.-.       ",
        "  /  BLOOM   \\      ", " /_____|______\\      ", "    /  / \\  \\       ",
        "  ~~~ SPRING ~~~     ",
    ),
    "autumn": (
        "  *       .    *    ", "    \\  |  /  *      ", "  *  \\ | /     .    ",
        "   ---\\|/---        ", "      . |  *         ", "    *  /|\\     .    ",
        "  ___/|||\\___       ", "  FALL  |||   LEAVES ", "   .  _/ \\_   *     ",
        "  ~~~ AUTUMN ~~~     ",
    ),
    "winter": (
        "  *    .    *   .    ", "       /\\    *      ", "      /  \\          ",
        "     /____\\    .    ", "       ||            ", "   *   /||\\    *     ",
        "      / || \\         ", "     O  ||  O         ", "    SNOW  SNOW        ",
        "  ~~~ WINTER ~~~     ",
    ),
}
CORE = ("sandbox.py", "inner.py", "seccomp.py", "probe.py", "transport.py", "guard.py", "neutral.py", "tomlmini.py", "ui.py", "tui.py", "textual_tui.py", "skills.py")
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
    scene_width = 21 if width >= 70 else 17
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
        rows += [f"[{a}] {label_a:<19} [{b}] {label_b}" for (a, label_a), (b, label_b) in zip(options[::2], options[1::2])]
        rows += ["[0] Выход", "", clip(note or "Правила агента действуют в выбранной копии проекта.")]
    else:
        rows += [f"[{number}] {label}" for number, label in options]
        rows += ["[0] Выход", clip(note or "Правила агента действуют в выбранной копии проекта.")]
    border = "=" * width
    lines = [border]
    for index, row in enumerate(rows):
        art = scene[index][:scene_width].ljust(scene_width) if index < len(scene) else " " * scene_width
        lines.append("  " + clip(row).ljust(left_width) + " | " + art)
    lines.append(border)
    return "\n".join(lines)


PIXEL_COLORS = {
    "summer": {"sky": (54, 112, 174), "sun": (255, 222, 113), "sea": (26, 133, 190), "foam": (151, 225, 222),
               "sand": (231, 190, 119), "shade": (242, 111, 71), "pole": (101, 67, 44), "leaf": (48, 147, 103),
               "wood": (165, 105, 64), "dark": (28, 52, 82), "flower": (255, 229, 130),
               "skyline": (91, 160, 194), "hill": (61, 158, 133), "ridge": (27, 105, 128), "light": (255, 245, 193)},
    "spring": {"sky": (117, 187, 218), "sun": (255, 231, 135), "sea": (104, 184, 153), "foam": (185, 230, 197),
               "sand": (112, 157, 91), "shade": (233, 120, 159), "pole": (101, 92, 58), "leaf": (60, 153, 92),
               "wood": (145, 100, 68), "dark": (53, 106, 76), "flower": (255, 221, 99),
               "skyline": (166, 218, 216), "hill": (89, 174, 112), "ridge": (62, 139, 105), "light": (242, 255, 218)},
    "autumn": {"sky": (105, 124, 176), "sun": (255, 208, 127), "sea": (174, 112, 66), "foam": (230, 164, 87),
               "sand": (108, 73, 54), "shade": (186, 72, 45), "pole": (83, 54, 41), "leaf": (220, 127, 45),
               "wood": (137, 83, 53), "dark": (48, 54, 83), "flower": (255, 190, 68),
               "skyline": (177, 133, 104), "hill": (151, 88, 53), "ridge": (105, 63, 55), "light": (255, 224, 156)},
    "winter": {"sky": (50, 76, 126), "sun": (203, 228, 255), "sea": (96, 151, 191), "foam": (222, 242, 255),
               "sand": (213, 231, 243), "shade": (102, 157, 207), "pole": (75, 92, 119), "leaf": (45, 115, 106),
               "wood": (126, 84, 64), "dark": (31, 47, 78), "flower": (246, 251, 255),
               "skyline": (113, 150, 186), "hill": (163, 198, 223), "ridge": (100, 145, 184), "light": (255, 255, 255)},
}


def seasonal_pixels(season, width, height, frame=0):
    """Render a layered, animated pixel-art wallpaper using only the terminal palette."""
    width, height = max(12, width), max(16, height)
    colors = PIXEL_COLORS[season]
    grid = [["sky" for _ in range(width)] for _ in range(height)]

    def rect(x, y, w, h, color):
        for yy in range(max(0, y), min(height, y + h)):
            for xx in range(max(0, x), min(width, x + w)):
                grid[yy][xx] = color

    def disk(cx, cy, radius, color):
        for yy in range(max(0, cy - radius), min(height, cy + radius + 1)):
            for xx in range(max(0, cx - radius), min(width, cx + radius + 1)):
                if (xx - cx) ** 2 + (yy - cy) ** 2 <= radius * radius:
                    grid[yy][xx] = color

    def triangle(cx, top, half, rows, color):
        for dy in range(rows):
            span = max(1, int(half * (dy + 1) / rows))
            rect(cx - span, top + dy, span * 2 + 1, 1, color)

    ground = int(height * .72)
    # Sky bands, soft block clouds and distant layered ridges make the whole card
    # read as a scene instead of a flat strip with a single large shape.
    rect(0, 0, width, max(1, height // 3), "skyline")
    rect(0, max(1, height // 3), width, height, "sky")
    for i in range(4):
        x = (i * (width // 3) + frame // 9) % width
        y = max(2, height // 7 + (i % 2) * 3)
        rect(x, y, max(3, width // 18), 1, "light")
        rect(x + 1, y - 1, max(2, width // 30), 1, "light")
    disk(int(width * .82), int(height * .20), max(2, height // 11), "sun")

    def ridge(base, amplitude, color, shift):
        for x in range(width):
            y = base + int(math.sin((x + shift) / max(3, width / 12)) * amplitude)
            rect(x, y, 1, height - y, color)

    ridge(int(height * .60), max(2, height // 12), "skyline", frame // 12)
    ridge(int(height * .68), max(2, height // 10), "hill", -frame // 18)
    rect(0, ground, width, height - ground, "sand")

    if season == "summer":
        rect(0, int(height * .62), width, int(height * .20), "sea")
        rect(0, int(height * .82), width, height - int(height * .82), "sand")
        for x in range((frame * 2) % 13, width, 13):
            y = int(height * .65) + (x % max(2, height // 5))
            rect(x, y, max(2, width // 35), 1, "foam")
        # Tall palm silhouette, striped umbrella and a little deck chair.
        palm_x, palm_y = int(width * .19), int(height * .38)
        rect(palm_x, palm_y, 2, int(height * .40), "wood")
        for dx, dy, span in ((-1, 0, 8), (-6, 2, 7), (5, 2, 7), (-8, 4, 6), (7, 4, 6)):
            triangle(palm_x + dx, palm_y + dy, max(2, width // 30), max(3, height // 7), "leaf")
        cx, top = int(width * .69), int(height * .46)
        triangle(cx, top, max(5, width // 10), max(4, height // 7), "shade")
        for stripe in range(cx - width // 12, cx + width // 12, max(2, width // 28)):
            rect(stripe, top + max(2, height // 14), max(1, width // 45), 1, "flower")
        rect(cx, top + max(4, height // 7), 2, int(height * .24), "pole")
        rect(int(width * .58), int(height * .82), max(7, width // 8), 2, "wood")
        rect(int(width * .60), int(height * .79), 2, int(height * .13), "wood")
        for i in range(3):
            fish_x = (int(width * (.25 + .2 * i)) + frame * (i + 1)) % width
            rect(fish_x, int(height * .72) + i % 3, 3, 1, "flower")
            rect(fish_x - 1, int(height * .72) + i % 3, 1, 1, "sun")
    elif season == "spring":
        # Rolling green foothills and a flowering orchard.
        ridge(int(height * .73), max(2, height // 14), "ridge", frame // 20)
        for cx, size in ((.22, .85), (.72, 1.0), (.88, .70)):
            x, trunk = int(width * cx), int(height * .60)
            rect(x - 1, trunk, 3, int(height * .22), "wood")
            for dx, dy, radius in ((-4, 0, 4), (0, -3, 5), (4, 0, 4), (0, 3, 4)):
                disk(x + dx, trunk + dy, max(2, int(height // 9 * size)), "leaf")
                if (dx + dy) % 2 == 0:
                    disk(x + dx, trunk + dy, 1, "flower")
        for i in range(12):
            x = (i * 17 + frame * (1 + i % 2)) % width
            y = (i * 7 + frame // 2) % max(1, height - ground) + ground
            rect(x, y, 1, 1, "flower")
    elif season == "autumn":
        # Warm rolling valley, a detailed cabin, and a full orange canopy.
        ridge(int(height * .76), max(2, height // 13), "ridge", frame // 16)
        cabin_x, cabin_y = int(width * .22), int(height * .57)
        rect(cabin_x, cabin_y, max(10, width // 12), max(7, height // 5), "wood")
        triangle(cabin_x + width // 24, cabin_y - max(3, height // 9), max(6, width // 15), max(4, height // 8), "shade")
        rect(cabin_x + 2, cabin_y + 2, max(2, width // 45), max(2, height // 12), "light")
        rect(cabin_x + max(6, width // 18), cabin_y + max(3, height // 10), 2, max(4, height // 9), "dark")
        tree_x, trunk = int(width * .70), int(height * .57)
        rect(tree_x - 2, trunk, 4, int(height * .31), "wood")
        rect(tree_x - 10, trunk + 5, 2, int(height * .14), "wood")
        rect(tree_x + 3, trunk + 4, 2, int(height * .17), "wood")
        for dx, dy, radius, color in ((-7, 0, 7, "shade"), (-3, -4, 8, "leaf"),
                                      (4, -4, 8, "leaf"), (8, 0, 7, "shade"),
                                      (0, 2, 8, "flower")):
            disk(tree_x + dx, trunk + dy, max(3, radius * height // 28), color)
        for i in range(14):
            x = (i * 19 + frame * (1 + i % 3)) % width
            y = (i * 11 + frame * 2) % max(2, int(height * .78))
            rect(x, y, 2, 1, "flower" if i % 3 == 0 else "shade")
        # A winding amber footpath through the foreground.
        for y in range(ground, height):
            x = int(width * .48 + math.sin((y + frame // 8) / 4) * width * .04)
            rect(x, y, max(2, width // 24), 1, "sea")
    else:
        ridge(int(height * .66), max(3, height // 7), "ridge", frame // 24)
        # Snow-capped mountain peaks, pine trees, cabin and drifting snow.
        triangle(int(width * .39), int(height * .25), max(7, width // 7), int(height * .48), "hill")
        triangle(int(width * .39), int(height * .25), max(2, width // 22), int(height * .17), "light")
        triangle(int(width * .60), int(height * .32), max(7, width // 8), int(height * .40), "skyline")
        triangle(int(width * .60), int(height * .32), max(2, width // 24), int(height * .14), "light")
        for cx, top in ((.14, .45), (.83, .42), (.92, .56)):
            x, y = int(width * cx), int(height * top)
            for tier in range(4):
                triangle(x, y + tier * max(2, height // 15), max(2, width // (27 + tier * 4)),
                         max(3, height // 7), "leaf")
            rect(x - 1, y + int(height * .30), 3, int(height * .13), "wood")
        cx, cy = int(width * .34), int(height * .68)
        rect(cx, cy, max(11, width // 13), max(7, height // 5), "wood")
        triangle(cx + width // 26, cy - max(3, height // 10), max(7, width // 16), max(4, height // 9), "dark")
        rect(cx + 2, cy + 2, max(3, width // 30), max(2, height // 12), "sun")
        for i in range(20):
            x = (i * 23 + frame * (1 + i % 3)) % width
            y = (i * 13 + frame) % max(1, ground)
            rect(x, y, 1, 1, "light")
    return grid, colors


def render_fullscreen(platform, backend, season, project, profile, access, items, progress=1.0,
                      note="", width=100, height=30, frame=0, color=True, controls=False):
    """Game-like full-screen desktop: live pixel landscape on the right, useful controls on the left."""
    width, height = max(64, int(width)), max(20, int(height))
    left_width = max(38, min(int(width * .43), 62))
    right_width = max(12, width - left_width - 2)
    pixel_height = (height - 2) * 2
    pixels, palette = seasonal_pixels(season, right_width, pixel_height, frame)
    options = [("1", "Открыть проект"), ("2", "Создать / импортировать"), ("3", "Агент и доступ"),
               ("4", "Навыки Claude / Codex"), ("5", "Проверки защиты"), ("6", "Запустить агента"),
               ("7", "Сменить сезон"), ("8", "Настройки Windows" if platform == "windows" else "Тесты проекта"),
               ("0", "Выход")]
    info = ["AI SANDBOX  /  " + ("WINDOWS" if platform == "windows" else "LINUX") + "  /  " + SEASONS[season].upper()]
    if height >= 28:
        info += ["╭─ РАБОЧИЙ СТОЛ ─────────────────────╮", "│ Проект  " + (project or "не выбран"),
                 "│ Агент   " + profile + "    доступ " + access, "│ Режим   " + str(backend),
                 "╰────────────────────────────────────╯", "ЗАГРУЗКА И СОСТОЯНИЕ",
                 "[" + "█" * round(16 * progress) + "·" * (16 - round(16 * progress)) + f"] {round(progress * 100)}%"]
        visible_items = list(items)[-3:]
        info += [f"{ {'ok': '●', 'bad': '!', 'warn': '◌'}[status] } {name}: {detail}"
                 for name, status, detail in visible_items]
        info += ["", "КНОПКИ · нажмите цифру"]
    else:
        info += ["ПРОЕКТ  " + (project or "не выбран"), "АГЕНТ  " + profile + "   ДОСТУП  " + access,
                 "ИЗОЛЯЦИЯ  " + str(backend), "СОСТОЯНИЕ  " + (note or "комплект проверен")[:left_width - 11],
                 "ЗАГРУЗКА  [" + "█" * round(12 * progress) + "·" * (12 - round(12 * progress)) + f"] {round(progress * 100)}%"]
        visible_items = list(items)[-1:]
        info += [f"{ {'ok': '●', 'bad': '!', 'warn': '◌'}[status] } {name}: {detail}"
                 for name, status, detail in visible_items]
        info += ["", "КНОПКИ · цифра 0–8"]
    info.extend(f"[{key}]  {label}" for key, label in options)
    info += [note or "0–8: выбрать действие · Esc: выход"]
    info = [str(line)[:left_width].ljust(left_width) for line in info[:height - 2]]
    info += [" " * left_width] * (height - 2 - len(info))
    glyphs = {"sky": " ", "skyline": "░", "hill": "▒", "ridge": "▓", "light": "*",
             "sun": "*", "sea": "~", "foam": "=", "sand": ".", "shade": "A",
             "pole": "|", "leaf": "T", "wood": "#", "dark": " ", "flower": "o"}
    rows = []
    for y in range(height - 2):
        line = info[y] + "  "
        py = y * 2
        previous_pair = None
        for x in range(right_width):
            top, bottom = palette[pixels[py][x]], palette[pixels[py + 1][x]]
            if color:
                pair = (top, bottom)
                if pair != previous_pair:
                    line += f"\x1b[38;2;{top[0]};{top[1]};{top[2]};48;2;{bottom[0]};{bottom[1]};{bottom[2]}m"
                    previous_pair = pair
                line += "▀"
            else:
                line += glyphs[pixels[py][x]]
        rows.append(line + ("\x1b[0m" if color else ""))
    scene_names = {"summer": "SAND · BEACH", "spring": "BLOOM · GARDEN", "autumn": "GOLDEN LEAVES", "winter": "SNOW · PINES"}
    caption = "PIXEL SEASON · " + SEASONS[season].upper() + " · " + scene_names[season]
    rows.append(("─" * left_width) + "  " + caption[:right_width].ljust(right_width))
    return ("\x1b[?25l\x1b[2J\x1b[H" if controls else "") + "\n".join(rows)


def terminal_width():
    try:
        return shutil.get_terminal_size((86, 24)).columns
    except OSError:
        return 86


def terminal_height():
    try:
        return max(20, min(shutil.get_terminal_size((100, 30)).lines, 50))
    except OSError:
        return 30


class Desktop:
    def __init__(self, platform, root, backend, season):
        self.platform, self.root, self.backend = platform, Path(root), backend
        self.season, self.project, self.profile, self.access = season_name(season), "", "claude", "read"
        self.username, self.interface, self.distro = "AIWorker", "", ""
        self.items, self.note, self.healthy, self.frame = [], "", False, 0

    def draw(self, progress=1.0):
        import ui
        color = ui.color_on() and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
        if os.name == "nt":
            color = color and ui.windows_ansi()
        screen = render_fullscreen(self.platform, self.backend, self.season, self.project, self.profile,
                                  self.access, self.items, progress, self.note, terminal_width(),
                                  terminal_height(), self.frame, color, controls=True)
        print(screen, end="", flush=True)
        self.frame += 1

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

    @staticmethod
    def read_key(timeout=0.12):
        """Read one key without Enter so the numbered desktop feels like clickable buttons."""
        if os.name == "nt":
            import msvcrt
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if msvcrt.kbhit():
                    key = msvcrt.getwch()
                    if key in ("\x00", "\xe0") and msvcrt.kbhit():
                        msvcrt.getwch()
                        return ""
                    return key
                time.sleep(0.02)
            return ""
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            return sys.stdin.read(1) if ready else ""
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    def loop(self):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("TUI нужен терминал. Для демонстрации: tui --preview linux|windows", file=sys.stderr)
            return 2
        self.boot()
        try:
            while True:
                self.draw()
                value = self.read_key()
                if not value:
                    continue
                if value in ("0", "\x1b", "q", "Q"):
                    return 0
                if value not in tuple(str(number) for number in range(1, 9)):
                    continue
                # Restore the normal terminal before asking questions or launching a child CLI.
                print("\x1b[?25h\x1b[0m\x1b[2J\x1b[H", end="", flush=True)
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
            return 130
        finally:
            print("\x1b[0m\x1b[?25h\x1b[2J\x1b[H", end="", flush=True)


def main(platform, root, backend="bubblewrap", preview=None, season="auto"):
    if not preview or (sys.stdin.isatty() and sys.stdout.isatty()):
        try:
            import textual_tui
        except ModuleNotFoundError as exc:
            if exc.name not in ("textual", "rich", "loguru", "openpyxl"):
                raise
            if not preview:
                print("Textual UI не установлен. Установите зависимости из requirements-tui.txt; "
                      "пока запускается облегчённый экран.", file=sys.stderr)
        else:
            if preview:
                demo_platform = preview
                demo_backend = "docker" if preview == "windows" else "bubblewrap"
                return textual_tui.main(demo_platform, root, backend=demo_backend, season=season, preview=True)
            return textual_tui.main(platform, root, backend=backend, season=season)
    desktop = Desktop(platform, root, backend, season)
    if preview:
        desktop.platform = preview
        desktop.backend = "Docker / WSL2 / user" if preview == "windows" else "bubblewrap"
        desktop.project, desktop.items = "demo", preview_checks()
        import ui
        color = ui.color_on()
        if os.name == "nt":
            color = color and ui.windows_ansi()
        print(render_fullscreen(desktop.platform, desktop.backend, desktop.season, desktop.project,
                                desktop.profile, desktop.access, desktop.items,
                                note="ДЕМО: проверки и запуск не выполнялись.", width=100, height=30,
                                frame=0, color=color))
        return 0
    return desktop.loop()
