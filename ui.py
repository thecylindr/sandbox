"""Оформление вывода для человека: цвет только в терминале, колонки и переносы по ширине окна.

Только стандартная библиотека. Правила цвета: NO_COLOR (любое непустое значение) выключает, FORCE_COLOR включает
и вне терминала, TERM=dumb выключает. Вывод в файл или канал остаётся прежним: без цвета и без переносов.
"""
import os
import re
import shutil
import sys
import textwrap

# ---------- стили и измерение ----------
CODES = {"ok": "32", "bad": "1;31", "warn": "33", "info": "36", "dim": "2", "bold": "1", "head": "1;36"}
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def visible(text):
    """Длина строки без управляющих последовательностей цвета."""
    return len(ANSI.sub("", text))


def is_tty(stream):
    try:
        return stream.isatty() is True       # заглушка из тестов отвечает не True и терминалом не считается
    except (AttributeError, ValueError, OSError):
        return False


def is_real_file(stream):
    try:
        return isinstance(stream.fileno(), int)
    except (AttributeError, ValueError, OSError):
        return False


def windows_ansi():
    """Консоль Windows показывает цвет только при включённом режиме виртуального терминала."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel = ctypes.windll.kernel32
        kernel.GetStdHandle.restype = ctypes.c_void_p
        kernel.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
        kernel.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        handle, mode = kernel.GetStdHandle(-11), ctypes.c_uint()
        return bool(kernel.GetConsoleMode(handle, ctypes.byref(mode)) and kernel.SetConsoleMode(handle, mode.value | 4))
    except Exception:                        # цвет — украшение: любая неудача означает «без цвета»
        return False


def color_on(stream=None):
    stream = sys.stdout if stream is None else stream
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR", "") not in ("", "0") and is_real_file(stream):
        return True
    return os.environ.get("TERM") != "dumb" and is_tty(stream) and windows_ansi()


def term_width(stream=None, default=100):
    """Ширина окна, ограниченная 60…160 столбцами; COLUMNS приоритетнее запроса к терминалу."""
    stream = sys.stdout if stream is None else stream
    try:
        columns = int(os.environ.get("COLUMNS", ""))
    except ValueError:
        columns = 0
    if columns <= 0:
        try:
            columns = os.get_terminal_size(stream.fileno()).columns
        except (AttributeError, TypeError, ValueError, OSError):
            columns = shutil.get_terminal_size((default, 24)).columns
    return max(60, min(columns, 160))


def encodable(char, stream):
    encoding = getattr(stream, "encoding", None)
    try:
        char.encode(encoding if isinstance(encoding, str) else "utf-8")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


# ---------- поток вывода ----------
class Out:
    """Один поток вывода: цвет и ширина определяются один раз; в тестах задаются явно.

    pretty — человеческая раскладка (таблицы, переносы): терминал или принудительный цвет.
    """

    def __init__(self, stream=None, color=None, width=None, pretty=None):
        self.stream = sys.stdout if stream is None else stream
        self.color = color_on(self.stream) if color is None else color
        self.width = term_width(self.stream) if width is None else width
        self.pretty = (is_tty(self.stream) or self.color) if pretty is None else pretty
        self.rule_char = "─" if encodable("─", self.stream) else "-"

    def paint(self, text, style):
        return f"\x1b[{CODES[style]}m{text}\x1b[0m" if self.color and text and style else text

    def say(self, text="", style=None, end="\n"):
        print(self.paint(text, style), file=self.stream, end=end)

    def tag(self, kind):
        """Статус в квадратных скобках: [ok], [!!], [..]."""
        text, style = {"ok": ("[ok]", "ok"), "bad": ("[!!]", "bad"), "warn": ("[..]", "warn")}[kind]
        return self.paint(text, style)

    def rule(self, title, style="head"):
        """Заголовок раздела: «── Название ─────»."""
        edge = self.rule_char * 2
        tail = self.rule_char * max(self.width - visible(title) - 5, 2)
        self.say(f"{edge} {title} {tail}", style)

    def item(self, marker, text, style=None, indent=0):
        """Пункт «маркер текст» с переносом под текст. marker — (простой текст, стиль)."""
        plain, mstyle = marker
        lead = " " * indent + plain + " "
        lines = textwrap.wrap(text, max(self.width - len(lead), 20)) if self.pretty else [text]
        for number, piece in enumerate(lines or [""]):
            head = " " * indent + self.paint(plain, mstyle) + " " if number == 0 else " " * len(lead)
            self.say(head + self.paint(piece, style))

    def table(self, rows, header=None, indent=2, gap=2):
        """Колонки по самой длинной ячейке; последняя переносится по ширине окна. Ячейка — строка или (строка, стиль)."""
        body = [[cell if isinstance(cell, tuple) else (cell, None) for cell in row] for row in ([header] if header else []) + list(rows)]
        if not body:
            return
        cols = len(body[0])
        widths = [max(len(row[i][0]) for row in body) for i in range(cols - 1)]
        room = max(self.width - indent - sum(widths) - gap * (cols - 1), 20)
        for number, row in enumerate(body):
            base = "dim" if header and number == 0 else None
            cells = [self.paint(text, style or base) + " " * (widths[i] - len(text)) for i, (text, style) in enumerate(row[:-1])]
            lead = " " * indent + "".join(cell + " " * gap for cell in cells)
            text, style = row[-1]
            pieces = (textwrap.wrap(text, room) or [""]) if self.pretty else [text]
            self.say(lead + self.paint(pieces[0], style or base))
            for piece in pieces[1:]:
                self.say(" " * visible(lead) + self.paint(piece, style or base))
