# tomlmini — разбор подмножества TOML для профилей, когда нет ни tomllib (Python < 3.11), ни tomli.
# Поддержано: комментарии, [таблицы], ключи (простые, в кавычках, через точку), строки "..." и '...',
# целые и дробные числа, true/false, массивы (в том числе многострочные), встроенные таблицы {a = 1}.
# Остальное (даты, [[массивы таблиц]], многострочные строки, 0x-числа) — ValueError с номером строки.
import re

_BARE = re.compile(r"[A-Za-z0-9_-]+")
_NUMBER = re.compile(r"[+-]?(?:0|[1-9](?:_?[0-9])*)(?:\.[0-9](?:_?[0-9])*)?(?:[eE][+-]?[0-9](?:_?[0-9])*)?")
_ESCAPES = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}


def loads(text):
    return _Parser(text).document()


class _Parser:
    def __init__(self, text):
        self.s, self.i, self.tables = text, 0, set()

    def fail(self, msg):
        raise ValueError(f"TOML, строка {self.s.count(chr(10), 0, self.i) + 1}: {msg}")

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def blanks(self, newlines):
        # пробелы и комментарии; при newlines — ещё и переводы строк
        while self.i < len(self.s):
            c = self.s[self.i]
            if c in " \t" or (newlines and c in "\r\n"):
                self.i += 1
            elif c == "#":
                while self.i < len(self.s) and self.s[self.i] != "\n":
                    self.i += 1
            else:
                break

    def document(self):
        root = table = {}
        while True:
            self.blanks(True)
            if not self.peek():
                return root
            table = self.header(root) if self.peek() == "[" else self.pair(table) or table
            self.blanks(False)
            if self.peek() not in ("", "\n", "\r"):
                self.fail("ожидался конец строки")

    def header(self, root):
        self.i += 1
        if self.peek() == "[":
            self.fail("массивы таблиц [[...]] не поддерживаются")
        keys = self.keys()
        if self.peek() != "]":
            self.fail("ожидалась ]")
        self.i += 1
        if tuple(keys) in self.tables:
            self.fail(f"таблица {'.'.join(keys)} объявлена повторно")
        self.tables.add(tuple(keys))
        table = root
        for k in keys:
            table = table.setdefault(k, {})
            if not isinstance(table, dict):
                self.fail(f"ключ {k} уже занят")
        return table

    def pair(self, table):
        keys = self.keys()
        if self.peek() != "=":
            self.fail("ожидалось =")
        self.i += 1
        self.blanks(False)
        value = self.value()
        for k in keys[:-1]:
            table = table.setdefault(k, {})
            if not isinstance(table, dict):
                self.fail(f"ключ {k} уже занят")
        if keys[-1] in table:
            self.fail(f"повтор ключа {keys[-1]}")
        table[keys[-1]] = value

    def keys(self):
        out = []
        while True:
            self.blanks(False)
            if self.peek() in ('"', "'"):
                out.append(self.string())
            else:
                m = _BARE.match(self.s, self.i)
                if not m:
                    self.fail("ожидался ключ")
                out.append(m[0])
                self.i = m.end()
            self.blanks(False)
            if self.peek() != ".":
                return out
            self.i += 1

    def value(self):
        c = self.peek()
        if c in ('"', "'"):
            return self.string()
        if c == "[":
            return self.array()
        if c == "{":
            return self.inline()
        for word, val in (("true", True), ("false", False)):
            if self.s.startswith(word, self.i):
                self.i += len(word)
                return val
        m = _NUMBER.match(self.s, self.i)
        if m and (m.end() >= len(self.s) or self.s[m.end()] in " \t\r\n,]}#"):
            self.i = m.end()
            t = m[0].replace("_", "")
            return float(t) if any(x in t for x in ".eE") else int(t)
        self.fail("неподдерживаемое значение")

    def string(self):
        q = self.s[self.i]
        if self.s.startswith(q * 3, self.i):
            self.fail("многострочные строки не поддерживаются")
        self.i += 1
        out = []
        while True:
            c = self.peek()
            if c in ("", "\n", "\r"):
                self.fail("строка не закрыта")
            self.i += 1
            if c == q:
                return "".join(out)
            if c != "\\" or q == "'":
                out.append(c)
                continue
            e = self.peek()
            self.i += 1
            if e in _ESCAPES:
                out.append(_ESCAPES[e])
            elif e in ("u", "U"):
                n = 4 if e == "u" else 8
                h = self.s[self.i:self.i + n]
                if len(h) != n or not re.fullmatch(r"[0-9A-Fa-f]+", h):
                    self.fail("неверная последовательность \\u")
                self.i += n
                out.append(chr(int(h, 16)))
            else:
                self.fail("неизвестная escape-последовательность")

    def array(self):
        self.i += 1
        out = []
        while True:
            self.blanks(True)
            if self.peek() == "]":
                self.i += 1
                return out
            out.append(self.value())
            self.blanks(True)
            if self.peek() == ",":
                self.i += 1
            elif self.peek() != "]":
                self.fail("ожидалась , или ]")

    def inline(self):
        self.i += 1
        out = {}
        self.blanks(False)
        if self.peek() == "}":
            self.i += 1
            return out
        while True:
            self.pair(out)
            self.blanks(False)
            c = self.peek()
            self.i += 1
            if c == "}":
                return out
            if c != ",":
                self.fail("ожидалась , или }")
            self.blanks(False)
