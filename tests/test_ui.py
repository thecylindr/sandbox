"""Оформление вывода (ui.py): правила цвета, ширина, колонки и переносы. Терминал подменяется заглушками."""
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ui


class FakeTerminal(io.StringIO):
    """Поток, который считает себя терминалом, но настоящего дескриптора не имеет."""
    encoding = "utf-8"

    def isatty(self):
        return True


def clean_environment():
    patcher = patch.dict(os.environ)
    patcher.start()
    for name in ("NO_COLOR", "FORCE_COLOR", "COLUMNS", "TERM"):
        os.environ.pop(name, None)
    return patcher


class ColorRuleTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(clean_environment().stop)

    def test_plain_streams_never_get_color(self):
        self.assertFalse(ui.color_on(io.StringIO()))
        self.assertFalse(ui.color_on(MagicMock()))           # заглушка sys.stdout из тестов

    def test_terminal_gets_color_unless_dumb(self):
        self.assertTrue(ui.color_on(FakeTerminal()))
        os.environ["TERM"] = "dumb"
        self.assertFalse(ui.color_on(FakeTerminal()))

    def test_no_color_beats_everything(self):
        os.environ["NO_COLOR"] = "1"
        os.environ["FORCE_COLOR"] = "1"
        with tempfile.TemporaryFile() as real:
            self.assertFalse(ui.color_on(real))
            self.assertFalse(ui.color_on(FakeTerminal()))

    def test_empty_no_color_is_ignored(self):
        os.environ["NO_COLOR"] = ""
        self.assertTrue(ui.color_on(FakeTerminal()))

    def test_force_color_applies_to_real_files_only(self):
        os.environ["FORCE_COLOR"] = "1"
        with tempfile.TemporaryFile() as real:
            self.assertTrue(ui.color_on(real))
        self.assertFalse(ui.color_on(io.StringIO()))
        self.assertFalse(ui.color_on(MagicMock()))
        os.environ["FORCE_COLOR"] = "0"
        with tempfile.TemporaryFile() as real:
            self.assertFalse(ui.color_on(real))

    def test_windows_console_mode_is_not_touched_elsewhere(self):
        self.assertTrue(ui.windows_ansi() if os.name != "nt" else True)


class WidthTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(clean_environment().stop)

    def test_columns_variable_is_clamped(self):
        for value, expected in (("120", 120), ("20", 60), ("500", 160)):
            os.environ["COLUMNS"] = value
            self.assertEqual(ui.term_width(io.StringIO()), expected)

    def test_unusable_columns_fall_back_to_a_sane_width(self):
        os.environ["COLUMNS"] = "много"
        self.assertTrue(60 <= ui.term_width(io.StringIO()) <= 160)
        self.assertTrue(60 <= ui.term_width(MagicMock()) <= 160)


class OutTests(unittest.TestCase):
    def make(self, color=False, width=60, pretty=True, stream=None):
        stream = stream or io.StringIO()
        return ui.Out(stream, color=color, width=width, pretty=pretty), stream

    def test_paint_only_when_color_is_on(self):
        plain, _ = self.make(color=False)
        painted, _ = self.make(color=True)
        self.assertEqual(plain.paint("текст", "ok"), "текст")
        self.assertEqual(painted.paint("текст", "ok"), "\x1b[32mтекст\x1b[0m")
        self.assertEqual(painted.paint("", "ok"), "")
        self.assertEqual(painted.paint("текст", None), "текст")
        self.assertEqual(ui.visible(painted.paint("текст", "bad")), 5)

    def test_status_tags(self):
        plain, _ = self.make()
        painted, _ = self.make(color=True)
        self.assertEqual([plain.tag(kind) for kind in ("ok", "bad", "warn")], ["[ok]", "[!!]", "[..]"])
        self.assertEqual(painted.tag("bad"), "\x1b[1;31m[!!]\x1b[0m")

    def test_rule_leaves_the_last_column_free(self):
        out, stream = self.make(width=70)
        out.rule("Процессы")
        line = stream.getvalue().rstrip("\n")
        self.assertEqual(len(line), 69)
        self.assertTrue(line.startswith("── Процессы ──"))

    def test_rule_falls_back_to_ascii_when_the_stream_cannot_encode(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        out = ui.Out(stream, color=False, width=60, pretty=True)
        self.assertEqual(out.rule_char, "-")

    def test_table_aligns_columns_and_wraps_the_last_one_under_itself(self):
        out, stream = self.make(width=60)
        out.table([("a", "сеть выключена", "короткое"), ("длинное имя", "5 доменов", "очень " * 12 + "длинное описание")],
                  header=("профиль", "сеть", "описание"))
        lines = stream.getvalue().splitlines()
        self.assertTrue(all(len(line) <= 60 for line in lines), lines)
        column = lines[0].index("описание")
        self.assertTrue(all(line.index(word) == column for line, word in ((lines[1], "короткое"), (lines[2], "очень"))))
        self.assertTrue(lines[3].startswith(" " * column + "очень") or lines[3].startswith(" " * column), lines)
        self.assertGreater(len(lines), 3)

    def test_table_header_is_dim_and_cells_keep_their_style(self):
        out, stream = self.make(color=True, width=80)
        out.table([(("A", "ok"), "b")], header=("имя", "значение"))
        header, row = stream.getvalue().splitlines()
        self.assertIn("\x1b[2m", header)
        self.assertIn("\x1b[32mA\x1b[0m", row)

    def test_table_does_not_wrap_when_not_pretty(self):
        out, stream = self.make(width=60, pretty=False)
        text = "слово " * 30
        out.table([("x", text)])
        self.assertEqual(len(stream.getvalue().splitlines()), 1)

    def test_single_column_table(self):
        out, stream = self.make(width=60)
        out.table([("один",), ("два",)])
        self.assertEqual(stream.getvalue().splitlines(), ["  один", "  два"])

    def test_item_wraps_under_the_text(self):
        out, stream = self.make(width=60)
        out.item(("[ok]", "ok"), "слово " * 20)
        lines = stream.getvalue().splitlines()
        self.assertTrue(lines[0].startswith("[ok] слово"))
        self.assertTrue(all(line.startswith("     слово") for line in lines[1:]))
        self.assertTrue(all(len(line) <= 60 for line in lines))

    def test_say_paints_with_the_given_style(self):
        out, stream = self.make(color=True)
        out.say("итог", "ok")
        self.assertEqual(stream.getvalue(), "\x1b[32mитог\x1b[0m\n")


if __name__ == "__main__":
    unittest.main()
