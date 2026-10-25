# guard — защита файлов рабочей папки, которые хост может выполнить сам: хуки и конфигурация git,
# настройки IDE, .envrc, конфигурации MCP/агентов. Структура: сканирование -> список для монтирования только
# для чтения (до запуска) -> сравнение снимков и разбор конфигураций git (после запуска или по запросу).
import hashlib, os, re

# относительные пути в корне рабочей папки; существующие монтируются внутрь песочницы только для чтения
DEFAULT_PROTECT = [".git/config", ".git/hooks", ".gitmodules", ".vscode", ".idea", ".envrc", ".mcp.json",
                   ".claude/settings.json", ".claude/settings.local.json", ".claude/hooks", ".claude/commands",
                   ".claude/agents", ".codex/config.toml"]
MAX_FILE = 1 << 20           # крупнее — в снимке учитываются размер и время, а не содержимое
MAX_MOUNTS = 200             # больше защищаемых путей — только проверка после запуска, без монтирования

# ключи конфигурации git, по которым хост выполнит команду или перенаправит обмен данными: секция -> ключи ("*" — любой)
RISKY = {"core": {"fsmonitor", "hookspath", "sshcommand", "editor", "pager", "askpass", "gitproxy"},
         "credential": {"helper"}, "gpg": {"program"}, "sequence": {"editor"}, "include": {"path"}, "includeif": {"path"},
         "diff": {"command", "textconv", "external"}, "merge": {"driver"}, "filter": {"clean", "smudge", "process"},
         "url": {"insteadof", "pushinsteadof"}, "mergetool": {"cmd"}, "difftool": {"cmd"}, "submodule": {"update"},
         "protocol": {"allow"}, "pager": {"*"}, "alias": {"*"}}
SECTION = re.compile(r'^\[\s*([A-Za-z0-9.-]+)(?:\s+"(.*)")?\s*\]\s*(?:[#;].*)?$')
KEYVAL = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$")


def _digest(path):
    try:
        if os.path.islink(path):
            return "link:" + os.readlink(path)
        st = os.stat(path)
        if st.st_size > MAX_FILE:
            return f"big:{st.st_size}:{int(st.st_mtime)}"
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest() + f":{st.st_mode & 0o111:o}"
    except OSError:
        return "?"


def _tree(path, prefix, out, limit=400):
    """Файлы дерева path -> out[prefix/относительный путь]; по ссылкам не переходит."""
    for base, dirs, files in os.walk(path, followlinks=False):
        rel = os.path.relpath(base, path)
        for name in files:
            if len(out) >= limit:
                return
            out[os.path.normpath(os.path.join(prefix, rel, name))] = _digest(os.path.join(base, name))
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(base, d))]


def _modules(git_dir):
    """Каталоги подмодулей внутри .git/modules (имена подмодулей могут содержать /); objects не просматриваются."""
    stack = [os.path.join(git_dir, "modules")]
    while stack:
        d = stack.pop()
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            sub = os.path.join(d, n)
            if os.path.isfile(os.path.join(sub, "config")):
                yield sub
                if os.path.isdir(os.path.join(sub, "modules")):
                    stack.append(os.path.join(sub, "modules"))
            elif os.path.isdir(sub) and not os.path.islink(sub):
                stack.append(sub)


def _parents(path, root):
    """Каталоги между корнем и path (корень не включается)."""
    out = []
    cur = os.path.dirname(path)
    while cur != root and cur.startswith(root + os.sep):
        if os.path.isdir(cur) and not os.path.islink(cur):
            out.append(cur)
        cur = os.path.dirname(cur)
    return out


def scan(root, extra=()):
    """Возвращает ([(путь, режим)] для монтирования, снимок {относительный путь: отпечаток}).
    Режим "ro" — защищаемый путь; "rw" — его родительский каталог, привязанный сам к себе: точку монтирования нельзя
    переименовать или удалить, иначе защиту обошли бы командой `mv .git .git-old` с созданием нового .git."""
    root = os.path.realpath(root)
    mounts, snap = [], {}

    def take(rel):
        full = os.path.join(root, rel)
        if os.path.lexists(full):
            mounts.append(full)
            if os.path.isdir(full) and not os.path.islink(full):
                _tree(full, rel, snap)
            else:
                snap[rel] = _digest(full)

    for rel in list(DEFAULT_PROTECT) + [e.strip("/") for e in extra if e.strip("/")]:
        take(rel)
    for base, dirs, files in os.walk(root, followlinks=False):
        rel = os.path.relpath(base, root)
        if ".git" in files:                               # файл-указатель gitdir (подмодуль, рабочее дерево)
            take(os.path.normpath(os.path.join(rel, ".git")))
        if ".git" in dirs:
            git = os.path.normpath(os.path.join(rel, ".git"))
            if rel != ".":
                take(os.path.join(git, "config"))
                take(os.path.join(git, "hooks"))
            for module in _modules(os.path.join(base, ".git")):
                take(os.path.join(os.path.relpath(module, root), "config"))
                take(os.path.join(os.path.relpath(module, root), "hooks"))
            dirs.remove(".git")
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(base, d))]
    mounts = list(dict.fromkeys(mounts))
    anchors = {a for m in mounts for a in _parents(m, root)} - set(mounts)
    result = [(a, "rw") for a in sorted(anchors, key=len)] + [(m, "ro") for m in mounts]
    return (result if len(result) <= MAX_MOUNTS else []), snap


def risky_config(text):
    """Опасные ключи в тексте конфигурации git -> [(секция, ключ)]."""
    found, section = [], ""
    for line in (l.strip() for l in text.splitlines()):
        m = SECTION.match(line)
        if m:
            section = m[1].lower()
            continue
        k = KEYVAL.match(line)
        if not k:
            continue
        key, value = k[1].lower(), (k[2] or "").strip().strip('"')
        keys = RISKY.get(section, ())
        if section == "alias":
            if value.startswith("!"):
                found.append((section, key))
        elif section == "pager":
            if value.lower() not in ("", "true", "false", "yes", "no", "on", "off"):
                found.append((section, key))
        elif key in keys:
            found.append((section, key))
    return found


def _read(full):
    try:
        with open(full, encoding="utf-8", errors="replace") as f:
            return f.read(MAX_FILE)
    except OSError:
        return ""


def classify(rel, full):
    """Описание файла для отчёта -> (текст, опасен_ли_сам_по_себе); None для безвредных файлов (хуки *.sample)."""
    name = os.path.basename(rel)
    if "/hooks/" in "/" + rel:
        return None if name.endswith(".sample") else ("хук git: выполняется при commit/checkout/push", True)
    if name == "config" and (rel.startswith(".git") or "/.git/" in rel):
        risky = risky_config(_read(full))
        if risky:
            return "git выполнит или перенаправит: " + ", ".join(f"{s}.{k}" for s, k in risky), True
        return "конфигурация git", False
    if name == ".git":
        return "указатель gitdir: git возьмёт конфигурацию из другого каталога", True
    if rel.startswith(".vscode"):
        return "настройки IDE (задачи могут запускаться при открытии папки)", "folderOpen" in _read(full)
    if rel.startswith(".idea"):
        return "настройки IDE", False
    if name == ".envrc":
        return "direnv выполнит файл после direnv allow", True
    if name == ".mcp.json":
        return "MCP-серверы: клиент запускает указанные команды", True
    if rel.startswith(".claude/hooks"):
        return "хуки Claude Code", True
    if rel.startswith(".claude/settings"):
        return "настройки Claude Code", '"hooks"' in _read(full)
    if rel.startswith(".codex"):
        return "настройки Codex", "mcp_servers" in _read(full) or "notify" in _read(full)
    return "конфигурация инструмента", False


def audit(root, before=None, extra=()):
    """Замечания [(путь, описание)] только об опасных файлах. С before — новые и изменённые с момента снимка; без — все имеющиеся."""
    root = os.path.realpath(root)
    _, after = scan(root, extra)
    notes = []
    for rel in sorted(after):
        if before is not None and before.get(rel) == after[rel]:
            continue
        info = classify(rel, os.path.join(root, rel))
        if info is None or not info[1]:
            continue
        what = "обнаружен" if before is None else ("новый файл" if rel not in before else "изменён")
        notes.append((rel, f"{what}; {info[0]}"))
    return notes


def report(notes):
    if not notes:
        return ""
    lines = ["", "ВНИМАНИЕ: в рабочей папке файлы, которые хост может выполнить сам (git, IDE, direnv, MCP):"]
    lines += [f"  {path}: {why}" for path, why in notes]
    lines += ["Проверьте их до запуска git/IDE на хосте; текущее состояние: sandbox audit ИМЯ.", ""]
    return "\n".join(lines)
