"""Install bundled, instruction-only skills into one managed project copy."""
from pathlib import Path
import os
import stat

ROOT = Path(__file__).resolve().parent
NAMES = ("sandbox-fix-report", "sandbox-project-tests")
TARGETS = (Path(".agents/skills"), Path(".claude/skills"))


def safe_path(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise OSError(f"Ссылка/junction в пути навыка запрещена: {item}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            raise OSError(f"Hardlink в пути навыка запрещён: {item}")
    return path


def prepare(project):
    """Never overwrite a project's own skills; only add known bundled text."""
    project = safe_path(project)
    if not project.is_dir():
        raise ValueError("Сначала выберите существующую копию проекта в sandbox.")
    plan = []
    for parent in TARGETS:
        for name in NAMES:
            source = safe_path(ROOT / "agent-skills" / name / "SKILL.md")
            target = safe_path(project / parent / name / "SKILL.md")
            if not source.is_file():
                raise OSError(f"Отсутствует встроенный навык: {name}")
            data = source.read_bytes()
            if target.exists() and target.read_bytes() != data:
                raise OSError(f"Навык уже изменён в проекте; файл сохранён: {target}")
            plan.append((target, data))
    created = []
    for target, data in plan:
        if target.exists():
            continue
        safe_path(target.parent).mkdir(parents=True, exist_ok=True)
        safe_path(target)
        with target.open("xb") as stream:
            stream.write(data)
        created.append(target)
    return created
