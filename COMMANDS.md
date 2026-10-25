# Команды AI Sandbox

[English](COMMANDS.en.md) · [Главная](README.md) · [Полное руководство](MANUAL.md)

Эта шпаргалка отвечает на вопрос «что ввести дальше». Обычно проще открыть рабочий стол: `sandbox` в Linux/WSL или `start.cmd` в Windows. Он показывает проекты и действия в меню. Команды ниже полезны для терминала и сценариев.

## Linux и WSL2: обычный рабочий цикл

Запускайте команды из установленной Linux/WSL-среды:

```bash
sandbox check                              # проверить, готова ли среда
sandbox new demo --copy ~/code/my-project  # создать изолированную копию проекта
sandbox audit demo                         # проверить опасные для хоста файлы проекта
sandbox skills demo                        # добавить навыки для Claude Code и Codex
sandbox selftest default                   # проверить защиту контролируемыми пробами
sandbox run claude demo --access edit      # запустить Claude с правом менять копию
```

Чтобы использовать Codex, замените `claude` на `codex`. Доступ `read` разрешает читать проект, `edit` — менять только его рабочую копию. При запуске лаунчер показывает настройки и обычно просит подтверждение. Для интерактивного терминала внутри среды используйте `sandbox shell default demo`.

Если вы уже находитесь внутри `~/sandbox/workspaces/demo`, имя проекта можно не указывать: `sandbox run claude`.

## Windows: выберите один backend

Откройте `cmd` или PowerShell в папке распакованного проекта. `start.cmd` запускает TUI; `start.cmd gui` — графическое окно. Ниже команды через Python напрямую; укажите backend явно, чтобы было понятно, где выполняется агент.

### WSL2

```powershell
py -3 windows.py setup-wsl
py -3 windows.py check --backend wsl
py -3 windows.py new demo --backend wsl --copy 'C:\Projects\my-project'
py -3 windows.py skills demo --backend wsl
py -3 windows.py selftest default --backend wsl
py -3 windows.py run claude demo --backend wsl --access edit
```

`setup-wsl` устанавливает файлы песочницы в WSL. Первую установку WSL2 и самого дистрибутива выполните заранее, как описано в [руководстве Windows](WINDOWS.md). WSL2 — подходящий вариант, если важно отделить список процессов и сетевых адаптеров агента от Windows-хоста.

### Docker Desktop

```powershell
py -3 windows.py build --backend docker
py -3 windows.py check --backend docker
py -3 windows.py new demo --backend docker --copy 'C:\Projects\my-project'
py -3 windows.py skills demo --backend docker
py -3 windows.py selftest default --backend docker
py -3 windows.py run claude demo --backend docker --access edit
```

Сначала соберите образ командой `build`. Нужен Docker Desktop с Linux-контейнерами. Без сети — добавьте `--offline`; иначе доступ определяется профилем. Подготовка может скачать образы и инструменты.

### Отдельный Windows-пользователь (`user`)

Этот вариант назначает ACL выбранной рабочей копии и пропускает разрешённый трафик через выбранный адаптер. Он не скрывает от агента процессы и сетевые адаптеры Windows. Настройка и запуск требуют административных прав у лаунчера; сам CLI-агент запускается под отдельной непривилегированной учётной записью.

```powershell
py -3 windows.py interfaces --backend user
py -3 windows.py setup-user --backend user --username AIWorker --interface '{АДАПТЕР-GUID}'
py -3 windows.py new demo --backend user --copy 'C:\Projects\my-project'
py -3 windows.py skills demo --backend user
py -3 windows.py run claude demo --backend user --access edit -- 'C:\Tools\claude.exe'
```

Скопируйте GUID адаптера из вывода `interfaces`. После `--` укажите путь к исполняемому CLI-агента. Удаление управляемой учётной записи и её правил: `py -3 windows.py remove-user --backend user --username AIWorker`. Подробности и ограничения — [WINDOWS_NATIVE.md](WINDOWS_NATIVE.md).

## Команды справки и обслуживания

| Команда | Что делает |
|---|---|
| `sandbox` / `sandbox tui` | Открывает терминальный рабочий стол. `--season spring` выбирает тему; `--preview windows` показывает демонстрацию интерфейса без запуска агента. |
| `sandbox new ИМЯ [--copy ПУТЬ]` | Создаёт рабочую папку, при необходимости копирует туда проект. Типичные секреты вроде `.env`, ключей и учётных данных пропускаются. Повторно поверх существующей папки не копирует. |
| `sandbox ws` | Показывает созданные рабочие копии. `--json` выводит только имена в JSON. |
| `sandbox list` | Показывает доступные профили запуска. |
| `sandbox show ПРОФИЛЬ` | Показывает настройки профиля: доступ к проекту, сеть, лимиты и разрешённые пути. `--json` выводит настройки в JSON. |
| `sandbox check` | Проверяет, установлены ли нужные компоненты и поддерживает ли система основные механизмы изоляции. Это проверка готовности, не проверка всех границ защиты. |
| `sandbox selftest [ПРОФИЛЬ]` | Запускает пробы изнутри песочницы на тестовых объектах. Показывает фактический результат для текущей системы; это не аудит исходного кода. |
| `sandbox audit [ИМЯ]` | Ищет в копии проекта файлы, которые может выполнить или загрузить сам хост (например, Git hooks и настройки IDE). Если имя пропущено, проверяет текущую папку, когда она является рабочей копией. |
| `sandbox skills ИМЯ` | Устанавливает комплект навыков Claude Code и Codex в копию проекта. Навыки подсказывают агенту рабочие правила, но сами по себе не создают изоляцию. |
| `sandbox log [-n 40]` | Показывает последние строки журнала запусков за сегодня. Например, `sandbox log -n 100`. |
| `sandbox run ПРОФИЛЬ ИМЯ -- КОМАНДА [АРГУМЕНТЫ]` | Запускает указанную программу внутри выбранного профиля. Без `-- КОМАНДА` запускает команду, заданную профилем. |

### Термины и параметры

- **Профиль** (`claude`, `codex`, `default`) задаёт команду, доступ к сети, дополнительные разрешённые пути и лимиты. Посмотреть настройки: `sandbox show claude`.
- **Рабочая копия** — отдельная папка под `~/sandbox/workspaces/`; оригинал проекта лаунчер не меняет.
- **Сеть** в Linux задаётся профилем: обычно выключена либо ограничена перечисленными доменами. `--net off` принудительно выключает её. На Windows есть `--offline`.
- `--ro ПУТЬ` добавляет внешний путь только для чтения; `--rw ПУТЬ` даёт программе запись в явно добавленный путь. Используйте их только когда это действительно нужно.
- `--dry-run` показывает собранную команду Linux без запуска агента; Windows поддерживает его для `run` и `shell`.
- `--yes` пропускает подтверждение запуска. `--allow-outside` и `--allow-sensitive` снимают защитные ограничения Linux; обычной работе они не нужны.
- В Windows `--backend` выбирает `wsl`, `docker` или `user`. В Linux этот параметр не используется.

Если команда не работает, сначала проверьте её аргументы через `sandbox --help`, `sandbox run --help` либо `py -3 windows.py --help`. Разбор платформ и ошибок — в [полном руководстве](MANUAL.md) и [руководстве Windows](WINDOWS.md).
