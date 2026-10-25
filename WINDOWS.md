# AI Sandbox для Windows: три режима запуска

[English](WINDOWS.en.md) · [Краткое описание проекта](README.md) · [Терминальный интерфейс](TUI.md)

Один Python-лаунчер и окно выбора: WSL2 + bubblewrap, Docker Linux containers или
отдельный локальный пользователь (`user`) с выбранным сетевым интерфейсом.
Python управляет запуском. Сам по себе Python не является механизмом изоляции.
В режиме user создаётся отдельная учётная запись; ACL исходных проектов не меняются.
Режим user слабее контейнеров: списки адаптеров и процессов хоста не скрываются.
Настройка, ограничения IPv4/WFP и приёмка — [WINDOWS_NATIVE.md](WINDOWS_NATIVE.md).
Далее подробно описаны два контейнерных режима.

| Возможность | WSL2 + bubblewrap | Python + Docker |
|---|---|---|
| Что установить | Python 3.11+ в Windows, WSL2 с Linux, Python 3.11+ и bubblewrap в Linux, нужный CLI агента | Python 3.11+ в Windows и Docker Desktop в режиме Linux containers |
| Где агент и его инструменты | Установлены в выбранном дистрибутиве WSL | В собственном образе с Claude, Codex, Node.js, Python, git, ripgrep, ffmpeg |
| Проект | Копия в `~/sandbox/workspaces/<имя>` внутри WSL | Копия в `windows-data/workspaces/<имя>` рядом с Windows-лаунчером |
| Доступ к проекту | `read` или `edit`, bind-mount bubblewrap | `read` или `edit`, bind-mount Docker |
| Процессы и сеть | Отдельные PID/net namespaces bubblewrap | Отдельный PID namespace, `--network none` у агента |
| Интернет | CONNECT-прокси с доменами профиля | Отдельный прокси-контейнер и Unix-сокет; у агента только loopback |
| Настройки/авторизация | Отдельный HOME для профиля WSL | Docker volume HOME отдельно для проекта и профиля |
| Лимиты ресурсов | cgroup при доступном `systemd --user` | Лимиты Docker: агент 8 ГиБ, 512 задач, 2 CPU; прокси 256 МиБ, 160 задач, 1 CPU |

Это два способа развёртывания с разными зависимостями. Docker не объявляется
безусловно более безопасным: результат зависит от ядра, Docker/WSL и конфигурации.
Docker Desktop может сам использовать WSL2 либо другой поддерживаемый Linux backend.
Docker-режим не требует установки launcher/bubblewrap/агента в пользовательский
дистрибутив WSL и не вызывает `wsl.exe`.

## Что выбрать, в том числе без WSL

| У вас | Что делать | Изоляция |
|---|---|---|
| Windows 10 (2004+) или 11, виртуализация включена | **WSL2**: `wsl --install -d Ubuntu`, затем `install.ps1 -Backend wsl` (работает и в редакции Home) | пространства имён, seccomp, Landlock внутри лёгкой ВМ WSL2 |
| WSL2 нельзя или не хочется, есть Docker Desktop | **Docker**: `install.ps1 -Backend docker -BuildImage` | контейнер без сети; Docker Desktop сам работает на WSL2 или другом Linux backend |
| ни WSL2, ни Docker | `install.ps1 -Backend user`, затем настройка управляемого пользователя и адаптера | ACL/WFP; адаптеры и процессы хоста не скрываются, см. WINDOWS_NATIVE.md |
| нужна строгая изоляция, но WSL/Docker недоступны | отдельная виртуальная машина | режим user не заменяет границу ВМ |

Вариант 3 (`user`) использует отдельную учётную запись, Job Object, NTFS ACL и WFP.
Настройка и обязательная приёмка описаны в [WINDOWS_NATIVE.md](WINDOWS_NATIVE.md);
полного AppContainer/VM-окружения он не создаёт.

Диагностика без изменений: `powershell -ExecutionPolicy Bypass -File .\install.ps1 -Check`
(версия Windows, Python 3.11+, дистрибутивы WSL и их версия, локальный Docker) и `-DryRun` (показать действия).

## Запуск интерфейса

Распакуйте Windows-архив и дважды нажмите `start.cmd`: откроется терминальный
рабочий стол с выбором режима, проекта и сезона. Описание меню и демонстрация —
[TUI.md](TUI.md). Прежнее графическое окно открывается командой:

```powershell
start.cmd gui
```

В окне выберите `wsl`, `docker` или `user`, агента, имя проекта и доступ:

- `read` — только чтение проекта, режим по умолчанию;
- `edit` — редактирование копии проекта;
- «Импорт копии…» — выбрать исходную папку через диалог;
- «Создать проект» — создать пустую рабочую папку;
- «Запустить» — открыть терминал с агентом;
- «Список проектов» — показать проекты выбранного режима.

Для WSL можно указать имя дистрибутива. Импорт и работа открываются в отдельном
окне терминала; дождитесь завершения импорта перед запуском проекта.
Исходная папка при импорте не изменяется, автоматической синхронизации обратно нет.
Редактируемую копию можно открыть обычным редактором из пути в таблице выше.

## Вариант 1: WSL2 + bubblewrap

Если WSL2 ещё не установлен, установите его по [инструкции Microsoft](https://learn.microsoft.com/en-us/windows/wsl/install).
В выбранном Linux-дистрибутиве нужны Python 3.11+, bubblewrap и установленный CLI
Claude/Codex. Например, для подходящей версии Ubuntu/Debian:

```bash
sudo apt update
sudo apt install python3 bubblewrap
```

Из распакованной папки в Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Backend wsl -Distribution Ubuntu
```

Название `Ubuntu` должно соответствовать вашему установленному дистрибутиву.
Установщик копирует только код в `~/sandbox`, сохраняет существующие профили и
запускает проверки. Если bubblewrap или самопроверка не работают, установка этого
режима не объявляется успешной. Системные настройки защиты автоматически не меняются.

Параметры `install.ps1`: `-Backend wsl|docker|both|user`, `-Distribution ИМЯ`, `-BuildImage`, `-InstallDir ПУТЬ`
(по умолчанию `%LOCALAPPDATA%\AISandbox`), `-NoPath`, `-Check`, `-DryRun`, `-Uninstall` [`-Purge`]. Повторный запуск из новой
копии обновляет код и сохраняет профили (изменённый профиль остаётся, новая версия рядом `*.new`) и проекты. Установщик
ищет Python 3.11+ и записывает его **абсолютный путь** в `sandbox.cmd`; сообщения только на английском (ASCII), чтобы Windows
PowerShell 5.1 не искажал их. Сам скрипт на Windows не запускался: начните с `-Check` и `-DryRun`.

После успешной установки откройте новый терминал:

```powershell
sandbox new demo --backend wsl --distro Ubuntu --copy "C:\Code\My Project"
sandbox run claude demo --backend wsl --distro Ubuntu --access read
sandbox run claude demo --backend wsl --distro Ubuntu --access edit
```

Укажите `codex` вместо `claude`, если нужен Codex. Если дистрибутив не указан,
используется WSL по умолчанию. Пути Windows передаются как аргументы и переводятся
существующим Linux-launcher, без подстановки в shell-код.

Без установки Windows-команды можно выполнить `py -3 windows.py setup-wsl`, затем
те же команды через `py -3 windows.py` вместо `sandbox`.

### Усиление WSL: отдельный дистрибутив

Песочница не показывает агенту `/mnt/c`, окружение WSL и сокет interop, но на уровне дистрибутива запуск программ
Windows и автомонтирование дисков по умолчанию включены, а ваш основной дистрибутив содержит ваши ключи. Надёжнее
отдельный дистрибутив только для песочницы (`wsl --install -d Ubuntu-24.04`, второй экземпляр — `wsl --import`) с `/etc/wsl.conf`:

```ini
[boot]
systemd=true          # лимиты памяти через systemd --user

[interop]
enabled=false         # из дистрибутива нельзя запускать программы Windows
appendWindowsPath=false

[automount]
enabled=false         # диски Windows не монтируются
```

Затем `wsl --terminate ИМЯ`. `sandbox check` внутри сообщает, включены ли interop и автомонтирование. Без автомонтирования
`--copy C:\...` через лаунчер не сработает (он читает путь как `/mnt/c/...`): скопируйте проект в `\\wsl$\ИМЯ\home\...`
вручную или временно включите автомонтирование на время импорта. Не проверялось на Windows.

## Вариант 2: самостоятельный Docker-режим

Установите [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/),
запустите его и выберите Linux containers. Нужен локальный Docker endpoint;
удалённые Docker hosts отклоняются. Учтите применимые условия лицензии Docker Desktop.

Установка Windows-launcher, сборка образа и контейнерная самопроверка:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Backend docker -BuildImage
```

Или без копирования launcher в LocalAppData:

```powershell
py -3 windows.py build
py -3 windows.py selftest --backend docker
py -3 windows.py new demo --backend docker --copy "C:\Code\My Project"
py -3 windows.py run claude demo --backend docker --access read
py -3 windows.py run claude demo --backend docker --access edit
```

При установленной команде заменяйте `py -3 windows.py` на `sandbox`.
Лаунчер устанавливается в `%LOCALAPPDATA%\AISandbox\app`; команда находится
в `%LOCALAPPDATA%\AISandbox\bin`. Проекты Docker после установки лежат в
`%LOCALAPPDATA%\AISandbox\app\windows-data\workspaces`.

Для установки обоих вариантов: `install.ps1 -Backend both -BuildImage`.
Параметры `--backend` в командах выше указываются явно; у `run/new` по умолчанию
выбран WSL, а в графическом окне первоначально выбран Docker.

Образ собирается из `docker/Dockerfile`. В build context допускается только явный
список исходных файлов через `.dockerignore`; проекты, HOME, токены и журналы туда
не отправляются. Сборка требует интернета и загрузки системных/npm-пакетов.
Версии клиентов можно закрепить при сборке:

```powershell
sandbox build --claude-version VERSION --codex-version VERSION
```

Замените `VERSION` на выбранные существующие версии. Значение по умолчанию —
`latest`, поэтому сборки без закрепления версий могут отличаться со временем.
Автообновление Claude отключено; обновляйте инструменты пересборкой образа.
При `run` автоматическая загрузка отсутствующего образа запрещена (`--pull never`):
сначала нужно самостоятельно собрать локальный образ командой `build`.

## Сеть, авторизация и инструменты

В Docker агент всегда запускается с `--network none`, без Docker socket, публикации
портов, привилегированного режима и host namespaces. При разрешённой сети Python-мост
в его контейнере соединяется с единственным Unix-сокетом доверенного прокси.
Общий volume сокета для агента доступен только для чтения. Прокси не получает
проект, HOME или API-ключи агента. Дополнительный seccomp-фильтр ставится entrypoint;
если он не установился, агент не запускается. Перед агентом также проверяются наличие
только интерфейса `lo` и реальный ответ прокси: одного существования сокета недостаточно.
Файлы `/etc/hosts` и `/etc/resolv.conf` созданы launcher и доступны только для чтения;
DNS-серверы, поисковые суффиксы и сетевые имена хоста в них не попадают. DNS для
разрешённых внешних доменов выполняет прокси. Его отдельная bridge-сеть создаётся
на каждый запуск; агент к ней не подключается. Оба моста ограничены 64 соединениями
и тайм-аутами. Устаревшие `--net on`/`--unsafe-host-net` запрещены также в WSL.

Разрешены только CONNECT к явным доменам профиля на порту 443; непубличные IP
отклоняются. Значение `domains = ["*"]`, сеть хоста и `allow_private_net = true`
в Docker-режиме не поддерживаются. Это не проверка TLS и не анонимизация внешнего IP.

Профили для Docker берутся из `profiles/` Windows-пакета; для WSL — из
`~/sandbox/profiles/` выбранного дистрибутива. Docker использует команду, режим сети
и домены профиля; хостовые `ro`/`rw`, `env_set` и произвольные `env_pass` не переносит.
Передаются только `ANTHROPIC_API_KEY` для Claude или `OPENAI_API_KEY` для Codex, если
переменная уже задана в окружении launcher. Значение ключа не попадает в аргументы
или журнал launcher, но доступно самому агенту и доверенному Docker daemon.
Не подключайте общий HOME хоста для переноса авторизации.

Обычная авторизация выполняется внутри песочницы. Если способ входа клиента
требует недоступного localhost callback, используйте поддерживаемый клиентом
вариант без такого callback или API-ключ. Привилегии и сеть хоста для входа
автоматически не открываются. Настройки Docker сохраняются в отдельном named volume
на проект/профиль; контейнеры одноразовые. HOME и данные WSL/Docker не объединяются.

Офлайн-оболочка с возможностью менять проект:

```powershell
sandbox shell default demo --backend docker --access edit --offline
```

Офлайн полезен для локальных инструментов; облачная LLM без интернета отвечать не сможет.
Для команд внутри вместо оболочки:

```powershell
sandbox run default demo --backend docker --access read --offline -- python3 --version
```

Установка зависимостей проекта из интернета требует осознанно добавить соответствующие
домены в профиль. В режиме `read` инструменты, пишущие cache/build/test-файлы в проект,
могут завершаться ошибкой; для таких проверок нужен `edit` либо запись в HOME/`/tmp`.

## Проверки и ограничения

После обновления исходников пересоберите Docker-образ и повторите setup-wsl для
установленной копии WSL. До приёмки на целевой Windows работоспособность Docker/WSL
не подтверждена; результаты текущего аудита — в начале SECURITY_REPORT.md.

```powershell
py -3 -m unittest discover -s tests -p "test_windows*.py" -v
py -3 windows.py check --backend docker
py -3 windows.py selftest --backend docker
py -3 windows.py selftest --backend wsl --distro Ubuntu
```

Контейнерный selftest использует отдельную временную рабочую папку и проверяет
режимы чтения/редактирования, UID, capabilities, seccomp, no_new_privs и доступность
правил только для чтения. Третий запуск проверяет мост к прокси, ответ на запрет
CONNECT к localhost, наличие только собственного `lo` и синтетические hosts/DNS.
Используются тестовый домен `.invalid` и собственный localhost, без API-ключей,
внешних запросов и обращения к службам хоста. Он не обследует процессы и интерфейсы хоста и не доказывает
отсутствие всех способов выхода из контейнера. Локальные unit-тесты проверяют планы
запуска и имитируют Docker/WSL; они не заменяют запуск на Windows.

При обычном выходе и Ctrl+C launcher удаляет только контейнеры, volume сокета и сеть своей
сессии; HOME сохраняется. При аварийном завершении самого launcher или недоступности
daemon очистка не гарантируется. Ошибка записи журнала не прерывает остальные шаги
очистки; ошибки завершения сообщаются с ненулевым кодом. Журналы прокси — `windows-data/logs/`.
Никаких `docker ps`, `prune`, поиска VPN и глобального завершения процессов нет.

При импорте пропускаются `.env*`, распространённые имена ключей, символические ссылки
и Windows reparse points/junctions. Это не универсальная проверка секретов в проекте.
Копии проекта и HOME занимают место; квот диска не предусмотрено.

## Безопасность запуска на Windows

- **Поиск программ.** Windows (cmd.exe, `CreateProcess`, `shutil.which`) ищет команды сначала в текущей папке. Проект принадлежит
  агенту, поэтому `docker.exe`, `wsl.exe` или `py.exe`, подложенные в него, выполнились бы с вашими правами при запуске
  `sandbox` из этой папки. Защита: `windows.py` ищет программы только в абсолютных каталогах `PATH` и пропускает файлы внутри
  каталога установки и `windows-data`; `start.cmd` сначала переходит в папку пакета; `sandbox.cmd` вызывает интерпретатор по
  абсолютному пути и задаёт `NoDefaultCurrentDirectoryInExePath`. Всё равно не запускайте в папках проектов агента программы
  по имени и не открывайте там терминал для работы с хостом.
- **Импорт копии.** Отклоняются домашний каталог целиком, корень диска, `AppData`, `.config`, `.ssh`, `.aws`, `.azure`, `.docker`,
  `.kube`, `.gnupg`, `.claude`, `.codex`, `Windows`, `Program Files`, `ProgramData`, каталоги самого лаунчера; пропускаются
  `.env*`, ключи, файлы с учётными данными и ссылки/junctions; в WSL-режиме то же проверяет Linux-лаунчер (`/mnt/<диск>`).
- **Проекты и журналы Docker-режима** лежат внутри каталога установки (`windows-data`): не запускайте оттуда файлы на хосте.
  Журнал прокси экранирует управляющие символы.
- **Сборка образа.** `docker/Dockerfile` берёт `node:24-bookworm-slim` и клиентов `latest`; для воспроизводимости закрепите версии
  (`sandbox build --claude-version … --codex-version …`) и при необходимости дайджест базового образа. Контрольные суммы в
  `SHA256.json` архива защищают от порчи, но не от подмены: это не подпись.
- **Приёмка на целевой машине** (на Windows эти проверки не выполнялись): `install.ps1 -Check`; `py -3 -m unittest discover -s tests -p "test_windows*.py"`;
  `windows.py selftest --backend docker|wsl`; проверка поиска программ — положите в папку проекта заглушку `docker.bat`
  или `wsl.exe`, пишущую маркер, запустите `sandbox` из этой папки: маркер появляться не должен.

Общие правила — [AGENT_POLICY.md](AGENT_POLICY.md), отчёт об исправлениях —
[SECURITY_REPORT.md](SECURITY_REPORT.md). Они загружаются агентом как инструкции;
гарантии доступа должны обеспечивать механизмы ОС. Сервисы внешних MCP/SSH могут
иметь отдельные права и автоматически этой изоляцией не ограничиваются.

Основания для реализации: [запуск Docker](https://docs.docker.com/engine/containers/run/),
[режим network none](https://docs.docker.com/engine/network/drivers/none/),
[seccomp Docker](https://docs.docker.com/engine/security/seccomp/),
[CLI WSL](https://learn.microsoft.com/en-us/windows/wsl/basic-commands),
[контейнеры Claude](https://code.claude.com/docs/en/devcontainer),
[Codex CLI](https://learn.chatgpt.com/docs/codex/cli).
