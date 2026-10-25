#!/bin/sh
# Установщик sandbox для Linux и WSL2. POSIX sh: работает без bash (Alpine, Void, Debian dash).
# Структура: параметры -> определение среды -> проверки -> зависимости -> файлы -> команда -> проверка и самопроверка.
# Без параметров: файлы остаются на месте (или копируются в ~/sandbox), команда `sandbox` ставится в ~/.local/bin.
set -eu

SRC=$(cd "$(dirname "$0")" && pwd -P)
PREFIX=${SANDBOX_PREFIX:-$HOME/sandbox}
BIN_DIR=${SANDBOX_BIN_DIR:-$HOME/.local/bin}
PY=${PYTHON:-python3}
YES=0 DRY=0 CHECK_ONLY=0 NO_LINK=0 NO_CHECK=0 SELFTEST=default INSTALL_DEPS=0 FIX_APPARMOR=0 ADD_PATH=0
UNINSTALL=0 PURGE=0 FORCE_PROFILES=0 PROFILES="" WRAPPER=""

usage() {
  cat <<EOF
Использование: ./install.sh [параметры]

Куда ставить
  --prefix КАТАЛОГ      каталог песочницы (по умолчанию ~/sandbox; из него же — на месте)
  --bin-dir КАТАЛОГ     где создать команду sandbox (по умолчанию ~/.local/bin)
  --no-link             только файлы, без команды sandbox
  --python КОМАНДА      интерпретатор для команды sandbox (например python3.12): создаётся скрипт-обёртка
  --profiles СПИСОК     встроенные профили через запятую (по умолчанию default,codex,claude)
  --force-profiles      заменить изменённые вами профили встроенными (иначе новая версия рядом, *.new)
  --add-path            дописать ~/.profile строку PATH для --bin-dir

Что делать
  --check               только проверить окружение, ничего не менять
  --install-deps        поставить bubblewrap и python3 пакетным менеджером (sudo; спросит)
  --fix-apparmor        Ubuntu 24.04+: разрешить user namespace только для bwrap профилем AppArmor (sudo; покажет файл)
  --no-check            не запускать sandbox check после установки
  --no-selftest         не запускать самопроверку (по умолчанию — профиль default)
  --selftest-all        самопроверка всех установленных профилей
  --uninstall           удалить команду sandbox (данные остаются); с --purge — и каталог установки
  --purge               с --uninstall: удалить каталог установки вместе с рабочими папками и HOME агентов
  -y, --yes             не задавать вопросов
  --dry-run             показать действия, ничего не меняя
  -h, --help            эта справка

Повторный запуск из новой копии обновляет код, сохраняя профили, рабочие папки, HOME, журналы и состояние.
Переменные: SANDBOX_PREFIX, SANDBOX_BIN_DIR, PYTHON. Руководство: MANUAL.md.
EOF
}

say() { printf '%s\n' "$*"; }
warn() { printf 'install: %s\n' "$*" >&2; }
die() { warn "$*"; exit 1; }
step() { printf '\n== %s ==\n' "$*"; }
need_value() { [ "$1" -ge 2 ] || die "параметр $2 требует значение (см. --help)"; }

run() {
  if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi
}

# ask "вопрос" y|n — ответ по умолчанию применяется без терминала; --yes отвечает «да» на всё
ask() {
  [ "$YES" = 1 ] && return 0
  if [ ! -t 0 ]; then [ "$2" = y ]; return; fi
  printf '%s [%s] ' "$1" "$(if [ "$2" = y ]; then echo 'Д/н'; else echo 'д/Н'; fi)"
  read -r answer || answer=""
  case "$answer" in "") [ "$2" = y ] ;; [YyДд]*) return 0 ;; *) return 1 ;; esac
}

# ---------- параметры ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) need_value $# "$1"; PREFIX=$2; shift 2 ;;
    --prefix=*) PREFIX=${1#*=}; shift ;;
    --bin-dir) need_value $# "$1"; BIN_DIR=$2; shift 2 ;;
    --bin-dir=*) BIN_DIR=${1#*=}; shift ;;
    --python) need_value $# "$1"; PY=$2; WRAPPER=$2; shift 2 ;;
    --python=*) PY=${1#*=}; WRAPPER=$PY; shift ;;
    --profiles) need_value $# "$1"; PROFILES=$2; shift 2 ;;
    --profiles=*) PROFILES=${1#*=}; shift ;;
    --no-link) NO_LINK=1; shift ;;
    --force-profiles) FORCE_PROFILES=1; shift ;;
    --add-path) ADD_PATH=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --fix-apparmor) FIX_APPARMOR=1; shift ;;
    --no-check) NO_CHECK=1; shift ;;
    --no-selftest) SELFTEST=none; shift ;;
    --selftest-all) SELFTEST=all; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -y|--yes) YES=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) warn "неизвестный параметр: $1"; usage >&2; exit 2 ;;
  esac
done
case "$PREFIX" in /*) ;; *) PREFIX=$(pwd -P)/$PREFIX ;; esac
case "$BIN_DIR" in /*) ;; *) BIN_DIR=$(pwd -P)/$BIN_DIR ;; esac
[ "$PURGE" = 1 ] && [ "$UNINSTALL" = 0 ] && die "--purge работает только вместе с --uninstall"

# ---------- удаление ----------
is_ours() {   # команда sandbox создана этим установщиком: ссылка на sandbox.py либо обёртка с его путём
  [ -L "$1" ] && case "$(readlink "$1")" in */sandbox.py) return 0 ;; esac
  [ -f "$1" ] && grep -q 'sandbox\.py' "$1" 2>/dev/null
}

if [ "$UNINSTALL" = 1 ]; then
  step "Удаление"
  target=$BIN_DIR/sandbox
  if [ -e "$target" ] || [ -L "$target" ]; then
    if is_ours "$target"; then run rm -f "$target"; say "команда $target удалена"; else warn "$target создан не этим установщиком — не трогаю"; fi
  else
    say "команды $target нет"
  fi
  if [ "$PURGE" = 1 ]; then
    case "$PREFIX" in ""|/|"$HOME"|"$HOME"/|/home|/usr|/usr/*|/etc|/etc/*|/var|/bin|/lib|/opt) die "отказ: $PREFIX не похож на каталог песочницы" ;; esac
    [ -f "$PREFIX/sandbox.py" ] && [ -d "$PREFIX/profiles" ] || die "отказ: в $PREFIX нет sandbox.py и profiles/ — это не каталог песочницы"
    say "Будет удалён весь $PREFIX: рабочие папки агентов, их HOME (токены), журналы, состояние."
    if ask "Удалить $PREFIX безвозвратно?" n; then run rm -rf "$PREFIX"; say "каталог $PREFIX удалён"; else say "каталог оставлен"; fi
  else
    say "файлы и данные в $PREFIX остались (полное удаление: --uninstall --purge)"
  fi
  exit 0
fi

# ---------- определение среды ----------
os_value() { [ -r /etc/os-release ] || return 0; ( . /etc/os-release; eval "printf '%s' \"\${$1:-}\"" ); }
OS_NAME=$(os_value PRETTY_NAME); OS_ID=$(os_value ID); OS_LIKE=$(os_value ID_LIKE)
KIND=linux
OSREL=$(cat /proc/sys/kernel/osrelease 2>/dev/null | tr 'A-Z' 'a-z' || true)
case "$OSREL" in
  *microsoft-standard*|*wsl2*) KIND=wsl2 ;;
  *microsoft*|*wsl*) KIND=wsl1 ;;
  *) if [ -e /.dockerenv ] || [ -e /run/.containerenv ]; then KIND=container; fi ;;
esac
PM=""
if command -v rpm-ostree >/dev/null 2>&1 && [ -e /run/ostree-booted ]; then PM=rpm-ostree
else for cand in apt-get dnf yum zypper pacman apk xbps-install emerge; do command -v "$cand" >/dev/null 2>&1 && { PM=$cand; break; }; done; fi
SUDO=""
if [ "$(id -u)" != 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO=sudo; elif command -v doas >/dev/null 2>&1; then SUDO=doas; fi
fi

pm_install_cmd() {   # пакеты: bubblewrap и интерпретатор Python 3
  case "$PM" in
    apt-get) echo "apt-get install -y bubblewrap python3" ;;
    dnf|yum) echo "$PM install -y bubblewrap python3" ;;
    zypper) echo "zypper --non-interactive install bubblewrap python3" ;;
    pacman) echo "pacman -S --needed --noconfirm bubblewrap python" ;;
    apk) echo "apk add bubblewrap python3" ;;
    xbps-install) echo "xbps-install -Sy bubblewrap python3" ;;
    emerge) echo "emerge --ask=n sys-apps/bubblewrap dev-lang/python" ;;
    rpm-ostree) echo "rpm-ostree install bubblewrap   # затем перезагрузка" ;;
    *) echo "" ;;
  esac
}

step "Среда"
say "система:   ${OS_NAME:-неизвестна} ($(uname -m)), среда: $KIND, пакетный менеджер: ${PM:-не найден}"
say "каталог:   $PREFIX    команда: $(if [ "$NO_LINK" = 1 ]; then echo 'не создаётся'; else echo "$BIN_DIR/sandbox"; fi)"

problems=0
fail() { warn "$*"; problems=$((problems + 1)); }

[ "$(uname -s)" = Linux ] || die "нужен Linux или WSL2 (система: $(uname -s)). Windows: install.ps1, WINDOWS.md; macOS — Linux в виртуальной машине"
[ "$(id -u)" != 0 ] || fail "запуск от root: песочница не должна работать от суперпользователя — запустите от обычного пользователя"
[ "$KIND" != wsl1 ] || fail "WSL1 не поддерживает пространства имён. В PowerShell: wsl --set-version ДИСТРИБУТИВ 2"
case "$(uname -m)" in x86_64|aarch64) ;; *) fail "архитектура $(uname -m): фильтр seccomp есть только для x86_64 и aarch64" ;; esac
command -v "$PY" >/dev/null 2>&1 || fail "не найден интерпретатор $PY"
if command -v "$PY" >/dev/null 2>&1 && ! "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
  fail "нужен Python 3.8+ (у $PY: $("$PY" -V 2>&1)); поставьте новее и укажите --python python3.12"
fi
[ -x /usr/bin/python3 ] || fail "нет /usr/bin/python3: он запускается первым внутри песочницы (NixOS и Guix не поддерживаются, см. MANUAL.md)"
if ! command -v bwrap >/dev/null 2>&1; then
  hint=$(pm_install_cmd)
  if [ "$INSTALL_DEPS" = 1 ] && [ -n "$hint" ]; then
    say "Не найден bubblewrap. Команда: ${SUDO:+$SUDO }$hint"
    if [ -z "$SUDO" ]; then fail "нет sudo/doas — выполните команду от администратора"
    elif ask "Установить пакеты?" n; then
      # shellcheck disable=SC2086
      run $SUDO $(echo "$hint" | sed 's/ *#.*//') || fail "установка пакетов не удалась"
    else fail "пакеты не установлены"; fi
  else
    fail "не найден bubblewrap${hint:+. Выполните: ${SUDO:+$SUDO }$hint (или запустите с --install-deps)}"
  fi
fi

# AppArmor Ubuntu 24.04+: общий запрет user namespace; узкое исключение только для bwrap вместо отключения для всей системы
restrict=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)
if [ "$restrict" = 1 ] && command -v bwrap >/dev/null 2>&1; then
  bw=$(command -v bwrap)
  profile="abi <abi/4.0>,
include <tunables/global>

profile sandbox-bwrap $bw flags=(unconfined) {
  userns,

  include if exists <local/sandbox-bwrap>
}"
  if [ "$FIX_APPARMOR" = 1 ]; then
    if [ ! -f /etc/apparmor.d/abi/4.0 ] || ! command -v apparmor_parser >/dev/null 2>&1; then
      fail "нужен AppArmor 4 (Ubuntu 24.04+): нет /etc/apparmor.d/abi/4.0 или apparmor_parser"
    elif [ -z "$SUDO" ]; then fail "нет sudo/doas для записи профиля AppArmor"
    else
      say "Будет записан /etc/apparmor.d/sandbox-bwrap (user namespace разрешены только для $bw):"
      printf '%s\n' "$profile" | sed 's/^/    /'
      if ask "Записать и загрузить профиль?" n; then
        if [ "$DRY" = 1 ]; then say "+ запись /etc/apparmor.d/sandbox-bwrap и apparmor_parser -r"
        else
          printf '%s\n' "$profile" | $SUDO tee /etc/apparmor.d/sandbox-bwrap >/dev/null && $SUDO apparmor_parser -r /etc/apparmor.d/sandbox-bwrap \
            || fail "не удалось загрузить профиль AppArmor"
        fi
      fi
    fi
  else
    warn "AppArmor ограничивает user namespace (kernel.apparmor_restrict_unprivileged_userns=1). Если проверка ниже не пройдёт — ./install.sh --fix-apparmor"
  fi
fi

if [ "$problems" != 0 ]; then
  [ "$CHECK_ONLY" = 1 ] && { say "Проблем: $problems"; exit 1; }
  die "исправьте перечисленное и запустите установку снова (проблем: $problems)"
fi
say "обязательные требования выполнены"

if [ "$CHECK_ONLY" = 1 ]; then
  if [ -f "$SRC/sandbox.py" ]; then step "sandbox check"; "$PY" "$SRC/sandbox.py" check; else say "sandbox.py рядом с установщиком нет — проверка пропущена"; fi
  exit $?
fi

# ---------- файлы ----------
step "Файлы"
[ -f "$SRC/sandbox.py" ] || die "рядом с install.sh нет sandbox.py — запускайте установщик из распакованной папки"
if [ "$SRC" != "$PREFIX" ]; then
  run mkdir -p "$PREFIX"
  for entry in "$SRC"/* "$SRC"/.[!.]*; do
    [ -e "$entry" ] || continue
    case "${entry##*/}" in home|workspaces|windows-data|state|logs|dist|profiles|__pycache__|.git) continue ;; esac
    run cp -R "$entry" "$PREFIX/"       # код и документация обновляются; данные пользователя не затрагиваются
  done
  say "код и документация скопированы в $PREFIX"
else
  say "файлы уже в $PREFIX"
fi
run mkdir -p "$PREFIX/profiles" "$PREFIX/logs" "$PREFIX/state/run" "$PREFIX/workspaces" "$PREFIX/home"
run chmod 700 "$PREFIX/state" "$PREFIX/home" "$PREFIX/workspaces"
run chmod +x "$PREFIX/sandbox.py" "$PREFIX/install.sh"
if [ "$SRC" != "$PREFIX" ]; then
  for p in "$SRC"/profiles/*.toml; do
    [ -e "$p" ] || continue
    name=${p##*/}
    if [ -n "$PROFILES" ]; then case ",$PROFILES," in *",${name%.toml},"*) ;; *) continue ;; esac; fi
    dest=$PREFIX/profiles/$name
    if [ ! -e "$dest" ]; then run cp "$p" "$dest"
    elif cmp -s "$p" "$dest"; then :
    elif [ "$FORCE_PROFILES" = 1 ]; then run cp "$p" "$dest"; say "профиль $name заменён встроенным"
    else run cp "$p" "$dest.new"; say "профиль $name изменён вами и сохранён; новая версия: $name.new"; fi
  done
fi

# ---------- команда ----------
if [ "$NO_LINK" = 0 ]; then
  step "Команда sandbox"
  target=$BIN_DIR/sandbox
  if { [ -e "$target" ] || [ -L "$target" ]; } && ! is_ours "$target"; then
    warn "$target уже существует и создан не этим установщиком — не заменяю (удалите его или укажите --bin-dir / --no-link)"
  else
    run mkdir -p "$BIN_DIR"
    if [ -n "$WRAPPER" ]; then
      if [ "$DRY" = 1 ]; then say "+ обёртка $target: exec $WRAPPER $PREFIX/sandbox.py"
      else
        printf '#!/bin/sh\nexec "%s" "%s/sandbox.py" "$@"\n' "$(command -v "$WRAPPER")" "$PREFIX" > "$target"
        chmod +x "$target"
      fi
    else
      run ln -sf "$PREFIX/sandbox.py" "$target"
    fi
    say "создано: $target"
  fi
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) if [ "$ADD_PATH" = 1 ]; then
         line="export PATH=\"$BIN_DIR:\$PATH\"   # sandbox"
         if grep -qs "# sandbox\$" "$HOME/.profile" 2>/dev/null; then say "~/.profile уже содержит строку PATH"
         elif [ "$DRY" = 1 ]; then say "+ дописать в ~/.profile: $line"
         else printf '\n%s\n' "$line" >> "$HOME/.profile"; say "строка PATH дописана в ~/.profile (войдите заново или: . ~/.profile)"; fi
       else
         say "$BIN_DIR не в PATH. bash/zsh: добавьте в ~/.profile  export PATH=\"$BIN_DIR:\$PATH\"   (или --add-path). fish: fish_add_path $BIN_DIR"
       fi ;;
  esac
fi

# ---------- проверка ----------
if [ "$DRY" = 1 ]; then say; say "dry-run: изменений не внесено"; exit 0; fi
if [ "$NO_CHECK" = 0 ]; then
  step "sandbox check"
  "$PY" "$PREFIX/sandbox.py" check || die "проверка окружения не пройдена; подсказки выше, документация: $PREFIX/MANUAL.md (раздел «Частые проблемы»)"
fi
if [ "$SELFTEST" != none ]; then
  profiles=default
  [ "$SELFTEST" = all ] && profiles=$(cd "$PREFIX/profiles" && ls *.toml 2>/dev/null | sed 's/\.toml$//')
  for prof in $profiles; do
    step "sandbox selftest $prof"
    "$PY" "$PREFIX/sandbox.py" selftest "$prof" || die "самопроверка профиля $prof не пройдена; установка не подтверждена — см. вывод выше"
  done
fi

cat <<EOF

Готово.
  Рабочая папка:  sandbox new проект [--copy ~/код/проект]
  Запуск агента:  sandbox run codex проект     (или claude; shell — оболочка внутри)
  Проверки:       sandbox check ; sandbox selftest ; sandbox audit проект
  Интерфейс:      sandbox tui
  Руководство:    $PREFIX/MANUAL.md
  Обновление:     запустить ./install.sh из новой копии; удаление: ./install.sh --uninstall [--purge]
EOF
