#!/bin/sh
# Единая точка входа Linux/WSL; использует локальное окружение проекта, если оно есть.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$ROOT"

if [ -x "$ROOT/.venv/bin/python" ]; then
    PY="$ROOT/.venv/bin/python"
elif [ -x "$ROOT/venv/bin/python" ]; then
    PY="$ROOT/venv/bin/python"
else
    PY=${PYTHON:-python3}
fi

if [ "$#" -eq 0 ]; then
    set -- tui
fi
exec "$PY" "$ROOT/sandbox.py" "$@"
