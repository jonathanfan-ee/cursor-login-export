#!/usr/bin/env sh
# Portable launcher for cursor-export-credential.py.
# It resolves the Python file relative to this launcher, so the directory can
# be copied to another machine without editing an absolute path.

set -eu

SCRIPT_DIR=$(
    CDPATH= cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P
) || {
    printf '%s\n' '无法确定启动器所在目录。' >&2
    exit 1
}
SCRIPT_PATH="$SCRIPT_DIR/cursor-export-credential.py"

if [ ! -f "$SCRIPT_PATH" ]; then
    printf '找不到脚本：%s\n' "$SCRIPT_PATH" >&2
    printf '%s\n' '请把整个分发目录一起复制，不要只复制启动器。' >&2
    exit 1
fi

is_supported_python() {
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' \
        >/dev/null 2>&1
}

PYTHON_BIN=${CURSOR_PYTHON:-}
if [ -n "$PYTHON_BIN" ]; then
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        printf 'CURSOR_PYTHON 不可执行：%s\n' "$PYTHON_BIN" >&2
        exit 1
    fi
    if ! is_supported_python "$PYTHON_BIN"; then
        printf '%s\n' 'CURSOR_PYTHON 需要 Python 3.8 或更高版本。' >&2
        exit 1
    fi
else
    PYTHON_BIN=
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            is_supported_python "$candidate"; then
            PYTHON_BIN=$candidate
            break
        fi
    done
    if [ -z "$PYTHON_BIN" ]; then
        printf '%s\n' '未找到 Python 3.8+。请先安装 Python，再重新运行。' >&2
        exit 1
    fi
fi

# Do not capture or rewrite stdout/stderr: --print-token and --show-token must
# retain the Python script's deliberately explicit output behavior.
exec "$PYTHON_BIN" "$SCRIPT_PATH" "$@"
