#!/usr/bin/env sh
# Finder double-click entry point for macOS. The pause keeps the token visible
# until the user closes the Terminal window explicitly.

set -u
SCRIPT_DIR=$(
    CDPATH= cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P
) || {
    printf '%s\n' '无法确定启动器所在目录。' >&2
    exit 1
}

status=0
if "$SCRIPT_DIR/cursor-export-token.sh" "$@"; then
    status=0
else
    status=$?
fi

if [ -t 0 ]; then
    printf '\n脚本已结束（退出码 %s）。按回车关闭此窗口。' "$status"
    IFS= read -r _ || true
fi
exit "$status"
