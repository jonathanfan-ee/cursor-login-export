#!/bin/sh
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
    echo "请先安装 Python 3.8 或更新版本。"
    exit 1
fi
exec python3 cursor_session_transfer.py "$@"
