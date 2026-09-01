#!/usr/bin/env sh
# One-click POSIX entry point equivalent to:
#   python3 cursor-export-credential.py --show-token

set -eu
SCRIPT_DIR=$(
    CDPATH= cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P
) || {
    printf '%s\n' '无法确定启动器所在目录。' >&2
    exit 1
}

exec "$SCRIPT_DIR/cursor-export-credential.sh" --show-token "$@"
