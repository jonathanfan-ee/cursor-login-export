#!/usr/bin/env python3
"""Cursor 网页 Token 提取与客户端登录状态迁移；仅依赖 Python 标准库。

网页读取沿用 cursor-login-export 的 WAL/快照实现。导出源库只读；客户端导入前
自动备份目标认证字段。所有凭据只在本机处理，不发起网络请求。
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as _datetime
import errno as _errno
import json
import os
import platform
import re
import shutil
import sqlite3
import stat as _stat
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


LEGACY_AUTH_KEYS: Tuple[str, ...] = (
    "cursorAuth/accessToken",
    "cursorAuth/refreshToken",
    "cursorAuth/userId",
    "cursorAuth/cachedEmail",
    "cursorAuth/cachedSignUpType",
)
USER_ID_RE = re.compile(r"^user_[A-Za-z0-9._-]+$")
JWT_PART_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")

# Cursor keeps this database in SQLite WAL mode on many installations.  A
# read-only client may fail when required ``-wal``/``-shm`` sidecars are
# unavailable, so a short retry is useful while Cursor/its extensions are
# checkpointing the database.  An automatic ``immutable=1`` fallback would
# risk silently ignoring newer WAL
# frames.  The latter is therefore available only through the explicit
# ``--immutable`` option below.  ``--snapshot`` uses SQLite backup when a
# non-empty WAL is present, and only falls back to a warned private main-file
# copy when there are no currently readable on-disk WAL frames.
READ_ATTEMPTS = 5
READ_RETRY_DELAY_SECONDS = 0.35
SNAPSHOT_ATTEMPTS = 3
SNAPSHOT_BACKUP_PAGES = 2048
WAL_HEADER_BYTES = 32


class CredentialError(RuntimeError):
    """An expected, user-actionable credential/export error."""


class _WalSidecarUnavailable(OSError):
    """The main file declares WAL mode but a required sidecar is unavailable."""


@dataclass
class TokenInfo:
    """Parsed, non-secret JWT metadata.

    ``token`` is kept only in memory and excluded from repr so an accidental
    debug print cannot expose it.
    """

    token: str = field(repr=False)
    header: Dict[str, Any]
    claims: Dict[str, Any]
    exp: Optional[int]
    iat: Optional[int]
    nbf: Optional[int]
    token_type: Optional[str]


@dataclass
class Credential:
    user_id: str
    access_token: str = field(repr=False)
    session_token: str = field(repr=False)
    access_info: TokenInfo = field(repr=False)
    email: Optional[str] = None
    email_source: Optional[str] = field(default=None, repr=False)
    refresh_token: Optional[str] = field(default=None, repr=False)
    refresh_info: Optional[TokenInfo] = field(default=None, repr=False)
    warnings: List[str] = field(default_factory=list)


@dataclass
class AuthReadResult:
    """Values read from ``ItemTable`` plus non-secret database warnings."""

    # The mapping contains access/refresh secrets; keep it out of accidental
    # dataclass repr/debug output just like ``Credential`` does.
    values: Dict[str, Optional[str]] = field(repr=False)
    warnings: List[str] = field(default_factory=list)


def _eprint(message: str) -> None:
    """Write non-secret status to stderr, keeping stdout pipe-safe."""

    print(message, file=sys.stderr)


def _expand_path(raw: str) -> Path:
    """Expand ``~`` and environment variables without ever executing input."""

    return Path(os.path.expandvars(raw.strip())).expanduser()


def _dedupe_paths(paths: Iterable[Path]) -> List[Path]:
    out: List[Path] = []
    seen: Set[str] = set()
    for path in paths:
        # ``absolute`` does not require the path to exist and avoids resolving a
        # symlink while merely constructing the list of candidates.
        key = str(path.absolute())
        if key not in seen:
            seen.add(key)
            out.append(path)
    return out


def candidate_db_paths() -> List[Path]:
    """Return platform-specific Cursor ``state.vscdb`` locations.

    ``CURSOR_STATE_DB`` is an explicit override used for portable installs and
    tests.  When it is set, no fallback path is silently selected.
    """

    override = os.environ.get("CURSOR_STATE_DB", "").strip()
    if override:
        return [_expand_path(override)]

    home = Path.home()
    system = platform.system().lower()
    candidates: List[Path] = []

    if system == "darwin":
        candidates.append(
            home
            / "Library"
            / "Application Support"
            / "Cursor"
            / "User"
            / "globalStorage"
            / "state.vscdb"
        )
    elif system == "windows":
        appdata = os.environ.get("APPDATA", "").strip()
        local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
        bases = [_expand_path(appdata)] if appdata else []
        if local_appdata:
            bases.append(_expand_path(local_appdata))
        if not bases:
            bases.append(home / "AppData" / "Roaming")
        for base in bases:
            for app_name in ("Cursor", "Cursor - Insiders"):
                candidates.append(
                    base / app_name / "User" / "globalStorage" / "state.vscdb"
                )
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
        config_home = _expand_path(xdg) if xdg else home / ".config"
        for app_name in ("Cursor", "Cursor - Insiders"):
            candidates.append(
                config_home / app_name / "User" / "globalStorage" / "state.vscdb"
            )

    return _dedupe_paths(candidates)


def locate_db(explicit: Optional[str]) -> Path:
    """Resolve an explicitly supplied or automatically discovered database."""

    if explicit:
        path = _expand_path(explicit)
        if not path.is_file():
            raise CredentialError(
                f"指定的 state.vscdb 不存在或不是普通文件：{path}"
            )
        return path

    candidates = candidate_db_paths()
    found = [path for path in candidates if path.is_file()]
    if not found:
        checked = "\n".join(f"  - {path}" for path in candidates)
        raise CredentialError(
            "未找到 Cursor 的 state.vscdb。请先关闭/安装 Cursor，或使用 --db 指定路径。"
            + (f"\n已检查：\n{checked}" if checked else "")
        )
    if len(found) > 1:
        paths = "\n".join(f"  - {path}" for path in found)
        raise CredentialError(
            "发现多个 Cursor 配置库，为避免误导出错误账号，请使用 --db 明确指定：\n"
            + paths
        )
    return found[0]


def _sqlite_uri(path: Path, *, immutable: bool = False) -> str:
    """Build a read-only SQLite URI that works with spaces and Windows paths.

    ``immutable=1`` is intentionally opt-in.  SQLite then ignores WAL and
    locking files, which is useful only for an explicitly requested static
    main-file read and can omit frames that have not been checkpointed into the
    main database.
    """

    # ``Path.as_uri`` handles drive letters, separators, spaces and URI control
    # characters on each supported platform.  ``mode=ro`` prevents writes to
    # the main database and its business tables.  A WAL reader may still create
    # or update SQLite's ``-shm`` locking sidecar on some builds.  The immutable
    # flag is added only for the explicit advanced mode.
    try:
        query = "mode=ro"
        if immutable:
            query += "&immutable=1"
        return path.absolute().as_uri() + "?" + query
    except ValueError as exc:
        raise CredentialError("state.vscdb 路径无法转换为只读 SQLite URI") from exc


def _db_text(value: Any) -> Optional[str]:
    """Convert an ItemTable value to text without changing token semantics."""

    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CredentialError("state.vscdb 中的凭证不是 UTF-8 文本") from exc
    if not isinstance(value, str):
        value = str(value)
    text = value.strip()
    # Some third-party builds have stored a JSON string literal in ItemTable.
    # Decode only an unambiguously quoted JSON string; ordinary JWT text is left
    # untouched.  Any JSON parse failure simply means it was ordinary text.
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        try:
            decoded = json.loads(text)
        except (TypeError, ValueError):
            decoded = None
        if isinstance(decoded, str):
            text = decoded.strip()
    return text or None


def _database_uses_wal(db_path: Path) -> bool:
    """Inspect SQLite's 20-byte header without opening or changing the DB."""

    try:
        with db_path.open("rb") as stream:
            header = stream.read(20)
    except (OSError, RuntimeError):
        # Let SQLite produce the normal actionable error for an unreadable or
        # disappearing path; this helper must not turn it into a false WAL
        # diagnosis.
        return False
    if len(header) < 20 or header[:16] != b"SQLite format 3\x00":
        return False
    # Bytes 18 and 19 are the file-format read/write versions.  A value of 2
    # denotes WAL mode; either byte is enough to require the sidecars for a
    # coherent read-only view.
    return header[18] == 2 or header[19] == 2


def _sidecar_path(db_path: Path, suffix: str) -> Path:
    """Return a WAL sidecar path next to the actual DB target.

    SQLite follows a symlink supplied as the database filename and places its
    ``-wal``/``-shm`` files next to the symlink target, not next to the alias.
    Resolve an existing path before checking sidecars so an explicit
    ``--db /path/to/link.vscdb`` behaves like SQLite itself.
    """

    try:
        base = db_path.resolve(strict=True)
    except (OSError, RuntimeError):
        # Preserve a useful path for the final diagnostic when the file is
        # disappearing or cannot be resolved; SQLite will report the actual
        # open error below.
        base = db_path.absolute()
    return Path(str(base) + suffix)


def _inspect_sidecar(path: Path) -> Tuple[str, Optional[int]]:
    """Inspect a sidecar without treating permission errors as absence.

    The first ``lstat`` also makes a dangling symlink visible.  Such an alias
    is not usable for a coherent SQLite read, and is therefore reported as
    ``unavailable`` rather than silently treated as a missing file.
    """

    try:
        info = os.lstat(str(path))
    except FileNotFoundError:
        return "missing", None
    except OSError:
        return "unavailable", None

    if _stat.S_ISLNK(info.st_mode):
        try:
            info = os.stat(str(path))
        except OSError:
            return "unavailable", None
    if not _stat.S_ISREG(info.st_mode):
        return "other", int(info.st_size)
    return "file", int(info.st_size)


def _require_wal_sidecars(db_path: Path) -> None:
    """Fail closed instead of allowing SQLite to open a stale main-only WAL."""

    if not _database_uses_wal(db_path):
        return
    wal_status, wal_size = _inspect_sidecar(_sidecar_path(db_path, "-wal"))
    # A cleanly closed WAL database commonly has no WAL file at all (or an
    # empty/header-only file).  There are no frames to merge in that state, but
    # a strict read-only connection may still be unable to create its index;
    # the explicit --snapshot path handles it by copying the main file.
    if wal_status == "missing" or (
        wal_status == "file"
        and wal_size is not None
        and wal_size in (0, WAL_HEADER_BYTES)
    ):
        raise _WalSidecarUnavailable("WAL file absent or contains no frames")

    missing: List[str] = []
    if wal_status != "file":
        missing.append("-wal")
    shm_status, _ = _inspect_sidecar(_sidecar_path(db_path, "-shm"))
    if shm_status != "file":
        missing.append("-shm")
    if missing:
        names = ", ".join(missing)
        raise _WalSidecarUnavailable(f"WAL sidecar missing or unusable: {names}")


def _wal_main_file_only(db_path: Path) -> bool:
    """Return whether a WAL-marked source has no currently readable frames."""

    if not _database_uses_wal(db_path):
        return False
    status, size = _inspect_sidecar(_sidecar_path(db_path, "-wal"))
    return status == "missing" or (
        status == "file" and size is not None and size in (0, WAL_HEADER_BYTES)
    )


def _query_auth_values(connection: sqlite3.Connection) -> Dict[str, Optional[str]]:
    """Read the auth rows from an already-open, read-only connection."""

    connection.execute("PRAGMA query_only = ON")
    # Cursor can update access/refresh/userId independently while a refresh is
    # in progress.  A read transaction gives all three values one coherent
    # snapshot and still cannot mutate the DB.
    connection.execute("BEGIN")
    try:
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ItemTable'"
        ).fetchone()
        if table is None:
            raise CredentialError(
                "state.vscdb 缺少 ItemTable，可能不是 Cursor 配置库或格式已变化"
            )
        values: Dict[str, Optional[str]] = {}
        for key in LEGACY_AUTH_KEYS:
            row = connection.execute(
                "SELECT value FROM ItemTable WHERE key = ?1 LIMIT 1", (key,)
            ).fetchone()
            values[key] = _db_text(row[0]) if row else None
        return values
    finally:
        # A failed SELECT can leave the transaction open.  Rollback is best
        # effort because the connection is closed by the caller immediately
        # afterwards, and must never mask the original error.
        try:
            connection.execute("ROLLBACK")
        except (sqlite3.Error, OSError):
            pass


def _read_auth_values_once(
    db_path: Path, *, immutable: bool = False
) -> Dict[str, Optional[str]]:
    """Read auth values once through a strictly read-only SQLite connection."""

    if not immutable:
        _require_wal_sidecars(db_path)
    connection = sqlite3.connect(
        _sqlite_uri(db_path, immutable=immutable),
        uri=True,
        timeout=2.0,
        isolation_level=None,
    )
    try:
        return _query_auth_values(connection)
    finally:
        connection.close()


def _retryable_read_error(exc: BaseException) -> bool:
    """Return whether a SQLite/OS error can plausibly be a transient WAL race."""

    if isinstance(exc, OSError):
        # The database path has already been checked by ``locate_db``.  Keep
        # retrying races such as a sidecar disappearing, but do not repeat a
        # potentially multi-gigabyte snapshot after a permanent destination
        # failure (permissions, read-only disk, or insufficient space).
        permanent = {
            _errno.EACCES,
            _errno.EPERM,
            _errno.ENOSPC,
            getattr(_errno, "EDQUOT", -1),
            _errno.EROFS,
            _errno.EINVAL,
            _errno.EISDIR,
            _errno.ENAMETOOLONG,
        }
        if getattr(exc, "errno", None) in permanent:
            return False
        return True
    if not isinstance(exc, sqlite3.Error):
        return False

    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int):
        # SQLite extended result codes keep the primary code in the low byte.
        primary = code & 0xFF
        if primary in {5, 6, 7, 10, 14, 15, 17}:  # BUSY/LOCKED/.../CANTOPEN
            return True
        if primary in {11, 12, 13, 20, 26}:  # CORRUPT/NOTADB and hard errors
            return False

    message = str(exc).lower()
    if "malformed" in message or "not a database" in message:
        return False
    return isinstance(exc, sqlite3.OperationalError)


def _file_signature(path: Path) -> Tuple[int, int, int, int, int]:
    """Return a cheap identity/size/time tuple for source-change detection."""

    stat = path.stat()
    return (
        int(getattr(stat, "st_dev", 0)),
        int(getattr(stat, "st_ino", 0)),
        int(stat.st_size),
        int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000))),
        int(getattr(stat, "st_ctime_ns", int(stat.st_ctime * 1_000_000_000))),
    )


def _wal_sidecar_state(db_path: Path) -> str:
    """Describe WAL sidecars without reading their contents or secrets."""

    states: List[str] = []
    for suffix in ("-wal", "-shm"):
        sidecar = _sidecar_path(db_path, suffix)
        status, size = _inspect_sidecar(sidecar)
        if status == "file":
            states.append(f"{suffix}=存在({size} 字节)")
        elif status == "missing":
            states.append(f"{suffix}=缺失")
        elif status == "other":
            states.append(f"{suffix}=不是普通文件")
        else:
            states.append(f"{suffix}=无法检查")
    return "，".join(states)


def _wal_sidecars_complete(db_path: Path) -> bool:
    """Return whether a WAL-marked DB has both sidecars available."""

    if not _database_uses_wal(db_path):
        return False
    for suffix in ("-wal", "-shm"):
        status, _ = _inspect_sidecar(_sidecar_path(db_path, suffix))
        if status != "file":
            return False
    return True


def _guard_immutable_source(db_path: Path) -> None:
    """Refuse immutable reads when WAL sidecars could contain newer values."""

    sidecars: List[str] = []
    for suffix in ("-wal", "-shm"):
        sidecar = _sidecar_path(db_path, suffix)
        status, size = _inspect_sidecar(sidecar)
        if status == "unavailable":
            raise CredentialError(
                "无法确认 immutable 输入的 WAL sidecar 状态；为避免读取不完整凭证，已拒绝"
            )
        if status != "missing":
            sidecars.append(
                f"{suffix}（{size if size is not None else '非普通文件'}）"
            )
    if sidecars:
        joined = "、".join(sidecars)
        raise CredentialError(
            f"拒绝 immutable：检测到 WAL sidecar {joined}。请关闭 Cursor 后使用 --snapshot；"
            "不要删除这些文件。"
        )


def _read_error_message(
    db_path: Path, attempts: int, *, snapshot: bool, immutable: bool = False
) -> str:
    sidecars = _wal_sidecar_state(db_path)
    if immutable:
        return (
            "读取 state.vscdb 的 immutable 主文件失败（"
            f"已重试 {attempts} 次；SQLite WAL 状态：{sidecars}）。"
            "请确认输入是完整、静态的数据库副本；不要对正在运行的 Cursor 使用此模式。"
        )
    if snapshot:
        if _wal_main_file_only(db_path):
            return (
                "创建 state.vscdb 主文件临时快照失败（"
                f"已重试 {attempts} 次；SQLite WAL 状态：{sidecars}）。"
                "当前未发现可读取的 WAL 帧；请完全退出 Cursor/FlyCursor 和 SpecStory 后重试，"
                "并确认临时目录有足够空间。可能是正常 checkpoint，也可能是 WAL sidecar 曾被异常删除；"
                "主文件因此可能缺少最近写入。"
            )
        return (
            "创建 state.vscdb 临时快照失败（"
            f"已重试 {attempts} 次；SQLite WAL 状态：{sidecars}）。"
            "请完全退出 Cursor/FlyCursor 和 SpecStory 后重试；"
            "当前版本不会手动拼接或删除 -wal/-shm 文件。"
            "若 -wal 已从磁盘丢失，其中的提交无法由脚本恢复；"
            "请从同一时刻的完整备份恢复或重新登录；"
            "只有确认主文件是完整、静态副本时，才可显式使用 --immutable（可能读到旧值）。"
        )
    if _database_uses_wal(db_path) and _wal_main_file_only(db_path):
        return (
            "读取 state.vscdb 失败（"
            f"已重试 {attempts} 次；SQLite WAL 状态：{sidecars}）。"
            "当前未发现可读取的 WAL 帧；普通模式不会自动读取可能过期的主文件，"
            "请完全退出 Cursor/FlyCursor 和 SpecStory 后重试，或显式使用 --snapshot 制作主文件副本。"
            "该副本可能缺少最近写入，请核对账号和有效期。"
        )
    if _database_uses_wal(db_path) and not _wal_sidecars_complete(db_path):
        return (
            "读取 state.vscdb 失败（"
            f"已重试 {attempts} 次；SQLite WAL 状态：{sidecars}）。"
            "当前 WAL sidecar 不完整；为避免在源库可能被占用时重建索引，--snapshot 暂不拼接或修改 sidecar。"
            "请完全退出 Cursor/FlyCursor 和 SpecStory 后重试，并保留同目录的 -wal/-shm 文件。"
            "如果 -wal 确实已经丢失，其中的提交无法由脚本恢复；只有确认主文件完整静态时，"
            "才考虑显式 --immutable（可能读到旧值）。"
        )
    return (
        "读取 state.vscdb 失败（"
        f"已重试 {attempts} 次；SQLite WAL 状态：{sidecars}）。"
        "请完全退出 Cursor/FlyCursor 和 SpecStory 后重试；"
        "如果 sidecar 随后恢复，可显式加 --snapshot 创建临时副本；"
        "当前版本不会手动拼接或删除 sidecar；如 -wal 已丢失，其中的提交只能从完整备份恢复，"
        "或重新登录；"
        "只有确认主文件完整静态时才考虑 --immutable。"
    )


def _copy_connection_to_snapshot(
    source: sqlite3.Connection, snapshot_path: Path
) -> None:
    """Copy a stable SQLite connection into a private rollback-mode database."""

    _create_private_file(snapshot_path)

    destination = sqlite3.connect(
        str(snapshot_path), timeout=2.0, isolation_level=None
    )
    try:
        # A bounded page size lets SQLite yield while copying a large Cursor
        # database and keeps the operation interruptible.
        source.backup(
            destination,
            pages=SNAPSHOT_BACKUP_PAGES,
            sleep=0.05,
        )
        # ``backup`` copies page 1, including the source WAL header.  The
        # temporary destination is ours, so switch it to rollback mode before
        # reopening it with a strict mode=ro URI (which needs no sidecars).
        journal_mode = destination.execute("PRAGMA journal_mode = DELETE").fetchone()
        if not journal_mode or str(journal_mode[0]).lower() != "delete":
            raise sqlite3.OperationalError(
                "temporary snapshot did not switch to rollback journal mode"
            )
        destination.commit()
    finally:
        destination.close()
    try:
        os.chmod(snapshot_path, 0o600)
    except OSError:
        pass


def _create_private_file(path: Path) -> None:
    """Create an empty 0600 file before writing secret-bearing snapshot data."""

    # Create the destination with restrictive permissions before SQLite opens
    # it.  The temporary directory is private too, but avoiding even a brief
    # world-readable window matters because the backup contains all local
    # Cursor settings, including authentication material.
    fd = os.open(
        str(path),
        os.O_CREAT | os.O_EXCL | os.O_RDWR,
        0o600,
    )
    os.close(fd)


def _copy_main_file_to_snapshot(db_path: Path, snapshot_path: Path) -> None:
    """Copy a WAL main file into a private rollback-mode snapshot.

    This is used only when there is no on-disk WAL frame to merge.  It never
    edits the source; the writable SQLite connection below belongs solely to
    the temporary copy and changes its persistent journal mode to DELETE.
    """

    _create_private_file(snapshot_path)
    try:
        # ``copyfile`` follows an explicit DB symlink just as SQLite does.
        # The destination already has mode 0600, so truncation does not open a
        # world-readable window for the copied authentication material.
        shutil.copyfile(str(db_path), str(snapshot_path))
        destination = sqlite3.connect(
            str(snapshot_path), timeout=2.0, isolation_level=None
        )
        try:
            journal_mode = destination.execute(
                "PRAGMA journal_mode = DELETE"
            ).fetchone()
            if not journal_mode or str(journal_mode[0]).lower() != "delete":
                raise sqlite3.OperationalError(
                    "main-file snapshot did not switch to rollback journal mode"
                )
            destination.commit()
        finally:
            destination.close()
    finally:
        try:
            os.chmod(snapshot_path, 0o600)
        except OSError:
            pass


def _open_snapshot_source(db_path: Path) -> sqlite3.Connection:
    """Open and pin a read transaction for a temporary SQLite snapshot."""

    _require_wal_sidecars(db_path)
    connection = sqlite3.connect(
        _sqlite_uri(db_path), uri=True, timeout=2.0, isolation_level=None
    )
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        # Force the transaction to establish its snapshot before backup starts.
        connection.execute("SELECT 1 FROM sqlite_master").fetchone()
        return connection
    except BaseException:
        connection.close()
        raise


def _read_auth_values_snapshot(db_path: Path) -> AuthReadResult:
    """Read through a temporary snapshot without silently bypassing WAL.

    A source with a non-empty WAL is copied through SQLite's backup API.  A
    WAL-marked source with no currently readable frames is copied as a warned
    static main-file snapshot because no WAL content is available to merge.
    """

    last_error: Optional[BaseException] = None
    attempts_completed = 0
    for attempt in range(1, SNAPSHOT_ATTEMPTS + 1):
        attempts_completed = attempt
        source: Optional[sqlite3.Connection] = None
        try:
            before = _file_signature(db_path)

            # A cleanly closed WAL database keeps the WAL header in the main
            # file but normally unlinks both sidecars.  There is then no
            # currently readable WAL frame for SQLite's backup API to merge, and a strict mode=ro
            # connection may still fail because it cannot create the index.
            # Copy the main file into our private temp directory instead.  The
            # result is deliberately marked as potentially stale: an
            # improperly deleted WAL cannot be reconstructed from the main
            # file alone.
            if _wal_main_file_only(db_path):
                with tempfile.TemporaryDirectory(
                    prefix="cursor-export-snapshot-"
                ) as directory:
                    snapshot_path = Path(directory) / "state.vscdb"
                    _copy_main_file_to_snapshot(db_path, snapshot_path)
                    after = _file_signature(db_path)
                    if before != after or not _wal_main_file_only(db_path):
                        raise sqlite3.OperationalError(
                            "source database or WAL state changed while copying main file"
                        )
                    values = _read_auth_values_once(snapshot_path)
                return AuthReadResult(
                    values=values,
                    warnings=[
                        "未发现可合并的 WAL；已读取主库静态临时副本。"
                        "这可能是正常 checkpoint 后的状态，也可能缺少最近写入；"
                        "请核对账号和有效期。"
                    ],
                )

            source = _open_snapshot_source(db_path)
            with tempfile.TemporaryDirectory(
                prefix="cursor-export-snapshot-"
            ) as directory:
                snapshot_path = Path(directory) / "state.vscdb"
                _copy_connection_to_snapshot(source, snapshot_path)
                source.close()
                source = None

                after = _file_signature(db_path)
                if before != after:
                    raise sqlite3.OperationalError(
                        "source database changed while creating snapshot"
                    )
                values = _read_auth_values_once(snapshot_path)
            return AuthReadResult(
                values=values,
                warnings=[
                    "已使用临时 SQLite 快照读取；临时文件会在本次运行结束后删除"
                ],
            )
        except CredentialError:
            raise
        except (sqlite3.Error, OSError) as exc:
            last_error = exc
            if not _retryable_read_error(exc) or attempt >= SNAPSHOT_ATTEMPTS:
                break
            time.sleep(READ_RETRY_DELAY_SECONDS * attempt)
        finally:
            if source is not None:
                try:
                    source.close()
                except (sqlite3.Error, OSError):
                    pass

    raise CredentialError(
        _read_error_message(db_path, attempts_completed, snapshot=True)
    ) from last_error


def _read_auth_values_immutable(db_path: Path) -> AuthReadResult:
    """Read an explicitly supplied static main-file copy while warning loudly."""

    _guard_immutable_source(db_path)
    last_error: Optional[BaseException] = None
    attempts_completed = 0
    for attempt in range(1, READ_ATTEMPTS + 1):
        attempts_completed = attempt
        try:
            before = _file_signature(db_path)
            values = _read_auth_values_once(db_path, immutable=True)
            after = _file_signature(db_path)
            if before != after:
                raise sqlite3.OperationalError(
                    "source database changed while reading immutable copy"
                )
            return AuthReadResult(
                values=values,
                warnings=[
                    "已显式使用 immutable 主文件读取；SQLite 会忽略 WAL，"
                    "结果可能不含最近写入，仅适用于已完全退出 Cursor 的静态副本。"
                ],
            )
        except CredentialError:
            raise
        except (sqlite3.Error, OSError) as exc:
            last_error = exc
            if not _retryable_read_error(exc) or attempt >= READ_ATTEMPTS:
                break
            time.sleep(READ_RETRY_DELAY_SECONDS * attempt)
    raise CredentialError(
        _read_error_message(
            db_path, attempts_completed, snapshot=False, immutable=True
        )
    ) from last_error


def _read_auth_values_result(
    db_path: Path, *, snapshot: bool = False, immutable: bool = False
) -> AuthReadResult:
    """Read auth values plus warnings, retrying transient WAL races."""

    if snapshot and immutable:
        raise CredentialError("--snapshot 与 --immutable 不能同时使用")
    if snapshot:
        return _read_auth_values_snapshot(db_path)
    if immutable:
        return _read_auth_values_immutable(db_path)

    last_error: Optional[BaseException] = None
    attempts_completed = 0
    for attempt in range(1, READ_ATTEMPTS + 1):
        attempts_completed = attempt
        try:
            return AuthReadResult(values=_read_auth_values_once(db_path))
        except CredentialError:
            raise
        except (sqlite3.Error, OSError) as exc:
            last_error = exc
            if not _retryable_read_error(exc) or attempt >= READ_ATTEMPTS:
                break
            time.sleep(READ_RETRY_DELAY_SECONDS * attempt)

    raise CredentialError(
        _read_error_message(db_path, attempts_completed, snapshot=False)
    ) from last_error


def read_auth_values(
    db_path: Path, *, snapshot: bool = False, immutable: bool = False
) -> Dict[str, Optional[str]]:
    """Read auth values and preserve the original dictionary-returning API."""

    return _read_auth_values_result(
        db_path, snapshot=snapshot, immutable=immutable
    ).values


def _normalise_user_id(raw: Optional[str]) -> str:
    if not raw:
        raise CredentialError("state.vscdb 缺少 cursorAuth/userId")
    user_id = raw.strip()
    if not USER_ID_RE.fullmatch(user_id):
        raise CredentialError("cursorAuth/userId 格式异常（应为 user_ 开头的 ID）")
    return user_id


def _normalise_access_token(
    raw: Optional[str],
    user_id: Optional[str],
    field_name: str,
    *,
    enforce_prefix: bool = True,
) -> str:
    if not raw:
        raise CredentialError(f"state.vscdb 缺少 {field_name}")
    token = raw.strip()
    # Accept values copied from a browser/export tool as well as the raw value
    # Cursor normally stores in SQLite.  This replacement is local-only and is
    # limited to the first cookie delimiter; JWT characters cannot contain it.
    if token.lower().startswith("workoscursorsessiontoken="):
        token = token.split("=", 1)[1].strip()
    token = re.sub(r"%3a%3a", "::", token, count=1, flags=re.IGNORECASE)
    # A few tools export the already-combined form.  For the access token the
    # prefix is only a hint (older Cursor/third-party state can leave it stale),
    # so callers may defer identity checking until the JWT subject is decoded.
    # Refresh-token callers keep the stricter default.
    if "::" in token:
        prefix, suffix = token.split("::", 1)
        if enforce_prefix and user_id and prefix != user_id:
            raise CredentialError(f"{field_name} 中的 userId 与 cursorAuth/userId 不一致")
        token = suffix.strip()
    if not token:
        raise CredentialError(f"{field_name} 为空")
    return token


def _decode_segment(segment: str, label: str) -> Dict[str, Any]:
    if not segment or not JWT_PART_RE.fullmatch(segment):
        raise CredentialError(f"accessToken 的 JWT {label} 段格式异常")
    try:
        padded = segment + ("=" * (-len(segment) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise CredentialError(f"accessToken 的 JWT {label} 段无法解析") from exc
    if not isinstance(value, dict):
        raise CredentialError(f"accessToken 的 JWT {label} 不是 JSON 对象")
    return value


def _numeric_claim(claims: Dict[str, Any], name: str) -> Optional[int]:
    value = claims.get(name)
    if value is None or isinstance(value, bool):
        return None
    try:
        # JWT NumericDate is seconds since epoch.  Do not guess at units; an
        # implausible value is reported as unknown metadata rather than used to
        # claim that a token is valid.
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed <= 0 or parsed > 10**11:
        return None
    return parsed


def parse_jwt(token: str, *, label: str = "accessToken") -> TokenInfo:
    """Parse JWT shape/claims; this is not cryptographic signature validation."""

    parts = token.split(".")
    if len(parts) != 3:
        raise CredentialError(f"{label} 不是三段式 JWT，无法安全转换")
    if not parts[2] or not JWT_PART_RE.fullmatch(parts[2]):
        raise CredentialError(f"{label} 的 JWT 签名段格式异常")
    header = _decode_segment(parts[0], "header")
    claims = _decode_segment(parts[1], "payload")
    token_type = claims.get("type")
    if token_type is not None and not isinstance(token_type, str):
        token_type = str(token_type)
    return TokenInfo(
        token=token,
        header=header,
        claims=claims,
        exp=_numeric_claim(claims, "exp"),
        iat=_numeric_claim(claims, "iat"),
        nbf=_numeric_claim(claims, "nbf"),
        token_type=token_type,
    )


def _normalise_email(raw: Optional[str]) -> Optional[str]:
    """Return a printable cached email without allowing terminal control text."""

    value = _db_text(raw)
    if not value or len(value) > 320:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None
    return value


def _email_from_claims(info: TokenInfo) -> Optional[str]:
    """Use an email claim only as an offline fallback when one is present."""

    for name in ("email", "email_address"):
        value = info.claims.get(name)
        if isinstance(value, str) and "@" in value:
            email = _normalise_email(value)
            if email:
                return email
    return None


def _user_id_from_subject(info: TokenInfo, label: str) -> str:
    """Derive Cursor's ``user_...`` id from the token's authoritative subject."""

    sub = info.claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise CredentialError(f"{label} 的 JWT 缺少可用的 sub，无法确定账号")

    # Cursor has used issuer-qualified subjects such as ``auth0|user_xxx`` and
    # ``google-oauth2|user_xxx``.  The final user_ segment is the cookie prefix.
    candidate = sub.rsplit("|", 1)[-1].strip()
    if not USER_ID_RE.fullmatch(candidate):
        raise CredentialError(
            f"{label} 的 JWT sub 未包含可识别的 user_... 账号 ID；为避免猜错账号，拒绝导出"
        )
    return candidate


def _validate_claim_identity(info: TokenInfo, user_id: str, label: str) -> None:
    claim_user_id = _user_id_from_subject(info, label)
    if claim_user_id != user_id:
        raise CredentialError(f"{label} 的 JWT sub 与账号 ID 不一致")


def _format_expiry(timestamp: Optional[int]) -> Optional[str]:
    if timestamp is None:
        return None
    try:
        return _datetime.datetime.fromtimestamp(
            timestamp, tz=_datetime.timezone.utc
        ).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def load_credential(
    db_path: Path,
    *,
    allow_expired: bool = False,
    strict_user_id: bool = False,
    snapshot: bool = False,
    immutable: bool = False,
) -> Credential:
    read_result = _read_auth_values_result(
        db_path, snapshot=snapshot, immutable=immutable
    )
    values = read_result.values
    access_token = _normalise_access_token(
        values.get("cursorAuth/accessToken"),
        # The JWT subject is authoritative.  Do not compare a legacy/stale
        # combined-value prefix before we have decoded that subject.
        None,
        "cursorAuth/accessToken",
        enforce_prefix=False,
    )
    access_info = parse_jwt(access_token)
    user_id = _user_id_from_subject(access_info, "accessToken")

    # Cursor normally caches the email under cachedEmail after a successful
    # login.  Keep this utility offline; a JWT email claim is only a fallback.
    email = _normalise_email(values.get("cursorAuth/cachedEmail"))
    email_source: Optional[str] = "本地缓存" if email else None
    if email is None:
        email = _email_from_claims(access_info)
        if email:
            email_source = "JWT claim"

    warnings: List[str] = list(read_result.warnings)
    stored_user_raw = values.get("cursorAuth/userId")
    if stored_user_raw:
        try:
            stored_user_id = _normalise_user_id(stored_user_raw)
        except CredentialError:
            if strict_user_id:
                raise
            warnings.append(
                "state.vscdb 的 cursorAuth/userId 格式异常；已忽略并以 accessToken 的 JWT sub 为准"
            )
        else:
            if stored_user_id != user_id:
                if strict_user_id:
                    raise CredentialError(
                        "state.vscdb 的 cursorAuth/userId 与 accessToken 的 JWT sub 不一致"
                    )
                warnings.append(
                    "state.vscdb 的 cursorAuth/userId 与 accessToken 不一致；"
                    "可能是旧版本/第三方残留，已以 JWT sub 为准"
                )

    now = int(time.time())
    if access_info.exp is not None and access_info.exp <= now:
        if not allow_expired:
            expiry = _format_expiry(access_info.exp) or "未知时间"
            raise CredentialError(
                f"accessToken 的 exp 已过期（{expiry}）；如确实要导出历史值，请显式加 --allow-expired"
            )
        warnings.append("accessToken 已过期；导出的候选值预计不能登录")
    elif access_info.exp is None:
        warnings.append("accessToken 没有可解析的 exp，无法估算有效期")
    if access_info.token_type and access_info.token_type != "session":
        warnings.append(
            f"JWT type={access_info.token_type!r} 不是常见的 session；网页接受与否未验证"
        )

    refresh_token: Optional[str] = None
    refresh_info: Optional[TokenInfo] = None
    refresh_raw = values.get("cursorAuth/refreshToken")
    if refresh_raw:
        try:
            refresh_token = _normalise_access_token(
                refresh_raw, user_id, "cursorAuth/refreshToken"
            )
            refresh_info = parse_jwt(refresh_token, label="refreshToken")
            _validate_claim_identity(refresh_info, user_id, "refreshToken")
        except CredentialError as exc:
            # The refresh value is not needed for the cookie candidate.  Keep
            # the default export useful, but refuse it later if the user asks
            # for the raw refresh secret explicitly.
            warnings.append(str(exc))
            # The default cookie export does not need a refresh credential.
            # Do not retain a malformed value in memory; explicit
            # ``--include-refresh`` will therefore fail closed below.
            refresh_token = None
            refresh_info = None

    return Credential(
        user_id=user_id,
        access_token=access_token,
        session_token=f"{user_id}::{access_token}",
        access_info=access_info,
        email=email,
        email_source=email_source,
        refresh_token=refresh_token,
        refresh_info=refresh_info,
        warnings=warnings,
    )


def _mask(value: str, head: int = 6, tail: int = 4) -> str:
    if len(value) <= head + tail:
        return "*" * len(value)
    return value[:head] + "…" + value[-tail:]


def _format_local_expiry(timestamp: Optional[int]) -> Optional[str]:
    if timestamp is None:
        return None
    try:
        return _datetime.datetime.fromtimestamp(timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (OverflowError, OSError, ValueError):
        return None


def _remaining_text(timestamp: Optional[int]) -> str:
    if timestamp is None:
        return "未知"
    seconds = timestamp - int(time.time())
    if seconds <= 0:
        return "已过期"
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days} 天 {hours} 小时"
    if hours:
        return f"{hours} 小时 {minutes} 分"
    if minutes:
        return f"{max(1, minutes)} 分钟"
    return "不到 1 分钟"


def _compact_warning(warning: str) -> str:
    """Turn known diagnostic warnings into one short, human-readable line."""

    if "cursorAuth/userId" in warning:
        return "本地账号 ID 与 token 不同，已按 token 账号生成"
    if "refreshToken" in warning:
        return "refreshToken 无法使用（不影响网页候选值）"
    return warning


def _print_compact_warnings(credential: Credential) -> None:
    seen: Set[str] = set()
    for warning in credential.warnings:
        compact = _compact_warning(warning)
        if compact not in seen:
            seen.add(compact)
            _eprint(f"提示：{compact}")


def print_summary(db_path: Path, credential: Credential, *, show_meta: bool) -> None:
    """Print a compact account summary; the secret never appears by default."""

    if not show_meta:
        _eprint("✅ Cursor 登录信息")
        email_label = (
            f"邮箱（{credential.email_source}）" if credential.email_source else "邮箱"
        )
        _eprint(f"{email_label}：{credential.email or '未缓存（离线无法确定）'}")
        _eprint(f"账号：{credential.user_id}")
        expiry = _format_local_expiry(credential.access_info.exp)
        if expiry:
            _eprint(
                f"有效期至：{expiry}（本地时间；剩余 {_remaining_text(credential.access_info.exp)}）"
            )
        else:
            _eprint("有效期：未知")
        _print_compact_warnings(credential)
        _eprint("复制候选值：加 --show-token；只输出纯 token：加 --print-token")
        return

    _eprint("已只读读取 Cursor 配置库。")
    _eprint(f"数据库：{db_path}")
    email_label = (
        f"邮箱（{credential.email_source}）" if credential.email_source else "邮箱"
    )
    _eprint(f"{email_label}：{credential.email or '未找到'}")
    _eprint(f"userId：{_mask(credential.user_id, head=8, tail=3)}")
    # Even a partially masked token is a credential fragment and can end up in
    # redirected stderr/logs.  Report only its length; the full value is
    # emitted solely via an explicit --print or --output request.
    _eprint(f"候选值：已生成（{len(credential.session_token)} 字符，未显示）")
    expiry = _format_expiry(credential.access_info.exp)
    if expiry:
        remaining = credential.access_info.exp - int(time.time())  # type: ignore[operator]
        days = remaining / 86400
        state = "已过期" if remaining <= 0 else f"约剩 {days:.1f} 天"
        _eprint(f"JWT exp：{expiry}（{state}；服务端仍可能提前吊销）")
    else:
        _eprint("JWT exp：未提供/无法解析")
    _eprint(
        "refreshToken：存在（默认不导出）"
        if credential.refresh_token
        else "refreshToken：未找到"
    )
    if show_meta:
        header = credential.access_info.header
        claims = credential.access_info.claims
        _eprint(f"JWT alg：{header.get('alg', '<unknown>')!r}")
        _eprint(f"JWT type：{claims.get('type', '<unknown>')!r}")
        _eprint(f"JWT iss：{claims.get('iss', '<unknown>')!r}")
        _eprint(f"JWT aud：{claims.get('aud', '<unknown>')!r}")
        if credential.access_info.iat:
            _eprint(f"JWT iat：{_format_expiry(credential.access_info.iat)}")
        if credential.access_info.nbf:
            _eprint(f"JWT nbf：{_format_expiry(credential.access_info.nbf)}")
    for warning in credential.warnings:
        _eprint(f"警告：{warning}")
    _eprint(
        "注意：这是由 IDE session JWT 拼出的候选 WorkosCursorSessionToken，"
        "未向 cursor.com 验证，网页端不一定接受。请按密码级秘密保护。"
    )


def _json_payload(credential: Credential, *, include_refresh: bool) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "format": "cursor-session-candidate",
        "version": 1,
        # Keep the project-facing spelling so the JSON can be inspected/copied
        # into a provider config without guessing which value is the cookie.
        "WorkosCursorSessionToken": credential.session_token,
        "email": credential.email,
        "emailSource": credential.email_source,
        "userId": credential.user_id,
        "accessToken": credential.access_token,
        "expiresAt": _format_expiry(credential.access_info.exp),
    }
    if include_refresh:
        if credential.refresh_token is None:
            raise CredentialError("请求导出 refreshToken，但 state.vscdb 中没有可用值")
        if credential.refresh_info is None:
            raise CredentialError(
                "请求导出 refreshToken，但其 JWT/账号一致性校验未通过；为安全起见拒绝导出"
            )
        payload["refreshToken"] = credential.refresh_token
    return payload


def _ensure_output_parent(path: Path) -> None:
    """Create only missing parent components with private 0700 permissions."""

    parent = path.parent
    missing: List[Path] = []
    cursor = parent
    while not cursor.exists():
        missing.append(cursor)
        next_cursor = cursor.parent
        if next_cursor == cursor:
            break
        cursor = next_cursor
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass
        except FileExistsError:
            if not directory.is_dir():
                raise CredentialError("输出目录不是目录")


def _write_new_private_file(path: Path, data: bytes) -> None:
    """Create a new 0600 file without replacing an existing path."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY  # type: ignore[attr-defined]
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise CredentialError(
            f"输出文件已存在：{path}（如确认要替换，请显式加 --force）"
        ) from exc
    except OSError as exc:
        raise CredentialError("创建输出文件失败；凭证未写出") from exc
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        try:
            path.unlink()
        except OSError:
            pass
        raise CredentialError("写入输出文件失败；凭证文件已尽力清理") from exc


def _replace_private_file(path: Path, data: bytes) -> None:
    """Atomically replace an existing regular file using a 0600 temp file."""

    parent = path.parent
    fd: Optional[int] = None
    temporary: Optional[Path] = None
    try:
        fd, temporary_name = tempfile.mkstemp(
            prefix=".cursor-export-", dir=str(parent)
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
        temporary = None
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        raise CredentialError("替换输出文件失败；凭证未安全写出") from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def write_private_output(path_text: str, data: bytes, *, force: bool, db_path: Path) -> Path:
    """Write exactly one private output file and reject accidental DB overwrite."""

    path = _expand_path(path_text)
    _ensure_output_parent(path)
    if path.absolute() == db_path.absolute() or (
        path.exists()
        and db_path.exists()
        and path.resolve() == db_path.resolve()
    ):
        raise CredentialError("输出路径不能覆盖源 state.vscdb")
    if path.is_symlink():
        raise CredentialError("为避免跟随符号链接，拒绝作为输出路径")
    if path.exists() and not path.is_file():
        raise CredentialError("输出路径已存在但不是普通文件")
    if force:
        _replace_private_file(path, data)
    else:
        _write_new_private_file(path, data)
    # POSIX exposes the mode bits we requested.  If a restrictive mode could
    # not be confirmed, remove the just-written secret rather than leaving an
    # unexpectedly readable file behind.  Windows ACLs do not map cleanly to
    # POSIX mode bits, so the 0600 check is best-effort there.
    if os.name == "posix":
        try:
            mode = path.stat().st_mode & 0o777
        except OSError as exc:
            try:
                path.unlink()
            except OSError:
                pass
            raise CredentialError("无法确认输出文件权限；凭证文件已尽力清理") from exc
        if mode != 0o600:
            try:
                path.unlink()
            except OSError:
                pass
            raise CredentialError(
                f"输出文件权限不是 0600（实际 {mode:04o}）；凭证文件已尽力清理"
            )
    return path


def _serialise_output(credential: Credential, fmt: str, include_refresh: bool) -> bytes:
    if fmt == "cookie":
        if include_refresh:
            raise CredentialError("--include-refresh 只适用于 --format json")
        return (credential.session_token + "\n").encode("utf-8")
    payload = _json_payload(credential, include_refresh=include_refresh)
    return (
        json.dumps(payload, ensure_ascii=False, indent=2, separators=(",", ": "))
        + "\n"
    ).encode("utf-8")


def _write_stdout(data: bytes) -> None:
    """Write an explicitly requested value without adding status text."""

    stdout_buffer = getattr(sys.stdout, "buffer", None)
    if stdout_buffer is not None:
        stdout_buffer.write(data)
        stdout_buffer.flush()
    else:
        # Makes the CLI easy to exercise with a text-only embedded stream.
        sys.stdout.write(data.decode("utf-8"))
        sys.stdout.flush()


def _serialise_human_token(credential: Credential) -> bytes:
    """Build the explicitly requested, labelled copy block."""

    email = credential.email or "未缓存"
    email_label = (
        f"邮箱（{credential.email_source}）" if credential.email_source else "邮箱"
    )
    return (
        f"{email_label}：{email}\n"
        "WorkosCursorSessionToken（复制下一行）：\n"
        f"{credential.session_token}\n"
    ).encode("utf-8")


def _synthetic_jwt(
    user_id: str,
    exp: int,
    *,
    sub: Optional[str] = None,
    email: Optional[str] = None,
) -> str:
    def encode(value: Dict[str, Any]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    payload: Dict[str, Any] = {"sub": sub or user_id, "type": "session", "exp": exp}
    if email is not None:
        payload["email"] = email
    return f"{encode({'alg': 'none', 'typ': 'JWT'})}.{encode(payload)}.synthetic"


def self_test() -> None:
    """Exercise read-only extraction, claim checking, and 0600 output safely."""

    with tempfile.TemporaryDirectory(prefix="cursor-export-test-") as directory:
        root = Path(directory)
        db_path = root / "state.vscdb"
        user_id = "user_test"
        # Cover the issuer-qualified subject form observed in Cursor auth
        # responses (for example ``auth0|user_xxx``).
        access = _synthetic_jwt(
            user_id, int(time.time()) + 3600, sub=f"auth0|{user_id}"
        )
        refresh = _synthetic_jwt(
            user_id, int(time.time()) + 3600, sub=f"auth0|{user_id}"
        )
        connection = sqlite3.connect(str(db_path))
        try:
            connection.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
            connection.executemany(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                [
                    ("cursorAuth/accessToken", access),
                    ("cursorAuth/refreshToken", refresh),
                    ("cursorAuth/userId", user_id),
                    ("cursorAuth/cachedEmail", "demo@example.com"),
                ],
            )
            connection.commit()
        finally:
            connection.close()

        source_signature = _file_signature(db_path)
        credential = load_credential(db_path)
        assert credential.session_token == f"{user_id}::{access}"
        assert credential.email == "demo@example.com"
        assert credential.email_source == "本地缓存"
        assert _file_signature(db_path) == source_signature

        # The explicit snapshot path should preserve the same coherent values
        # while reading through a temporary rollback-mode copy.
        snapshot_source_signature = _file_signature(db_path)
        snapshot_credential = load_credential(db_path, snapshot=True)
        assert snapshot_credential.session_token == credential.session_token
        assert any("临时 SQLite 快照" in warning for warning in snapshot_credential.warnings)
        assert _file_signature(db_path) == snapshot_source_signature

        # Immutable mode is intentionally explicit and always carries a stale-
        # data warning, even for a normal rollback-mode test database.
        immutable_credential = load_credential(db_path, immutable=True)
        assert immutable_credential.session_token == credential.session_token
        assert any("immutable" in warning for warning in immutable_credential.warnings)

        # Keep a WAL connection open while taking a snapshot.  The initial
        # value is checkpointed in the main file and the replacement value is
        # left in WAL, proving that normal/snapshot reads see the newest value
        # while immutable main-file reads are intentionally stale.
        old_access = _synthetic_jwt(
            user_id, int(time.time()) + 3600, sub=f"auth0|{user_id}"
        )
        new_access = _synthetic_jwt(
            user_id, int(time.time()) + 7200, sub=f"auth0|{user_id}"
        )
        wal_db = root / "wal.vscdb"
        initial = sqlite3.connect(str(wal_db))
        try:
            initial.execute(
                "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)"
            )
            initial.executemany(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                [
                    ("cursorAuth/accessToken", old_access),
                    ("cursorAuth/userId", user_id),
                ],
            )
            initial.commit()
        finally:
            initial.close()

        wal_connection = sqlite3.connect(str(wal_db))
        wal_reader: Optional[sqlite3.Connection] = None
        try:
            journal_mode = wal_connection.execute(
                "PRAGMA journal_mode = WAL"
            ).fetchone()[0]
            assert str(journal_mode).lower() == "wal"
            # Pin an older reader before the replacement write.  This makes
            # the test independent of whether a particular SQLite build
            # checkpoints and removes the WAL immediately when the writer
            # closes later.
            wal_reader = sqlite3.connect(str(wal_db), isolation_level=None)
            wal_reader.execute("BEGIN")
            assert wal_reader.execute(
                "SELECT value FROM ItemTable WHERE key = ?", ("cursorAuth/accessToken",)
            ).fetchone()[0] == old_access
            wal_connection.execute(
                "UPDATE ItemTable SET value = ? WHERE key = ?",
                (new_access, "cursorAuth/accessToken"),
            )
            wal_connection.commit()
            live_credential = load_credential(wal_db)
            assert live_credential.access_token == new_access
            wal_credential = load_credential(wal_db, snapshot=True)
            assert wal_credential.access_token == new_access

            # SQLite follows a symlinked database filename but keeps WAL
            # sidecars beside the target.  The preflight must resolve that
            # target rather than looking beside the alias.
            if os.name != "nt":
                wal_link = root / "wal-link.vscdb"
                try:
                    wal_link.symlink_to(wal_db)
                except OSError:
                    pass
                else:
                    linked = load_credential(wal_link)
                    assert linked.access_token == new_access

            try:
                load_credential(wal_db, immutable=True)
            except CredentialError as exc:
                assert "WAL sidecar" in str(exc)
            else:
                raise AssertionError("immutable mode did not reject a live WAL source")

            # Copy only the main file to model a stale/incomplete handoff.
            main_only_db = root / "wal-main-only.vscdb"
            shutil.copyfile(wal_db, main_only_db)
        finally:
            wal_connection.close()
            if wal_reader is not None:
                wal_reader.close()

        try:
            load_credential(main_only_db)
        except CredentialError as exc:
            assert "--snapshot" in str(exc)
        else:
            raise AssertionError("main-only WAL file unexpectedly read without sidecars")
        assert not Path(str(main_only_db) + "-wal").exists()
        assert not Path(str(main_only_db) + "-shm").exists()
        main_only_source_signature = _file_signature(main_only_db)
        main_only_snapshot = load_credential(main_only_db, snapshot=True)
        assert main_only_snapshot.access_token == old_access
        assert any(
            "主库静态临时副本" in warning
            for warning in main_only_snapshot.warnings
        )
        assert _file_signature(main_only_db) == main_only_source_signature
        assert not Path(str(main_only_db) + "-wal").exists()
        assert not Path(str(main_only_db) + "-shm").exists()

        # A zero-length/header-only WAL has no frames to merge and follows the
        # same explicit snapshot fallback.  Keep the sidecar beside the test
        # copy so the source database itself remains untouched.
        header_only_db = root / "wal-header-only.vscdb"
        shutil.copyfile(main_only_db, header_only_db)
        Path(str(header_only_db) + "-wal").write_bytes(b"\x00" * WAL_HEADER_BYTES)
        header_source_signature = _file_signature(header_only_db)
        header_snapshot = load_credential(header_only_db, snapshot=True)
        assert header_snapshot.access_token == old_access
        assert any(
            "主库静态临时副本" in warning
            for warning in header_snapshot.warnings
        )
        assert _file_signature(header_only_db) == header_source_signature
        assert Path(str(header_only_db) + "-wal").stat().st_size == WAL_HEADER_BYTES
        assert not Path(str(header_only_db) + "-shm").exists()

        # A non-empty WAL without its shared-memory index must remain fail
        # closed: the missing frames may contain a newer credential value.
        incomplete_wal_db = root / "wal-incomplete.vscdb"
        shutil.copyfile(main_only_db, incomplete_wal_db)
        Path(str(incomplete_wal_db) + "-wal").write_bytes(
            b"\x00" * (WAL_HEADER_BYTES + 1)
        )
        try:
            load_credential(incomplete_wal_db, snapshot=True)
        except CredentialError as exc:
            assert "-shm" in str(exc)
        else:
            raise AssertionError("snapshot unexpectedly bypassed an incomplete WAL")
        stale = load_credential(main_only_db, immutable=True)
        assert stale.access_token == old_access
        assert any("immutable" in warning for warning in stale.warnings)

        cookie_path = root / "candidate.txt"
        write_private_output(
            str(cookie_path),
            _serialise_output(credential, "cookie", False),
            force=False,
            db_path=db_path,
        )
        assert cookie_path.read_text(encoding="utf-8").strip() == credential.session_token
        assert (cookie_path.stat().st_mode & 0o777) == 0o600

        json_path = root / "candidate.json"
        write_private_output(
            str(json_path),
            _serialise_output(credential, "json", True),
            force=False,
            db_path=db_path,
        )
        parsed = json.loads(json_path.read_text(encoding="utf-8"))
        assert parsed["WorkosCursorSessionToken"] == credential.session_token
        assert parsed["email"] == "demo@example.com"
        assert parsed["emailSource"] == "本地缓存"
        assert parsed["refreshToken"] == refresh
        assert (json_path.stat().st_mode & 0o777) == 0o600

        # A stale/legacy standalone userId must not override the JWT subject.
        # The candidate should use the token's account and retain a warning.
        bad_db = root / "stale-user-id.vscdb"
        connection = sqlite3.connect(str(bad_db))
        try:
            connection.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
            connection.executemany(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                [
                    (
                        "cursorAuth/accessToken",
                        _synthetic_jwt(
                            "user_other", int(time.time()) + 3600, sub="auth0|user_other"
                        ),
                    ),
                    ("cursorAuth/userId", user_id),
                ],
            )
            connection.commit()
        finally:
            connection.close()
        stale = load_credential(bad_db)
        assert stale.user_id == "user_other"
        assert stale.session_token.startswith("user_other::")
        assert stale.warnings
        try:
            load_credential(bad_db, strict_user_id=True)
        except CredentialError:
            pass
        else:
            raise AssertionError("strict userId mismatch was not rejected")

        # Newer builds may not retain a standalone userId key at all.
        no_user_id_db = root / "no-user-id.vscdb"
        connection = sqlite3.connect(str(no_user_id_db))
        try:
            connection.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
            connection.execute(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                (
                    "cursorAuth/accessToken",
                    _synthetic_jwt(user_id, int(time.time()) + 3600),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        no_email = load_credential(no_user_id_db)
        assert no_email.user_id == user_id
        assert no_email.email is None
        assert no_email.email_source is None

        # If the local email cache is absent, an email claim is a harmless
        # offline fallback; no network request is made.
        claim_email_db = root / "claim-email.vscdb"
        connection = sqlite3.connect(str(claim_email_db))
        try:
            connection.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
            connection.execute(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                (
                    "cursorAuth/accessToken",
                    _synthetic_jwt(
                        user_id,
                        int(time.time()) + 3600,
                        email="claim@example.com",
                    ),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        claim_email = load_credential(claim_email_db)
        assert claim_email.email == "claim@example.com"
        assert claim_email.email_source == "JWT claim"

        missing_sub_db = root / "missing-sub.vscdb"
        connection = sqlite3.connect(str(missing_sub_db))
        try:
            connection.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
            connection.execute(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                (
                    "cursorAuth/accessToken",
                    _synthetic_jwt(user_id, int(time.time()) + 3600, sub="opaque-sub"),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        try:
            load_credential(missing_sub_db)
        except CredentialError:
            pass
        else:
            raise AssertionError("opaque sub was not rejected")
    _eprint("self-test passed（未访问网络，未接触真实凭证）")


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="读取 Cursor 登录信息，并生成网页端可尝试使用的候选 token。",
        epilog=(
            "常用：无参数=简洁信息；--show-token=邮箱+候选值；--print-token=纯一行候选值；"
            "--output PATH=保存文件；WAL 异常时可用 --snapshot。脚本离线运行，"
            "候选值不保证网页端一定接受。"
        ),
    )


def web_export_main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    parser.add_argument(
        "--db",
        metavar="PATH",
        help="state.vscdb 路径；省略时按当前平台自动查找（CURSOR_STATE_DB 可覆盖）",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="写入目标文件（新文件 0600；已存在文件需 --force）",
    )
    parser.add_argument(
        "--format",
        choices=("cookie", "json"),
        default="cookie",
        help="输出格式：cookie=纯 userId::JWT（默认），json=结构化导出",
    )
    parser.add_argument(
        "--include-refresh",
        action="store_true",
        help="仅 JSON 模式显式包含 refreshToken（默认绝不导出）",
    )
    parser.add_argument(
        "--print",
        "--print-token",
        "--token-only",
        dest="print_secret",
        action="store_true",
        help="显式把 cookie 候选 token 原样输出为 stdout 的一行（--print 兼容别名）",
    )
    parser.add_argument(
        "--show-token",
        action="store_true",
        help="显式在终端输出邮箱和带标签的候选 token（会显示完整凭证）",
    )
    parser.add_argument(
        "--show-meta",
        action="store_true",
        help="在 stderr 显示更多 JWT 元数据（仍不显示完整凭证）",
    )
    parser.add_argument(
        "--dry-run",
        "--info",
        dest="dry_run",
        action="store_true",
        help="只读取并显示简洁账号信息，不写文件也不打印 token",
    )
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help=(
            "先创建临时副本再读取；有非空 WAL 时用只读 SQLite backup，"
            "无 WAL 帧时复制主库并给出可能过期的警告，临时文件自动删除"
        ),
    )
    parser.add_argument(
        "--immutable",
        "--allow-stale",
        dest="immutable",
        action="store_true",
        help=(
            "显式按 immutable 主文件读取（可能缺少 WAL 中的最新写入）；"
            "必须配合 --db，仅适用于已完全退出 Cursor 且没有 WAL sidecar 的静态副本"
        ),
    )
    parser.add_argument(
        "--allow-expired",
        action="store_true",
        help="允许导出 exp 已过期的值（仅用于取证/诊断，通常不应使用）",
    )
    parser.add_argument(
        "--strict-user-id",
        action="store_true",
        help="严格要求旧版 cursorAuth/userId 与 JWT sub 一致（默认以 JWT sub 为准）",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="原子替换已存在的普通输出文件；不会跟随符号链接",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="使用合成 SQLite/JWT 做本地自测，不读取真实 Cursor 数据库",
    )
    args = parser.parse_args(argv)

    # These storage modes are mutually exclusive even in self-test mode.  Do
    # the validation before the early self-test return so an accidental
    # ``--self-test --immutable`` cannot mask the explicit-path safeguard.
    if args.snapshot and args.immutable:
        parser.error("--snapshot 与 --immutable 不能同时使用")
    if args.immutable and not args.db:
        parser.error("--immutable 必须显式指定 --db，避免误读自动发现的活动数据库")

    if args.self_test:
        try:
            self_test()
            return 0
        except (AssertionError, CredentialError, OSError, sqlite3.Error) as exc:
            _eprint(f"self-test failed：{type(exc).__name__}")
            return 1

    if args.include_refresh and args.format != "json":
        parser.error("--include-refresh 必须与 --format json 一起使用")
    if args.dry_run and args.output:
        parser.error("--dry-run 不应同时指定 --output（不会写入该文件）")
    if args.dry_run and args.print_secret:
        parser.error("--dry-run 不应同时指定 --print-token")
    if args.dry_run and args.show_token:
        parser.error("--dry-run 不应同时指定 --show-token")
    if args.print_secret and args.show_token:
        parser.error("--print-token 与 --show-token 二选一")
    if args.print_secret and args.format != "cookie":
        parser.error("--print-token 只适用于默认 cookie 格式；JSON 请使用 --output")
    if args.output and (args.print_secret or args.show_token):
        parser.error("--output 不能与 --print-token/--show-token 同时使用")
    if args.show_token and args.format != "cookie":
        parser.error("--show-token 只适用于默认 cookie 格式")
    if args.show_meta and (args.print_secret or args.show_token):
        parser.error("--show-meta 不能与 --print-token/--show-token 同时使用")
    if args.force and not args.output:
        parser.error("--force 需要 --output")
    if args.format == "json" and not args.output and not args.print_secret:
        parser.error("JSON 模式需要 --output PATH，或显式使用 --print-token")

    try:
        db_path = locate_db(args.db)
        credential = load_credential(
            db_path,
            allow_expired=args.allow_expired,
            strict_user_id=args.strict_user_id,
            snapshot=args.snapshot,
            immutable=args.immutable,
        )

        # Keep stdout machine-friendly: --print-token emits exactly one raw
        # candidate line, while --show-token is the labelled human copy block.
        if args.print_secret:
            _print_compact_warnings(credential)
            _write_stdout(
                _serialise_output(
                    credential, args.format, include_refresh=args.include_refresh
                )
            )
            return 0
        if args.show_token:
            _print_compact_warnings(credential)
            _write_stdout(_serialise_human_token(credential))
            return 0

        output = _serialise_output(
            credential, args.format, include_refresh=args.include_refresh
        )
        if args.output:
            path = write_private_output(
                args.output, output, force=args.force, db_path=db_path
            )
            _print_compact_warnings(credential)
            _eprint(f"✅ 已导出：{path}")
            _eprint(f"邮箱：{credential.email or '未缓存'}")
            return 0

        # No arguments is an intentionally useful info mode.
        print_summary(db_path, credential, show_meta=args.show_meta)
        if args.dry_run:
            _eprint("（仅检查，未写文件）")
        return 0
    except CredentialError as exc:
        _eprint(f"错误：{exc}")
        return 1
    except (OSError, sqlite3.Error) as exc:
        # Do not print raw exception strings: SQLite/OS messages can vary by
        # platform and should never become a channel for credential material.
        _eprint(f"错误：{type(exc).__name__}（凭证未输出）")
        return 1



# 以下为跨设备迁移和统一菜单；AUTH_KEYS 与网页读取模块的常量独立。

import argparse
import base64
import csv
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import uuid


AUTH_KEYS = (
    "cursorAuth/accessToken",
    "cursorAuth/refreshToken",
    "cursorAuth/cachedEmail",
    "cursorAuth/cachedSignUpType",
)
# 缓存应由目标客户端重新获取，避免沿用目标设备上一个账号的资料。
CACHE_KEYS = (
    "cursorAuth/cachedScopedProfile",
    "cursorAuth/cachedTeam",
    "cursorAuth/stripeMembershipType",
    "cursorAuth/stripeMembershipAuthId",
)
MANAGED_KEYS = AUTH_KEYS + CACHE_KEYS
NOTICE = "两台设备将共用会话；任一端退出或撤销会话，都可能让另一端失效。"


class TransferError(Exception):
    pass


def default_db(system=None, home=None, env=None):
    system = system or sys.platform
    home = Path.home() if home is None else Path(home)
    env = os.environ if env is None else env
    if system == "darwin":
        root = home / "Library" / "Application Support"
    elif system == "win32":
        root = Path(env.get("APPDATA") or home / "AppData" / "Roaming")
    elif system.startswith("linux"):
        root = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    else:
        raise TransferError("无法自动识别系统，请用 --db 指定 state.vscdb。")
    return root / "Cursor" / "User" / "globalStorage" / "state.vscdb"


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def unique_name(prefix):
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return "{}-{}-{}.json".format(prefix, stamp, uuid.uuid4().hex[:8])


def connect_db(path, *, writable=False):
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise TransferError("找不到 Cursor 数据库：{}\n请先启动一次 Cursor 再关闭；自定义安装可用 --db 指定路径。".format(path))
    # mode=rw 防止路径错误时悄悄新建一个空库；只读模式仍正确读取 WAL。
    mode = "rw" if writable else "ro"
    con = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True, timeout=5)
    return con


def read_keys(con, keys):
    placeholders = ",".join("?" for _ in keys)
    rows = dict(con.execute(
        "SELECT key, value FROM ItemTable WHERE key IN ({})".format(placeholders), keys
    ))
    return {key: rows.get(key) for key in keys}


def validate_values(values, keys):
    if not isinstance(values, dict) or set(values) != set(keys):
        raise TransferError("凭据文件字段不完整或格式不兼容。")
    for value in values.values():
        if value is not None and (not isinstance(value, str) or len(value) > 262144):
            raise TransferError("凭据文件中存在不支持的字段值。")


def access_claims(token):
    try:
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise ValueError()
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        if not isinstance(claims, dict) or not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise ValueError()
        return claims
    except (ValueError, TypeError, UnicodeError, AttributeError):
        raise TransferError("accessToken 不是可识别的 JWT；没有写入任何凭据。") from None


def validate_auth(auth):
    validate_values(auth, AUTH_KEYS)
    for key in AUTH_KEYS[:2]:
        value = auth[key]
        if not value or any(c.isspace() or ord(c) < 32 for c in value):
            raise TransferError("缺少可用的 accessToken 或 refreshToken；请确认源客户端仍有登录状态。")
    # 这里只检查格式，不验证签名、服务端有效性或设备绑定。
    access_claims(auth[AUTH_KEYS[0]])


def terminal_text(value):
    return "".join(c for c in str(value or "") if c.isprintable())[:200]


def show_account(auth):
    claims = access_claims(auth[AUTH_KEYS[0]])
    email = auth[AUTH_KEYS[2]] or claims.get("email") or "未缓存"
    print("邮箱：" + terminal_text(email))
    print("账号：" + terminal_text(claims["sub"]))
    try:
        expiry = dt.datetime.fromtimestamp(float(claims["exp"]), dt.timezone.utc).astimezone()
        suffix = "（已过期；能否续期取决于刷新凭据）" if expiry.timestamp() <= dt.datetime.now().timestamp() else ""
        print("访问凭据到期：" + expiry.strftime("%Y-%m-%d %H:%M:%S %Z") + suffix)
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        print("访问凭据到期：无法解析")


def write_json(path, payload):
    # 明确生成明文迁移文件；不覆盖已有文件，也不通过网络传递。
    path = Path(path).expanduser().resolve()
    data = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise TransferError("文件已存在，请换一个文件名：{}".format(path)) from None
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def load_json(path, kind):
    with Path(path).expanduser().open("rb") as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise TransferError("文件超过 1 MiB，不是正常的凭据文件。")
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError):
        raise TransferError("无法读取 JSON 文件，请选择本工具生成的文件。") from None
    if not isinstance(payload, dict) or payload.get("kind") != kind or payload.get("version") != 1:
        raise TransferError("文件类型或版本不兼容，请选择正确的导出/备份文件。")
    return payload


def export_session(db, output):
    result = _read_auth_values_result(Path(db).expanduser().resolve(), snapshot=True)
    auth = {key: result.values.get(key) for key in AUTH_KEYS}
    validate_auth(auth)
    for warning in result.warnings:
        _eprint("提示：" + warning)
    output = write_json(output, {
        "kind": "cursor-session-transfer", "version": 1,
        "exported_at": utc_now(), "source_platform": sys.platform, "auth": auth,
    })
    return auth, output


def apply_values(db, values):
    validate_values(values, MANAGED_KEYS)
    db = Path(db).expanduser().resolve()
    backup_dir = db.parent / "cursor-session-backups"
    backup_dir.mkdir(mode=0o700, exist_ok=True)
    con = connect_db(db, writable=True)
    backup = None
    try:
        con.execute("BEGIN IMMEDIATE")
        original = read_keys(con, MANAGED_KEYS)
        backup = write_json(backup_dir / unique_name("before-import"), {
            "kind": "cursor-session-backup", "version": 1,
            "saved_at": utc_now(), "database": str(db), "values": original,
        })
        for key, value in values.items():
            if value is None:
                con.execute("DELETE FROM ItemTable WHERE key = ?", (key,))
            else:
                con.execute("INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)", (key, value))
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()
    return backup


def import_session(db, payload):
    auth = payload.get("auth")
    validate_auth(auth)
    values = dict(auth)
    values.update({key: None for key in CACHE_KEYS})
    return apply_values(db, values)


def restore_session(db, payload):
    db = Path(db).expanduser().resolve()
    if payload.get("database") != str(db):
        raise TransferError("该备份不属于这台设备的目标数据库。")
    return apply_values(db, payload.get("values"))


def require_closed(assumed_closed=False):
    if assumed_closed:
        return
    try:
        command = ["tasklist", "/FO", "CSV", "/NH"] if sys.platform == "win32" else ["ps", "-axo", "comm="]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                encoding="utf-8", errors="replace", timeout=10, check=True)
        if sys.platform == "win32":
            running = any(row and row[0].lower() == "cursor.exe" for row in csv.reader(result.stdout.splitlines()))
        else:
            running = any(Path(line.strip()).name.lower() in ("cursor", "cursor-bin")
                          or "/cursor.app/contents/" in line.lower()
                          for line in result.stdout.splitlines())
    except (OSError, subprocess.SubprocessError):
        raise TransferError("无法检查 Cursor 进程。请手动完全关闭 Cursor，再加 --closed 重试。") from None
    if running:
        raise TransferError("Cursor 还在运行。请完全退出程序（不要点 Sign Out），再从系统终端运行此工具。")


def ask_path(prompt, default=None):
    value = input(prompt + (" [{}]".format(default) if default else "") + "：").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not value and default is None:
        raise TransferError("没有选择文件。")
    return Path(value or default).expanduser()


def make_parser():
    parser = argparse.ArgumentParser(
        description="Cursor 网页 Token 提取与跨设备登录状态复制；无参数显示中文菜单。",
        epilog="兼容旧用法：--snapshot --show-token；--self-test 仅使用合成数据检查网页读取模块。",
    )
    parser.add_argument("--db", help="自定义 state.vscdb 路径")
    parser.add_argument("--closed", action="store_true", help="已手动完全关闭 Cursor，跳过进程检查")
    commands = parser.add_subparsers(dest="command")
    for name, help_text in (("export", "旧设备导出客户端凭据"), ("import", "新设备导入客户端凭据"),
                            ("restore", "恢复本机导入前备份"), ("info", "查看本地账号信息"),
                            ("web-token", "显示邮箱和网页 WorkosCursorSessionToken")):
        child = commands.add_parser(name, help=help_text)
        child.add_argument("--db", default=argparse.SUPPRESS, help="自定义 state.vscdb 路径")
        child.add_argument("--closed", action="store_true", default=argparse.SUPPRESS,
                           help="已手动完全关闭 Cursor，跳过进程检查")
        if name == "export":
            child.add_argument("--output", help="导出文件路径；默认放在用户主目录")
        elif name not in ("info", "web-token"):
            child.add_argument("file", help="导出文件或本机备份文件")
            child.add_argument("--yes", action="store_true", help="确认替换本机登录状态")
    return parser


def web_token(db):
    _eprint("提醒：网页端不要点 Log out，否则共用会话的客户端也可能失效。")
    return web_export_main(["--db", str(db), "--snapshot", "--show-token"])


def main(argv=None):
    raw_args = list(sys.argv[1:] if argv is None else argv)
    commands = {"export", "import", "restore", "info", "web-token"}
    legacy_flags = {"--snapshot", "--show-token", "--print-token", "--print", "--token-only",
                    "--self-test", "--show-meta", "--dry-run", "--info", "--immutable",
                    "--allow-stale", "--format", "--output", "-o", "--allow-expired"}
    if not commands.intersection(raw_args) and legacy_flags.intersection(raw_args):
        if {"--show-token", "--print-token", "--print", "--token-only"}.intersection(raw_args):
            _eprint("提醒：网页端不要点 Log out，否则共用会话的客户端也可能失效。")
        return web_export_main(raw_args)
    parser = make_parser()
    args = parser.parse_args(raw_args)
    try:
        db = Path(args.db).expanduser() if args.db else default_db()
        if args.command is None:
            if not sys.stdin.isatty():
                # curl | python - 已占用 stdin；重新连接本机终端才能读取菜单选择。
                try:
                    console = open("CONIN$" if sys.platform == "win32" else "/dev/tty", "r")
                except OSError:
                    parser.print_help()
                    return 2
                with console:
                    if not console.isatty():
                        parser.print_help()
                        return 2
                    original_stdin = sys.stdin
                    try:
                        sys.stdin = console
                        return main(raw_args)
                    finally:
                        sys.stdin = original_stdin
            print("Cursor 账号工具\n1. 旧设备：导出客户端凭据\n2. 新设备：导入客户端凭据"
                  "\n3. 恢复本机备份\n4. 查看本地账号\n5. 提取网页 Token\n0. 退出")
            choice = input("请选择：").strip()
            if choice == "0":
                return 0
            args.command = {"1": "export", "2": "import", "3": "restore", "4": "info", "5": "web-token"}.get(choice)
            if not args.command:
                raise TransferError("请输入 0 至 5。")
            args.yes = False
            if args.command == "export":
                args.output = ask_path("保存到", Path.home() / unique_name("cursor-session"))
            elif args.command not in ("info", "web-token"):
                args.file = ask_path("请粘贴文件完整路径")

        if args.command == "web-token":
            # 网页提取沿用旧工具的自动发现与快照读取，不要求 refreshToken 存在。
            return web_token(locate_db(args.db))

        if args.command == "info":
            con = connect_db(db)
            try:
                auth = read_keys(con, AUTH_KEYS)
            finally:
                con.close()
            validate_auth(auth)
            show_account(auth)
            print("仅查看本地记录，未联网核验。")
            return 0

        require_closed(args.closed)
        print(NOTICE)
        if args.command == "export":
            output = args.output or Path.home() / unique_name("cursor-session")
            auth, output = export_session(db, output)
            show_account(auth)
            print("已导出：{}\n将此文件带到新设备，选择“导入”。旧设备凭据没有修改。".format(output))
            print("文件含明文登录凭据；只交给账号本人，勿上传到公开仓库。")
        else:
            kind = "cursor-session-transfer" if args.command == "import" else "cursor-session-backup"
            payload = load_json(args.file, kind)
            if args.command == "import":
                validate_auth(payload.get("auth"))
                show_account(payload["auth"])
            else:
                validate_values(payload.get("values"), MANAGED_KEYS)
            if not args.yes:
                if not sys.stdin.isatty():
                    raise TransferError("写入前需要确认；无人值守运行请加 --yes。")
                if input("确认替换本机登录状态？输入 y 继续：").strip().lower() != "y":
                    print("已取消，没有修改数据库。")
                    return 0
            backup = import_session(db, payload) if args.command == "import" else restore_session(db, payload)
            print("已写入。原状态备份：{}".format(backup))
            print("请重新启动 Cursor 并发送一次请求；首次请求成功仍不代表之后一定能续期。")
        return 0
    except (TransferError, CredentialError) as exc:
        print("错误：" + str(exc), file=sys.stderr)
    except (OSError, sqlite3.Error) as exc:
        # SQL/文件异常可能夹带敏感字段，不回显原始异常正文。
        print("操作失败（{}）：请检查文件路径、权限及 Cursor 是否已完全关闭；数据库未提交的变更会回滚。".format(type(exc).__name__), file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print("\n已取消。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
