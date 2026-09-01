#!/usr/bin/env python3
"""Export a *candidate* Cursor web session value from the local Cursor client.

This utility deliberately has a very small scope:

* it opens Cursor's ``state.vscdb`` in SQLite read-only mode;
* it reads ``cursorAuth/accessToken`` and, when present, cached account metadata
  plus the legacy ``cursorAuth/userId``/``cursorAuth/refreshToken`` fields;
* it derives the canonical ``userId::accessToken`` from the access JWT subject
  in memory; it only emits the complete value when the user explicitly asks for
  ``--show-token``, ``--print-token`` (or supplies an output path).

There is no HTTP client, browser automation, URL construction, clipboard access,
or upload code in this file.  The derived value is only a candidate for a
``WorkosCursorSessionToken`` cookie.  Cursor may reject it as a web session (and
the server can revoke a token before its JWT ``exp`` claim); this script does no
online validation.

The code intentionally uses only Python's standard library so it can be copied
to another machine and run with ``python3``/``py`` without installing packages.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as _datetime
import json
import os
import platform
import re
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


AUTH_KEYS: Tuple[str, ...] = (
    "cursorAuth/accessToken",
    "cursorAuth/refreshToken",
    "cursorAuth/userId",
    "cursorAuth/cachedEmail",
)
USER_ID_RE = re.compile(r"^user_[A-Za-z0-9._-]+$")
JWT_PART_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


class CredentialError(RuntimeError):
    """An expected, user-actionable credential/export error."""


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


def _sqlite_uri(path: Path) -> str:
    """Build a read-only SQLite URI that works with spaces and Windows paths."""

    # ``Path.as_uri`` handles drive letters, separators, spaces and URI control
    # characters on each supported platform.  Appending only ``mode=ro`` keeps
    # SQLite from creating or mutating the database.
    try:
        return path.absolute().as_uri() + "?mode=ro"
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


def read_auth_values(db_path: Path) -> Dict[str, Optional[str]]:
    """Read auth values through a strictly read-only SQLite connection."""

    try:
        connection = sqlite3.connect(
            _sqlite_uri(db_path), uri=True, timeout=2.0, isolation_level=None
        )
    except (sqlite3.Error, OSError) as exc:
        raise CredentialError(
            "无法以只读方式打开 state.vscdb（Cursor 可能正在写入；可先复制数据库后重试）"
        ) from exc

    try:
        try:
            connection.execute("PRAGMA query_only = ON")
            # Cursor can update access/refresh/userId independently while a
            # refresh is in progress.  A read transaction gives all three
            # values one coherent snapshot and still cannot mutate the DB.
            connection.execute("BEGIN")
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ItemTable'"
            ).fetchone()
            if table is None:
                raise CredentialError(
                    "state.vscdb 缺少 ItemTable，可能不是 Cursor 配置库或格式已变化"
                )
            values: Dict[str, Optional[str]] = {}
            for key in AUTH_KEYS:
                row = connection.execute(
                    "SELECT value FROM ItemTable WHERE key = ?1 LIMIT 1", (key,)
                ).fetchone()
                values[key] = _db_text(row[0]) if row else None
            connection.execute("ROLLBACK")
            return values
        except CredentialError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise CredentialError(
                "读取 state.vscdb 失败；请确认文件完整，必要时关闭 Cursor 后使用数据库副本"
            ) from exc
    finally:
        connection.close()


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
) -> Credential:
    values = read_auth_values(db_path)
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

    warnings: List[str] = []
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

        credential = load_credential(db_path)
        assert credential.session_token == f"{user_id}::{access}"
        assert credential.email == "demo@example.com"
        assert credential.email_source == "本地缓存"
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
            "--output PATH=保存文件。脚本离线运行，候选值不保证网页端一定接受。"
        ),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
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


if __name__ == "__main__":
    raise SystemExit(main())
