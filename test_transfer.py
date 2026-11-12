"""全部使用合成凭据和临时数据库，不接触真实 Cursor 配置。"""

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("cursor_session_transfer.py")
SPEC = importlib.util.spec_from_file_location("transfer", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


def token(subject="auth0|user_synthetic", expires=None):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return ".".join((encode({"alg": "HS256", "typ": "JWT"}),
                     encode({"sub": subject, "exp": expires or time.time() + 3600}),
                     "synthetic-signature-not-a-real-credential"))


def make_db(path, auth=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    con.execute("PRAGMA user_version = 42")
    values = {"chat/history": "聊天与插件数据必须保留", "telemetry.machineId": "target-machine"}
    if auth:
        values.update({key: value for key, value in auth.items() if value is not None})
    con.executemany("INSERT INTO ItemTable VALUES (?, ?)", values.items())
    con.commit()
    con.close()


def rows(path):
    con = sqlite3.connect(str(path))
    try:
        return dict(con.execute("SELECT key, value FROM ItemTable"))
    finally:
        con.close()


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source" / "state.vscdb"
        self.target = self.root / "target" / "state.vscdb"
        self.auth = {
            tool.AUTH_KEYS[0]: token(), tool.AUTH_KEYS[1]: "synthetic-refresh-value",
            tool.AUTH_KEYS[2]: "owner@example.invalid", tool.AUTH_KEYS[3]: "Auth_0",
        }
        make_db(self.source, self.auth)
        make_db(self.target, {tool.AUTH_KEYS[0]: "previous-access", tool.AUTH_KEYS[1]: "previous-refresh",
                              tool.CACHE_KEYS[0]: '{"email":"old@example.invalid"}'})
        self.output = self.root / "portable.json"

    def exported(self):
        tool.export_session(self.source, self.output)
        return tool.load_json(self.output, "cursor-session-transfer")

    def cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              encoding="utf-8", timeout=15)

    def test_platform_paths_and_custom_roots(self):
        cases = [
            ("darwin", {}, "Library/Application Support"),
            ("win32", {}, "AppData/Roaming"),
            ("linux", {}, ".config"),
            ("win32", {"APPDATA": str(self.root / "roaming")}, "roaming"),
            ("linux", {"XDG_CONFIG_HOME": str(self.root / "xdg")}, "xdg"),
        ]
        for system, env, relative in cases:
            with self.subTest(system=system, env=env):
                self.assertEqual(tool.default_db(system, self.root, env),
                                 self.root / relative / "Cursor/User/globalStorage/state.vscdb")

    def test_export_is_read_only_and_ignores_stale_user_id(self):
        con = sqlite3.connect(str(self.source))
        con.execute("INSERT INTO ItemTable VALUES ('cursorAuth/userId', 'different-old-id')")
        con.commit()
        con.close()
        original = rows(self.source)
        payload = self.exported()
        self.assertEqual(payload["auth"], self.auth)
        self.assertEqual(rows(self.source), original)
        self.assertNotIn("telemetry.machineId", self.output.read_text())
        self.assertNotIn("cursorAuth/userId", self.output.read_text())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_export_observes_committed_wal_snapshot(self):
        con = sqlite3.connect(str(self.source))
        self.addCleanup(con.close)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("UPDATE ItemTable SET value='committed@example.invalid' WHERE key=?", (tool.AUTH_KEYS[2],))
        con.commit()
        con.execute("UPDATE ItemTable SET value='uncommitted@example.invalid' WHERE key=?", (tool.AUTH_KEYS[2],))
        auth, _ = tool.export_session(self.source, self.output)
        self.assertEqual(auth[tool.AUTH_KEYS[2]], "committed@example.invalid")
        con.rollback()

    def test_import_preserves_other_data_and_restore_roundtrip(self):
        source_before, target_before = rows(self.source), rows(self.target)
        backup = tool.import_session(self.target, self.exported())
        after = rows(self.target)
        for key, value in self.auth.items():
            self.assertEqual(after[key], value)
        for key in tool.CACHE_KEYS:
            self.assertNotIn(key, after)
        self.assertEqual(after["chat/history"], target_before["chat/history"])
        self.assertEqual(after["telemetry.machineId"], "target-machine")
        self.assertEqual(rows(self.source), source_before)
        con = sqlite3.connect(str(self.target))
        self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], 42)
        con.close()
        second_backup = tool.restore_session(self.target, tool.load_json(backup, "cursor-session-backup"))
        self.assertTrue(second_backup.is_file())
        self.assertNotEqual(second_backup, backup)
        self.assertEqual(rows(self.target), target_before)

    def test_signed_out_target_can_be_restored(self):
        fresh = self.root / "fresh" / "state.vscdb"
        make_db(fresh)
        original = rows(fresh)
        backup = tool.import_session(fresh, self.exported())
        tool.restore_session(fresh, tool.load_json(backup, "cursor-session-backup"))
        self.assertEqual(rows(fresh), original)

    def test_write_failure_rolls_back_all_fields(self):
        original = rows(self.target)
        con = sqlite3.connect(str(self.target))
        con.execute("CREATE TRIGGER fail_refresh BEFORE INSERT ON ItemTable "
                    "WHEN NEW.key='cursorAuth/refreshToken' BEGIN SELECT RAISE(ABORT, 'test failure'); END")
        con.commit()
        con.close()
        with self.assertRaises(sqlite3.Error):
            tool.import_session(self.target, self.exported())
        self.assertEqual(rows(self.target), original)
        self.assertEqual(len(list((self.target.parent / "cursor-session-backups").glob("*.json"))), 1)

    def test_failed_backup_prevents_database_write(self):
        original = rows(self.target)
        payload = self.exported()
        with mock.patch.object(tool, "write_json", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                tool.import_session(self.target, payload)
        self.assertEqual(rows(self.target), original)

    def test_restore_rejects_backup_for_another_database(self):
        backup = tool.import_session(self.target, self.exported())
        original = rows(self.source)
        with self.assertRaises(tool.TransferError):
            tool.restore_session(self.source, tool.load_json(backup, "cursor-session-backup"))
        self.assertEqual(rows(self.source), original)

    def test_no_overwrite_of_existing_export(self):
        self.exported()
        original = self.output.read_bytes()
        with self.assertRaises(tool.TransferError):
            tool.export_session(self.source, self.output)
        self.assertEqual(self.output.read_bytes(), original)

    def test_invalid_auth_does_not_change_target(self):
        payload = self.exported()
        original = rows(self.target)
        invalid_values = [None, {}, {**self.auth, "unknown": "x"},
                          {**self.auth, tool.AUTH_KEYS[1]: None},
                          {**self.auth, tool.AUTH_KEYS[0]: "not-a-jwt"}]
        for invalid in invalid_values:
            with self.subTest(invalid_type=type(invalid).__name__):
                with self.assertRaises(tool.TransferError):
                    tool.import_session(self.target, {**payload, "auth": invalid})
                self.assertEqual(rows(self.target), original)

    def test_export_without_refresh_is_rejected(self):
        con = sqlite3.connect(str(self.source))
        con.execute("DELETE FROM ItemTable WHERE key=?", (tool.AUTH_KEYS[1],))
        con.commit()
        con.close()
        with self.assertRaises(tool.TransferError):
            tool.export_session(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_load_rejects_wrong_kind_and_bad_json_without_echoing_contents(self):
        self.exported()
        with self.assertRaises(tool.TransferError):
            tool.load_json(self.output, "cursor-session-backup")
        self.output.write_text('{"secret": "synthetic-sensitive-value"', encoding="utf-8")
        with self.assertRaises(tool.TransferError) as raised:
            tool.load_json(self.output, "cursor-session-transfer")
        self.assertNotIn("synthetic-sensitive-value", str(raised.exception))

    def test_process_detection_on_all_platforms(self):
        for system, output in (("win32", '"Cursor.exe","42","Console","1","100 K"'),
                               ("darwin", "/Applications/Cursor.app/Contents/MacOS/Cursor\n"),
                               ("linux", "/opt/cursor/cursor\n")):
            with self.subTest(system=system), mock.patch.object(tool.sys, "platform", system), \
                    mock.patch.object(tool.subprocess, "run", return_value=mock.Mock(stdout=output)):
                with self.assertRaises(tool.TransferError):
                    tool.require_closed()
        with mock.patch.object(tool.subprocess, "run", side_effect=FileNotFoundError()):
            with self.assertRaises(tool.TransferError):
                tool.require_closed()
            tool.require_closed(True)

    def test_cli_roundtrip_and_output_has_no_tokens(self):
        exported = self.cli("--db", self.source, "export", "--closed", "--output", self.output)
        self.assertEqual(exported.returncode, 0, exported.stderr)
        original = rows(self.target)
        imported = self.cli("import", self.output, "--db", self.target, "--closed", "--yes")
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertIn("owner@example.invalid", imported.stdout)
        for secret in (self.auth[tool.AUTH_KEYS[0]], self.auth[tool.AUTH_KEYS[1]], "previous-access", "previous-refresh"):
            self.assertNotIn(secret, exported.stdout + exported.stderr + imported.stdout + imported.stderr)
        backup = next((self.target.parent / "cursor-session-backups").glob("*.json"))
        restored = self.cli("restore", backup, "--db", self.target, "--closed", "--yes")
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(rows(self.target), original)

    def test_cli_confirmation_is_required_and_cancellation_is_unchanged(self):
        self.exported()
        original = rows(self.target)
        result = self.cli("import", self.output, "--db", self.target, "--closed")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(rows(self.target), original)
        with mock.patch.object(tool.sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", return_value="n"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(tool.main(["import", str(self.output), "--db", str(self.target), "--closed"]), 0)
        self.assertEqual(rows(self.target), original)

    def test_cli_missing_database_is_not_created(self):
        missing = self.root / "missing.vscdb"
        result = self.cli("info", "--db", missing)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(missing.exists())

    def test_cli_menu_and_error_do_not_leak_malformed_token(self):
        self.exported()
        with mock.patch.object(tool.sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", side_effect=["2", str(self.output), "y"]), \
                mock.patch.object(tool, "require_closed"), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(tool.main(["--db", str(self.target)]), 0)
        self.assertIn("已写入", output.getvalue())
        self.assertNotIn(self.auth[tool.AUTH_KEYS[0]], output.getvalue())
        invalid = {**self.auth, tool.AUTH_KEYS[0]: "synthetic-malformed-secret"}
        self.output.write_text(json.dumps({"kind": "cursor-session-transfer", "version": 1, "auth": invalid}))
        result = self.cli("import", self.output, "--db", self.target, "--closed", "--yes")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("synthetic-malformed-secret", result.stdout + result.stderr)

    def test_web_token_subcommand_and_legacy_flags(self):
        original = rows(self.source)
        expected = "user_synthetic::" + self.auth[tool.AUTH_KEYS[0]]
        for flags in (("web-token",), ("--snapshot", "--show-token")):
            with self.subTest(flags=flags):
                result = self.cli(*flags, "--db", self.source)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("owner@example.invalid", result.stdout)
                self.assertIn(expected, result.stdout)
                self.assertNotIn(self.auth[tool.AUTH_KEYS[1]], result.stdout + result.stderr)
                self.assertIn("Log out", result.stderr)
                self.assertEqual(rows(self.source), original)

    def test_web_token_uses_jwt_subject_despite_stale_user_id(self):
        con = sqlite3.connect(str(self.source))
        con.execute("INSERT INTO ItemTable VALUES ('cursorAuth/userId', 'user_old')")
        con.commit()
        con.close()
        result = self.cli("web-token", "--db", self.source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("user_synthetic::", result.stdout)
        self.assertNotIn("user_old::", result.stdout)

    def test_web_token_does_not_need_refresh_token(self):
        con = sqlite3.connect(str(self.source))
        con.execute("DELETE FROM ItemTable WHERE key=?", (tool.AUTH_KEYS[1],))
        con.commit()
        con.close()
        result = self.cli("web-token", "--db", self.source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WorkosCursorSessionToken", result.stdout)

    def test_web_token_menu_and_pure_token_mode(self):
        with mock.patch.object(tool.sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", return_value="5"), \
                mock.patch.object(tool, "web_token", return_value=0) as show:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(tool.main(["--db", str(self.source)]), 0)
            show.assert_called_once_with(self.source)
        result = self.cli("--snapshot", "--print-token", "--db", self.source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "user_synthetic::" + self.auth[tool.AUTH_KEYS[0]] + "\n")

    def test_no_terminal_returns_help_without_reading_database(self):
        with mock.patch.object(tool.sys.stdin, "isatty", return_value=False), \
                mock.patch("builtins.open", side_effect=OSError()), \
                mock.patch.object(tool, "connect_db") as read, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(tool.main([]), 2)
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
