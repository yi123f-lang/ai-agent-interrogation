"""__main__.py の単体テスト（一時フォルダーに架空の JSON を書き出して検証）。"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from interrogation_room.__main__ import EXIT_FINDINGS, EXIT_INPUT_ERROR, EXIT_OK, main


class MainTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def write_bytes(self, data: bytes, name: str = "fictional.json") -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def write_text(self, text: str) -> Path:
        return self.write_bytes(text.encode("utf-8"))

    def write_config(self, allow: list[object], deny: list[object] | None = None) -> Path:
        permissions: dict[str, object] = {"allow": allow}
        if deny is not None:
            permissions["deny"] = deny
        return self.write_text(
            json.dumps({"agent_name": "fictional-agent", "permissions": permissions}, ensure_ascii=False)
        )

    def run_main(self, *argv: str | Path) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main([str(a) for a in argv])
        return code, stdout.getvalue(), stderr.getvalue()


class TestExitCodes(MainTestCase):
    def test_no_findings_returns_0(self) -> None:
        code, out, err = self.run_main(self.write_config(["Bash(git status)"]))
        self.assertEqual(code, EXIT_OK)
        self.assertIn("判定: 問題なし", out)
        self.assertEqual(err, "")

    def test_warnings_only_returns_0(self) -> None:
        code, out, _ = self.run_main(self.write_config([123]))
        self.assertEqual(code, EXIT_OK)
        self.assertIn("--- 警告", out)

    def test_active_finding_returns_1(self) -> None:
        code, out, err = self.run_main(self.write_config(["Bash(*)"]))
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("判定: 要改善", out)
        self.assertEqual(err, "")

    def test_blocked_only_still_returns_1(self) -> None:
        code, out, _ = self.run_main(self.write_config(["Bash(*)"], deny=["Bash(*)"]))
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("判定: 要整理", out)
        self.assertIn("■ 設定上のリスク: 高", out)
        self.assertIn("■ 現在の実効権限: 無効（deny により拒否）", out)

    def test_report_contents(self) -> None:
        _, out, _ = self.run_main(self.write_config(["Bash(*)"]))
        self.assertIn("簡易静的解析", out)
        self.assertIn("エージェント名: fictional-agent", out)
        self.assertIn("【集計】", out)


class TestInputErrors(MainTestCase):
    def assert_input_error(self, path: Path, message: str) -> None:
        code, out, err = self.run_main(path)
        self.assertEqual(code, EXIT_INPUT_ERROR)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("エラー: "), err)
        self.assertIn(message, err)

    def test_missing_file(self) -> None:
        self.assert_input_error(self.dir / "missing.json", "ファイルが見つかりません")

    def test_directory(self) -> None:
        self.assert_input_error(self.dir, "ファイルを読み込めません")

    def test_invalid_utf8(self) -> None:
        self.assert_input_error(self.write_bytes(b'{"permissions": {"allow": ["\xff"]}}'), "UTF-8")

    def test_json_syntax_error(self) -> None:
        self.assert_input_error(self.write_text('{"permissions": {"allow": [}'), "JSON の構文エラー")

    def test_structure_error(self) -> None:
        self.assert_input_error(self.write_text('{"permissions": {"deny": []}}'), "permissions.allow")

    def test_duplicate_top_level_key(self) -> None:
        # 前の permissions にある Bash(*) が、後の permissions で黙って隠れるケース
        text = '{"permissions": {"allow": ["Bash(*)"]}, "permissions": {"allow": []}}'
        self.assert_input_error(self.write_text(text), "キー「permissions」が重複")

    def test_duplicate_nested_key(self) -> None:
        text = '{"permissions": {"allow": ["Bash(*)"], "allow": []}}'
        self.assert_input_error(self.write_text(text), "キー「allow」が重複")

    def test_missing_argument(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                main([])
        self.assertEqual(cm.exception.code, EXIT_INPUT_ERROR)


class TestEncoding(MainTestCase):
    def test_utf8_with_bom(self) -> None:
        body = json.dumps({"permissions": {"allow": ["Bash(*)"]}}).encode("utf-8")
        code, out, err = self.run_main(self.write_bytes(b"\xef\xbb\xbf" + body))
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("R001", out)
        self.assertEqual(err, "")


class TestR003Cli(MainTestCase):
    def test_r003_blocked_by_identical_deny_keeps_high_and_returns_1(self) -> None:
        path = self.write_config(["Bash(rm /etc/*)"], deny=["Bash(rm /etc/*)"])
        code, out, err = self.run_main(path)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(err, "")
        self.assertIn("[総合危険度: 高] R003", out)
        self.assertIn("■ 設定上のリスク: 高", out)
        self.assertIn("■ 現在の実効権限: 無効（deny により拒否）", out)
        self.assertIn("総合危険度: 高 1件 / 中 0件 / 低 0件", out)
        self.assertIn("【推定】", out)
        self.assertIn("判定: 要整理", out)

    def test_r003_undetermined_by_compound_deny_keeps_high_and_returns_1(self) -> None:
        path = self.write_config(["Bash(rm /etc/*)"], deny=["Bash(sudo rm:*)"])
        code, out, err = self.run_main(path)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(err, "")
        self.assertIn("[総合危険度: 高] R003", out)
        self.assertIn("■ 設定上のリスク: 高", out)
        self.assertIn("■ 現在の実効権限: 判定不能（要確認）", out)
        self.assertIn("【判定不能】", out)
        self.assertIn("関連 deny: Bash(sudo rm:*)", out)
        self.assertIn("判定: 要確認", out)


class TestR004Cli(MainTestCase):
    def test_r004_secret_is_not_printed_and_returns_1(self) -> None:
        fake_token = "FAKE" + "0" * 12 + "TEST"
        setting = f"Bash(git push --token {fake_token} origin)"
        code, out, err = self.run_main(self.write_config([setting], deny=[setting]))
        self.assertFalse(fake_token in out)
        self.assertFalse(fake_token in err)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(err, "")
        self.assertIn("R004", out)
        self.assertIn("■ 現在の実効権限: 判定対象外", out)
        self.assertIn("判定: 要対応", out)
        self.assertIn("[REDACTED]", out)


class TestR005Cli(MainTestCase):
    def test_r005_bypass_permissions_is_reported_and_returns_1(self) -> None:
        fake_token = "FAKE" + "0" * 12 + "TEST"
        config = {
            "agent_name": "fictional-agent",
            "permissions": {
                "defaultMode": "bypassPermissions",
                "allow": [f"Bash(git push --token {fake_token} origin)"],
                "deny": [],
            },
        }
        code, out, err = self.run_main(self.write_text(json.dumps(config)))
        self.assertFalse(fake_token in out)
        self.assertFalse(fake_token in err)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(err, "")
        self.assertIn("[総合危険度: 高] R005", out)
        self.assertIn('defaultMode: "bypassPermissions"', out)
        self.assertIn("■ 現在の実効権限: 判定不能（要確認）", out)
        self.assertNotIn("判定: 問題なし", out)

    def test_r005_alone_is_reported_once_and_returns_1(self) -> None:
        config = {
            "agent_name": "fictional-agent",
            "permissions": {"defaultMode": "bypassPermissions", "allow": [], "deny": []},
        }
        code, out, err = self.run_main(self.write_text(json.dumps(config)))
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(err, "")
        self.assertIn("検出件数      : 1件", out)
        self.assertIn("--- 指摘 1/1 [総合危険度: 高] R005 ---", out)
        for rule_id in ("R001", "R002", "R003", "R004"):
            self.assertNotIn(f"] {rule_id} ---", out)
        self.assertNotIn("判定: 問題なし", out)


if __name__ == "__main__":
    unittest.main()
