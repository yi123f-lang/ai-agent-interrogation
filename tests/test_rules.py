"""R001 / R002 と allow・deny 評価の単体テスト（架空の JSON のみを使用）。"""

import json
import unittest

from interrogation_room.models import AnalysisResult, ConfigError, EffectiveStatus, Severity
from interrogation_room.rules import analyze_config, parse_entry


def analyze_json(text: str) -> AnalysisResult:
    return analyze_config(json.loads(text))


def analyze_permissions(allow: list[object], deny: list[object] | None = None) -> AnalysisResult:
    permissions: dict[str, object] = {"allow": allow}
    if deny is not None:
        permissions["deny"] = deny
    return analyze_json(json.dumps({"agent_name": "fictional-agent", "permissions": permissions}))


class TestParseEntry(unittest.TestCase):
    def test_with_pattern(self) -> None:
        parsed = parse_entry("Bash(git status)")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tool, "Bash")
        self.assertEqual(parsed.pattern, "git status")

    def test_without_parentheses(self) -> None:
        parsed = parse_entry("Bash")
        self.assertIsNotNone(parsed)
        self.assertIsNone(parsed.pattern)

    def test_normalizes_whitespace(self) -> None:
        self.assertEqual(parse_entry("  Bash( * )  ").key, "Bash(*)")

    def test_unparsable_returns_none(self) -> None:
        self.assertIsNone(parse_entry("*"))


class TestR001(unittest.TestCase):
    def test_detects_bash_wildcard(self) -> None:
        result = analyze_permissions(["Bash(git status)", "Bash(*)"])
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "R001")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.entry, "Bash(*)")
        self.assertEqual(finding.locations, ("permissions.allow[1]",))
        self.assertEqual(finding.effective_status, EffectiveStatus.ACTIVE)

    def test_detects_wildcard_variants(self) -> None:
        for entry in ["Bash(**)", "Bash(:*)", "Bash(*:*)", "Bash( * )"]:
            with self.subTest(entry=entry):
                result = analyze_permissions([entry])
                self.assertEqual([f.rule_id for f in result.findings], ["R001"])

    def test_messages_are_japanese(self) -> None:
        finding = analyze_permissions(["Bash(*)"]).findings[0]
        self.assertIn("任意のシェルコマンド", finding.evidence)
        self.assertIn("個別に許可", finding.recommendation)
        self.assertIn("そのまま有効", finding.effective_note)


class TestR002(unittest.TestCase):
    def test_detects_bash_without_pattern(self) -> None:
        result = analyze_permissions(["Bash"])
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "R002")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn("引数パターンが指定されていない", finding.evidence)
        self.assertIn("Bash(コマンド)", finding.recommendation)

    def test_detects_empty_pattern(self) -> None:
        result = analyze_permissions(["Bash()"])
        self.assertEqual([f.rule_id for f in result.findings], ["R002"])
        self.assertIn("引数パターンが空", result.findings[0].evidence)


class TestR003(unittest.TestCase):
    """R003 は RULES に登録する前なので、ルール関数を直接呼んで確認する。"""

    def test_scoped_rm_is_detected_with_lowered_setting_risk(self) -> None:
        from interrogation_room.rules import _rule_r003

        hit = _rule_r003(parse_entry("Bash(rm /tmp/*)"))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.rule_id, "R003")
        self.assertEqual(hit.command, "rm")
        self.assertEqual(hit.setting_risk, Severity.MEDIUM)

    def test_path_traversal_is_not_treated_as_scoped(self) -> None:
        from interrogation_room.rules import _rule_r003

        hit = _rule_r003(parse_entry("Bash(rm /tmp/../etc/*)"))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.rule_id, "R003")
        self.assertEqual(hit.setting_risk, Severity.HIGH)

    def test_broad_rm_keeps_high_setting_risk(self) -> None:
        from interrogation_room.rules import _rule_r003

        hit = _rule_r003(parse_entry("Bash(rm:*)"))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.rule_id, "R003")
        self.assertEqual(hit.command, "rm")
        self.assertEqual(hit.setting_risk, Severity.HIGH)

    def test_identical_deny_is_blocked_as_estimate_without_lowering_risk(self) -> None:
        from interrogation_room.rules import (
            _collect_entries,
            _describe_command_effect,
            _evaluate_command_deny,
            _rule_r003,
        )

        hit = _rule_r003(parse_entry("Bash(rm /etc/*)"))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.setting_risk, Severity.HIGH)

        deny = _collect_entries(["Bash(rm /etc/*)"], "permissions.deny", [])
        status, related_deny = _evaluate_command_deny("Bash(rm /etc/*)", deny)
        self.assertEqual(status, EffectiveStatus.BLOCKED)
        self.assertEqual(related_deny, ("Bash(rm /etc/*)",))

        note, _ = _describe_command_effect(status, related_deny, hit.command)
        self.assertIn("【推定】", note)
        self.assertIn("保証できない", note)
        self.assertIn("総合危険度は下げていません", note)

    def test_compound_deny_is_undetermined(self) -> None:
        from interrogation_room.rules import (
            _collect_entries,
            _describe_command_effect,
            _evaluate_command_deny,
            _rule_r003,
        )

        hit = _rule_r003(parse_entry("Bash(rm /etc/*)"))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.setting_risk, Severity.HIGH)

        deny = _collect_entries(["Bash(sudo rm:*)"], "permissions.deny", [])
        status, related_deny = _evaluate_command_deny("Bash(rm /etc/*)", deny)
        self.assertEqual(status, EffectiveStatus.UNDETERMINED)
        self.assertEqual(related_deny, ("Bash(sudo rm:*)",))

        note, _ = _describe_command_effect(status, related_deny, hit.command)
        self.assertIn("【判定不能】", note)
        self.assertIn("deny で制限されていることを意味しません", note)

    def test_unrelated_deny_keeps_curl_active(self) -> None:
        from interrogation_room.rules import (
            _collect_entries,
            _describe_command_effect,
            _evaluate_command_deny,
            _rule_r003,
        )

        hit = _rule_r003(parse_entry("Bash(curl:*)"))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.rule_id, "R003")
        self.assertEqual(hit.command, "curl")
        self.assertEqual(hit.setting_risk, Severity.MEDIUM)
        self.assertIn("実際の攻撃や不正を示すものではありません", hit.evidence)

        deny = _collect_entries(["Read(*)"], "permissions.deny", [])
        status, related_deny = _evaluate_command_deny("Bash(curl:*)", deny)
        self.assertEqual(status, EffectiveStatus.ACTIVE)
        self.assertEqual(related_deny, ())

        note, _ = _describe_command_effect(status, related_deny, hit.command)
        self.assertIn("【推定】", note)


class TestR003Integration(unittest.TestCase):
    """RULES に登録した R003 を analyze_config 経由で確認する。"""

    def test_broad_rm_without_deny_is_active_and_high(self) -> None:
        result = analyze_permissions(["Bash(rm:*)"], deny=[])
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "R003")
        self.assertEqual(finding.entry, "Bash(rm:*)")
        self.assertEqual(finding.setting_risk, Severity.HIGH)
        self.assertEqual(finding.effective_status, EffectiveStatus.ACTIVE)
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_identical_deny_is_blocked_but_severity_stays_high(self) -> None:
        result = analyze_permissions(["Bash(rm /etc/*)"], deny=["Bash(rm /etc/*)"])
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "R003")
        self.assertEqual(finding.entry, "Bash(rm /etc/*)")
        self.assertEqual(finding.setting_risk, Severity.HIGH)
        self.assertEqual(finding.effective_status, EffectiveStatus.BLOCKED)
        self.assertEqual(finding.severity, Severity.HIGH)


class TestNoFinding(unittest.TestCase):
    def test_limited_permissions_are_not_flagged(self) -> None:
        result = analyze_permissions(
            ["Bash(git status)", "Bash(npm test)", "Bash(git:*)", "Read(*)", "Write(*)"]
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.warnings, ())

    def test_empty_allow(self) -> None:
        result = analyze_permissions([])
        self.assertEqual(result.findings, ())
        self.assertEqual(result.warnings, ())


class TestDeduplication(unittest.TestCase):
    def test_same_setting_is_reported_once(self) -> None:
        result = analyze_permissions(["Bash(*)", "Bash(git status)", "Bash(*)", " Bash( * ) "])
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(
            finding.locations,
            ("permissions.allow[0]", "permissions.allow[2]", "permissions.allow[3]"),
        )
        self.assertIn("3 箇所", finding.evidence)

    def test_one_rule_per_setting(self) -> None:
        result = analyze_permissions(["Bash(*)", "Bash"])
        self.assertEqual(
            [(f.entry, f.rule_id) for f in result.findings],
            [("Bash(*)", "R001"), ("Bash", "R002")],
        )


class TestDenyEvaluation(unittest.TestCase):
    def test_missing_deny_is_active(self) -> None:
        finding = analyze_permissions(["Bash(*)"]).findings[0]
        self.assertEqual(finding.effective_status, EffectiveStatus.ACTIVE)
        self.assertEqual(finding.related_deny, ())

    def test_unrelated_deny_is_active(self) -> None:
        finding = analyze_permissions(["Bash(*)"], deny=["Read(*)"]).findings[0]
        self.assertEqual(finding.effective_status, EffectiveStatus.ACTIVE)
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_partial_deny_keeps_high_severity(self) -> None:
        finding = analyze_permissions(["Bash(*)"], deny=["Bash(rm:*)"]).findings[0]
        self.assertEqual(finding.effective_status, EffectiveStatus.PARTIALLY_RESTRICTED)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.related_deny, ("Bash(rm:*)",))
        self.assertIn("依然として広範", finding.effective_note)

    def test_full_deny_blocks(self) -> None:
        for deny_entry in ["Bash(*)", "Bash", "*"]:
            with self.subTest(deny=deny_entry):
                finding = analyze_permissions(["Bash(*)"], deny=[deny_entry]).findings[0]
                self.assertEqual(finding.effective_status, EffectiveStatus.BLOCKED)
                self.assertEqual(finding.severity, Severity.LOW)
                self.assertEqual(finding.related_deny, (deny_entry,))

    def test_full_deny_takes_precedence_over_partial(self) -> None:
        finding = analyze_permissions(["Bash"], deny=["Bash(rm:*)", "Bash(*)"]).findings[0]
        self.assertEqual(finding.effective_status, EffectiveStatus.BLOCKED)
        self.assertEqual(finding.related_deny, ("Bash(*)",))

    def test_blocked_setting_is_still_reported_as_allow_setting(self) -> None:
        finding = analyze_permissions(["Bash(*)"], deny=["Bash(*)"]).findings[0]
        self.assertEqual(finding.entry, "Bash(*)")
        self.assertEqual(finding.locations, ("permissions.allow[0]",))
        self.assertIn("実効権限はありません", finding.effective_note)
        self.assertIn("矛盾", finding.recommendation)

    def test_setting_risk_is_independent_of_deny(self) -> None:
        cases = [
            ([], EffectiveStatus.ACTIVE, Severity.HIGH),
            (["Bash(rm:*)"], EffectiveStatus.PARTIALLY_RESTRICTED, Severity.HIGH),
            (["Bash(*)"], EffectiveStatus.BLOCKED, Severity.LOW),
        ]
        for deny, status, severity in cases:
            with self.subTest(deny=deny):
                for allow in ["Bash(*)", "Bash"]:
                    finding = analyze_permissions([allow], deny=deny).findings[0]
                    self.assertEqual(finding.setting_risk, Severity.HIGH)
                    self.assertEqual(finding.effective_status, status)
                    self.assertEqual(finding.severity, severity)

    def test_deny_only_is_not_a_finding(self) -> None:
        result = analyze_permissions([], deny=["Bash(*)"])
        self.assertEqual(result.findings, ())

    def test_empty_pattern_in_deny_is_not_trusted(self) -> None:
        result = analyze_permissions(["Bash(*)"], deny=["Bash()"])
        self.assertEqual(result.findings[0].effective_status, EffectiveStatus.ACTIVE)
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("permissions.deny[0]", result.warnings[0])


class TestInvalidInput(unittest.TestCase):
    def test_structural_errors(self) -> None:
        cases = {
            "トップレベルが配列": ("[]", "トップレベル"),
            "permissions なし": ('{"agent_name": "fictional-agent"}', "permissions"),
            "permissions が配列": ('{"permissions": []}', "permissions"),
            "allow なし": ('{"permissions": {"deny": []}}', r"permissions\.allow"),
            "allow が文字列": ('{"permissions": {"allow": "Bash(*)"}}', r"permissions\.allow"),
            "deny が文字列": ('{"permissions": {"allow": [], "deny": "Bash"}}', r"permissions\.deny"),
            "deny が null": ('{"permissions": {"allow": [], "deny": null}}', r"permissions\.deny"),
        }
        for name, (text, message) in cases.items():
            with self.subTest(name):
                with self.assertRaisesRegex(ConfigError, message):
                    analyze_json(text)

    def test_non_string_allow_entries_are_skipped_with_warning(self) -> None:
        result = analyze_permissions([123, None, {"tool": "Bash"}, "Bash(*)"])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].locations, ("permissions.allow[3]",))
        self.assertEqual(len(result.warnings), 3)
        self.assertIn("文字列ではない", result.warnings[0])

    def test_empty_string_entry_is_skipped_with_warning(self) -> None:
        result = analyze_permissions(["   "])
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("空文字列", result.warnings[0])

    def test_non_string_deny_entry_does_not_block(self) -> None:
        result = analyze_permissions(["Bash(*)"], deny=[True])
        self.assertEqual(result.findings[0].effective_status, EffectiveStatus.ACTIVE)
        self.assertIn("permissions.deny[0]", result.warnings[0])


class TestFindSecrets(unittest.TestCase):
    """値はすべて架空のダミー。実在の認証情報ではない。"""

    def test_bearer_token_position_is_found_without_returning_value(self) -> None:
        from interrogation_room.rules import _find_secrets

        fake_token = "FAKE" + "0" * 12 + "TEST"
        text = f'curl -H "Authorization: Bearer {fake_token}" https://example.invalid/*'
        spans = _find_secrets(text)
        expected_start = text.index(fake_token)
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].kind, "認証ヘッダーの値")
        self.assertEqual((spans[0].start, spans[0].end), (expected_start, expected_start + len(fake_token)))
        self.assertFalse(fake_token in spans[0].kind)


class TestMaskSecrets(unittest.TestCase):
    """値はすべて架空のダミー。失敗時に値が表示されないよう assertTrue/assertFalse で比べる。"""

    def test_multiple_secrets_are_masked_and_placeholder_is_kept(self) -> None:
        from interrogation_room.rules import _mask_secrets

        fake_token = "FAKE" + "0" * 12 + "TEST"
        fake_password = "FAKEPASS" + "1" * 8
        fake_url_password = "FAKEURL" + "2" * 8
        text = (
            f'curl -H "Authorization: Bearer {fake_token}" '
            f"--password {fake_password} --token $GH_TOKEN "
            f"https://demo:{fake_url_password}@example.invalid/*"
        )
        masked = _mask_secrets(text)
        self.assertFalse(fake_token in masked)
        self.assertFalse(fake_password in masked)
        self.assertFalse(fake_url_password in masked)
        self.assertEqual(masked.count("[REDACTED]"), 3)
        self.assertTrue("--token $GH_TOKEN" in masked)
        self.assertTrue(
            masked
            == 'curl -H "Authorization: Bearer [REDACTED]" '
            "--password [REDACTED] --token $GH_TOKEN "
            "https://demo:[REDACTED]@example.invalid/*"
        )

    def test_text_without_real_secrets_is_unchanged(self) -> None:
        from interrogation_room.rules import _mask_secrets

        cases = [
            "Bash(git status)",
            "Bash(gh api --token $GH_TOKEN)",
            "Bash(curl -H 'Authorization: Bearer ${API_TOKEN}')",
            "token=<your-token>",
        ]
        for index, text in enumerate(cases):
            with self.subTest(index=index):
                self.assertTrue(_mask_secrets(text) == text)


class TestSecretMasking(unittest.TestCase):
    """analyze_config の出力に秘密値が残らないことを確かめる。値はすべて架空のダミー。"""

    @staticmethod
    def _texts(finding) -> list[str]:
        from dataclasses import fields

        texts: list[str] = []
        for field in fields(finding):
            value = getattr(finding, field.name)
            if isinstance(value, str):
                texts.append(value)
            elif isinstance(value, tuple):
                texts.extend(item for item in value if isinstance(item, str))
        return texts

    @staticmethod
    def _rule_findings(result) -> list:
        """R004 を除き、R001〜R003 の指摘だけを返す。"""
        return [f for f in result.findings if f.rule_id in ("R001", "R002", "R003")]

    def test_allow_secret_is_masked_in_entry_and_evidence(self) -> None:
        fake_token = "FAKE" + "0" * 12 + "TEST"
        result = analyze_permissions([f'Bash(curl -H "Authorization: Bearer {fake_token}":*)'])
        findings = self._rule_findings(result)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "R003")
        self.assertEqual(finding.setting_risk, Severity.MEDIUM)
        self.assertEqual(finding.effective_status, EffectiveStatus.ACTIVE)
        self.assertFalse(any(fake_token in text for f in result.findings for text in self._texts(f)))
        self.assertTrue(finding.entry == 'Bash(curl -H "Authorization: Bearer [REDACTED]":*)')
        self.assertTrue("[REDACTED]" in finding.evidence)

    def test_deny_secret_is_masked_in_related_deny_and_effective_note(self) -> None:
        fake_token = "FAKE" + "0" * 12 + "TEST"
        # 比較用の $TOKEN も架空の値も、deny の判定に影響しない文字だけで構成する。
        deny_template = "Bash(curl --token {} https://example.invalid/)"
        cases = [
            ("Bash(*)", "R001", Severity.HIGH, Severity.HIGH, EffectiveStatus.PARTIALLY_RESTRICTED),
            ("Bash(curl:*)", "R003", Severity.MEDIUM, Severity.MEDIUM, EffectiveStatus.UNDETERMINED),
        ]

        def judged(finding):
            return (finding.rule_id, finding.setting_risk, finding.severity, finding.effective_status)

        for index, (allow, rule_id, setting_risk, severity, status) in enumerate(cases):
            with self.subTest(index=index):
                result = analyze_permissions([allow], deny=[deny_template.format(fake_token)])
                control = analyze_permissions([allow], deny=[deny_template.format("$TOKEN")])
                findings = self._rule_findings(result)
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(judged(finding), (rule_id, setting_risk, severity, status))
                self.assertEqual([judged(f) for f in findings], [judged(f) for f in self._rule_findings(control)])
                self.assertFalse(any(fake_token in text for f in result.findings for text in self._texts(f)))
                self.assertEqual(finding.related_deny, ("Bash(curl --token [REDACTED] https://example.invalid/)",))
                self.assertTrue("[REDACTED]" in finding.effective_note)

    def test_warnings_are_masked_before_output(self) -> None:
        from unittest import mock

        from interrogation_room import rules

        fake_token = "FAKE" + "0" * 12 + "TEST"
        original = rules._evaluate_bash_deny

        def evaluate_with_fake_warning(deny, warnings):
            # 今の実装では警告に秘密値が入る経路がないため、架空の警告を1件足して再現する。
            warnings.append(f"架空の警告: token={fake_token}")
            return original(deny, warnings)

        def judged(finding):
            return (finding.rule_id, finding.setting_risk, finding.severity, finding.effective_status)

        with mock.patch.object(
            rules, "_evaluate_bash_deny", side_effect=evaluate_with_fake_warning
        ) as patched:
            result = analyze_permissions(["Bash(*)"])
        control = analyze_permissions(["Bash(*)"])
        self.assertEqual(patched.call_count, 1)
        self.assertEqual([judged(f) for f in result.findings], [judged(f) for f in control.findings])
        self.assertEqual(len(result.warnings), 1)
        self.assertFalse(any(fake_token in warning for warning in result.warnings))
        self.assertEqual(result.warnings, ("架空の警告: token=[REDACTED]",))

    def test_placeholders_are_kept_and_real_values_are_masked(self) -> None:
        placeholders = ("$TOKEN", "YOUR_API_KEY", "<YOUR_TOKEN>")
        # プレースホルダーは _PLACEHOLDER_RE（$、your_、< で始まる値）で除外される位置に置く。
        template = (
            'Bash(curl -H "Authorization: Bearer $TOKEN" --api-key YOUR_API_KEY '
            "-d token=<YOUR_TOKEN> --password {} https://example.invalid/*)"
        )

        placeholder_only = template.format("$PASSWORD")
        result = analyze_permissions([placeholder_only])
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "R003")
        self.assertEqual(finding.entry, placeholder_only)
        self.assertNotIn("[REDACTED]", finding.entry)
        self.assertNotIn("[REDACTED]", finding.evidence)

        fake_password = "FAKEPASS" + "1" * 12
        result = analyze_permissions([template.format(fake_password)])
        findings = self._rule_findings(result)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertFalse(any(fake_password in text for f in result.findings for text in self._texts(f)))
        self.assertEqual(finding.entry, template.format("[REDACTED]"))
        self.assertIn("[REDACTED]", finding.evidence)
        for placeholder in placeholders:
            self.assertIn(placeholder, finding.entry)

    def test_judgment_is_unchanged_by_masking(self) -> None:
        fake_token = "FAKE" + "0" * 12 + "TEST"
        other_fake_token = "FAKE" + "9" * 12 + "TEST"
        header_allow = 'Bash(curl -H "Authorization: Bearer {}":*)'
        token_deny = "Bash(curl --token {} https://example.invalid/)"
        cases = [
            (header_allow, None, ("R003", Severity.MEDIUM, Severity.MEDIUM, EffectiveStatus.ACTIVE)),
            (header_allow, header_allow, ("R003", Severity.MEDIUM, Severity.MEDIUM, EffectiveStatus.BLOCKED)),
            ("Bash", token_deny, ("R002", Severity.HIGH, Severity.HIGH, EffectiveStatus.PARTIALLY_RESTRICTED)),
        ]

        def judged(result):
            return [(f.rule_id, f.setting_risk, f.severity, f.effective_status) for f in self._rule_findings(result)]

        def analyze(allow, deny, value):
            return analyze_permissions([allow.format(value)], deny=None if deny is None else [deny.format(value)])

        for index, (allow, deny, expected) in enumerate(cases):
            with self.subTest(index=index):
                result = analyze(allow, deny, fake_token)
                control = analyze(allow, deny, "$TOKEN")
                self.assertFalse(any(fake_token in text for f in result.findings for text in self._texts(f)))
                self.assertEqual(judged(result), [expected])
                self.assertEqual(judged(control), [expected])

        # 表示上は同じ [REDACTED] になる別々の値を、同じ設定として扱わないこと（判定は元の値で行う）。
        result = analyze_permissions([header_allow.format(fake_token)], deny=[header_allow.format(other_fake_token)])
        texts = [text for f in result.findings for text in self._texts(f)]
        self.assertFalse(any(token in text for token in (fake_token, other_fake_token) for text in texts))
        self.assertEqual(judged(result), [("R003", Severity.MEDIUM, Severity.MEDIUM, EffectiveStatus.UNDETERMINED)])
        finding = self._rule_findings(result)[0]
        self.assertEqual(finding.related_deny, (finding.entry,))


class TestR004Integration(unittest.TestCase):
    """R004（平文の認証情報）を analyze_config 経由で確かめる。値はすべて架空のダミー。"""

    FAKE_TOKEN = "FAKE" + "0" * 12 + "TEST"

    @staticmethod
    def _r004(result) -> list:
        return [f for f in result.findings if f.rule_id == "R004"]

    @staticmethod
    def _texts(result) -> list[str]:
        from dataclasses import fields

        texts = list(result.warnings)
        for finding in result.findings:
            for field in fields(finding):
                value = getattr(finding, field.name)
                if isinstance(value, str):
                    texts.append(value)
                elif isinstance(value, tuple):
                    texts.extend(item for item in value if isinstance(item, str))
        return texts

    def _assert_no_secret(self, result) -> None:
        self.assertFalse(any(self.FAKE_TOKEN in text for text in self._texts(result)))

    def test_allow_secret_is_reported_as_r004(self) -> None:
        # 番号0は通常の表記、番号1は括弧の内側に空白がある表記（表示用には正規化される）。
        cases = [
            f"Bash(git push --token {self.FAKE_TOKEN} origin)",
            f"Bash( git push --token {self.FAKE_TOKEN} origin )",
        ]
        for index, setting in enumerate(cases):
            with self.subTest(index=index):
                result = analyze_permissions([setting])
                self._assert_no_secret(result)
                self.assertEqual([f.rule_id for f in result.findings], ["R004"])
                finding = result.findings[0]
                self.assertEqual(finding.severity, Severity.HIGH)
                self.assertEqual(finding.setting_risk, Severity.HIGH)
                self.assertEqual(finding.effective_status, EffectiveStatus.NOT_APPLICABLE)
                self.assertEqual(finding.locations, ("permissions.allow[0]",))
                self.assertEqual(finding.related_deny, ())
                self.assertEqual(finding.entry, "Bash(git push --token [REDACTED] origin)")
                self.assertIn("オプションの値", finding.evidence)
                self.assertIn("判定対象外", finding.effective_note)

    def test_deny_secret_is_reported_as_r004(self) -> None:
        result = analyze_permissions([], deny=[f"Bash(git push --token {self.FAKE_TOKEN} origin)"])
        self._assert_no_secret(result)
        findings = self._r004(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].locations, ("permissions.deny[0]",))
        self.assertEqual(findings[0].effective_status, EffectiveStatus.NOT_APPLICABLE)

    def test_r003_and_r004_are_reported_separately(self) -> None:
        result = analyze_permissions([f"Bash(curl --token {self.FAKE_TOKEN} https://example.invalid/*)"])
        self._assert_no_secret(result)
        self.assertEqual(sorted(f.rule_id for f in result.findings), ["R003", "R004"])
        r003 = next(f for f in result.findings if f.rule_id == "R003")
        self.assertEqual(
            (r003.setting_risk, r003.severity, r003.effective_status),
            (Severity.MEDIUM, Severity.MEDIUM, EffectiveStatus.ACTIVE),
        )
        self.assertEqual(self._r004(result)[0].effective_status, EffectiveStatus.NOT_APPLICABLE)

    def test_same_setting_in_allow_and_deny_is_reported_once(self) -> None:
        setting = f"Bash(git push --token {self.FAKE_TOKEN} origin)"
        result = analyze_permissions([setting], deny=[setting])
        self._assert_no_secret(result)
        findings = self._r004(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].locations, ("permissions.allow[0]", "permissions.deny[0]"))
        self.assertIn("2 箇所", findings[0].evidence)

    def test_unparsable_entry_is_reported_as_r004(self) -> None:
        result = analyze_permissions([f"git push --token {self.FAKE_TOKEN} origin"])
        self._assert_no_secret(result)
        self.assertEqual([f.rule_id for f in result.findings], ["R004"])
        self.assertEqual(result.findings[0].entry, "git push --token [REDACTED] origin")

    def test_placeholders_are_not_reported_as_r004(self) -> None:
        result = analyze_permissions(
            ["Bash(git push --token $GH_TOKEN origin)", "Bash(git push --token <YOUR_TOKEN> origin)"],
            deny=["Bash(git push --password YOUR_PASSWORD origin)"],
        )
        self.assertEqual(self._r004(result), [])


class TestR005(unittest.TestCase):
    """R005（人による承認の省略）を analyze_config 経由で確かめる。値はすべて架空のダミー。"""

    @staticmethod
    def _analyze(extra: dict[str, object], allow: list[object] | None = None) -> AnalysisResult:
        permissions: dict[str, object] = {"allow": allow or [], "deny": [], **extra}
        return analyze_json(json.dumps({"agent_name": "fictional-agent", "permissions": permissions}))

    @staticmethod
    def _r005(result) -> list:
        return [f for f in result.findings if f.rule_id == "R005"]

    def test_bypass_permissions_is_high_risk(self) -> None:
        result = self._analyze({"defaultMode": "bypassPermissions"})
        findings = self._r005(result)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.setting_risk, Severity.HIGH)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.effective_status, EffectiveStatus.UNDETERMINED)
        self.assertEqual(finding.entry, 'defaultMode: "bypassPermissions"')
        self.assertEqual(finding.locations, ("permissions.defaultMode",))
        self.assertEqual(result.warnings, ())

    def test_accept_edits_is_medium_risk(self) -> None:
        result = self._analyze({"defaultMode": "acceptEdits"})
        findings = self._r005(result)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.setting_risk, Severity.MEDIUM)
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.effective_status, EffectiveStatus.UNDETERMINED)
        self.assertEqual(finding.entry, 'defaultMode: "acceptEdits"')
        self.assertEqual(result.warnings, ())

    def test_default_and_plan_are_not_reported(self) -> None:
        for index, mode in enumerate(["default", "plan"]):
            with self.subTest(index=index):
                result = self._analyze({"defaultMode": mode})
                self.assertEqual(self._r005(result), [])
                self.assertEqual(result.warnings, ())

    def test_missing_default_mode_is_not_reported(self) -> None:
        result = self._analyze({})
        self.assertEqual(self._r005(result), [])
        self.assertEqual(result.warnings, ())

    def test_unknown_value_or_type_is_warned_without_value(self) -> None:
        unknown_value = "FAKEMODE" + "0" * 8
        cases = [unknown_value, "BypassPermissions", 1, None, ["bypassPermissions"]]
        for index, mode in enumerate(cases):
            with self.subTest(index=index):
                result = self._analyze({"defaultMode": mode})
                self.assertEqual(self._r005(result), [])
                self.assertEqual(len(result.warnings), 1)
                self.assertFalse(isinstance(mode, str) and mode in result.warnings[0])
                self.assertIn("permissions.defaultMode", result.warnings[0])

    def test_conflict_with_disable_bypass_is_undetermined(self) -> None:
        unknown_value = "FAKEVALUE" + "0" * 8
        cases = [("disable", 0), (unknown_value, 1)]
        for index, (disable, warning_count) in enumerate(cases):
            with self.subTest(index=index):
                result = self._analyze(
                    {"defaultMode": "bypassPermissions", "disableBypassPermissionsMode": disable}
                )
                self.assertFalse(any(unknown_value in warning for warning in result.warnings))
                findings = self._r005(result)
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(finding.severity, Severity.HIGH)
                self.assertEqual(finding.effective_status, EffectiveStatus.UNDETERMINED)
                self.assertEqual(
                    finding.locations, ("permissions.defaultMode", "permissions.disableBypassPermissionsMode")
                )
                self.assertIn("判定不能", finding.effective_note)
                self.assertEqual(len(result.warnings), warning_count)

    def test_r001_to_r004_are_unchanged_by_r005(self) -> None:
        fake_token = "FAKE" + "0" * 12 + "TEST"
        allow = ["Bash(*)", f"Bash(git push --token {fake_token} origin)"]
        with_mode = self._analyze({"defaultMode": "bypassPermissions"}, allow=allow)
        without_mode = self._analyze({}, allow=allow)
        for result in (with_mode, without_mode):
            self.assertFalse(any(fake_token in text for text in TestR004Integration._texts(result)))

        def summary(result):
            return [
                (f.rule_id, f.setting_risk, f.severity, f.effective_status, f.entry, f.locations)
                for f in result.findings
                if f.rule_id != "R005"
            ]

        self.assertEqual(summary(with_mode), summary(without_mode))
        self.assertEqual([f.rule_id for f in with_mode.findings], ["R001", "R004", "R005"])


if __name__ == "__main__":
    unittest.main()
