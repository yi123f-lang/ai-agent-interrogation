"""report.py の単体テスト（Finding を直接組み立てて検証）。"""

import unittest

from interrogation_room.models import AnalysisResult, EffectiveStatus, Finding, Severity
from interrogation_room.report import DISCLAIMER, format_report, verdict


def make_finding(
    *,
    rule_id: str = "R001",
    entry: str = "Bash(*)",
    status: EffectiveStatus = EffectiveStatus.ACTIVE,
    locations: tuple[str, ...] = ("permissions.allow[0]",),
    related_deny: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.LOW if status is EffectiveStatus.BLOCKED else Severity.HIGH,
        setting_risk=Severity.HIGH,
        entry=entry,
        locations=locations,
        evidence="検出根拠のテスト文",
        effective_status=status,
        effective_note="実効権限のテスト文",
        related_deny=related_deny,
        recommendation="改善案のテスト文",
    )


def render(*findings: Finding, warnings: tuple[str, ...] = (), agent_name: str | None = "demo") -> str:
    result = AnalysisResult(findings=findings, warnings=warnings)
    return format_report(result, source="fictional.json", agent_name=agent_name)


class TestVerdict(unittest.TestCase):
    def test_no_findings(self) -> None:
        self.assertIn("問題なし", verdict([]))

    def test_live_risk(self) -> None:
        for status in [EffectiveStatus.ACTIVE, EffectiveStatus.PARTIALLY_RESTRICTED]:
            with self.subTest(status=status):
                findings = [make_finding(status=EffectiveStatus.BLOCKED), make_finding(status=status)]
                self.assertIn("要改善", verdict(findings))

    def test_blocked_only(self) -> None:
        text = verdict([make_finding(status=EffectiveStatus.BLOCKED)])
        self.assertIn("要整理", text)
        self.assertIn("危険な allow 設定が残っています", text)

    def test_undetermined(self) -> None:
        text = verdict([make_finding(status=EffectiveStatus.UNDETERMINED)])
        self.assertIn("要確認", text)

    def test_live_risk_takes_precedence_over_undetermined(self) -> None:
        findings = [
            make_finding(status=EffectiveStatus.UNDETERMINED),
            make_finding(status=EffectiveStatus.ACTIVE),
        ]
        self.assertIn("要改善", verdict(findings))

    def test_r004_only_requires_action(self) -> None:
        findings = [
            make_finding(rule_id="R004", status=EffectiveStatus.NOT_APPLICABLE),
            make_finding(rule_id="R004", status=EffectiveStatus.NOT_APPLICABLE, locations=("permissions.deny[0]",)),
        ]
        self.assertIn("要対応", verdict(findings))

    def test_live_risk_takes_precedence_over_r004(self) -> None:
        findings = [
            make_finding(rule_id="R004", status=EffectiveStatus.NOT_APPLICABLE),
            make_finding(rule_id="R001", status=EffectiveStatus.ACTIVE),
        ]
        self.assertIn("要改善", verdict(findings))

    def test_r004_takes_precedence_over_undetermined(self) -> None:
        findings = [
            make_finding(rule_id="R003", status=EffectiveStatus.UNDETERMINED),
            make_finding(rule_id="R004", status=EffectiveStatus.NOT_APPLICABLE),
        ]
        self.assertIn("要対応", verdict(findings))

    def test_r004_takes_precedence_over_blocked(self) -> None:
        findings = [
            make_finding(rule_id="R001", status=EffectiveStatus.BLOCKED),
            make_finding(rule_id="R004", status=EffectiveStatus.NOT_APPLICABLE),
        ]
        self.assertIn("要対応", verdict(findings))

    def test_r001_to_r003_only_keep_existing_verdicts(self) -> None:
        cases = [
            ([make_finding(rule_id="R002", status=EffectiveStatus.ACTIVE)], "要改善"),
            ([make_finding(rule_id="R003", status=EffectiveStatus.UNDETERMINED)], "要確認"),
            ([make_finding(rule_id="R001", status=EffectiveStatus.BLOCKED)], "要整理"),
            (
                [
                    make_finding(rule_id="R003", status=EffectiveStatus.BLOCKED),
                    make_finding(rule_id="R003", status=EffectiveStatus.UNDETERMINED),
                ],
                "要確認",
            ),
        ]
        for index, (findings, expected) in enumerate(cases):
            with self.subTest(index=index):
                text = verdict(findings)
                self.assertIn(expected, text)
                self.assertNotIn("要対応", text)


class TestVerdictWithR005(unittest.TestCase):
    """R005 の追加後も、判定の文言が合意どおりに選ばれることを確かめる。"""

    LIVE = "要改善（現在有効な広範権限があります）"
    R004_ACTION = "要対応（平文の認証情報らしき文字列が含まれています）"
    DENY_UNDETERMINED = "要確認（deny の効果を判定できない設定があります）"
    R005_UNDETERMINED = "要確認（人による承認を省略するモードが指定されており、実際の動作を判定できない設定があります）"
    BLOCKED = "要整理（deny により実効権限がないと推定されますが、危険な allow 設定が残っています）"
    NO_FINDINGS = "問題なし（検査ルールに該当する設定は見つかりませんでした）"

    def test_r005_only_uses_approval_bypass_wording(self) -> None:
        findings = [make_finding(rule_id="R005", status=EffectiveStatus.UNDETERMINED)]
        self.assertEqual(verdict(findings), self.R005_UNDETERMINED)

    def test_r003_wording_takes_precedence_over_r005(self) -> None:
        findings = [
            make_finding(rule_id="R005", status=EffectiveStatus.UNDETERMINED),
            make_finding(rule_id="R003", status=EffectiveStatus.UNDETERMINED),
        ]
        self.assertEqual(verdict(findings), self.DENY_UNDETERMINED)

    def test_r004_with_r005_keeps_requires_action(self) -> None:
        findings = [
            make_finding(rule_id="R005", status=EffectiveStatus.UNDETERMINED),
            make_finding(rule_id="R004", status=EffectiveStatus.NOT_APPLICABLE),
        ]
        self.assertEqual(verdict(findings), self.R004_ACTION)

    def test_live_risk_with_r005_keeps_requires_improvement(self) -> None:
        findings = [
            make_finding(rule_id="R005", status=EffectiveStatus.UNDETERMINED),
            make_finding(rule_id="R001", status=EffectiveStatus.ACTIVE),
        ]
        self.assertEqual(verdict(findings), self.LIVE)

    def test_r001_to_r004_only_keep_existing_wordings(self) -> None:
        cases = [
            ([make_finding(rule_id="R001", status=EffectiveStatus.ACTIVE)], self.LIVE),
            ([make_finding(rule_id="R002", status=EffectiveStatus.PARTIALLY_RESTRICTED)], self.LIVE),
            ([make_finding(rule_id="R003", status=EffectiveStatus.UNDETERMINED)], self.DENY_UNDETERMINED),
            ([make_finding(rule_id="R001", status=EffectiveStatus.BLOCKED)], self.BLOCKED),
            ([make_finding(rule_id="R004", status=EffectiveStatus.NOT_APPLICABLE)], self.R004_ACTION),
        ]
        for index, (findings, expected) in enumerate(cases):
            with self.subTest(index=index):
                self.assertEqual(verdict(findings), expected)

    def test_warnings_only_wording_is_unchanged(self) -> None:
        # 警告だけの場合の文言は別課題。対応するときは、このテストも合わせて見直す。
        text = render(warnings=("架空の警告: 判定に使えなかった項目があります（値は表示していません）。",))
        self.assertEqual(text.splitlines()[-1], f"判定: {self.NO_FINDINGS}")


class TestFormatReport(unittest.TestCase):
    def test_disclaimer_is_at_the_top(self) -> None:
        lines = render().splitlines()
        self.assertEqual(lines[1], DISCLAIMER)
        self.assertIn("簡易静的解析", DISCLAIMER)
        self.assertIn("保証するものではありません", DISCLAIMER)

    def test_empty_result(self) -> None:
        text = render(agent_name=None)
        self.assertIn("エージェント名: （未設定）", text)
        self.assertIn("検出件数      : 0件", text)
        self.assertNotIn("--- 指摘", text)
        self.assertNotIn("警告", text)
        self.assertTrue(text.endswith("判定: 問題なし（検査ルールに該当する設定は見つかりませんでした）"))

    def test_summary_separates_setting_risk_and_effective_permission(self) -> None:
        text = render(
            make_finding(status=EffectiveStatus.ACTIVE),
            make_finding(entry="Bash", rule_id="R002", status=EffectiveStatus.BLOCKED),
        )
        self.assertIn("設定上のリスク（allow の記述そのもの）: 高 2件 / 中 0件 / 低 0件", text)
        self.assertIn(
            "現在の実効権限（deny 考慮後）: 有効 1件 / 一部制限 0件 / 無効（deny により拒否） 1件", text
        )
        self.assertIn("総合危険度: 高 1件 / 中 0件 / 低 1件", text)

    def test_summary_comes_before_findings(self) -> None:
        text = render(make_finding())
        self.assertLess(text.index("【集計】"), text.index("--- 指摘 1/1"))

    def test_sorted_by_overall_severity(self) -> None:
        text = render(
            make_finding(entry="Bash", rule_id="R002", status=EffectiveStatus.BLOCKED),
            make_finding(entry="Bash(*)", status=EffectiveStatus.ACTIVE),
        )
        self.assertIn('--- 指摘 1/2 [総合危険度: 高] R001 ---\n設定上の許可: "Bash(*)"', text)
        self.assertIn('--- 指摘 2/2 [総合危険度: 低] R002 ---\n設定上の許可: "Bash"', text)

    def test_blocked_finding_keeps_high_setting_risk(self) -> None:
        text = render(make_finding(status=EffectiveStatus.BLOCKED, related_deny=("Bash(*)",)))
        self.assertIn("■ 設定上のリスク: 高", text)
        self.assertIn("■ 現在の実効権限: 無効（deny により拒否）", text)
        self.assertIn("  関連 deny: Bash(*)", text)
        self.assertIn("要整理", text)

    def test_related_deny_line_only_when_present(self) -> None:
        self.assertNotIn("関連 deny", render(make_finding()))

    def test_multiple_locations(self) -> None:
        text = render(make_finding(locations=("permissions.allow[0]", "permissions.allow[2]")))
        self.assertIn("記載箇所    : permissions.allow[0], permissions.allow[2]", text)

    def test_warnings_section(self) -> None:
        text = render(warnings=("permissions.allow[0] は文字列ではないため検査対象外にしました（型: int）。",))
        self.assertIn("--- 警告（検査対象外にした項目）---", text)
        self.assertIn("・permissions.allow[0] は文字列ではない", text)


if __name__ == "__main__":
    unittest.main()
