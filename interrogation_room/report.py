"""検査結果を日本語の診断レポート（調書）に整形する。"""

from collections import Counter
from collections.abc import Iterable, Sequence

from .models import AnalysisResult, EffectiveStatus, Finding, Severity

DISCLAIMER = (
    "※ 本レポートは架空の権限設定 JSON に対する簡易静的解析の結果です。"
    "実際の Claude Code でのコマンド実行可否を保証するものではありません。"
)

_SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.LOW)
_STATUS_ORDER = (
    EffectiveStatus.ACTIVE,
    EffectiveStatus.PARTIALLY_RESTRICTED,
    EffectiveStatus.BLOCKED,
    EffectiveStatus.UNDETERMINED,
    EffectiveStatus.NOT_APPLICABLE,
)
_LIVE_STATUSES = frozenset({EffectiveStatus.ACTIVE, EffectiveStatus.PARTIALLY_RESTRICTED})


def has_live_risk(findings: Iterable[Finding]) -> bool:
    """現在の実効権限として広範な許可が残っている指摘があるか。"""
    return any(f.effective_status in _LIVE_STATUSES for f in findings)


def verdict(findings: Sequence[Finding]) -> str:
    """判定の文言。指摘が1件でもあれば終了コードは 1 になる（__main__ 側で判断）。"""
    if not findings:
        return "問題なし（検査ルールに該当する設定は見つかりませんでした）"
    if has_live_risk(findings):
        return "要改善（現在有効な広範権限があります）"
    if any(f.rule_id == "R004" and f.effective_status is EffectiveStatus.NOT_APPLICABLE for f in findings):
        return "要対応（平文の認証情報らしき文字列が含まれています）"
    undetermined = [f for f in findings if f.effective_status is EffectiveStatus.UNDETERMINED]
    if any(f.rule_id != "R005" for f in undetermined):
        return "要確認（deny の効果を判定できない設定があります）"
    if undetermined:
        return "要確認（人による承認を省略するモードが指定されており、実際の動作を判定できない設定があります）"
    return "要整理（deny により実効権限がないと推定されますが、危険な allow 設定が残っています）"


def format_report(result: AnalysisResult, *, source: str, agent_name: str | None) -> str:
    """検査結果をレポート文字列にする。"""
    findings = sorted(result.findings, key=lambda f: _SEVERITY_ORDER.index(f.severity))
    lines = [
        "=== AI Agent取調室 調書 ===",
        DISCLAIMER,
        "",
        f"対象ファイル  : {source}",
        f"エージェント名: {agent_name or '（未設定）'}",
        f"検出件数      : {len(findings)}件",
        "",
        *_format_summary(findings),
    ]
    for number, finding in enumerate(findings, start=1):
        lines += ["", *_format_finding(finding, number, len(findings))]
    if result.warnings:
        lines += ["", "--- 警告（検査対象外にした項目）---"]
        lines += [f"・{warning}" for warning in result.warnings]
    lines += ["", f"判定: {verdict(findings)}"]
    return "\n".join(lines)


def _format_counts[T](values: Iterable[T], order: Sequence[T]) -> str:
    counts = Counter(values)
    return " / ".join(f"{key} {counts[key]}件" for key in order)


def _format_summary(findings: Sequence[Finding]) -> list[str]:
    setting = _format_counts((f.setting_risk for f in findings), _SEVERITY_ORDER)
    effective = _format_counts((f.effective_status for f in findings), _STATUS_ORDER)
    overall = _format_counts((f.severity for f in findings), _SEVERITY_ORDER)
    return [
        "【集計】",
        f"  設定上のリスク（allow の記述そのもの）: {setting}",
        f"  現在の実効権限（deny 考慮後）: {effective}",
        f"  総合危険度: {overall}",
    ]


def _format_finding(finding: Finding, number: int, total: int) -> list[str]:
    lines = [
        f"--- 指摘 {number}/{total} [総合危険度: {finding.severity}] {finding.rule_id} ---",
        f'設定上の許可: "{finding.entry}"',
        f"記載箇所    : {', '.join(finding.locations)}",
        f"■ 設定上のリスク: {finding.setting_risk}",
        f"  検出根拠: {finding.evidence}",
        f"■ 現在の実効権限: {finding.effective_status}",
        f"  説明     : {finding.effective_note}",
    ]
    if finding.related_deny:
        lines.append(f"  関連 deny: {', '.join(finding.related_deny)}")
    lines.append(f"改善案: {finding.recommendation}")
    return lines
