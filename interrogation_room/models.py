"""検出結果を表すデータモデル。"""

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    """危険度。"""

    HIGH = "高"
    MEDIUM = "中"
    LOW = "低"


class EffectiveStatus(StrEnum):
    """deny を考慮した実効権限の状態。

    Finding が指すのは allow に書かれた「設定」であり、
    その設定が実際に効いているかどうかはこの値で区別する。
    """

    ACTIVE = "有効"
    PARTIALLY_RESTRICTED = "一部制限"
    BLOCKED = "無効（deny により拒否）"
    UNDETERMINED = "判定不能（要確認）"
    NOT_APPLICABLE = "判定対象外"


class ConfigError(ValueError):
    """設定の構造が想定と異なり、検査を続行できないことを表す。"""


@dataclass(frozen=True, slots=True)
class Finding:
    """allow 内の1つの設定に対する指摘。"""

    rule_id: str
    severity: Severity  # 総合危険度（設定上のリスク × 現在の実効権限）
    setting_risk: Severity  # 設定上のリスク（allow の記述そのもの。deny の影響を受けない）
    entry: str  # 正規化した allow の設定値
    locations: tuple[str, ...]  # 例: ("permissions.allow[0]",)
    evidence: str  # 設定そのものが広すぎる根拠
    effective_status: EffectiveStatus
    effective_note: str  # deny を踏まえた実効権限の説明
    related_deny: tuple[str, ...]
    recommendation: str


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """検査結果。warnings には検査対象外にした項目などを記録する。"""

    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
