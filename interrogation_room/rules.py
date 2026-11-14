"""Bash の広範な許可を検出するルール（R001 / R002）。

架空の権限設定 JSON を対象とし、評価は次の前提で行う。

- deny は allow より優先される。
- allow 側の曖昧なパターンは広い許可とみなし、deny 側の曖昧なパターンは
  拒否として扱わない（どちらも安全側に倒す）。
- Finding は allow に書かれた設定を指す。deny を踏まえた実効権限は
  effective_status / effective_note に分けて記録する。
- 正規化後に同一となる設定への指摘は1件にまとめ、
  1つの設定には最初に該当したルールだけを適用する。
- deny の照合結果は文字列に基づく静的解析の推定であり、
  実際の Claude Code の実行可否を保証しない。
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .models import AnalysisResult, ConfigError, EffectiveStatus, Finding, Severity

_ENTRY_RE = re.compile(
    r"(?P<tool>[A-Za-z_][A-Za-z0-9_]*)(?:\((?P<pattern>.*)\))?", re.DOTALL
)
_WILDCARD_CHARS = frozenset("*: \t")
_ALL_TOOLS = "*"
_COMMAND_RE = re.compile(r"(?P<command>[^\s*]+?)(?=:\*|\s|\*|$)")
_PATH_SCOPE_RE = re.compile(r"/tmp/|\./[^/*]+/")
_URL_SCOPE_RE = re.compile(r"https?://[^/*@]+/")
_UNSAFE_TARGET_CHARS = frozenset("$~`;|&<>()")
_LOWER_RISK = {Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW}


@dataclass(frozen=True, slots=True)
class _DangerousCommand:
    setting_risk: Severity
    capability: str
    scope_re: re.Pattern[str] | None = None  # None なら対象を絞っても危険度を下げない


_CODE_EXECUTION = _DangerousCommand(Severity.HIGH, "任意のコードを実行できるコマンドです。")
_NETWORK = _DangerousCommand(
    Severity.MEDIUM, "外部との通信に使えるコマンドです。", _URL_SCOPE_RE
)

# 分類は暫定。コマンド名は「できること」の目安であり、攻撃や不正の断定には使わない。
_DANGEROUS_COMMANDS = {
    "rm": _DangerousCommand(
        Severity.HIGH, "ファイルの削除に使えるコマンドです。", _PATH_SCOPE_RE
    ),
    "sudo": _DangerousCommand(Severity.HIGH, "他のコマンドを高い権限で実行できるコマンドです。"),
    "python": _CODE_EXECUTION,
    "python3": _CODE_EXECUTION,
    "bash": _CODE_EXECUTION,
    "sh": _CODE_EXECUTION,
    "powershell": _CODE_EXECUTION,
    "pwsh": _CODE_EXECUTION,
    "curl": _NETWORK,
    "wget": _NETWORK,
    "ssh": _DangerousCommand(Severity.MEDIUM, "他のマシンへの接続に使えるコマンドです。"),
    "chmod": _DangerousCommand(Severity.MEDIUM, "ファイルの権限を変更できるコマンドです。"),
}


@dataclass(frozen=True, slots=True)
class ParsedEntry:
    """「ツール名(引数パターン)」形式の権限エントリ。pattern が None なら括弧なし。"""

    tool: str
    pattern: str | None

    @property
    def key(self) -> str:
        """重複判定と表示に使う正規化済みの表記。"""
        return self.tool if self.pattern is None else f"{self.tool}({self.pattern})"


@dataclass(frozen=True, slots=True)
class RuleHit:
    rule_id: str
    setting_risk: Severity
    evidence: str
    recommendation: str
    command: str | None = None  # R003 の対象コマンド。None なら Bash 全体


@dataclass(frozen=True, slots=True)
class _Entry:
    location: str
    text: str  # 前後の空白を除いた文字列
    parsed: ParsedEntry | None


type Rule = Callable[[ParsedEntry], RuleHit | None]


def parse_entry(text: str) -> ParsedEntry | None:
    """権限エントリを分解する。形式に合わなければ None を返す。"""
    match = _ENTRY_RE.fullmatch(text.strip())
    if match is None:
        return None
    pattern = match["pattern"]
    return ParsedEntry(match["tool"], None if pattern is None else pattern.strip())


def _is_wildcard_only(pattern: str) -> bool:
    return "*" in pattern and set(pattern) <= _WILDCARD_CHARS


def _rule_r001(entry: ParsedEntry) -> RuleHit | None:
    """R001: Bash(*) などワイルドカードだけで構成された一括許可。"""
    if entry.tool != "Bash" or entry.pattern is None:
        return None
    if not _is_wildcard_only(entry.pattern):
        return None
    return RuleHit(
        rule_id="R001",
        setting_risk=Severity.HIGH,
        evidence=(
            f"引数パターン「{_mask_secrets(entry.pattern)}」はワイルドカードだけで構成されており、"
            "任意のシェルコマンドの実行を許可する設定です。"
            "ファイル削除・外部への送信・権限昇格につながるコマンドも許可対象に含まれます。"
        ),
        recommendation=(
            "ワイルドカードによる一括許可をやめ、必要なコマンドだけを個別に許可してください。"
            '例: "Bash(git status)", "Bash(npm test)"'
        ),
    )


def _rule_r002(entry: ParsedEntry) -> RuleHit | None:
    """R002: 引数パターンで制限されていない Bash の許可。"""
    if entry.tool != "Bash":
        return None
    if entry.pattern is None:
        reason = "引数パターンが指定されていないため"
    elif entry.pattern == "":
        reason = "引数パターンが空で、制限として機能するか判断できないため"
    else:
        return None
    return RuleHit(
        rule_id="R002",
        setting_risk=Severity.HIGH,
        evidence=f"{reason}、Bash のすべてのコマンドを許可する設定とみなしました。",
        recommendation=(
            "Bash を丸ごと許可せず、「Bash(コマンド)」の形式で必要なコマンドだけを許可してください。"
            '例: "Bash(git status)", "Bash(npm test)"'
        ),
    )


def _normalize_command(raw: str) -> str:
    name = raw.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removesuffix(".exe")


def _is_scoped_target(token: str, scope_re: re.Pattern[str]) -> bool:
    if ".." in token or not _UNSAFE_TARGET_CHARS.isdisjoint(token):
        return False
    return scope_re.match(token.split("*", 1)[0]) is not None


def _is_scoped(arguments: str, spec: _DangerousCommand) -> bool:
    """引数のすべての対象が、限定された範囲だと推定できるか。"""
    if spec.scope_re is None:
        return False
    tokens = arguments.removeprefix(":").split()
    targets = [token for token in tokens if not token.startswith("-")]
    return bool(targets) and all(_is_scoped_target(t, spec.scope_re) for t in targets)


def _rule_r003(entry: ParsedEntry) -> RuleHit | None:
    """R003: 危険なコマンドに対するワイルドカード付きの許可。

    allow の記述だけから設定上のリスクを決める。deny による制限はここでは扱わない。
    """
    if entry.tool != "Bash" or not entry.pattern or "*" not in entry.pattern:
        return None
    if _is_wildcard_only(entry.pattern):
        return None
    match = _COMMAND_RE.match(entry.pattern)
    if match is None:
        return None
    raw_command = match["command"]
    command = _normalize_command(raw_command)
    spec = _DANGEROUS_COMMANDS.get(command)
    if spec is None:
        return None
    if _is_scoped(entry.pattern[len(raw_command):], spec):
        setting_risk = _LOWER_RISK[spec.setting_risk]
        scope = (
            "文字列からは対象が限定されていると推定されるため、危険度を1段階下げています。"
            "ワイルドカードの実際の照合範囲は未確認で、範囲外に及ぶ可能性があります。"
        )
    else:
        setting_risk = spec.setting_risk
        scope = "引数の範囲を限定できていません。"
    return RuleHit(
        rule_id="R003",
        setting_risk=setting_risk,
        evidence=(
            f"{command} は{spec.capability}"
            f"引数パターン「{_mask_secrets(entry.pattern)}」はワイルドカードを含みます。{scope}"
            "これは設定から読み取れる可能性の指摘であり、実際の攻撃や不正を示すものではありません。"
            "deny との照合結果を含む判定は静的解析の推定で、"
            "実際の Claude Code の実行可否を保証しません。"
        ),
        recommendation=(
            "ワイルドカードをなくして実行内容を具体的に指定するか、"
            "allow から外して実行のたびに確認する運用にしてください。"
        ),
        command=command,
    )


@dataclass(frozen=True, slots=True)
class _SecretSpan:
    """認証情報らしき部分の位置と種類。値そのものは持たない。"""

    kind: str
    start: int
    end: int


# パターンは推定。value グループがあるものは、その部分だけを秘密情報として扱う。
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Anthropic API キーらしき文字列", re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}")),
    ("API キーらしき文字列", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("GitHub トークンらしき文字列", re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("Slack トークンらしき文字列", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("AWS アクセスキー ID らしき文字列", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API キーらしき文字列", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("認証ヘッダーの値", re.compile(r"(?i)\bauthorization:\s*(?:bearer|basic)\s+(?P<value>[^\s'\"]+)")),
    ("URL 内の認証情報", re.compile(r"://[^/\s:@]+:(?P<value>[^@\s/]+)@")),
    ("キーワード付きの値", re.compile(r"(?i)(?<![A-Za-z0-9])(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*(?P<value>[^\s'\"&;]+)")),
    ("オプションの値", re.compile(r"(?i)--(?:password|token|api-key|secret)(?:=|\s+)(?P<value>[^\s'\"]+)")),
)
_PLACEHOLDER_RE = re.compile(r"(?i)^(?:\$|<|\*|x{3,}$|your[-_]|example|dummy|changeme|redacted)")


def _find_secrets(text: str) -> list[_SecretSpan]:
    """平文の認証情報らしき部分の位置と種類を返す。値そのものは返さない。"""
    spans: list[_SecretSpan] = []
    for kind, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if "value" in pattern.groupindex:
                start, end = match.span("value")
                value = match["value"]
                if len(value) < 8 or _PLACEHOLDER_RE.match(value):
                    continue
            else:
                start, end = match.span()
            if any(start < s.end and s.start < end for s in spans):
                continue
            spans.append(_SecretSpan(kind, start, end))
    return sorted(spans, key=lambda s: s.start)


_REDACTED = "[REDACTED]"


def _mask_secrets(text: str) -> str:
    """認証情報らしき部分の値だけを [REDACTED] に置き換え、周囲の文字列は残す。"""
    parts: list[str] = []
    position = 0
    for span in _find_secrets(text):
        parts.append(text[position:span.start])
        parts.append(_REDACTED)
        position = span.end
    parts.append(text[position:])
    return "".join(parts)


def _display_entry(entry: _Entry) -> str:
    """出力用の表記を返す。表記全体の認証情報らしき値だけを [REDACTED] にし、元の _Entry は変えない。"""
    parsed = entry.parsed
    if parsed is None:
        display = entry.text
    elif parsed.pattern is None:
        display = parsed.tool
    else:
        display = f"{parsed.tool}({parsed.pattern})"
    return _mask_secrets(display)


_R004_NOTE = (
    "R004 はコマンドの実行権限ではなく、認証情報の保存に関する指摘のため、"
    "deny による実効権限の判定対象外です。"
)
_R004_RECOMMENDATION = (
    "設定ファイルから認証情報を削除し、環境変数などから参照する形にしてください。"
    "すでに共有した可能性がある場合は、その認証情報を無効化してください。"
)


def _r004_finding(entry: _Entry, locations: list[str]) -> Finding:
    """R004 の指摘を作る。表示用の文字列と種類はここで作り、認証情報の値は持たない。"""
    kinds = list(dict.fromkeys(span.kind for span in _find_secrets(entry.text)))
    evidence = (
        f"{'、'.join(kinds)}を検出しました。値は表示していません。"
        "設定ファイルに平文で保存されているため、共有やバックアップ、ログから漏洩するおそれがあります。"
        "文字列パターンによる推定で、実際に有効な認証情報かどうかは確認していません。"
    )
    if len(locations) > 1:
        evidence += (
            f"同じ設定が {len(locations)} 箇所（{'、'.join(locations)}）に"
            "記述されているため、1件にまとめて指摘しています。"
        )
    return Finding(
        rule_id="R004",
        severity=Severity.HIGH,
        setting_risk=Severity.HIGH,
        entry=_display_entry(entry),
        locations=tuple(locations),
        evidence=evidence,
        effective_status=EffectiveStatus.NOT_APPLICABLE,
        effective_note=_R004_NOTE,
        related_deny=(),
        recommendation=_R004_RECOMMENDATION,
    )


_R005_MODES = {
    "bypassPermissions": (
        Severity.HIGH,
        "権限の確認をすべて省略する設定と読み取れます。人による承認なしに、ツールの実行が許可されるおそれがあります。",
        "bypassPermissions を使わず確認を行うモードにし、必要な操作だけを allow で個別に許可してください。",
    ),
    "acceptEdits": (
        Severity.MEDIUM,
        "ファイルの編集を確認なしで受け入れる設定と読み取れます。人による承認なしに、ファイルが変更されるおそれがあります。",
        "acceptEdits が必要か見直し、確認を行うモードに戻すか、編集を許可する範囲を限定してください。",
    ),
}
# 指摘しない値。設定全体が安全であることを意味するものではない。
_R005_NO_FINDING_MODES = frozenset({"default", "plan"})
_R005_UNCERTAINTY = (
    "設定ファイルの種類、設定の優先順位、Claude Code のバージョンを確認できないため、"
    "実際の動作は断定しません。静的解析による推定です。"
)


def _r005_finding(permissions: Mapping, warnings: list[str]) -> Finding | None:
    """R005: permissions.defaultMode による人の承認の省略を検出する。値が不明なら警告だけを残す。

    設定ファイル間の優先順位や起動時の指定による上書きは確認できないため、実効権限は常に判定不能とする。
    """
    if "defaultMode" not in permissions:
        return None
    mode = permissions["defaultMode"]
    if not isinstance(mode, str):
        warnings.append(
            "permissions.defaultMode は文字列ではないため、R005 の判定に使いませんでした"
            f"（型: {type(mode).__name__}）。"
        )
        return None
    if mode in _R005_NO_FINDING_MODES:
        return None
    if mode not in _R005_MODES:
        warnings.append(
            "permissions.defaultMode は R005 が判定できる値ではないため、安全とはみなさず、"
            "判定に使いませんでした（値は表示していません）。"
        )
        return None
    setting_risk, capability, recommendation = _R005_MODES[mode]
    locations = ["permissions.defaultMode"]
    note = (
        "【判定不能】この設定ファイルではこのモードが指定されていますが、"
        "他の設定ファイルとの優先順位や起動時の指定による上書きを確認できないため、"
        "承認の省略が実際に起きるかは判定できません。"
    )
    if mode == "bypassPermissions" and "disableBypassPermissionsMode" in permissions:
        locations.append("permissions.disableBypassPermissionsMode")
        if permissions["disableBypassPermissionsMode"] == "disable":
            note = (
                "【判定不能】同じ設定ファイルに disableBypassPermissionsMode: \"disable\" もあります。"
                "どちらが優先されるかを確認できないため、承認の省略が実際に起きるかは判定できません。"
            )
        else:
            warnings.append(
                "permissions.disableBypassPermissionsMode は R005 が判定できる値ではないため、"
                "判定に使いませんでした（値は表示していません）。"
            )
    return Finding(
        rule_id="R005",
        severity=setting_risk,
        setting_risk=setting_risk,
        entry=f'defaultMode: "{mode}"',
        locations=tuple(locations),
        evidence=f'permissions.defaultMode が "{mode}" です。{capability}{_R005_UNCERTAINTY}',
        effective_status=EffectiveStatus.UNDETERMINED,
        effective_note=note,
        related_deny=(),
        recommendation=recommendation,
    )


RULES: tuple[Rule, ...] = (_rule_r001, _rule_r002, _rule_r003)


def analyze_config(config: object) -> AnalysisResult:
    """json.loads 済みの権限設定を検査する。構造が不正なら ConfigError を送出する。"""
    allow_values, deny_values = _extract_permissions(config)
    warnings: list[str] = []
    allow = _collect_entries(allow_values, "permissions.allow", warnings)
    deny = _collect_entries(deny_values, "permissions.deny", warnings)

    # deny の照合は文字列に基づく静的解析の推定で、実際の実行可否を保証しない。
    # 分類と警告の記録は1回だけ行い、実効権限は指摘ごとに組み立てる。
    bash_status, bash_related_deny = _evaluate_bash_deny(deny, warnings)

    hits: dict[str, tuple[RuleHit, list[str]]] = {}
    for entry in allow:
        if entry.parsed is None:
            continue
        key = entry.parsed.key
        if key in hits:
            hits[key][1].append(entry.location)
            continue
        hit = _first_hit(entry.parsed)
        if hit is not None:
            hits[key] = (hit, [entry.location])

    findings = []
    for key, (hit, locations) in hits.items():
        if hit.command is None:
            # R001/R002 は Bash 全体の許可なので、Bash に対する deny の評価をそのまま使う。
            status = bash_status
            related_deny = tuple(_mask_secrets(text) for text in bash_related_deny)
            severity = _overall_severity(hit.setting_risk, status)
            effective_note, extra_recommendation = _describe_effect(status, related_deny)
        else:
            # R003: deny の照合は推定なので、総合危険度を下げる根拠にしない。
            status, raw_related_deny = _evaluate_command_deny(key, deny)
            related_deny = tuple(_mask_secrets(text) for text in raw_related_deny)
            severity = hit.setting_risk
            effective_note, extra_recommendation = _describe_command_effect(
                status, related_deny, hit.command
            )
        evidence = hit.evidence
        if len(locations) > 1:
            evidence += (
                f"同じ設定が {len(locations)} 箇所（{'、'.join(locations)}）に"
                "記述されているため、1件にまとめて指摘しています。"
            )
        findings.append(
            Finding(
                rule_id=hit.rule_id,
                severity=severity,
                setting_risk=hit.setting_risk,
                entry=_mask_secrets(key),
                locations=tuple(locations),
                evidence=evidence,
                effective_status=status,
                effective_note=effective_note,
                related_deny=related_deny,
                recommendation=hit.recommendation + extra_recommendation,
            )
        )

    # R004: 平文の認証情報は保存方法の問題なので、RULES とは別に allow・deny の全項目を検査する。
    # 設定文字列は照合に使うだけで、実行しない。同じ設定は1件にまとめ、場所をすべて記録する。
    secret_hits: dict[str, tuple[_Entry, list[str]]] = {}
    for entry in (*allow, *deny):
        if not _find_secrets(entry.text):
            continue
        key = entry.parsed.key if entry.parsed is not None else entry.text
        if key in secret_hits:
            secret_hits[key][1].append(entry.location)
        else:
            secret_hits[key] = (entry, [entry.location])
    for first_entry, locations in secret_hits.values():
        findings.append(_r004_finding(first_entry, locations))

    # R005: 人の承認を省略するモードは、Bash のルールや認証情報とは別に検査する。
    # _extract_permissions で、permissions が JSON オブジェクトであることは確認済み。
    r005 = _r005_finding(config["permissions"], warnings)
    if r005 is not None:
        findings.append(r005)
    return AnalysisResult(tuple(findings), tuple(_mask_secrets(warning) for warning in warnings))


def _extract_permissions(config: object) -> tuple[list[object], list[object]]:
    if not isinstance(config, Mapping):
        raise ConfigError("設定のトップレベルが JSON オブジェクトではありません。")
    permissions = config.get("permissions")
    if not isinstance(permissions, Mapping):
        raise ConfigError("permissions が存在しないか、JSON オブジェクトではありません。")
    allow = permissions.get("allow")
    if not isinstance(allow, list):
        raise ConfigError("permissions.allow が存在しないか、配列ではありません。")
    deny = permissions.get("deny", [])
    if not isinstance(deny, list):
        raise ConfigError("permissions.deny が配列ではありません。")
    return allow, deny


def _collect_entries(values: list[object], path: str, warnings: list[str]) -> list[_Entry]:
    entries = []
    for index, value in enumerate(values):
        location = f"{path}[{index}]"
        if not isinstance(value, str):
            warnings.append(
                f"{location} は文字列ではないため検査対象外にしました（型: {type(value).__name__}）。"
            )
            continue
        text = value.strip()
        if not text:
            warnings.append(f"{location} は空文字列のため検査対象外にしました。")
            continue
        entries.append(_Entry(location, text, parse_entry(text)))
    return entries


def _first_hit(entry: ParsedEntry) -> RuleHit | None:
    for rule in RULES:
        hit = rule(entry)
        if hit is not None:
            return hit
    return None


def _blocks_all_bash(entry: _Entry) -> bool:
    if entry.text == _ALL_TOOLS:
        return True
    parsed = entry.parsed
    return (
        parsed is not None
        and parsed.tool == "Bash"
        and (parsed.pattern is None or _is_wildcard_only(parsed.pattern))
    )


def _evaluate_bash_deny(
    deny: list[_Entry], warnings: list[str]
) -> tuple[EffectiveStatus, tuple[str, ...]]:
    full: list[str] = []
    partial: list[str] = []
    for entry in deny:
        if _blocks_all_bash(entry):
            full.append(entry.text)
        elif entry.parsed is not None and entry.parsed.tool == "Bash":
            if entry.parsed.pattern == "":
                warnings.append(
                    f"{entry.location}「{entry.text}」は引数パターンが空のため、"
                    "拒否設定として扱いませんでした。"
                )
            else:
                partial.append(entry.text)
    if full:
        return EffectiveStatus.BLOCKED, tuple(dict.fromkeys(full))
    if partial:
        return EffectiveStatus.PARTIALLY_RESTRICTED, tuple(dict.fromkeys(partial))
    return EffectiveStatus.ACTIVE, ()


def _command_names(pattern: str) -> set[str]:
    """パターンに現れるコマンド名の候補を返す。sudo rm なら sudo と rm の両方。"""
    names: set[str] = set()
    for token in re.split(r"[\s;|&]+", pattern):
        name = _normalize_command(token.split("*", 1)[0].removesuffix(":"))
        if name and not name.startswith("-"):
            names.add(name)
    return names


def _may_affect_command(entry: _Entry, allow_names: set[str]) -> bool:
    """この deny が allow と無関係だと、文字列から言い切れない場合に True を返す。"""
    parsed = entry.parsed
    if parsed is None:
        return not allow_names.isdisjoint(re.findall(r"[a-z0-9_+-]+", entry.text.lower()))
    if parsed.tool.lower() != "bash":
        return False
    deny_names = _command_names(parsed.pattern or "")
    return not deny_names or not allow_names.isdisjoint(deny_names)


def _evaluate_command_deny(
    allow_key: str, deny: list[_Entry]
) -> tuple[EffectiveStatus, tuple[str, ...]]:
    """R003 の設定に対する deny の影響を推定する。

    無効とするのは Bash 全体の拒否と、正規化後の表記が完全に同じ deny だけ。
    無関係と言い切れない deny があれば判定不能とする。
    返すのは実効権限の推定だけで、総合危険度を下げる根拠には使わない。
    """
    allow_names = _command_names(allow_key.removeprefix("Bash(").removesuffix(")"))
    blocked: list[str] = []
    uncertain: list[str] = []
    for entry in deny:
        same_setting = entry.parsed is not None and entry.parsed.key == allow_key
        if _blocks_all_bash(entry) or same_setting:
            blocked.append(entry.text)
        elif _may_affect_command(entry, allow_names):
            uncertain.append(entry.text)
    if blocked:
        return EffectiveStatus.BLOCKED, tuple(dict.fromkeys(blocked))
    if uncertain:
        return EffectiveStatus.UNDETERMINED, tuple(dict.fromkeys(uncertain))
    return EffectiveStatus.ACTIVE, ()


def _overall_severity(setting_risk: Severity, status: EffectiveStatus) -> Severity:
    """総合危険度。deny で全面拒否されていれば低、それ以外は設定上のリスクのまま。"""
    return Severity.LOW if status is EffectiveStatus.BLOCKED else setting_risk


def _describe_effect(
    status: EffectiveStatus, related_deny: tuple[str, ...]
) -> tuple[str, str]:
    """実効権限の状態から (実効権限の説明, 追加の改善案) を返す。"""
    denied = "、".join(f"「{d}」" for d in related_deny)
    match status:
        case EffectiveStatus.ACTIVE:
            return (
                "deny に Bash を制限する設定がないため、この許可はそのまま有効です。",
                "",
            )
        case EffectiveStatus.PARTIALLY_RESTRICTED:
            return (
                f"deny の {denied} に一致するコマンドは拒否されますが、"
                "それ以外の任意のコマンドは引き続き許可されており、実効権限は依然として広範です。",
                "deny による個別の拒否は別のコマンドや書き換えで回避されやすいため、"
                "deny に頼らず allow 側を絞り込んでください。",
            )
        case EffectiveStatus.BLOCKED:
            return (
                f"deny の {denied} により Bash は全面的に拒否されるため、現時点の実効権限はありません。"
                "ただし allow 側の設定は残っており、deny が削除・変更されると直ちに有効になります。",
                "allow と deny が矛盾しているため、allow 側のこの設定を削除して意図を明確にしてください。",
            )


def _describe_command_effect(
    status: EffectiveStatus, related_deny: tuple[str, ...], command: str
) -> tuple[str, str]:
    """R003 用に (実効権限の説明, 追加の改善案) を返す。説明はすべて推定として示す。"""
    denied = "、".join(f"「{d}」" for d in related_deny)
    match status:
        case EffectiveStatus.ACTIVE:
            return (
                f"【推定】deny に {command} と関係すると読み取れる設定がないため、"
                "この許可は有効と推定されます。",
                "",
            )
        case EffectiveStatus.BLOCKED:
            return (
                f"【推定】deny の {denied} により、この設定は拒否されると推定されます。"
                "実際に拒否されることは保証できないため、総合危険度は下げていません。"
                "他の allow 経由で同じ操作ができないことも保証しません。",
                "allow と deny が重なっているため、allow 側のこの設定を削除して意図を明確にしてください。",
            )
        case _:
            # R003 は一部制限を使わず、不確実な場合はすべて判定不能として扱う。
            return (
                f"【判定不能】deny の {denied} は {command} に関係する可能性がありますが、"
                "文字列だけでは拒否される範囲を判断できません。"
                "deny で制限されていることを意味しません。実際の照合仕様と設定を人が確認してください。",
                "deny に頼らず、allow 側を具体的にしてください。",
            )
