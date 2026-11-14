"""コマンドラインの入口: python -m interrogation_room <設定ファイル.json>

終了コード:
    0 = 指摘なし
    1 = 指摘あり（実効権限が無効でも、危険な allow 設定が残っていれば 1）
    2 = 入力エラー（ファイル読込・JSON 構文・重複キー・構造・引数の誤り）
"""

import argparse
import io
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from .models import ConfigError
from .report import DISCLAIMER, format_report
from .rules import analyze_config

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT_ERROR = 2


class InputError(Exception):
    """ファイル読込・JSON 解析の失敗（日本語メッセージ付き）。"""


class _DuplicateKeyError(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def load_config(path: Path) -> object:
    """JSON を読み込む。失敗時は InputError に変換して送出する。"""
    try:
        text = path.read_text(encoding="utf-8-sig")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except FileNotFoundError:
        raise InputError(f"ファイルが見つかりません: {path}") from None
    except UnicodeDecodeError:
        raise InputError(f"UTF-8 として読み込めません: {path}") from None
    except OSError as e:
        raise InputError(f"ファイルを読み込めません: {path}（{e.strerror}）") from None
    except json.JSONDecodeError as e:
        raise InputError(f"JSON の構文エラーです（{e.lineno} 行 {e.colno} 列目）: {e.msg}") from None
    except _DuplicateKeyError as e:
        raise InputError(
            f"JSON 内でキー「{e.key}」が重複しています。"
            "どちらの値が使われるか曖昧なため、検査を中止しました。"
        ) from None


def main(argv: Sequence[str] | None = None) -> int:
    _configure_output()
    args = _build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        result = analyze_config(config)
    except (InputError, ConfigError) as e:
        print(f"エラー: {e}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    print(format_report(result, source=str(args.config), agent_name=_agent_name(config)))
    return EXIT_FINDINGS if result.findings else EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m interrogation_room",
        description="架空の AI エージェント権限設定 JSON から、広すぎる Bash 許可を検出します。"
        + DISCLAIMER,
    )
    parser.add_argument("config", type=Path, help="検査する権限設定 JSON ファイルのパス")
    return parser


def _agent_name(config: object) -> str | None:
    name = config.get("agent_name") if isinstance(config, Mapping) else None
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None


def _configure_output() -> None:
    # cp932 などで表せない文字があっても異常終了しないようにする。
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="replace")


if __name__ == "__main__":
    sys.exit(main())
