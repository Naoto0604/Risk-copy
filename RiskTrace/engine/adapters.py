"""既存 checks.py の出力を Observation へ変換する暫定アダプタ。

checks.py はまだ severity を返す（絶対原則1には未準拠）。Collector 化は
Phase 5 で行うため、移行期間中はここで dict を Observation に包む。

severity は data に載せたまま残す。既存の scoring.py / priority.py が
今もこれを参照しているため、ここで落とすと既存機能が壊れる。
data["legacy"] = True を立て、移行途中の Observation を判別できるようにする。

取り込み規則は2段構え:
    1. LEGACY_COPY_KEYS のホワイトリスト（既知の意味を持つキー）
    2. それ以外で秘密名のキー（authorization など。値は Observation がマスクする）
無関係なキー（デバッグ用の内部値など）は引き継がない。

Phase 5 で collectors/http/ 配下の本実装ができたら、このモジュールは不要になる。
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

from engine.observations import Observation, is_secret_name

#: レガシー Finding から Observation へ引き継ぐ既知キー。
LEGACY_COPY_KEYS: tuple[str, ...] = (
    "type",
    "subtype",
    "title",
    "description",
    "evidence",
    "recommendation",
)

DEFAULT_COLLECTOR = "legacy_check"


def _collector_name(finding: Mapping, collector: str | None) -> str:
    """collector 名を決める。明示指定が最優先、次に finding["type"]。"""
    if collector is not None:
        if not collector.strip():
            raise ValueError("collector は空でない文字列である必要があります")
        return collector.strip()

    raw_type = finding.get("type")
    if isinstance(raw_type, str) and raw_type.strip():
        return raw_type.strip().lower()
    return DEFAULT_COLLECTOR


def _copy_value(value: Any) -> str | None:
    """文字列として意味のある値だけを返す。空文字と非文字列は None。"""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def from_legacy_finding(finding: Mapping[str, Any], *, collector: str | None = None) -> Observation:
    """レガシー Finding 1件を Observation に変換する。

    変換結果は status=ok の観測事実として扱う。Finding の有無ではなく
    「その検査が走って何を観測したか」を表すため、usable は True のまま。
    """
    if not isinstance(finding, Mapping):
        raise TypeError(f"finding は mapping である必要があります: {type(finding).__name__}")

    subject = finding.get("url")
    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("finding に url がありません")

    data: dict[str, Any] = {}

    for key in LEGACY_COPY_KEYS:
        copied = _copy_value(finding.get(key))
        if copied is not None:
            data[key] = copied

    # 秘密名のキーは、既知キーでなくても残す（値は Observation がマスクする）。
    for key, value in finding.items():
        if not isinstance(key, str) or key in LEGACY_COPY_KEYS or not is_secret_name(key):
            continue
        copied = _copy_value(value)
        if copied is not None:
            data[key] = copied

    severity = _copy_value(finding.get("severity"))
    if severity is not None:
        data["severity"] = severity.upper()

    data["legacy"] = True

    return Observation.ok(_collector_name(finding, collector), subject.strip(), data)


def from_legacy_findings(
    findings: Iterable[Mapping[str, Any]],
    *,
    collector: str | None = None,
) -> list[Observation]:
    """レガシー Finding の列を Observation の列に変換する。順序は保つ。"""
    if findings is None:
        return []
    return [from_legacy_finding(finding, collector=collector) for finding in findings]


def observations_from_checker(
    checker: Callable[[Any], Iterable[Mapping[str, Any]]],
    response: Any,
    *,
    collector: str | None = None,
) -> list[Observation]:
    """``checker(response) -> list[dict]`` 形式の既存検査をそのまま包む。

    Phase 5 までの間、checks.py の関数を Scheduler 配下で動かすための入口。
    """
    return from_legacy_findings(checker(response), collector=collector)