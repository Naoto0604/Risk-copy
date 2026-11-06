"""観測から攻撃経路を組み立てる。

経路は Finding ではない。スコアには直接加算せず、優先度の理由付けと
画面の「経路」欄にだけ使う。

方針:
    - 材料は Finding の rule_id と subject だけ。観測の再解釈はしない
    - 同じ subject で条件が揃ったときだけ1本作る
    - 断定ではなく「〜につながる可能性」と書く
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from engine.rule_runner import Finding

#: HTTPS 未使用を表す rule_id。
INSECURE_TRANSPORT = "transport.https-missing"

#: セッション保護の不足。
COOKIE_WEAK = frozenset({
    "cookies.over-http",
    "cookies.secure-missing",
    "cookies.httponly-missing",
    "cookies.samesite-missing",
    "cookies.samesite-none",
})

#: ブラウザ側の防御不足。
HEADER_WEAK = frozenset({
    "headers.csp-missing",
    "headers.x-content-type-options-missing",
    "headers.x-frame-options-missing",
    "headers.referrer-policy-missing",
})


@dataclass(frozen=True)
class AttackPath:
    key: str
    title: str
    severity: str
    subject: str
    steps: tuple[str, ...]
    description: str
    rule_ids: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "severity": self.severity,
            "subject": self.subject,
            "steps": list(self.steps),
            "description": self.description,
            "rule_ids": list(self.rule_ids),
        }


_COOKIE_PATH = AttackPath(
    key="path:insecure-transport-cookie",
    title="通信保護の不足からセッションリスクにつながる可能性",
    severity="HIGH",
    subject="",
    steps=(
        "HTTPS未使用",
        "Cookie保護属性の不足",
        "セッション情報が盗聴されうる可能性",
        "セッション奪用につながる可能性",
    ),
    description=(
        "HTTPS が使用されておらず、さらに Cookie の保護属性にも不足があるため、"
        "通信およびセッション保護に関する攻撃経路が成立する可能性があります。"
    ),
    rule_ids=(),
)

_HEADER_PATH = AttackPath(
    key="path:insecure-transport-header",
    title="通信保護の不足とブラウザ防御不足による攻撃リスク",
    severity="HIGH",
    subject="",
    steps=(
        "HTTPS未使用",
        "セキュリティヘッダー不足",
        "ブラウザ側の防御機構が不十分",
        "Web攻撃につながる可能性",
    ),
    description=(
        "HTTPS が使用されておらず、さらにセキュリティヘッダーも不足しているため、"
        "複数の防御機構が不足した状態となっています。"
    ),
    rule_ids=(),
)


def _by_subject(findings: Iterable[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.subject, []).append(finding)
    return grouped


def _build(template: AttackPath, subject: str, items: list[Finding]) -> AttackPath:
    return AttackPath(
        key=template.key,
        title=template.title,
        severity=template.severity,
        subject=subject,
        steps=template.steps,
        description=template.description,
        rule_ids=tuple(sorted({item.rule_id for item in items})),
    )


def generate(findings: Iterable[Finding]) -> tuple[AttackPath, ...]:
    """条件が揃った subject について経路を作る。"""
    paths: list[AttackPath] = []

    for subject, items in _by_subject(findings).items():
        if not subject:
            continue
        rule_ids = {item.rule_id for item in items}
        if INSECURE_TRANSPORT not in rule_ids:
            continue

        if rule_ids & COOKIE_WEAK:
            paths.append(_build(_COOKIE_PATH, subject, items))
        if rule_ids & HEADER_WEAK:
            paths.append(_build(_HEADER_PATH, subject, items))

    return tuple(paths)