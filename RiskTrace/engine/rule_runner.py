"""Observation に対してルールを評価し、Finding を生成する。

Collector は判定しない。severity と confidence を決めるのはここだけ。

方針:
    - eval / exec を使わない。述語は型で分岐する
    - 参照した Observation の evidence_id を Finding に集める
    - Finding ID は rule_id と subject から決める（再実行で安定）
    - confidence=low の Finding は low_confidence 側に分ける
    - requires が満たされていないルールは適用しない
    - 1 ルールあたりの生成数に上限を置く（大量 URL での flooding 防止）

判断できない場合は Finding を作らない。作らないことは「安全」ではない。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Sequence

from engine.observations import Observation
from engine.rules import (
    AllPredicate,
    AnyPredicate,
    NotPredicate,
    ObsPredicate,
    Predicate,
    Rule,
    RuleSet,
)

MISSING = object()

#: 1 ルールあたりの Finding 上限。
MAX_FINDINGS_PER_RULE = 200

SEVERITY_ORDER: tuple[str, ...] = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class RuleRunError(Exception):
    """評価に失敗した。"""


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    subject: str
    message: str
    why: str
    fix: str
    verify: str
    evidence_ids: tuple[str, ...] = ()
    observed: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()

    @property
    def is_low_confidence(self) -> bool:
        return self.confidence == "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "subject": self.subject,
            "message": self.message,
            "why": self.why,
            "fix": self.fix,
            "verify": self.verify,
            "evidence_ids": list(self.evidence_ids),
            "observed": self.observed,
            "tags": list(self.tags),
        }


def finding_id(rule_id: str, subject: str) -> str:
    digest = hashlib.sha1(f"{rule_id}\x00{subject}".encode("utf-8")).hexdigest()
    return f"fnd_{digest[:16]}"


class ObservationIndex:
    """Collector 名で引ける Observation の索引。

    usable=False（skipped）は載せない。error は載せる。載せないと
    「取得に失敗した」ことすらルールから見えなくなる。
    """

    def __init__(self) -> None:
        self._by_collector: dict[str, list[Observation]] = {}
        self._all: list[Observation] = []

    def add(self, observation: Observation) -> None:
        if not observation.usable:
            return
        self._all.append(observation)
        self._by_collector.setdefault(observation.collector, []).append(observation)

    def extend(self, observations: Iterable[Observation]) -> None:
        for observation in observations:
            self.add(observation)

    def of(self, collector: str) -> tuple[Observation, ...]:
        return tuple(self._by_collector.get(collector, ()))

    def subjects(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(o.subject for o in self._all))

    def __len__(self) -> int:
        return len(self._all)


def _walk(value: Any, parts: Sequence[str]) -> Any:
    if not parts:
        return value
    head, rest = parts[0], parts[1:]
    if isinstance(value, dict):
        if head not in value:
            return MISSING
        return _walk(value[head], rest)
    if isinstance(value, (list, tuple)):
        # 配列は全要素を同じ残りパスで辿り、値のリストを返す。
        # ``cookies.attributes.secure`` のように配列の中を参照するため。
        collected = []
        for item in value:
            found = _walk(item, parts)
            if found is not MISSING:
                collected.append(found)
        return collected if collected else MISSING
    return MISSING

def lookup(observations: Iterable[Observation], ref: str) -> Iterator[tuple[Observation, Any]]:
    """``ref``（ドット区切り）を各 Observation の data から引く。"""
    parts = ref.split(".") if ref else []
    for observation in observations:
        value = _walk(observation.data, parts)
        if value is not MISSING:
            yield observation, value


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(str(item) for item in value)
    return str(value)


def _compare(op: str, value: Any, expected: Any, compiled) -> bool:
    if op == "present":
        return value is not None and value is not MISSING
    if op == "absent":
        return value is MISSING or value is None
    if op == "empty":
        return value is MISSING or value is None or value == "" or value == [] or value == {}
    if op == "eq":
        return value == expected
    if op == "ne":
        return value != expected
    if op == "in":
        return value in expected
    if op == "not_in":
        return value not in expected
    if op == "contains":
        if isinstance(value, (list, tuple)):
            return expected in value
        return str(expected) in _as_text(value)
    if op == "regex":
        return compiled is not None and compiled.search(_as_text(value)) is not None
    if op in ("gt", "lt"):
        try:
            left = float(value)
            right = float(expected)
        except (TypeError, ValueError):
            return False
        return left > right if op == "gt" else left < right
    raise RuleRunError(f"未実装の op: {op}")


def _matched(op: str, value: Any, expected: Any, compiled) -> bool:
    """op が成立しうる値かどうか（absent/present 系の前段判定）。"""
    return _compare(op, value, expected, compiled)


def evaluate_obs(predicate: ObsPredicate, index: ObservationIndex) -> tuple[bool, list[Observation], dict]:
    """obs 述語を評価する。戻り値は (成立, 参照した Observation, 観測値)。"""
    observations = index.of(predicate.collector)
    if not observations:
        # Collector が走っていない。present 系は不成立、absent 系は成立。
        if predicate.op in ("absent", "empty"):
            return True, [], {}
        return False, [], {}

    consulted: list[Observation] = []
    observed: dict[str, Any] = {}
    hits = 0
    total = 0

    for observation, value in lookup(observations, predicate.ref):
        total += 1
        consulted.append(observation)
        if _compare(predicate.op, value, predicate.value, predicate.compiled):
            hits += 1
            observed[observation.subject] = value

    if hits:
        return True, consulted, observed

    # 値が1件も無い場合の absent / empty は成立扱い。
    if total == 0 and predicate.op in ("absent", "empty"):
        return True, [], {}
    return False, consulted, observed


def evaluate(predicate: Predicate, index: ObservationIndex) -> tuple[bool, list[Observation], dict]:
    if isinstance(predicate, ObsPredicate):
        return evaluate_obs(predicate, index)

    if isinstance(predicate, NotPredicate):
        result, consulted, observed = evaluate(predicate.child, index)
        return (not result), consulted, observed

    if isinstance(predicate, AllPredicate):
        consulted: list[Observation] = []
        observed: dict[str, Any] = {}
        for child in predicate.children:
            result, child_consulted, child_observed = evaluate(child, index)
            consulted.extend(child_consulted)
            if not result:
                return False, consulted, observed
            observed.update(child_observed)
        return True, consulted, observed

    if isinstance(predicate, AnyPredicate):
        consulted = []
        observed = {}
        for child in predicate.children:
            result, child_consulted, child_observed = evaluate(child, index)
            consulted.extend(child_consulted)
            if result:
                observed.update(child_observed)
                return True, consulted, observed
        return False, consulted, observed

    raise RuleRunError(f"未知の述語型: {type(predicate).__name__}")


def _subjects_for(rule: Rule, index: ObservationIndex) -> list[str]:
    subjects: list[str] = []
    for collector in rule.collectors:
        for observation in index.of(collector):
            if observation.subject not in subjects:
                subjects.append(observation.subject)
    return subjects


def run_rule(
    rule: Rule,
    index: ObservationIndex,
    *,
    satisfied: frozenset[str] = frozenset(),
) -> list[Finding]:
    """1 ルールを評価して Finding を作る。"""
    if not set(rule.requires) <= satisfied:
        return []

    findings: list[Finding] = []
    for subject in _subjects_for(rule, index):
        matched, consulted, observed = evaluate(rule.when, index)
        if not matched:
            continue

        evidence = tuple(
            dict.fromkeys(
                o.evidence_id for o in consulted if o.evidence_id is not None
            )
        )
        findings.append(
            Finding(
                id=finding_id(rule.id, subject),
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                subject=subject,
                message=rule.message,
                why=rule.why,
                fix=rule.fix,
                verify=rule.verify,
                evidence_ids=evidence,
                observed={subject: observed.get(subject)},
                tags=rule.tags,
            )
        )
        if len(findings) >= MAX_FINDINGS_PER_RULE:
            break

    return findings


def run(
    ruleset: RuleSet,
    observations: Iterable[Observation],
    *,
    satisfied: frozenset[str] = frozenset(),
) -> tuple[list[Finding], list[Finding]]:
    """ルールセットを実行する。

    戻り値は ``(通常の Finding, confidence=low の Finding)``。
    重複は rule_id と subject で落とす。
    """
    index = ObservationIndex()
    index.extend(observations)

    seen: set[tuple[str, str]] = set()
    normal: list[Finding] = []
    low: list[Finding] = []

    for rule in ruleset:
        for finding in run_rule(rule, index, satisfied=satisfied):
            key = (finding.rule_id, finding.subject)
            if key in seen:
                continue
            seen.add(key)
            (low if finding.is_low_confidence else normal).append(finding)

    return normal, low


def by_severity(findings: Iterable[Finding]) -> list[Finding]:
    """重大度の高い順に並べる。"""
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 0,
        reverse=True,
    )