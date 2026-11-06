"""複数の Observation をまたぐ相関ルール。

単一 Observation で出ない組み合わせだけを扱う。severity と confidence を
決めるのはここも同じ。Collector は判定しない。

方針:
    - ルールは ``collectors`` に 2 つ以上の Collector を要求する
    - 前提 Collector の観測が 1 つでも欠けたら評価しない（推測で埋めない）
    - 述語評価と Finding は rule_runner をそのまま使う
    - Finding の rule_id には ``corr:`` を付け、単一ルールと出所を分ける
    - 対象は診断対象 1 つに固定する（Observation の subject ではない）
    - confidence=low は別枠へ分ける

前提が欠けた場合は Finding を作らない。作らないことは「安全」ではない。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from engine.rule_runner import (
    MAX_FINDINGS_PER_RULE,
    Finding,
    ObservationIndex,
    evaluate,
    finding_id,
)
from engine.rules import (
    AllPredicate,
    AnyPredicate,
    NotPredicate,
    ObsPredicate,
    Predicate,
    Rule,
    RuleLoadError,
    RuleSet,
    load_rules_from_text,
)

CORRELATION_PREFIX = "corr:"

MIN_COLLECTORS = 2


@dataclass(frozen=True)
class CorrelationResult:
    findings: tuple[Finding, ...] = ()
    low_confidence: tuple[Finding, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()

    def __len__(self) -> int:
        return len(self.findings) + len(self.low_confidence)


def _predicate_collectors(predicate: Predicate) -> set[str]:
    """述語木が参照する Collector 名。"""
    if isinstance(predicate, ObsPredicate):
        return {predicate.collector}
    if isinstance(predicate, NotPredicate):
        return _predicate_collectors(predicate.child)
    if isinstance(predicate, (AllPredicate, AnyPredicate)):
        found: set[str] = set()
        for child in predicate.children:
            found |= _predicate_collectors(child)
        return found
    return set()


def _validate(ruleset: RuleSet, source: str) -> None:
    """相関ルール固有の検証。"""
    errors: list[str] = []

    for rule in ruleset.rules:
        if len(set(rule.collectors)) < MIN_COLLECTORS:
            errors.append(
                f"{source}: {rule.id}: collectors には {MIN_COLLECTORS} つ以上が必要です"
            )

        referenced = _predicate_collectors(rule.when)
        unknown = sorted(referenced - set(rule.collectors))
        if unknown:
            errors.append(
                f"{source}: {rule.id}: when が collectors にない参照を使っています: {unknown}"
            )

    if errors:
        raise RuleLoadError(errors)


def load_correlations_from_text(text: str, source: str = "<memory>") -> RuleSet:
    ruleset = load_rules_from_text(text, source)
    _validate(ruleset, source)
    return ruleset


def load_correlations_from_dir(directory: str | Path) -> RuleSet:
    """``*.yaml`` / ``*.yml`` を読む。無ければ空。"""
    path = Path(directory)
    if not path.is_dir():
        return RuleSet()

    rules: list[Rule] = []
    errors: list[str] = []

    for file in sorted({*path.glob("*.yaml"), *path.glob("*.yml")}):
        try:
            ruleset = load_correlations_from_text(file.read_text(encoding="utf-8"), file.name)
        except RuleLoadError as exc:
            errors.extend(exc.errors)
            continue
        rules.extend(ruleset.rules)

    if errors:
        raise RuleLoadError(errors)

    seen: dict[str, str] = {}
    for rule in rules:
        if rule.id in seen:
            errors.append(f"{rule.source}: 相関ルール ID が重複しています: {rule.id}")
        seen[rule.id] = rule.source
    if errors:
        raise RuleLoadError(errors)

    return RuleSet(tuple(rules))


def _evidence(consulted: Iterable) -> tuple[str, ...]:
    ids = {
        observation.evidence_id
        for observation in consulted
        if getattr(observation, "has_evidence", False)
    }
    return tuple(sorted(ids))


def run(
    ruleset: RuleSet,
    index: ObservationIndex,
    *,
    target: str,
    satisfied: Iterable[str] = (),
) -> CorrelationResult:
    """相関ルールを評価する。前提が欠けたルールは飛ばす。"""
    if not (target or "").strip():
        raise ValueError("target が空です")

    required = set(satisfied)
    findings: list[Finding] = []
    low: list[Finding] = []
    skipped: list[tuple[str, str]] = []

    for rule in ruleset.rules:
        if len(findings) + len(low) >= MAX_FINDINGS_PER_RULE:
            skipped.append((rule.id, "limit"))
            continue

        if rule.requires and not set(rule.requires) <= required:
            skipped.append((rule.id, "requires"))
            continue

        missing = [name for name in rule.collectors if not index.of(name)]
        if missing:
            skipped.append((rule.id, f"missing_collector:{missing[0]}"))
            continue

        matched, consulted, observed = evaluate(rule.when, index)
        if not matched:
            skipped.append((rule.id, "no_match"))
            continue

        rule_id = f"{CORRELATION_PREFIX}{rule.id}"
        finding = Finding(
            id=finding_id(rule_id, target),
            rule_id=rule_id,
            title=rule.title,
            severity=rule.severity,
            confidence=rule.confidence,
            subject=target,
            message=rule.message,
            why=rule.why,
            fix=rule.fix,
            verify=rule.verify,
            evidence_ids=_evidence(consulted),
            observed=observed,
            tags=rule.tags,
        )

        if finding.is_low_confidence:
            low.append(finding)
        else:
            findings.append(finding)

    return CorrelationResult(tuple(findings), tuple(low), tuple(skipped))