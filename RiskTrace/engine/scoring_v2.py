"""3軸スコア。

スコアは判定ではなく要約。Finding の severity と confidence を材料にするが、
Finding を作り直すことはしない。

方針:
    - 軸は影響・到達可能性・露出度の3つ。それぞれ独立に 0..100
    - 同じ rule_id は1回だけ数える（個別の evidence_id は保持する）
    - confidence=low は既定で除外し、件数だけ別に返す
    - 軸は飽和関数で丸める。件数が増えても 100 を超えない
    - 被覆率は別に返す。スコアと混ぜず、参考値として下げるだけ
    - 既存 scoring.py の閾値（90/70/30）をそのまま使う

CVE 候補は INFO 扱いなので、スコアを押し上げない。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from engine.rule_runner import Finding

#: severity が影響軸へ寄与する量。
SEVERITY_IMPACT = {
    "CRITICAL": 10.0,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFO": 0.5,
}

#: confidence による減衰。
CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.7, "low": 0.4}

#: タグから到達可能性軸への寄与。
TAG_REACHABILITY = {
    "exposure": 8.0,
    "transport": 6.0,
    "tls": 6.0,
    "browser": 5.0,
    "cookie": 4.0,
}
DEFAULT_REACHABILITY = 3.0

#: タグから露出度軸への寄与。
TAG_EXPOSURE = {
    "exposure": 6.0,
    "privacy": 4.0,
    "transport": 3.0,
}
DEFAULT_EXPOSURE = 2.0

#: 飽和関数の半減定数。小さいほど少ない件数で立ち上がる。
#: 実測で 1 件の CRITICAL が 14/100 と低すぎたため、低件数側を上げた。
HALF = {"impact": 8.0, "reachability": 40.0, "exposure": 32.0}

#: 総合への重み。
AXIS_WEIGHTS = {"impact": 0.5, "reachability": 0.3, "exposure": 0.2}

#: 既存 scoring.py と同じ閾値。
LEVELS = ((90, "CRITICAL"), (70, "HIGH"), (30, "MEDIUM"), (0, "LOW"))

CONFIDENCE_ORDER = ("low", "medium", "high")


class ScoringError(Exception):
    """採点に失敗した。"""


@dataclass(frozen=True)
class ScoreResult:
    overall: int
    level: str
    axes: dict[str, int]
    counts: dict[str, int] = field(default_factory=dict)
    coverage: float | None = None
    excluded_low_confidence: int = 0
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "overall": self.overall,
            "level": self.level,
            "axes": dict(self.axes),
            "counts": dict(self.counts),
            "coverage": self.coverage,
            "excluded_low_confidence": self.excluded_low_confidence,
            "evidence_ids": list(self.evidence_ids),
        }


def _level(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "LOW"


def _saturate(total: float, half: float) -> int:
    if total <= 0:
        return 0
    value = 100.0 * (1.0 - 2.0 ** (-total / half))
    return max(0, min(100, round(value)))


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """rule_id ごとに severity の高い1件だけ残す。evidence は寄せる。"""
    best: dict[str, Finding] = {}
    for finding in findings:
        current = best.get(finding.rule_id)
        if current is None:
            best[finding.rule_id] = finding
            continue

        if SEVERITY_IMPACT.get(finding.severity, 0) > SEVERITY_IMPACT.get(current.severity, 0):
            merged = tuple(dict.fromkeys(current.evidence_ids + finding.evidence_ids))
            best[finding.rule_id] = Finding(
                id=finding.id,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                confidence=finding.confidence,
                subject=finding.subject,
                message=finding.message,
                why=finding.why,
                fix=finding.fix,
                verify=finding.verify,
                evidence_ids=merged,
                observed=finding.observed,
                tags=finding.tags,
            )
        else:
            merged = tuple(dict.fromkeys(current.evidence_ids + finding.evidence_ids))
            best[finding.rule_id] = Finding(
                id=current.id,
                rule_id=current.rule_id,
                title=current.title,
                severity=current.severity,
                confidence=current.confidence,
                subject=current.subject,
                message=current.message,
                why=current.why,
                fix=current.fix,
                verify=current.verify,
                evidence_ids=merged,
                observed=current.observed,
                tags=current.tags,
            )

    return list(best.values())


def _tag_sum(tags: tuple[str, ...], table: dict[str, float], default: float) -> float:
    values = [table[tag] for tag in tags if tag in table]
    return max(values) if values else default


def score(
    findings,
    *,
    executed: int = 0,
    planned: int = 0,
    include_low_confidence: bool = False,
) -> ScoreResult:
    """Finding 群を採点する。"""
    items = [f for f in findings if isinstance(f, Finding)]

    low = [f for f in items if f.is_low_confidence]
    if include_low_confidence:
        target = items
        excluded = 0
    else:
        target = [f for f in items if not f.is_low_confidence]
        excluded = len(low)

    unique = _dedupe(target)

    impact = reachability = exposure = 0.0
    for finding in unique:
        weight = CONFIDENCE_WEIGHT.get(finding.confidence, 0.5)
        impact += SEVERITY_IMPACT.get(finding.severity, 0.0) * weight
        reachability += _tag_sum(finding.tags, TAG_REACHABILITY, DEFAULT_REACHABILITY) * weight
        exposure += _tag_sum(finding.tags, TAG_EXPOSURE, DEFAULT_EXPOSURE) * weight

    axes = {
        "impact": _saturate(impact, HALF["impact"]),
        "reachability": _saturate(reachability, HALF["reachability"]),
        "exposure": _saturate(exposure, HALF["exposure"]),
    }

    raw = sum(axes[axis] * weight for axis, weight in AXIS_WEIGHTS.items())

    coverage = None
    if planned > 0:
        coverage = max(0.0, min(1.0, executed / planned))
        raw *= 0.7 + 0.3 * coverage

    overall = max(0, min(100, round(raw)))

    counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for finding in unique:
        if finding.severity in counts:
            counts[finding.severity] += 1

    evidence = tuple(
        dict.fromkeys(
            evidence_id for finding in unique for evidence_id in finding.evidence_ids
        )
    )

    return ScoreResult(
        overall=overall,
        level=_level(overall),
        axes=axes,
        counts=counts,
        coverage=None if coverage is None else round(coverage, 3),
        excluded_low_confidence=excluded,
        evidence_ids=evidence,
    )