"""レポートの表示モデル。

テンプレートに渡す前の構造だけを作る。HTML も CSV もここでは扱わない。
判定はせず、PlanResult と ScoreResult を並べ替えて束ねるだけ。

方針:
    - 同じ rule_id は概要で1件にまとめ、個別の URL と Evidence は保持する
    - 「次にやること」は severity と confidence の順で上位3件まで
    - confidence=low は通常の Finding と別の配列に分ける
    - 実行できなかった Collector と、エラーになった観測は「要確認」へ回す
    - 被覆率は数値と注記の両方を持つ。表示だけで成功と誤認させない
    - 秘密値は載せない。Evidence は ID と所在だけ

「要確認」が空であることは、安全を意味しない。status_note で必ず触れる。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from analyzer import priority as priority_module
from engine.rule_runner import SEVERITY_ORDER, Finding

MAX_ACTIONS = 3

#: 飛ばした理由の表示文。
SKIP_REASONS = {
    "not_consented": "同意されていないため実行していません",
    "empty": "結果が空でした",
    "budget": "予算または時間の都合で打ち切りました",
    "skipped_observation": "対象外として飛ばしました",
    "error_observation": "取得に失敗しました",
    "limit": "件数の上限に達しました",
}

COVERAGE_LOW = 0.5


class ReportError(Exception):
    """レポートを組み立てられない。"""


@dataclass(frozen=True)
class FindingGroup:
    rule_id: str
    title: str
    severity: str
    confidence: str
    subjects: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    count: int

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "subjects": list(self.subjects),
            "evidence_ids": list(self.evidence_ids),
            "count": self.count,
        }


@dataclass(frozen=True)
class Action:
    rule_id: str
    title: str
    severity: str
    reason: str
    fix: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "reason": self.reason,
            "fix": self.fix,
        }


@dataclass(frozen=True)
class ReviewItem:
    kind: str
    label: str
    detail: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "label": self.label, "detail": self.detail}


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    collector: str
    subject: str
    status: str

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "collector": self.collector,
            "subject": self.subject,
            "status": self.status,
        }


@dataclass(frozen=True)
class ReportModel:
    target: str
    generated_at: str
    overall: int
    level: str
    axes: dict[str, int]
    coverage: float | None
    counts: dict[str, int]
    status_note: str
    actions: tuple[Action, ...] = ()
    groups: tuple[FindingGroup, ...] = ()
    low_confidence: tuple[FindingGroup, ...] = ()
    needs_review: tuple[ReviewItem, ...] = ()
    evidence: tuple[EvidenceRef, ...] = ()
    previous: dict[str, Any] | None = None
    log: tuple[dict[str, Any], ...] = ()
    excluded_low_confidence: int = 0

    @property
    def review_count(self) -> int:
        return len(self.needs_review)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "overall": self.overall,
            "level": self.level,
            "axes": dict(self.axes),
            "coverage": self.coverage,
            "counts": dict(self.counts),
            "status_note": self.status_note,
            "review_count": self.review_count,
            "actions": [item.to_dict() for item in self.actions],
            "groups": [item.to_dict() for item in self.groups],
            "low_confidence": [item.to_dict() for item in self.low_confidence],
            "needs_review": [item.to_dict() for item in self.needs_review],
            "evidence": [item.to_dict() for item in self.evidence],
            "previous": self.previous,
            "log": list(self.log),
            "excluded_low_confidence": self.excluded_low_confidence,
        }


def _order(finding: Finding) -> tuple[int, int]:
    severity = SEVERITY_ORDER.index(finding.severity) if finding.severity in SEVERITY_ORDER else 0
    confidence = {"high": 2, "medium": 1, "low": 0}.get(finding.confidence, 0)
    return (severity, confidence)


def _group(findings: Iterable[Finding]) -> tuple[FindingGroup, ...]:
    """rule_id ごとにまとめる。並びは重大度の高い順。"""
    buckets: dict[str, list[Finding]] = {}
    for finding in findings:
        buckets.setdefault(finding.rule_id, []).append(finding)

    groups: list[FindingGroup] = []
    for rule_id, items in buckets.items():
        best = max(items, key=_order)
        groups.append(
            FindingGroup(
                rule_id=rule_id,
                title=best.title,
                severity=best.severity,
                confidence=best.confidence,
                subjects=tuple(dict.fromkeys(item.subject for item in items)),
                evidence_ids=tuple(
                    dict.fromkeys(eid for item in items for eid in item.evidence_ids)
                ),
                count=len(items),
            )
        )

    groups.sort(key=lambda group: (_order_key(group), group.rule_id), reverse=False)
    return tuple(sorted(groups, key=_order_key, reverse=True))


def _order_key(group: FindingGroup) -> tuple[int, int]:
    severity = SEVERITY_ORDER.index(group.severity) if group.severity in SEVERITY_ORDER else 0
    confidence = {"high": 2, "medium": 1, "low": 0}.get(group.confidence, 0)
    return (severity, confidence)


def _reason_for(reason: str) -> str:
    if reason.startswith("needs:"):
        return f"前提の Collector が実行できませんでした（{reason.split(':', 1)[1]}）"
    if reason.startswith("error:"):
        return f"実行中に例外が出ました（{reason.split(':', 1)[1]}）"
    return SKIP_REASONS.get(reason, reason)


def build(
    target: str,
    *,
    findings: Iterable[Finding] = (),
    low_confidence: Iterable[Finding] = (),
    correlations: Iterable[Finding] = (),
    low_correlations: Iterable[Finding] = (),
    observations: Iterable[Any] = (),
    skipped: Iterable[tuple[str, str]] = (),
    score_result: Any,
    previous: dict[str, Any] | None = None,
    log: Iterable[dict[str, Any]] = (),
    generated_at: str | None = None,
) -> ReportModel:
    """表示モデルを組み立てる。"""
    if not (target or "").strip():
        raise ReportError("target が空です")

    normal = [*findings, *correlations]
    low = [*low_confidence, *low_correlations]

    groups = _group(normal)
    ranked: list[Action] = []
    seen_rules: set[str] = set()
    for row in priority_module.priority_rows(normal):
        rule_id = str(row.get("rule_id") or "")
        if not rule_id or rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)
        ranked.append(Action(
            rule_id=rule_id,
            title=str(row.get("title") or ""),
            severity=str(row.get("severity") or ""),
            reason=(
                f"{row.get('priority') or ''}（{row.get('priority_score')}）"
                f" / {row.get('priority_reason') or ''}"
            ),
            fix=str(row.get("recommended_action") or ""),
        ))
        if len(ranked) >= MAX_ACTIONS:
            break

    if ranked:
        actions = tuple(ranked)
    else:
        # 優先度が付かない（INFO のみ等）場合は重大度順に戻す。
        actions = tuple(
            Action(
                rule_id=group.rule_id,
                title=group.title,
                severity=group.severity,
                reason=f"{group.count} 件の対象で観測されました",
                fix="",
            )
            for group in groups[:MAX_ACTIONS]
        )

    review: list[ReviewItem] = []
    for name, reason in skipped:
        review.append(ReviewItem(kind="collector", label=name, detail=_reason_for(reason)))

    evidence: list[EvidenceRef] = []
    for observation in observations:
        if getattr(observation, "is_error", False):
            review.append(
                ReviewItem(
                    kind="observation",
                    label=getattr(observation, "collector", "?"),
                    detail=getattr(observation, "note", "") or "取得に失敗しました",
                )
            )
        if getattr(observation, "has_evidence", False):
            evidence.append(
                EvidenceRef(
                    evidence_id=observation.evidence_id,
                    collector=observation.collector,
                    subject=observation.subject,
                    status=observation.status,
                )
            )

    coverage = getattr(score_result, "coverage", None)
    if coverage is not None and coverage < COVERAGE_LOW:
        review.append(
            ReviewItem(
                kind="coverage",
                label="被覆率",
                detail=f"{round(coverage * 100)}% しか実行できていません",
            )
        )

    status_note = (
        f"実行できていない項目が {len(review)} 件あります。0 件は安全を意味しません。"
        if review
        else "計画した Collector はすべて実行されました。"
    )

    return ReportModel(
        target=target.strip(),
        generated_at=generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        overall=int(getattr(score_result, "overall", 0)),
        level=str(getattr(score_result, "level", "LOW")),
        axes=dict(getattr(score_result, "axes", {})),
        coverage=coverage,
        counts=dict(getattr(score_result, "counts", {})),
        status_note=status_note,
        actions=actions,
        groups=groups,
        low_confidence=_group(low),
        needs_review=tuple(review),
        evidence=tuple(evidence),
        previous=previous,
        log=tuple(log),
        excluded_low_confidence=int(getattr(score_result, "excluded_low_confidence", 0)),
    )