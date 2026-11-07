"""診断の実行サービス。

ゲート → Job 投入 → 実行 → 採点 → レポート、を1本にまとめる。
呼び出し側はここだけ知っていればよい。

方針:
    - 同意があればゲートに通し、許可された Collector だけを実行する
    - 予算とスコープはゲートの結果をそのまま使う。ここで作らない
    - 実行は Worker 経由。lease・heartbeat・中断の扱いを迂回しない
    - 採点とレポートは実行結果から組み立てる。表示の判断はしない
    - ゲート拒否は GateError のまま投げる

同期実行（``run_scan``）はテストと単発実行用。常駐は ``enqueue_scan`` と
別プロセスの Worker に任せる。
"""

from __future__ import annotations
from urllib.parse import urlsplit
from dataclasses import dataclass, replace
from typing import Any, Iterable
from database import report_store
from engine import scoring_v2
from database import queue as queue_module
from engine import cve
from engine import attack_path
from engine import plan
from engine.correlation import load_correlations_from_dir, run as run_correlations
from engine.rule_runner import run as run_rules
from engine.rules import RuleSet, load_rules_from_dir
from engine.worker import Worker
from report import model
from verification import gate as gate_module
from verification.scope import build_checker
from collections import OrderedDict

_LAST_REPORTS: "OrderedDict[str, model.ReportModel]" = OrderedDict()
_MAX_KEPT_REPORTS = 50


def _remember(scan_id: str, report: model.ReportModel) -> None:
    _LAST_REPORTS[scan_id] = report
    _LAST_REPORTS.move_to_end(scan_id)
    while len(_LAST_REPORTS) > _MAX_KEPT_REPORTS:
        _LAST_REPORTS.popitem(last=False)


def last_report(scan_id: str) -> dict:
    """保存済みのレポートを返す。無ければ KeyError。"""
    stored = report_store.load_report(scan_id)
    if stored is None:
        raise KeyError(f"レポートがありません: {scan_id}")
    return stored
REQUIREMENTS: tuple[str, ...] = ("proof", "consent")


@dataclass(frozen=True)
class ServiceResult:
    job_id: str | None
    status: str
    score: Any
    report: model.ReportModel
    plan_result: plan.PlanResult
    paths: tuple = ()

    @property
    def findings(self) -> tuple:
        return self.plan_result.findings + self.plan_result.correlations


def enqueue_scan(scan_id: str) -> str:
    """Job を投入して Job ID を返す。実行は Worker に任せる。"""
    return queue_module.enqueue(scan_id)


def run_scan(
    scan_id: str,
    *,
    consent_id: str | None = None,
    allowed: Iterable[str] | None = None,
    satisfied: Iterable[str] = REQUIREMENTS,
    steps: Iterable[plan.Step] = plan.DEFAULT_STEPS,
    rules: RuleSet | None = None,
    correlations: RuleSet | None = None,
    budgets: Any = None,
    scope: Any = None,
    worker_options: dict[str, Any] | None = None,
    cve_lookup: bool = True,
) -> ServiceResult:
    """1 回分の診断を実行し、結果を返す。

    ``consent_id`` を渡すとゲートを通す。省略時は ``allowed`` をそのまま使う。
    """
    target = plan.target_of(_Job(scan_id))
    step_list = list(steps)

    if consent_id is not None:
        host = urlsplit(target).hostname or ""
        result = gate_module.ensure(host, consent_id=consent_id)

        allowed = result.consent.allowed_collectors if result.consent else allowed
        budgets = result.budgets
        scope = build_checker(result.scope) if result.scope is not None else scope

    captured: dict[str, plan.PlanResult] = {}
    planned = len(step_list)

    def runner(job, scheduler):
        outcome = plan.run_plan(
            target,
            scheduler,
            job_id=getattr(job, "id", None),
            steps=step_list,
            allowed=allowed,
            satisfied=satisfied,
            rules=rules,
            correlations=correlations,
        )
        captured["plan"] = outcome

        skipped = len(outcome.skipped)
        note = None
        if skipped:
            note = f"飛ばした Collector: {skipped} 件"
        status = queue_module.PARTIAL if skipped else queue_module.COMPLETED
        from engine.worker import RunResult

        return RunResult(status=status, note=note)

    options = dict(worker_options or {})
    if budgets is not None:
        options.setdefault("budgets", budgets)
    if scope is not None:
        options.setdefault("scope", scope)

    worker = Worker(runner, **options)
    job_id = enqueue_scan(scan_id)

    try:
        status = worker.run_once() or queue_module.FAILED
    finally:
        worker.stop()

    plan_result = captured.get("plan") or plan.PlanResult()
    paths = attack_path.generate(plan_result.findings)
    executed = max(0, planned - len(plan_result.skipped))

    if cve_lookup:
        extra = cve.lookup_from_observations(plan_result.observations)
        if extra:
            plan_result = replace(
                plan_result, findings=plan_result.findings + tuple(extra)
            )
    score_result = scoring_v2.score(        
        [*plan_result.findings, *plan_result.correlations],
        executed=executed,
        planned=planned,
    )

    report = model.build(
        target,
        findings=plan_result.findings,
        low_confidence=plan_result.low_confidence,
        correlations=plan_result.correlations,
        low_correlations=plan_result.low_correlations,
        observations=plan_result.observations,
        skipped=plan_result.skipped,
        score_result=score_result,
        log=worker.log(),
        paths=paths,
    )
    previous = report_store.previous_for(target, exclude_scan_id=scan_id)
    if previous is not None:
        report = model.build(
            target,
            findings=plan_result.findings,
            low_confidence=plan_result.low_confidence,
            correlations=plan_result.correlations,
            low_correlations=plan_result.low_correlations,
            observations=plan_result.observations,
            skipped=plan_result.skipped,
            score_result=score_result,
            previous=previous,
            log=worker.log(),
            paths=paths,
        )

    report_store.save_report(
        scan_id,
        report,
        findings=plan_result.findings + plan_result.correlations,
        low_confidence=plan_result.low_confidence + plan_result.low_correlations,
    )
    _remember(scan_id, report)

    return ServiceResult(
        job_id=job_id,
        status=status,
        score=score_result,
        report=report,
        plan_result=plan_result,
        paths=paths,
    )


class _Job:
    """``plan.target_of`` に渡すための最小の Job。"""

    __slots__ = ("scan_id",)

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id