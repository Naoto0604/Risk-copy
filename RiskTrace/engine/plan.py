"""診断の実行計画。

Collector を順に呼び、Observation を Evidence に保存し、ルールと相関へ渡す。
部品同士を繋ぐのはここだけで、各 Collector は互いを知らない。

方針:
    - 実行順は明示。前提のある Collector は前提が成功しなければ飛ばす
    - 同意されていない Collector は飛ばす（理由を残す）
    - 保存できた Observation だけをルールに渡す。保存前の生データは使わない
    - 中断は伝播させる。個々の Collector の失敗は記録して先へ進む
    - 判断はせず、判定はすべてルール側に任せる

予算・スコープ・時間は渡された Scheduler が持つ。ここでは作らない。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit
from database import db
from collectors.baas import endpoints as baas
from collectors.dns import records
from collectors.explore import assets, crawl, discover, repo, subdomains
from collectors.http import cookies, cors, headers, redirects, transport
from collectors.ports import scan as ports
from collectors.tls import probe as tls
from engine.correlation import load_correlations_from_dir, run as run_correlations
from engine.observations import Observation
from engine.rule_runner import Finding, ObservationIndex, run as run_rules
from engine.rules import RuleSet, load_rules_from_dir
from evidence import store

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
CORRELATIONS_DIR = RULES_DIR / "correlations"

def load_all_rules() -> RuleSet:
    """カテゴリ別ディレクトリのルールをまとめて読む。

    ``rules/`` 直下には YAML を置かない。``correlations`` は相関用の書式
    なので、通常ルールとしては読まない。
    """
    if not RULES_DIR.is_dir():
        return RuleSet()

    rules: list = []
    for directory in sorted(RULES_DIR.iterdir()):
        if not directory.is_dir() or directory.name == "correlations":
            continue
        rules.extend(load_rules_from_dir(directory).rules)
    return RuleSet(tuple(rules))

@dataclass(frozen=True)
class Step:
    """1 Collector の実行単位。"""

    name: str
    collect: Callable[[str, Any, dict], Any]
    needs: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlanResult:
    observations: tuple[Observation, ...] = ()
    findings: tuple[Finding, ...] = ()
    low_confidence: tuple[Finding, ...] = ()
    correlations: tuple[Finding, ...] = ()
    low_correlations: tuple[Finding, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()

    def __len__(self) -> int:
        return len(self.observations)


def _host(url: str) -> str:
    return urlsplit(url).hostname or ""


def _dns_step(url: str, scheduler, context: dict) -> Observation:
    host = _host(url)
    if not host:
        return Observation.skipped(records.COLLECTOR, url, "ホスト名を取得できません")
    return records.collect(host, scheduler)


def _assets_step(url: str, scheduler, context: dict) -> Observation:
    urls = context.get("urls") or []
    if not urls:
        return Observation.skipped(assets.COLLECTOR, url, "対象 URL がありません")
    return assets.collect(urls, scheduler)


def _baas_step(url: str, scheduler, context: dict) -> Observation:
    documents = context.get("documents") or []
    if not documents:
        return Observation.skipped(baas.COLLECTOR, url, "本文が渡されていません")
    return baas.collect(documents, scheduler, asset_urls=context.get("asset_urls") or ())


#: 実行順。前提は左から満たされる。
DEFAULT_STEPS: tuple[Step, ...] = (
    Step("http_transport", lambda url, scheduler, context: transport.collect(url)),
    Step("http_headers", lambda url, scheduler, context: headers.collect(url, scheduler)),
    Step("http_cookies", lambda url, scheduler, context: cookies.collect(url, scheduler)),
    Step("tls", lambda url, scheduler, context: tls.collect(url, scheduler)),
    Step("http_redirects", lambda url, scheduler, context: redirects.collect(url, scheduler)),
    Step("dns", _dns_step),
    Step("explore_repo", lambda url, scheduler, context: repo.collect(url, scheduler)),
    Step("explore_discover", lambda url, scheduler, context: discover.collect(url, scheduler)),
    Step("explore_crawl", lambda url, scheduler, context: crawl.collect(url, scheduler)),
    Step("explore_assets", _assets_step, needs=("explore_crawl",)),
    Step("explore_subdomains", lambda url, scheduler, context: subdomains.collect(url, scheduler)),
    Step("ports", lambda url, scheduler, context: ports.collect(url, scheduler)),
)


def _as_list(result: Any) -> list[Observation]:
    if result is None:
        return []
    if isinstance(result, Observation):
        return [result]
    return [item for item in result if isinstance(item, Observation)]


def run_plan(
    target: str,
    scheduler,
    *,
    job_id: str | None = None,
    steps: Iterable[Step] = DEFAULT_STEPS,
    allowed: Iterable[str] | None = None,
    satisfied: Iterable[str] = (),
    rules: RuleSet | None = None,
    correlations: RuleSet | None = None,
    save_evidence: bool = True,
) -> PlanResult:
    """計画を実行し、保存済み Observation から Finding を作る。"""
    if not (target or "").strip():
        raise ValueError("target が空です")

    permitted = None if allowed is None else set(allowed)
    observations: list[Observation] = []
    skipped: list[tuple[str, str]] = []
    context: dict = {"urls": []}
    done: set[str] = set()
    failed: set[str] = set()

    for step in steps:
        scheduler.check_cancel()

        if permitted is not None and step.name not in permitted:
            skipped.append((step.name, "not_consented"))
            continue

        unmet = [need for need in step.needs if need not in done or need in failed]
        if unmet:
            skipped.append((step.name, f"needs:{unmet[0]}"))
            continue

        try:
            produced = _as_list(step.collect(target, scheduler, context))
        except Exception as exc:  # noqa: BLE001 - 1 段の失敗で計画全体を落とさない
            failed.add(step.name)
            skipped.append((step.name, f"error:{type(exc).__name__}"))
            continue

        if not produced:
            failed.add(step.name)
            skipped.append((step.name, "empty"))
            continue

        done.add(step.name)

        if any(observation.is_error for observation in produced):
            failed.add(step.name)
            skipped.append((step.name, "error_observation"))
        elif all(observation.is_skipped for observation in produced):
            skipped.append((step.name, "skipped_observation"))

        for observation in produced:
            saved = observation
            if save_evidence and observation.usable:
                saved = store.save_observation(observation, job_id=job_id)
            observations.append(saved)

            for url in saved.data.get("urls") or ():
                if isinstance(url, str) and url not in context["urls"]:
                    context["urls"].append(url)

    usable = tuple(o for o in observations if o.usable)

    index = ObservationIndex()
    index.extend(usable)

    ruleset = rules if rules is not None else load_all_rules()
    findings, low = run_rules(ruleset, usable, satisfied=frozenset(satisfied))

    correlation_set = (
        correlations if correlations is not None else load_correlations_from_dir(CORRELATIONS_DIR)
    )
    correlated = run_correlations(correlation_set, index, target=target, satisfied=satisfied)

    return PlanResult(
        observations=tuple(observations),
        findings=tuple(findings),
        low_confidence=tuple(low),
        correlations=correlated.findings,
        low_correlations=correlated.low_confidence,
        skipped=tuple(skipped),
    )

def target_of(job: Any) -> str:
    """Job から対象 URL を引く。"""
    scan_id = getattr(job, "scan_id", None)
    if not scan_id:
        raise ValueError("job に scan_id がありません")

    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT target_url FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise ValueError(f"scan が見つかりません: {scan_id}")

    value = row[0]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"scan に対象 URL がありません: {scan_id}")
    return value.strip()


def make_runner(
    resolve_target: Callable[[Any], str] | None = None,
    *,
    allowed: Iterable[str] | None = None,
    satisfied: Iterable[str] = (),
    steps: Iterable[Step] = DEFAULT_STEPS,
):
    """Worker に差し込む runner を作る。

    ``resolve_target`` を省略すると ``target_of`` を使う。
    ゲート通過は呼び出し側の責任。
    """
    from database import queue as queue_module
    from engine.worker import RunResult

    resolve = resolve_target or target_of

    def runner(job: Any, scheduler) -> Any:
        target = resolve(job)

        result = run_plan(
            target,
            scheduler,
            job_id=getattr(job, "id", None),
            steps=steps,
            allowed=allowed,
            satisfied=satisfied,
        )

        note = None
        if result.skipped:
            note = "飛ばした Collector: " + ", ".join(name for name, _reason in result.skipped)

        status = queue_module.PARTIAL if result.skipped else queue_module.COMPLETED
        return RunResult(status=status, note=note)

    return runner