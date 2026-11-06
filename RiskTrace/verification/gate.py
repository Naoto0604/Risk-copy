"""診断開始ゲート。

所有証明・同意・スコープの三者が揃っていることを確認してから、
診断に使う Scheduler を組み立てる。

規則（§4.10〜§4.12）:
    - 通常の診断 Collector は proof と consent の両方を要求する
    - 証明確認の限定通信だけは proof のみで通る（§4.11）
    - 証明対象・同意対象・実対象の範囲が一致しなければ拒否する
      → 同意スコープの全ホストに有効な証明が必要
    - 同意は ACTIVE かつ期限内であること
    - 許可されていない Collector は動かせない

proof のみで通した場合は同意が無いので、証明確認専用の最小スコープ
（ホストは対象のみ・ポートは 80/443）と既定予算を返す。診断 Collector は
``allows_collector`` が False になるため、そのままでは動かせない。

拒否は理由を全部集めて返す。1回の呼び出しで不足が分かるようにする。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from engine.scheduler import Budgets, Scheduler
from verification import consent as consent_module
from verification import ownership
from verification.scope import Scope, build_checker

CONSENT = "consent"
PROOF = "proof"

REQUIREMENTS: tuple[str, ...] = (CONSENT, PROOF)

#: 証明確認だけに使う最小スコープのポート。
PROOF_ONLY_PORTS: frozenset[int] = frozenset({80, 443})


class GateError(Exception):
    """診断を開始できない。``reasons`` に全件を保持する。"""

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = list(reasons)
        super().__init__(" / ".join(self.reasons))


@dataclass(frozen=True)
class GateResult:
    allowed: bool
    target: str
    reasons: tuple[str, ...] = ()
    consent: consent_module.Consent | None = None
    scope: Scope | None = None
    budgets: Budgets | None = None
    verified_hosts: frozenset[str] = field(default_factory=frozenset)

    @property
    def proof_only(self) -> bool:
        """同意なしで証明だけ通した状態か。"""
        return self.allowed and self.consent is None

    def allows_collector(self, name: str) -> bool:
        if self.consent is None:
            return False
        return name in self.consent.allowed_collectors

    def require_collector(self, name: str) -> None:
        if not self.allows_collector(name):
            raise GateError([f"同意されていない Collector です: {name}"])

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "target": self.target,
            "reasons": list(self.reasons),
            "verified_hosts": sorted(self.verified_hosts),
            "consent_id": self.consent.id if self.consent else None,
            "collectors": list(self.consent.allowed_collectors) if self.consent else [],
            "proof_only": self.proof_only,
        }


def _normalize(target: str) -> str:
    return (target or "").strip().lower().rstrip(".")


def _build_budgets(values: dict[str, float]) -> Budgets:
    return Budgets(
        requests=int(values["requests"]),
        redirects=int(values["redirects"]),
        retries=int(values["retries"]),
        seconds=float(values["seconds"]),
        per_host_interval=float(values["per_host_interval"]),
        max_inflight=int(values["max_inflight"]),
    )


def evaluate(
    target: str,
    *,
    consent_id: str | None = None,
    require: Iterable[str] = REQUIREMENTS,
) -> GateResult:
    """ゲートを評価する。例外は投げない。"""
    required = tuple(require)
    unknown = [item for item in required if item not in REQUIREMENTS]
    if unknown:
        raise ValueError(f"未知の要求条件: {unknown}")

    normalized = _normalize(target)
    reasons: list[str] = []

    if not normalized:
        return GateResult(allowed=False, target="", reasons=("対象が空です",))

    # --- 同意 ---
    record: consent_module.Consent | None = None
    if CONSENT in required or consent_id is not None:
        record = consent_module.get_consent(consent_id) if consent_id else None
        if record is None:
            if consent_id:
                reasons.append(f"同意記録が見つかりません: {consent_id}")
            else:
                reasons.append("同意記録が指定されていません")
        elif record.target != normalized:
            reasons.append(
                f"同意対象が一致しません（同意: {record.target} / 実対象: {normalized}）"
            )
        elif record.status != consent_module.ACTIVE:
            reasons.append(f"同意が有効ではありません（状態: {record.status}）")
        elif not record.is_active:
            reasons.append("同意の有効期限が切れています")
        elif not record.allowed_collectors:
            reasons.append("同意に許可された診断機能がありません")

    if record is not None and record.target != normalized:
        record = None

    # --- 証明 ---
    verified: set[str] = set()
    if PROOF in required or record is not None:
        if not ownership.is_valid(normalized):
            reasons.append(f"所有証明が成立していません: {normalized}")

        if record is not None:
            for host in sorted(record.scope["hosts"]):
                if ownership.is_valid(host):
                    verified.add(host)
                else:
                    reasons.append(f"同意スコープ内で証明が無いホストがあります: {host}")

    if reasons:
        return GateResult(
            allowed=False,
            target=normalized,
            reasons=tuple(reasons),
            consent=record,
            verified_hosts=frozenset(verified),
        )

    if record is None:
        # proof のみ。証明確認専用の最小スコープを返す。
        return GateResult(
            allowed=True,
            target=normalized,
            consent=None,
            scope=Scope(hosts=frozenset({normalized}), ports=PROOF_ONLY_PORTS),
            budgets=Budgets(),
            verified_hosts=frozenset({normalized}),
        )

    scope = record.build_scope()
    return GateResult(
        allowed=True,
        target=normalized,
        consent=record,
        scope=scope,
        budgets=_build_budgets(record.budgets),
        verified_hosts=frozenset(verified),
    )


def ensure(
    target: str,
    *,
    consent_id: str | None = None,
    require: Iterable[str] = REQUIREMENTS,
) -> GateResult:
    """ゲートを評価し、拒否なら GateError。"""
    result = evaluate(target, consent_id=consent_id, require=require)
    if not result.allowed:
        raise GateError(list(result.reasons))
    return result


def open_scheduler(
    result: GateResult,
    *,
    resolver: Callable[[str], list[str]] | None = None,
) -> Scheduler:
    """ゲート通過済みの結果から Scheduler を作る。

    スコープ判定は結果のスコープから作る。予算も結果の値をそのまま使う。
    """
    if not result.allowed or result.scope is None or result.budgets is None:
        raise GateError(list(result.reasons) or ["ゲートを通過していません"])

    return Scheduler(result.budgets, scope=build_checker(result.scope, resolver))