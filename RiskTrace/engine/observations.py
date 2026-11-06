"""Collector 出力の統一契約（Observation）。

Collector は判定しない。このモジュールが扱うのは観測事実のみで、
severity / confidence / Finding を決めるのは Rule Engine の責務である。

契約の要点:
    - status は ok / error / skipped の3値のみ
    - skipped は usable=False として扱う
    - error を「検出なし」と混同しない（usable は True のまま status で区別する）
    - ヘッダー名は小文字化する
    - 秘密値は生成時にマスキングする（値は保存しない。種類だけ残す）
    - Observation は不変。修正は新しいインスタンスを作る
    - Evidence とは evidence_id で関連付ける
    - 実行できなかった理由は note に必ず残す

値の正規化は行うが、観測事実そのものは書き換えない。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from typing import Any

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"

STATUSES: tuple[str, ...] = (STATUS_OK, STATUS_ERROR, STATUS_SKIPPED)

#: 秘密値を伏せたことを示す固定文字列。
MASKED = "<masked>"

#: 値を保存してはいけないキー名（ハイフン形で正規化して保持する）。
#: ヘッダーはハイフン、JSON のキーはアンダースコアが通例なので、
#: 比較は ``_canonical_name()`` で両者を同一視する。
SECRET_KEY_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "www-authenticate",
        "proxy-authenticate",
        "x-api-key",
        "api-key",
        "api-token",
        "apikey",
        "auth-token",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "access-token",
        "refresh-token",
        "id-token",
        "client-secret",
        "private-key",
        "password",
    }
)

#: 後方互換のための別名。
SECRET_HEADER_NAMES = SECRET_KEY_NAMES

#: Authorization で「種類」として残してよいスキーム。
_AUTH_SCHEMES = frozenset(
    {"bearer", "basic", "digest", "negotiate", "token", "hoba", "mutual", "aws4-hmac-sha256"}
)

_AUTH_KEY_NAMES = frozenset({"authorization", "proxy-authorization"})

OBSERVATION_ID_PREFIX = "ob_"


def new_observation_id() -> str:
    """推測困難な Observation ID を生成する。"""
    return f"{OBSERVATION_ID_PREFIX}{uuid.uuid4().hex}"


def _canonical_name(name: Any) -> str:
    """比較用のキー名。小文字化し、アンダースコアをハイフンに寄せる。

    ``api_key`` と ``api-key``、``X-Api-Key`` をすべて同じ秘密キーとして扱う。
    """
    return str(name).strip().lower().replace("_", "-")


def is_secret_name(name: Any) -> bool:
    """秘密値として扱うキー名か。"""
    return _canonical_name(name) in SECRET_KEY_NAMES


def mask_header_value(name: str, value: Any) -> Any:
    """ヘッダー1件の値を必要に応じてマスキングする。

    秘密キー以外はそのまま返す。None は None のまま返す。
    Authorization 系はスキームのみ残す（例: ``Bearer <masked>``）。
    """
    if value is None:
        return None

    canonical = _canonical_name(name)
    if canonical not in SECRET_KEY_NAMES:
        return value

    text = str(value).strip()
    if canonical in _AUTH_KEY_NAMES:
        scheme, separator, _rest = text.partition(" ")
        if separator and scheme.lower() in _AUTH_SCHEMES:
            return f"{scheme} {MASKED}"

    return MASKED


def mask_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """ヘッダー名を小文字化し、秘密値をマスキングした新しい dict を返す。

    元の dict は変更しない。同名ヘッダーが大文字小文字違いで重複した場合は
    後勝ちになる（HTTP の同名複数ヘッダーは Collector 側で連結して渡す）。
    """
    masked: dict[str, Any] = {}
    for raw_name, raw_value in headers.items():
        name = str(raw_name).strip().lower()
        masked[name] = mask_header_value(name, raw_value)
    return masked


def _mask_nested(value: Any) -> Any:
    """data 全体を走査し、秘密キーの値をマスキングする。

    ヘッダー以外の階層（Cookie 一覧、抽出したトークン一覧など）にも
    秘密キーが現れ得るため、再帰的に適用する。マスキングは冪等。
    """
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, child in value.items():
            if is_secret_name(key) and not isinstance(child, (dict, list, tuple)):
                result[key] = mask_header_value(str(key), child)
            else:
                result[key] = _mask_nested(child)
        return result
    if isinstance(value, (list, tuple)):
        return [_mask_nested(item) for item in value]
    return value


def _normalize_data(data: dict[str, Any]) -> dict[str, Any]:
    """data を保存可能な形へ正規化する。

    ヘッダーは小文字化＋マスキング、その他の階層は秘密キーのみマスキング。
    観測された事実（キーの集合、値）は変えない。
    """
    normalized = dict(data)

    headers = normalized.get("headers")
    if isinstance(headers, dict):
        normalized["headers"] = mask_headers(headers)

    return _mask_nested(normalized)


def _require_text(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} は空でない文字列である必要があります: {value!r}")


@dataclass(frozen=True)
class Observation:
    """Collector が返す観測事実1件。

    生成時に検証と正規化を行う。生成後の変更はできない。
    """

    collector: str
    subject: str
    status: str
    data: dict[str, Any] = field(default_factory=dict)
    note: str | None = None
    evidence_id: str | None = None
    observation_id: str = field(default_factory=new_observation_id)

    def __post_init__(self) -> None:
        _require_text(self.collector, "collector")
        _require_text(self.subject, "subject")
        _require_text(self.observation_id, "observation_id")

        if self.status not in STATUSES:
            raise ValueError(
                f"status は {STATUSES} のいずれかである必要があります: {self.status!r}"
            )

        if not isinstance(self.data, dict):
            raise TypeError(f"data は dict である必要があります: {type(self.data).__name__}")

        if self.note is not None and not isinstance(self.note, str):
            raise TypeError(f"note は str または None である必要があります: {type(self.note).__name__}")

        if self.evidence_id is not None:
            _require_text(self.evidence_id, "evidence_id")

        # 実行できなかった理由は必ず残す。
        if self.status in (STATUS_ERROR, STATUS_SKIPPED):
            if not (self.note or "").strip():
                raise ValueError(f"status={self.status} には note（理由）が必須です")

        object.__setattr__(self, "data", _normalize_data(self.data))

    # --- 状態判定 -------------------------------------------------------

    @property
    def usable(self) -> bool:
        """判定材料として使えるか。skipped のみ False。

        error は「取得に失敗した」であり「検出なし」ではないため True のまま。
        """
        return self.status != STATUS_SKIPPED

    @property
    def is_ok(self) -> bool:
        return self.status == STATUS_OK

    @property
    def is_error(self) -> bool:
        return self.status == STATUS_ERROR

    @property
    def is_skipped(self) -> bool:
        return self.status == STATUS_SKIPPED

    @property
    def has_evidence(self) -> bool:
        return self.evidence_id is not None

    # --- 生成ヘルパ -----------------------------------------------------

    @classmethod
    def ok(
        cls,
        collector: str,
        subject: str,
        data: dict[str, Any] | None = None,
        *,
        note: str | None = None,
        evidence_id: str | None = None,
    ) -> "Observation":
        return cls(
            collector=collector,
            subject=subject,
            status=STATUS_OK,
            data=data or {},
            note=note,
            evidence_id=evidence_id,
        )

    @classmethod
    def error(
        cls,
        collector: str,
        subject: str,
        note: str,
        *,
        data: dict[str, Any] | None = None,
        evidence_id: str | None = None,
    ) -> "Observation":
        return cls(
            collector=collector,
            subject=subject,
            status=STATUS_ERROR,
            data=data or {},
            note=note,
            evidence_id=evidence_id,
        )

    @classmethod
    def skipped(
        cls,
        collector: str,
        subject: str,
        note: str,
        *,
        data: dict[str, Any] | None = None,
        evidence_id: str | None = None,
    ) -> "Observation":
        return cls(
            collector=collector,
            subject=subject,
            status=STATUS_SKIPPED,
            data=data or {},
            note=note,
            evidence_id=evidence_id,
        )

    # --- 派生 -----------------------------------------------------------

    def with_evidence(self, evidence_id: str) -> "Observation":
        """Evidence を関連付けた新しい Observation を返す。observation_id は維持する。"""
        _require_text(evidence_id, "evidence_id")
        return replace(self, evidence_id=evidence_id)

    # --- 永続化 ---------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """保存・出力用の dict。"""
        return {
            "observation_id": self.observation_id,
            "collector": self.collector,
            "subject": self.subject,
            "status": self.status,
            "data": self.data,
            "note": self.note,
            "evidence_id": self.evidence_id,
            "usable": self.usable,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Observation":
        """保存済み dict から復元する。``usable`` は再計算するため無視する。"""
        if not isinstance(payload, dict):
            raise TypeError("payload は dict である必要があります")

        return cls(
            collector=payload["collector"],
            subject=payload["subject"],
            status=payload["status"],
            data=payload.get("data") or {},
            note=payload.get("note"),
            evidence_id=payload.get("evidence_id"),
            observation_id=payload["observation_id"],
        )