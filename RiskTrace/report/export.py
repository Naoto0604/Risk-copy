"""レポートのエクスポート（JSON / CSV）。

ReportModel からでも、保存済み payload（dict）からでも書き出せる。
判定も並べ替えもしない。集計は model 側の責務なので、ここでは形だけ整える。

方針:
    - Finding と Evidence ID の対応を崩さない。group に evidence_ids を残す
    - CSV は数式インジェクションを無害化する（先頭の = + - @）
    - 秘密値は出さない。payload に入っていないものは出さない
    - JSON は UTF-8、日本語はそのまま
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from report.model import ReportModel

SCHEMA_VERSION = "2.0"

CSV_COLUMNS = (
    "schema_version",
    "target",
    "generated_at",
    "overall",
    "level",
    "coverage",
    "section",
    "rule_id",
    "title",
    "severity",
    "confidence",
    "subject",
    "evidence_ids",
    "count",
    "detail",
)

FORMULA_PREFIXES = ("=", "+", "-", "@")


def _cell(value: Any) -> str:
    """1 セルを文字列化し、数式として解釈されないようにする。"""
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        text = " ".join(str(item) for item in value)
    elif isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        text = str(value)

    if text.lstrip(" \t\r\n").startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def _base(payload: dict) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "target": payload.get("target"),
        "generated_at": payload.get("generated_at"),
        "overall": payload.get("overall"),
        "level": payload.get("level"),
        "coverage": payload.get("coverage"),
    }


def build_payload(report: ReportModel) -> dict[str, Any]:
    """JSON 用の辞書。"""
    payload = _base(report.to_dict())
    payload.update(report.to_dict())
    payload["schema_version"] = SCHEMA_VERSION
    return payload


def _rows(payload: dict):
    base = _base(payload)

    for group in payload.get("groups") or ():
        yield {
            **base,
            "section": "finding",
            "rule_id": group.get("rule_id"),
            "title": group.get("title"),
            "severity": group.get("severity"),
            "confidence": group.get("confidence"),
            "subject": group.get("subjects"),
            "evidence_ids": group.get("evidence_ids"),
            "count": group.get("count"),
            "detail": "",
        }

    for group in payload.get("low_confidence") or ():
        yield {
            **base,
            "section": "low_confidence",
            "rule_id": group.get("rule_id"),
            "title": group.get("title"),
            "severity": group.get("severity"),
            "confidence": group.get("confidence"),
            "subject": group.get("subjects"),
            "evidence_ids": group.get("evidence_ids"),
            "count": group.get("count"),
            "detail": "",
        }

    for item in payload.get("needs_review") or ():
        yield {
            **base,
            "section": "needs_review",
            "rule_id": "",
            "title": item.get("label"),
            "severity": "",
            "confidence": "",
            "subject": "",
            "evidence_ids": (),
            "count": "",
            "detail": item.get("detail"),
        }

    for item in payload.get("evidence") or ():
        yield {
            **base,
            "section": "evidence",
            "rule_id": "",
            "title": item.get("collector"),
            "severity": "",
            "confidence": "",
            "subject": item.get("subject"),
            "evidence_ids": (item.get("evidence_id"),),
            "count": "",
            "detail": item.get("status"),
        }


def build_json_bytes_from_payload(payload: dict) -> bytes:
    """payload を UTF-8 JSON にする。"""
    body = dict(payload)
    body["schema_version"] = SCHEMA_VERSION
    return json.dumps(body, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8")


def build_json_bytes(report: ReportModel) -> bytes:
    return build_json_bytes_from_payload(build_payload(report))


def build_csv_bytes_from_payload(payload: dict) -> bytes:
    """payload を 1 行 1 項目の UTF-8 CSV にする。"""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()

    for row in _rows(payload):
        writer.writerow({key: _cell(value) for key, value in row.items()})

    return output.getvalue().encode("utf-8")


def build_csv_bytes(report: ReportModel) -> bytes:
    return build_csv_bytes_from_payload(build_payload(report))