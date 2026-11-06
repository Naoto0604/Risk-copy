"""v1 のエクスポート経路を v2 のレポート形式に寄せる変換層。

v1 は scans / findings の行をそのまま出していた。ここで Finding と
ReportModel に写し、書き出しは ``report/export.py`` に任せる。
"""

from __future__ import annotations

import re
from dataclasses import replace
from analyzer import scoring_v2
from engine.rule_runner import Finding, finding_id
from report import export as report_export
from report import model as report_model

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SAFE = re.compile(r"[^A-Za-z0-9_-]")


def _to_finding(row: dict) -> Finding:
    kind = str(row.get("type") or "LEGACY")
    subtype = str(row.get("subtype") or "")
    rule_id = f"legacy:{kind}" + (f":{subtype}" if subtype else "")
    subject = str(row.get("url") or "")
    severity = str(row.get("severity") or "INFO").upper()
    if severity not in _SEVERITIES:
        severity = "INFO"
    return Finding(
        id=finding_id(rule_id, subject),
        rule_id=rule_id,
        title=str(row.get("title") or ""),
        severity=severity,
        confidence="high",
        subject=subject,
        message=str(row.get("description") or ""),
        why=str(row.get("evidence") or ""),
        fix=str(row.get("recommendation") or ""),
        verify="",
    )


def _report(scan_row, findings_rows) -> report_model.ReportModel:
    if scan_row is None:
        raise ValueError("Scan情報がありません")
    scan = dict(scan_row)
    findings = [_to_finding(dict(row)) for row in findings_rows]
    result = scoring_v2.score(findings)
    return report_model.build(
        str(scan.get("target_url") or ""),
        findings=findings,
        score_result=result,
    )


def build_json_bytes(scan_row, findings_rows) -> bytes:
    return report_export.build_json_bytes(_report(scan_row, findings_rows))


def build_csv_bytes(scan_row, findings_rows) -> bytes:
    # Excel 向けに BOM を付ける（v1 の従来挙動）。
    return b"\xef\xbb\xbf" + report_export.build_csv_bytes(_report(scan_row, findings_rows))

def build_export_payload(scan_row, findings_rows, *, exported_at=None) -> dict:
    """レポート辞書を返す。旧名の互換用。"""
    report = _report(scan_row, findings_rows)
    if exported_at:
        report = replace(report, generated_at=exported_at)
    payload = report.to_dict()
    payload["schema_version"] = report_export.SCHEMA_VERSION
    return payload

def register_export_routes(app, get_scan, get_findings) -> None:
    """``/export/<scan_id>/<export_format>`` を登録する。"""
    from flask import Response, abort

    def export_scan(scan_id: str, export_format: str):
        if export_format not in {"json", "csv"}:
            abort(404)

        scan_row = get_scan(scan_id)
        if scan_row is None:
            abort(404, description="Scanが見つかりません。")

        scan = dict(scan_row)
        if scan.get("status") != "COMPLETED":
            abort(409, description="診断が完了していないため、エクスポートできません。")

        report = _report(scan, get_findings(scan_id))
        safe_id = _SAFE.sub("_", str(scan.get("id") or scan_id))[:80]

        if export_format == "json":
            body = report_export.build_json_bytes(report)
            content_type = "application/json; charset=utf-8"
        else:
            body = report_export.build_csv_bytes(report)
            content_type = "text/csv; charset=utf-8"

        return Response(
            body,
            content_type=content_type,
            headers={
                "Content-Disposition": (
                    f'attachment; filename="risktrace_scan_{safe_id}.{export_format}"'
                ),
                "X-Content-Type-Options": "nosniff",
            },
        )

    app.add_url_rule(
        "/export/<scan_id>/<export_format>",
        endpoint="export_scan",
        view_func=export_scan,
        methods=["GET"],
    )