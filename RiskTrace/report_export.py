"""RiskTrace scan-result export helpers and Flask route registration.

The module intentionally avoids importing Flask at module load time so the
pure serialization helpers can be tested independently.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable


EXPORT_SCHEMA_VERSION = "1.0"

SCAN_FIELDS = (
    "id",
    "target_url",
    "protocol",
    "status",
    "created_at",
    "analysis_options",
    "checks_options",
)

FINDING_FIELDS = (
    "id",
    "scan_id",
    "type",
    "subtype",
    "severity",
    "title",
    "url",
    "description",
    "evidence",
    "recommendation",
)

CSV_COLUMNS = (
    "schema_version",
    "scan_id",
    "target_url",
    "protocol",
    "scan_status",
    "scan_created_at",
    "analysis_options",
    "checks_options",
    "finding_id",
    "type",
    "subtype",
    "severity",
    "title",
    "url",
    "description",
    "evidence",
    "recommendation",
)


def _to_dict(row: Any) -> dict[str, Any]:
    """Convert dict/SQLite Row/mapping-like objects into a plain dict."""
    if row is None:
        return {}
    if isinstance(row, dict):
        return dict(row)
    try:
        return dict(row)
    except (TypeError, ValueError):
        keys = getattr(row, "keys", None)
        if callable(keys):
            return {key: row[key] for key in keys()}
        raise ValueError("エクスポート対象データの形式が不正です")


def _decode_options(value: Any) -> Any:
    """Decode persisted JSON option fields without losing malformed legacy data."""
    if isinstance(value, (list, tuple, set)):
        return sorted(value) if isinstance(value, set) else list(value)
    if not isinstance(value, str):
        return value
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return value
    return decoded


def _jsonable(value: Any) -> Any:
    """Normalize values that may appear in nested export data."""
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def build_export_payload(
    scan_row: Any,
    findings_rows: Iterable[Any],
    *,
    exported_at: str | None = None,
) -> dict[str, Any]:
    """Build a versioned JSON payload containing the scan and its findings."""
    scan = _to_dict(scan_row)
    if not scan:
        raise ValueError("Scan情報がありません")

    scan_data = {field: scan.get(field) for field in SCAN_FIELDS if field in scan}
    if "analysis_options" in scan_data:
        scan_data["analysis_options"] = _decode_options(scan_data["analysis_options"])
    if "checks_options" in scan_data:
        scan_data["checks_options"] = _decode_options(scan_data["checks_options"])

    findings = [_to_dict(item) for item in findings_rows]
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "UNKNOWN").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    timestamp = exported_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    return _jsonable({
        "schema_version": EXPORT_SCHEMA_VERSION,
        "exported_at": timestamp,
        "scan": scan_data,
        "summary": {
            "finding_count": len(findings),
            "severity_counts": severity_counts,
        },
        "findings": findings,
    })


def build_json_bytes(scan_row: Any, findings_rows: Iterable[Any]) -> bytes:
    """Serialize a scan export as UTF-8 JSON with Japanese text preserved."""
    payload = build_export_payload(scan_row, findings_rows)
    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=False,
    ).encode("utf-8")


def _serialize_csv_cell(value: Any) -> str:
    """Format one cell and mitigate spreadsheet formula injection."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        text = json.dumps(_jsonable(value), ensure_ascii=False, separators=(",", ":"))
    else:
        text = str(value)

    # Excel and some spreadsheet applications may execute formula-like cells.
    # Check after leading whitespace, but preserve the original text in output.
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def build_csv_bytes(scan_row: Any, findings_rows: Iterable[Any]) -> bytes:
    """Serialize one row per finding as Excel-friendly UTF-8 CSV."""
    scan = _to_dict(scan_row)
    if not scan:
        raise ValueError("Scan情報がありません")

    findings = [_to_dict(item) for item in findings_rows]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()

    analysis_options = _decode_options(scan.get("analysis_options"))
    checks_options = _decode_options(scan.get("checks_options"))

    for finding in findings:
        row = {
            "schema_version": EXPORT_SCHEMA_VERSION,
            "scan_id": scan.get("id"),
            "target_url": scan.get("target_url"),
            "protocol": scan.get("protocol"),
            "scan_status": scan.get("status"),
            "scan_created_at": scan.get("created_at"),
            "analysis_options": analysis_options,
            "checks_options": checks_options,
            "finding_id": finding.get("id"),
            "type": finding.get("type"),
            "subtype": finding.get("subtype"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "url": finding.get("url"),
            "description": finding.get("description"),
            "evidence": finding.get("evidence"),
            "recommendation": finding.get("recommendation"),
        }
        writer.writerow({key: _serialize_csv_cell(value) for key, value in row.items()})

    # utf-8-sig adds a BOM that makes Japanese text more reliable in Excel.
    return output.getvalue().encode("utf-8-sig")


def register_export_routes(app, get_scan, get_findings) -> None:
    """Register /export/<scan_id>/<export_format> on an existing Flask app.

    Only completed scans are exportable. Supported formats are JSON and CSV.
    The caller supplies the application's existing DB access functions.
    """
    from flask import Response, abort

    def export_scan(scan_id: str, export_format: str):
        if export_format not in {"json", "csv"}:
            abort(404)

        scan_row = get_scan(scan_id)
        if scan_row is None:
            abort(404, description="Scanが見つかりません。")

        scan = _to_dict(scan_row)
        if scan.get("status") != "COMPLETED":
            abort(409, description="診断が完了していないため、エクスポートできません。")

        finding_rows = get_findings(scan_id)
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", str(scan.get("id") or scan_id))[:80]

        if export_format == "json":
            body = build_json_bytes(scan_row, finding_rows)
            return Response(
                body,
                content_type="application/json; charset=utf-8",
                headers={
                    "Content-Disposition": f'attachment; filename="risktrace_scan_{safe_id}.json"',
                    "X-Content-Type-Options": "nosniff",
                },
            )

        body = build_csv_bytes(scan_row, finding_rows)
        return Response(
            body,
            content_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="risktrace_scan_{safe_id}.csv"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    app.add_url_rule(
        "/export/<scan_id>/<export_format>",
        endpoint="export_scan",
        view_func=export_scan,
        methods=["GET"],
    )
