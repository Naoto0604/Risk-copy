"""低侵襲アクティブ診断の画面（v2）。

既存 app.py とは別アプリとして動かす。パスはすべて /v2 配下に置き、
既存ルートと衝突させない。

方針:
    - 同意 ID を受け取り、ゲートを通してから実行する
    - 実行は別スレッド。画面は /v2/status をポーリングして完了を待つ
    - 状態は scans.status を使う。独自の状態は持たない
    - 結果は ReportModel をテンプレートに渡すだけ。判定はしない
    - ゲート拒否は理由を並べて返す。500 にしない
    - Jinja2 の autoescape を維持し、|safe を使わない
"""

from __future__ import annotations

import threading
import uuid

from flask import Flask, abort, jsonify, render_template, request
import re
from urllib.parse import urlsplit
from flask import Response
from report import export as report_export

from database import report_store
from database.models import create_scan, get_scan, init_db, update_scan_status
from engine import service
from engine.rules import RuleLoadError
from evidence import store
from verification import consent as consent_module
from verification import ownership
from verification.gate import GateError
from verification.scope import ScopeError

app = Flask(__name__)

#: 同意画面で選べる Collector。
COLLECTORS: tuple[str, ...] = tuple(step.name for step in service.plan.DEFAULT_STEPS)

#: 実行中スキャン。二重起動の防止に使う。
_RUNNING: dict[str, threading.Thread] = {}
_LOCK = threading.Lock()


def _bootstrap() -> None:
    init_db()
    store.init_evidence()
    report_store.init_reports()
    consent_module.init_consents()
    ownership.init_proofs()


def _run(scan_id: str, target: str, consent_id: str | None, selected: tuple[str, ...]) -> None:
    """バックグラウンドで実行する。失敗は scans.status に残す。"""
    update_scan_status(scan_id, "RUNNING")
    try:
        service.run_scan(scan_id, consent_id=consent_id, allowed=selected or None)
    except GateError as exc:
        update_scan_status(scan_id, "FAILED", " / ".join(exc.reasons))
    except (ScopeError, RuleLoadError) as exc:
        update_scan_status(scan_id, "FAILED", str(exc))
    except Exception as exc:  # noqa: BLE001 - 画面を壊さない
        update_scan_status(scan_id, "FAILED", f"{type(exc).__name__}: {exc}")
    else:
        update_scan_status(scan_id, "COMPLETED")
    finally:
        with _LOCK:
            _RUNNING.pop(scan_id, None)


@app.route("/v2/", methods=["GET"])
def index():
    return render_template("scan_form_v2.html", collectors=COLLECTORS)


@app.route("/v2/scan", methods=["POST"])
def scan():
    target = (request.form.get("target") or "").strip()
    consent_id = (request.form.get("consent_id") or "").strip()
    selected = tuple(request.form.getlist("collectors"))

    if not target:
        return render_template("scan_form_v2.html", collectors=COLLECTORS,
                               error="対象 URL を入力してください"), 400

    scan_id = str(uuid.uuid4())
    protocol = "https" if target.startswith("https://") else "http"
    create_scan(scan_id, target, protocol, "QUEUED")

    thread = threading.Thread(
        target=_run,
        args=(scan_id, target, consent_id or None, selected),
        name=f"scan-{scan_id}",
        daemon=True,
    )
    with _LOCK:
        _RUNNING[scan_id] = thread
    thread.start()

    return render_template("scanning_v2.html", scan_id=scan_id, target=target)


@app.route("/v2/status/<scan_id>", methods=["GET"])
def status(scan_id: str):
    row = get_scan(scan_id)
    if row is None:
        abort(404)

    with _LOCK:
        running = scan_id in _RUNNING

    return jsonify({
        "scan_id": scan_id,
        "status": row["status"],
        "error": row["error_message"],
        "running": running,
    })

def _stored_or_404(scan_id: str) -> dict:
    if get_scan(scan_id) is None:
        abort(404)
    stored = report_store.load_report(scan_id)
    if stored is None:
        abort(404)
    stored["scan_id"] = scan_id
    return stored

def _filename(stored: dict, scan_id: str, suffix: str) -> str:
    """ダウンロード名。ホスト以外の文字は落とす。"""
    raw = str(stored.get("target") or "")
    host = urlsplit(raw).hostname if "://" in raw else raw
    host = re.sub(r"[^A-Za-z0-9.-]+", "-", host or "report").strip("-") or "report"
    return f"risktrace-{host}-{scan_id[:8]}.{suffix}"

def _attachment(body: bytes, filename: str, mimetype: str) -> Response:
    response = Response(body, mimetype=mimetype)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@app.route("/v2/report/<scan_id>/json", methods=["GET"])
def report_json(scan_id: str):
    stored = _stored_or_404(scan_id)
    return _attachment(
        report_export.build_json_bytes_from_payload(stored),
        _filename(stored, scan_id, "json"),
        "application/json",
    )


@app.route("/v2/report/<scan_id>/csv", methods=["GET"])
def report_csv(scan_id: str):
    stored = _stored_or_404(scan_id)
    return _attachment(
        report_export.build_csv_bytes_from_payload(stored),
        _filename(stored, scan_id, "csv"),
        "text/csv",
    )

@app.route("/v2/report/<scan_id>", methods=["GET"])
def report(scan_id: str):
    if get_scan(scan_id) is None:
        abort(404)
    try:
        stored = service.last_report(scan_id)
    except KeyError:
        abort(404)
    stored["scan_id"] = scan_id
    return render_template("report_v2.html", report=stored)

if __name__ == "__main__":
    _bootstrap()
    app.run(debug=True, port=5001)