"""手動スモークテスト用。使い捨て。"""

import tempfile
from pathlib import Path

from database import db as db_module
from database import report_store
from database.models import create_scan, init_db
from engine import service
from database import queue as queue_module
from evidence import store

TARGET = "http://127.0.0.1:8099/"

tmp = tempfile.TemporaryDirectory()
db_module.DB_DIR = tmp.name
db_module.DB_PATH = str(Path(tmp.name, "smoke.db"))
db_module._wal_initialized = False

init_db()
queue_module.init_queue()
store.init_evidence()
report_store.init_reports()

create_scan("smoke", TARGET, "http", "QUEUED")

result = service.run_scan(
    "smoke",
    satisfied=("proof", "consent"),
    scope=lambda url: True,
)

report = result.report
print("status:", result.status)
print("overall:", report.overall, report.level)
print("coverage:", report.coverage)
print("groups:", [g.title for g in report.groups])
print("low:", [g.title for g in report.low_confidence])
print("skipped:", report.status_note)
print("log:", len(report.log))
print("skipped_detail:", result.plan_result.skipped if result.plan_result else None)
print("obs:", [(o.collector, o.status) for o in (result.plan_result.observations if result.plan_result else ())])
print("review:", list(report.needs_review))
print("counts:", report.counts)
