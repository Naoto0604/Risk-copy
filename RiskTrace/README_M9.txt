RiskTrace M9 - Diagnostic Report Export (JSON / CSV)
===================================================

Files in this package
---------------------
1) report_export.py
   Add this file to the project root: C:\Users\cre\RiskTrace\report_export.py
2) tests/test_report_export.py
   Add this test file to C:\Users\cre\RiskTrace\tests\test_report_export.py

Integration in app.py
---------------------
1) Add this import with the other imports:

    from report_export import register_export_routes

2) After `app = Flask(__name__)` and after the existing imports of `get_scan`
   and `get_findings`, register the export routes once:

    register_export_routes(app, get_scan, get_findings)

Do not add the registration inside a route or inside execute_scan(). The existing
`get_scan` and `get_findings` functions are passed in; database/models.py does
not need to change.

Expose links in templates (optional but recommended)
----------------------------------------------------
In templates/result.html and templates/report.html, put these links near the
existing report / rescan links. Both templates already receive `scan_id`:

    <a href="{{ url_for('export_scan', scan_id=scan_id, export_format='json') }}">JSONをダウンロード</a>
    <a href="{{ url_for('export_scan', scan_id=scan_id, export_format='csv') }}">CSVをダウンロード</a>

Endpoints
---------
GET /export/<scan_id>/json
GET /export/<scan_id>/csv

Exports are allowed only when a scan status is COMPLETED. JSON contains scan
metadata, options, a summary by severity, and all stored findings. CSV exports
one row per finding and uses UTF-8 with BOM for Japanese text in Excel. CSV cells
that could be interpreted as spreadsheet formulas are prefixed with an apostrophe.

Run from C:\Users\cre\RiskTrace
---------------------------------
    python -m py_compile report_export.py tests/test_report_export.py
    python -m unittest discover -s tests -v

The route tests run when Flask is installed in the active environment. The pure
serialization tests do not need Flask. The scanner, app.py, and database schema
are otherwise unchanged.
