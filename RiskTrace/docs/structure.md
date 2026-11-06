# 構成

現行ツリー。`__pycache__` は省略。

```
RiskTrace/
├─ app.py                    v1 の入口（併存中）
├─ app_v2.py                 v2 の入口
├─ requirements.txt
├─ README.md
├─ .gitignore
├─ config/config.py
├─ engine/
│  ├─ adapters.py
│  ├─ correlation.py
│  ├─ observations.py
│  ├─ plan.py
│  ├─ rule_runner.py
│  ├─ rules.py
│  ├─ scheduler.py
│  ├─ service.py
│  └─ worker.py
├─ collectors/
│  ├─ baas/endpoints.py
│  ├─ dns/
│  ├─ explore/  crawl.py discover.py assets.py repo.py subdomains.py
│  ├─ http/     client.py cors.py cookies.py headers.py tls.py
│  ├─ ports/scan.py
│  └─ tls/
├─ verification/
│  ├─ consent.py
│  ├─ gate.py
│  ├─ ownership.py
│  └─ scope.py
├─ evidence/store.py
├─ rules/
│  ├─ cookies/ dns/ explore/ headers/ ports/ tls/   *.yaml
├─ analyzer/
│  ├─ scoring.py             v1
│  ├─ scoring_v2.py          v2
│  └─ vulnerability_lookup.py
├─ report/
│  ├─ export.py
│  └─ model.py
├─ report_export.py          v1
├─ scanner/                  v1
├─ database/
│  ├─ db.py models.py queue.py report_store.py
├─ templates/                v2 は *_v2.html
├─ tests/
└─ docs/                     design_memo.md milestones.md structure.md legacy_v1.md
```

v1 と v2 の重複（`scanner/port_check.py` → `collectors/ports/scan.py`、`scanner/crawler.py` → `collectors/explore/crawl.py`、`scanner/checks.py` → `collectors/http/headers.py`、`analyzer/scoring.py` → `analyzer/scoring_v2.py`、`report_export.py` → `report/export.py`）は順次解消する。
```
