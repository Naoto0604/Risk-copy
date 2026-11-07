全文を下の内容で上書きしてください。

```markdown
# 構成

現行ツリー。`__pycache__` は省略。

```
RiskTrace/
├─ app.py                    入口（Flask）
├─ requirements.txt
├─ README.md
├─ .gitignore
├─ config/config.py
├─ engine/
│  ├─ adapters.py
│  ├─ attack_path.py
│  ├─ correlation.py
│  ├─ cve.py
│  ├─ observations.py
│  ├─ plan.py
│  ├─ priority.py
│  ├─ rule_runner.py
│  ├─ rules.py
│  ├─ scheduler.py
│  ├─ scoring_v2.py
│  ├─ service.py
│  └─ worker.py
├─ collectors/
│  ├─ baas/endpoints.py
│  ├─ dns/
│  ├─ explore/  crawl.py discover.py assets.py repo.py subdomains.py
│  ├─ http/     client.py cookies.py cors.py headers.py redirects.py transport.py
│  ├─ ports/scan.py
│  └─ tls/
├─ verification/
│  ├─ consent.py
│  ├─ gate.py
│  ├─ ownership.py
│  └─ scope.py
├─ evidence/store.py
├─ rules/
│  ├─ cookies/ dns/ explore/ headers/ ports/ redirects/ tls/ transport/   *.yaml
│  └─ correlations/           相関ルール
├─ report/
│  ├─ export.py
│  └─ model.py
├─ web/
│  ├─ auth.py
│  ├─ csrf.py
│  └─ ratelimit.py
├─ database/
│  ├─ db.py models.py queue.py report_store.py
├─ templates/
├─ tests/
└─ docs/                      design_memo.md milestones.md structure.md legacy_v1.md
```

`rules/` はカテゴリごとにディレクトリを切り、`correlations/` だけ別扱いで読む。
```
