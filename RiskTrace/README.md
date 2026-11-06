# RiskTrace

管理対象ホストに対する低侵襲アクティブ診断ツール。所有証明・同意・スコープ・ゲートを通したうえで収集を行い、観測をルールで判定し、相関・スコアリングを経てレポートに落とす。

v2 パイプライン（`app_v2.py`）が主線。v1 の `app.py` と `scanner/` 系は当面併存しており、その仕様は [docs/legacy_v1.md](docs/legacy_v1.md) を参照する。

## 位置づけ

- 対象は学習・開発用。認証層・エクスプロイト・ファジングはしない。
- 出力は判定ではなく根拠・確度・次にやること。
- 「非侵入型」ではなく「低侵襲アクティブ診断」と呼ぶ。TCP 接続や HTTP 取得は行うが、書き込みはしない。
- 確認できるのは検査端末から見えた事実だけ。別経路やインターネット全体からの到達性は証明しない。

## 構成

```
app_v2.py                  v2 の入口（Flask）
engine/
  service.py               スキャン実行の組み立て
  plan.py                  実行計画と step の取捨
  scheduler.py             HTTP 取得の直列化・レート制御
  worker.py                キュー消費・heartbeat・キャンセル
  rule_runner.py           観測に対するルール適用
  correlation.py           観測間の相関
  observations.py          観測契約（frozen dataclass）
  adapters.py              収集器の適合層
  rules.py                 ルールローダ
collectors/
  http/ dns/ tls/ ports/ explore/ baas/
verification/
  ownership.py consent.py scope.py gate.py
evidence/store.py          根拠の保存
rules/
  headers/ cookies/ tls/ ports/ dns/ explore/   YAML ルール
analyzer/scoring_v2.py     スコアリング
report/model.py            レポートモデル
report/export.py           JSON / CSV エクスポート
database/
  db.py queue.py report_store.py models.py
templates/                 画面（v2 は *_v2.html）
tests/                     テスト
docs/                      設計メモ・履歴・旧ドキュメント
```

## 動作環境

- Windows + PowerShell を想定
- Python 3.12
- SQLite（WAL）

## セットアップ

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 起動

```powershell
python app_v2.py
セッション署名鍵は環境変数 `RISKTRACE_SECRET` から読む。未設定なら起動ごとに生成するため、再起動でセッションが切れる。
```

`/v2/` を開く。

## 使い方

1. `/v2/` で対象 URL と検査項目を選ぶ
2. 所有証明・同意が未登録なら先に通す
3. 実行するとキューに積まれ、Worker が処理する
4. `/v2/status/<scan_id>` で進行を見る
5. 完了後 `/v2/report/<scan_id>` でレポート、`/json` `/csv` でエクスポート

## パイプライン

所有証明 → 同意 → スコープ判定 → ゲート → 実行計画 → 収集 → 観測 → ルール判定 → 相関 → スコアリング → レポート生成 → 保存

- ゲートはホスト名単位で証明・同意・対象を突き合わせる。URL を渡すと `ProofError` になるため、呼び出し側でホスト名に落とす。
- スコープ外への遷移は `ScopeViolation`。クロール時の `robots.txt` 取得などは全許可で継続する。
- キャンセルは `Cancelled`。`except Exception` より前に再送出させる。

## ルール

`rules/<カテゴリ>/*.yaml`。ファイル直下はルールのリストで、1ファイル1リスト。

```yaml
- id: example-rule
  when:
    collectors: [http_headers]
    all:
      - obs: header_missing
        path: name
        eq: x-content-type-options
  then:
    title: X-Content-Type-Options が無い
    severity: low
    confidence: high
```

- 述語は `all` / `any` / `not` / `obs`
- `when.collectors` に無い collector を参照すると読み込み時に弾かれる
- 値にコロンを含む行は引用符で囲む（`"nosniff"` など）
- `any` に `path` を付けると意図どおりに動かないことがある。分割を検討する

## レポート

- `report/model.py` が Finding をグループ・アクション・レビュー項目に整理する
- `report/export.py` は JSON と CSV。CSV は UTF-8 BOM、数式解釈されるセルはアポストロフィを前置
- 出力は COMPLETED のスキャンに限る
- 前回比の比較元はホストで決める。スキーム・末尾スラッシュ・大文字小文字は無視する

## テスト

```powershell
python -m unittest discover -s tests -v
```

## 既知の未対応

- セッション署名鍵は環境変数 `RISKTRACE_SECRET` から読む。未設定なら起動ごとに生成するため、再起動でセッションが切れる。
- 相関ルールは `rules/correlations/` に置く。`collectors` に2つ以上を列挙し、`when` はその中だけを参照する
- 相関の Finding は `rule_id` に `corr:` が付き、単独ルールと出所が分かれる
- 前回比の比較元の選び方が未決定
- 保存期間を過ぎたレポートは起動時に消える。Finding も同時に消え、`scans` の行だけ履歴として残る
- バナーからの CVE 照合は未移植（旧実装は requests 直呼びのため Scheduler 経由化が必要）
- 旧 `port_check` / `crawler` / `checks` / `scoring` / `report_export` と v2 の重複が残る

## 併存と移行

v1 は壊さず残し、v2 は別モジュール・別テーブル（`findings_v2` / `reports_v2`）で動かす。旧コードは判定と通信を含むものだけ移し替え、含まないものはそのまま使う。旧モジュールを新側から呼ぶときは `client.fetch` か Scheduler 経由にし、`requests` 直呼びを残さない。

## ドキュメント

- [docs/design_memo.md](docs/design_memo.md) 設計メモ
- [docs/milestones.md](docs/milestones.md) マイルストーン履歴
- [docs/structure.md](docs/structure.md) 構成図
- [docs/legacy_v1.md](docs/legacy_v1.md) v1 ドキュメント

## ライセンス

未設定。
```