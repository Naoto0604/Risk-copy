# RiskTrace v1 旧ドキュメント

v2 パイプライン（app_v2.py）導入前の README をそのまま保存したもの。v1 の app.py と scanner/ 系は当面併存しており、その仕様・手順はここを参照する。現行の主線は ../README.md を見ること。

---

# RiskTrace

**RiskTrace** は、Webサイトのセキュリティ状態を診断し、検出結果を関連付けて、リスクと推奨対応を確認するための Python / Flask 製の学習・開発用Webアプリケーションです。

本READMEは、現在実装されている機能（M7.1時点）をまとめた全体ガイドです。今後の計画と、実装済みの機能を区別して記載しています。

> **利用上の注意**：診断は、自分が管理しているシステム、または所有者から明示的に許可を得た対象に限って実行してください。RiskTraceの結果は補助的な確認情報であり、ペネトレーションテストや正式なセキュリティ監査を代替するものではありません。

---

## 目次

- [主な機能](#主な機能)
- [技術スタック](#技術スタック)
- [処理の流れ](#処理の流れ)
- [ディレクトリ構成](#ディレクトリ構成)
- [動作環境](#動作環境)
- [セットアップ](#セットアップ)
- [起動方法](#起動方法)
- [使い方](#使い方)
- [診断・分析項目](#診断分析項目)
- [ポート・サービス検査](#ポートサービス検査)
- [CVE候補照合](#cve候補照合)
- [結果の保存と表示](#結果の保存と表示)
- [テスト](#テスト)
- [ローカルHTTPSテストサーバー](#ローカルhttpsテストサーバー)
- [セキュリティ上の設計と制約](#セキュリティ上の設計と制約)
- [トラブルシューティング](#トラブルシューティング)
- [開発ロードマップ](#開発ロードマップ)

---

## 主な機能

### Webサイトの基本診断

- 入力されたURLの形式を確認し、HTTP / HTTPSを対象にする
- 同一スコープ内のリンクを巡回するクローラー
- HTTPS利用状況の確認
- セキュリティヘッダーの確認
- Cookie属性の確認
- HTTPリダイレクト、HTML Meta Refresh、JavaScriptリダイレクトの検出

### リスク分析

- 0〜100のRisk ScoreとRisk Levelの算出
- Finding同士のRisk Correlation（複合リスク分析）
- Correlationに基づくAttack Path（攻撃経路分析）
- Remediation Priority（対応優先順位）の算出
- URLごとのFindingとSeverityをまとめるRisk Map
- 再診断と、対応する比較元がある場合のBefore / After比較

### ポート・サービス検査（M3〜M6）

- 固定リストに含まれるTCPポートへの接続確認
- HTTPステータス行と `Server` ヘッダーの観測
- HTTPS / TLSのバージョン、暗号スイート、証明書情報の取得
- 証明書検証失敗の検出と、自己署名・ホスト名不一致・期限などのエラー分類
- SSH、FTP、SMTP、MySQL、Redisの限定的なプロトコル応答確認
- ループバック・プライベート・リンクローカル・グローバルアドレスの分類
- 「TCP接続のみ確認」「プロトコル応答を観測」などの検出確度の明示

### CVE候補照合（M7 / M7.1）

- 認識可能なサービスバナーから製品名・バージョン候補を抽出
- NIST NVD CVE API 2.0への問い合わせ
- CPEの製品識別子とバージョン範囲の照合
- 明らかに対象コンポーネントが異なる候補の除外（例：MySQL Serverに対するMySQL Client / C API専用候補）
- CVE ID、公開情報、CVSSなどの情報をFindingとして保存・表示
- NVDへの接続失敗や候補なしを、脆弱性がないという意味にしない処理

**注意：** CVE照合はトリアージ用の候補検索です。バナー文字列は偽装可能であり、CPEの条件が一致しても、インストール済みビルド、OS、ベンダーパッチ、構成条件までは自動で確定できません。

---

## 技術スタック

| 技術 | 用途 |
|---|---|
| Python | 診断ロジック、分析処理 |
| Flask | Webアプリケーション、ルーティング |
| Requests | HTTP通信、NVD APIへの問い合わせ |
| Beautiful Soup 4 | HTML解析とリンク抽出 |
| SQLite | Scan / Findingデータの保存 |
| HTML / CSS / JavaScript | 診断フォーム、進行状況、結果画面、レポート |
| Python `ssl` / `socket` | TLS情報取得、TCP接続、サービス応答確認 |
| NIST NVD CVE API 2.0 | 既知の脆弱性候補との照合 |
| `unittest` | 自動テスト |

開発環境では Windows、PowerShell、Visual Studio Code、Python 3.14.3 が使用されています。

---

## 処理の流れ

```text
URL入力
  ↓
URL形式チェック（HTTP / HTTPS）
  ↓
Scan ID発行、DBにRUNNING保存
  ↓
バックグラウンドで診断開始
  ↓
Crawler（同一スコープのURLを探索）
  ↓
選択されたSecurity Check
  ├─ HTTPS / Headers / Cookies / Redirects
  └─ TCPポート確認・サービス応答・TLS情報
        ↓
      CVE候補照合（対象バナーを認識できた場合）
  ↓
FindingをDBに保存
  ↓
選択されている分析を実行
  ├─ Risk Score
  ├─ Risk Correlation
  ├─ Attack Path
  └─ Remediation Priority
  ↓
Risk Mapを構築、ScanをCOMPLETEDに更新
  ↓
Result / Report画面
```

診断はスレッドでバックグラウンド実行されます。画面はScan IDを使って進行状況を確認します。

---

## ディレクトリ構成

```text
RiskTrace/
├── app.py                         # Flaskアプリ、ルート、Scan処理
├── requirements.txt               # Python依存パッケージ
├── README.md                      # このファイル
├── analyzer/
│   ├── scoring.py                 # Risk Score / Risk Level
│   ├── correlation.py             # Finding間の関連分析
│   ├── attack_path.py             # 攻撃経路の生成
│   ├── priority.py                # 対応優先順位
│   ├── comparison.py              # Findingの差分比較
│   └── vulnerability_lookup.py    # NVD CVE候補照合（M7.1）
├── scanner/
│   ├── crawler.py                 # URL探索
│   ├── checks.py                  # HTTPS / Header / Cookie / Redirect診断
│   └── port_check.py              # TCP / HTTP / TLS / サービス検査
├── database/
│   ├── db.py                      # SQLite接続
│   └── models.py                  # Scan / Findingの保存・取得
├── data/
│   └── risktrace.db               # 実行時に作成されるSQLite DB
├── templates/
│   ├── index.html                 # 診断フォーム
│   ├── scanning.html              # 診断中画面
│   ├── result.html                # 診断結果
│   └── report.html                # レポート
├── static/
│   └── css/
│       ├── style.css
│       ├── result.css
│       └── report.css
└── tests/
    ├── test_crawler.py
    ├── test_safe_request.py
    ├── test_port_check.py
    ├── test_service_probe.py
    ├── test_vulnerability_lookup.py
    └── https_test_server.py        # ローカルTLSテスト用（任意）
```

`old_port_check.py`、`old2_port_check.py`、そのバックアップなどのファイルが手元に残っている場合がありますが、現行アプリの正規モジュールは `scanner/port_check.py` です。変更・テスト時は `app.py` のimport先を基準にし、古いファイルを誤って上書きしないでください。

---

## 動作環境

- Windows 10 / 11（開発時の環境）
- Python 3.x（開発時は Python 3.14.3）
- PowerShell または VS Codeターミナル
- Webブラウザー
- NVD CVE照合にはインターネット接続が必要

### 主な依存パッケージ

- Flask
- Requests
- BeautifulSoup4
- cryptography（ローカルHTTPSテストサーバーで必要になる場合があります）

---

## セットアップ

以下は Windows PowerShell での手順です。

### 1. プロジェクトフォルダへ移動

```powershell
cd C:\Users\cre\RiskTrace
```

別の場所に置いた場合は、そのプロジェクトのパスへ変更してください。

### 2. 仮想環境を作成（初回のみ）

```powershell
python -m venv .venv
```

既に `.venv` がある場合は、作り直す必要はありません。

### 3. 仮想環境を有効化

```powershell
.\.venv\Scripts\Activate.ps1
```

ターミナルの先頭に `(.venv)` が表示されれば有効です。

PowerShellの実行ポリシーによって有効化できない場合は、現在のターミナルのプロセスに限定して、次を実行できます。

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 4. 依存パッケージをインストール

```powershell
python -m pip install --upgrade pip
python -m pip install Flask requests beautifulsoup4 cryptography
```

`requirements.txt` が使用できる場合は、次でもインストールできます。

```powershell
python -m pip install -r requirements.txt
```

依存関係のインストール後、テストも実行してください。

---

## 起動方法

プロジェクトルート（`app.py` があるディレクトリ）で、仮想環境を有効にして実行します。

```powershell
python app.py
```

ブラウザーで次を開きます。

```text
http://127.0.0.1:5000/
```

終了する場合は、起動中のターミナルで `Ctrl + C` を押します。

> Flaskの `debug=True` は開発用です。インターネットに公開する本番サーバーとして、そのまま使用しないでください。

---

## 使い方

1. ホーム画面で診断対象URLを入力します。
2. 実行したい診断項目を選択します。
3. 必要に応じて分析項目を選択します。
4. 診断を開始します。診断中画面が表示されます。
5. 完了後、診断結果とレポートを確認します。
6. 対象を修正した後は再診断し、利用可能な比較機能で前後の違いを確認します。

### 診断対象のルール

- URLは `http://` または `https://` から始めます。
- 許可を得たホストだけを対象にします。
- ポート・サービス検査では、選択されたホストに対して固定リストのTCPポートへ接続を試みます。
- 公開サイトに対する追加検査や繰り返し診断は、管理者の明示的な許可を得てください。

---

## 診断・分析項目

### 診断項目

| フォーム値 | 内容 |
|---|---|
| `https` | HTTP / HTTPSの利用状況 |
| `headers` | 主要なセキュリティヘッダーの有無など |
| `cookies` | `Secure`、`HttpOnly`、`SameSite` などのCookie属性 |
| `redirects` | HTTPリダイレクト、Meta Refresh、JavaScriptリダイレクト |
| `ports` | 固定リストのTCPポート、サービス応答、TLS、CVE候補照合 |

最低1つの診断項目が必要です。分析機能は未選択でも診断できます。

### 分析項目

| フォーム値 | 内容 |
|---|---|
| `score` | Risk Score / Risk Level |
| `correlation` | Findingの複合リスク分析 |
| `attack_path` | 攻撃経路分析 |
| `priority` | Remediation Priority |

選択されていない分析は、結果画面で未選択として扱います。Attack PathやPriorityは内部計算上、Correlationなどの依存分析を必要とする場合がありますが、未選択の分析を表示対象として扱わない設計です。

---

## ポート・サービス検査

### 固定ポートリスト

現在の実装で確認対象としているTCPポートは次のとおりです。

| ポート | 想定用途（推測） |
|---:|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 80 | HTTP |
| 443 | HTTPS |
| 445 | SMB / ファイル共有 |
| 1433 | Microsoft SQL Server |
| 3000 | 開発用Webサーバーなど |
| 3306 | MySQL |
| 3389 | RDP / リモートデスクトップ |
| 5000 | 開発用Webサーバーなど |
| 5432 | PostgreSQL |
| 587 | SMTP Submission |
| 6379 | Redis |
| 8000 | 開発用Webサーバーなど |
| 8080 | 代替HTTP |
| 8443 | 代替HTTPS |
| 27017 | MongoDB |

この一覧は固定リストであり、全TCPポートの網羅的スキャンではありません。

### サービス識別の確度

RiskTraceは、証拠の種類を分けて記録します。

- **TCP接続のみ確認**：接続は成立したが、実サービスの応答は確認していない
- **HTTP応答を観測**：HTTPステータス行などを取得した
- **TLSハンドシェイクを観測**：TLSバージョン・暗号スイート・証明書情報を取得した
- **プロトコル応答を観測**：SSH、FTP、SMTP、MySQL、Redisなどの限定的な応答を確認した

サービス名やバージョン文字列はサーバー側が返す情報であり、偽装される可能性があります。単一のバナーから製品の同一性や脆弱性を確定しません。

---

## CVE候補照合

M7.1の照合対象は、識別可能なバナー形式に限定された製品（現状：MySQL Server、OpenSSH、Apache HTTP Server）です。認識できない製品・バージョンの情報から、無理にCPEを推定しません。

CVE照合の動作概要：

1. `PORT_SCAN` Findingから認識対象のバナーとバージョンを抽出します。
2. 製品・バージョンからCPE候補を構成し、NVD CVE API 2.0へ問い合わせます。
3. RejectedのCVE、明らかなコンポーネント違い、明示されたバージョン範囲に一致しない候補を除外します。
4. 照合候補、CVE詳細、CVSS、CPEの照合メモをFindingに保存します。

### NVD APIキー（任意）

NVD APIキーがある場合は、PowerShellの現在のセッションで環境変数に設定できます。

```powershell
$env:NVD_API_KEY = "取得したAPIキー"
```

その後、同じターミナルから `python app.py` を起動します。APIキーをソースコードやGitへコミットしないでください。キーを設定しなくても照会を試みますが、API制限やネットワーク障害により照合できない場合があります。

### CVE結果の解釈

- CVE候補は `INFO` として登録され、未検証のバナーのみでRisk Scoreを引き上げません。
- CPEやバージョン範囲が一致しても、OS、ベンダーパッチ、正確なビルド、構成条件が一致するとは限りません。
- CVE候補が見つからない場合も、脆弱性が存在しないことを意味しません。
- NVDに接続できない場合は、照合不能の情報を記録し、基本の診断を継続します。
- 適用可否はNVDのCVEページと製品ベンダーのセキュリティ情報で最終確認してください。

---

## 結果の保存と表示

### SQLite

DB接続は `database/db.py` で管理されています。既定のDBファイルは次の場所です。

```text
data/risktrace.db
```

主なテーブル：

- `scans`：対象URL、プロトコル、状態、診断・分析オプション、作成日時など
- `findings`：診断結果、Severity、タイトル、URL、説明、Evidence、Recommendationなど

`database/models.py` は、Scan / Findingの保存、取得、状態更新を担当します。開発中にDBスキーマを変更する場合は既存DBへの影響を確認し、必要に応じてバックアップしてください。診断履歴を保持したい場合は、`data/risktrace.db` をむやみに削除しないでください。

### 主な画面・ルート

| ルート | メソッド | 用途 |
|---|---|---|
| `/` | GET | 診断フォーム |
| `/scan` | POST | 新しい診断の開始 |
| `/status/<scan_id>` | GET | Scan状態の取得 |
| `/rescan/<scan_id>` | POST | 保存済み設定を使った再診断 |
| `/result/<scan_id>` | GET | 診断結果 |
| `/report/<scan_id>` | GET | レポート |

アプリには、リダイレクト・Cookie・ヘッダー・クローラーの確認に使う開発用テストルートもあります。テストルートを本番環境で公開しないでください。

---

## テスト

### 全テスト

プロジェクトルートで実行します。

```powershell
python -m unittest discover -s tests -v
```

M7.1の適用後、開発環境では **42件すべて成功（`OK`）** したことを確認しています。コード変更後はテスト数や内容が変わることがあるため、必ず現在の環境で再実行してください。

### 構文チェック

```powershell
python -m py_compile app.py scanner/port_check.py analyzer/vulnerability_lookup.py
```

### テストファイルの名前に注意

`unittest discover` は通常 `test*.py` という名前のファイルを探索します。たとえば `test_vulnerability_lookup (1).py` のように名前が変わると自動検出されません。正しい名前は次です。

```text
tests/test_vulnerability_lookup.py
```

---

## ローカルHTTPSテストサーバー

必要な場合、`tests/https_test_server.py` を使い、ローカルのTLSテストを行えます。これは自己署名証明書の検証失敗などを確認する開発用サーバーです。ファイルが配置されていない場合は、プロジェクトに追加してから使用してください。

1. 依存パッケージを入れ、プロジェクトルートで仮想環境を有効にします。
2. 1つ目のターミナルで実行します。

   ```powershell
   python tests/https_test_server.py
   ```

3. 別ターミナルから、必要に応じてポート検査関数またはRiskTrace画面で次を診断します。

   ```text
   https://127.0.0.1:8443/
   ```

4. テスト終了後、サーバーを起動したターミナルで `Ctrl + C` を押して停止します。

テスト用証明書はローカル検証用であり、本番サイトで使用しないでください。

---

## セキュリティ上の設計と制約

- クローラーは開始URLと同じスキーム・ホスト・ポートの範囲でURLを探索します。既定のページ数上限は10です。
- HTTPリクエストのリダイレクトは自動追跡せず、上限（5回）、対象外ホスト、認証情報を含むURL、HTTPSからHTTPへのダウングレードなどをチェックします。
- ポート検査は固定リストに限定したTCP接続確認です。SYNスキャンや全ポートスキャンではありません。
- TCP接続できたという事実は、この検査端末から接続できたことのみを示し、インターネット上の全地点から到達可能であることは証明しません。
- ループバックの検査結果を、別ホストやインターネットからの公開状態と混同しないようにします。
- サービスバナーは未検証の観測値です。バナーだけから製品やバージョンを断定しません。
- CVE照合結果は候補情報です。候補を脆弱性確定として報告せず、正確な製品・ビルド・構成条件の確認を促します。
- FTP / SMTP / SSHなどのプローブは初期応答の観測に限定し、認証情報を送信しません。Redisの確認は限定的なPING応答確認で、データ変更を行いません。
- `debug=True`、テストルート、テスト用HTTPSサーバーは開発環境限定です。
- 本番利用を想定する場合は、認証・認可、CSRF対策、レート制限、ジョブキュー、ログ・監査、秘密情報管理、公開時のネットワーク制限などを別途レビューしてください。

---

## トラブルシューティング

### 仮想環境が有効にならない

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

これは現在のPowerShellプロセスに対する設定です。学校・会社の管理ポリシーに反する操作は行わず、必要ならコマンドプロンプトで `.venv\Scripts\activate.bat` を使用してください。

### `python app.py` で起動しない

```powershell
python --version
python -m pip show Flask requests beautifulsoup4
```

仮想環境が `(.venv)` と表示されていること、プロジェクトルート（`app.py` がある場所）にいることを確認します。

### `test_port_check` やCVＥテストが実行されない

```powershell
Get-ChildItem .\tests -Force | Select-Object Name, Extension
```

`test_port_check.py`、`test_service_probe.py`、`test_vulnerability_lookup.py` などのファイル名が正しいか確認します。ZIP展開時に `(1)` が付いていたら、他の同名ファイルと重複しないよう中身を確認してから正しい名前に戻してください。

### NVDの照合結果が出ない

NVDへのインターネット接続、API制限、バナーから製品・バージョンを識別できるか、CPE条件に一致する候補があるかを確認します。候補がゼロでも脆弱性がないとは断定できません。

### TLS情報が出ない

対象ポートがTLS対応であることを確認してください。`http://127.0.0.1:5000/` のような通常のHTTP接続では、TLS証明書情報は取得されません。ローカルHTTPSテストでは `https://127.0.0.1:8443/` を使用できます。

---

## 開発ロードマップ

### 完了（M1〜M7.1）

- M1：クロール範囲とリダイレクトの安全制御
- M2：診断項目・分析機能の選択
- M3：Webポート・TLS検査
- M4：重要サービス用ポートの追加
- M5：ネットワーク範囲と検出確度を考慮したサービス別評価
- M6：SSH / FTP / SMTP / MySQL / Redisの応答観測
- M7：NVD CVE候補照合
- M7.1：CPE製品識別子、コンポーネント、バージョン範囲の照合精度改善

### 次の予定：M8

- CVSS、検出確度、観測されたネットワーク範囲、追加確認が必要な条件を使った対応優先順位付け
- 未検証のCVE候補と、根拠がより強い検出結果を区別した説明
- 優先度の根拠・推奨対策を結果画面とレポートに整理

M8は本README作成時点では計画段階であり、完了機能としては扱っていません。

---

## 開発時の基本コマンド

```powershell
# 仮想環境を有効化
.\.venv\Scripts\Activate.ps1

# アプリ起動
python app.py

# 全テスト
python -m unittest discover -s tests -v

# 主要ファイルの構文確認
python -m py_compile app.py scanner/port_check.py analyzer/vulnerability_lookup.py

# Gitの変更を確認
git status
```

---

## ライセンス

本READMEでは、RiskTraceのライセンスを指定していません。再配布や商用利用を行う場合は、プロジェクトのライセンス方針を別途明記してください。
