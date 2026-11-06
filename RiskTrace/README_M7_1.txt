RiskTrace M7.1 - CVE誤検出を減らす照合改善
============================================================

今回置き換えるファイルは2つです。

1. analyzer/vulnerability_lookup.py
   既存ファイルを置き換えてください。

2. tests/test_vulnerability_lookup.py
   既存ファイルを置き換えてください。

app.py の呼び出し名 `lookup_cve_candidates` は維持しているため、M7統合済みの app.py は変更不要です。
scanner/port_check.py、old2_port_check.py、database/models.py は変更しないでください。

主な改善:
- MySQL Server のバナーから検索したとき、明らかにMySQL Client / C API向けのCVE候補を除外します。
- NVDのCPE configurationにある vendor/product を確認します。
- versionStartIncluding / versionStartExcluding / versionEndIncluding / versionEndExcluding と観測バージョンを比較します。
- 製品・バージョンの条件に一致しない候補は、該当CVEとして出さず、フィルター結果をINFOとして記録します。
- CPE構成が返らず独立した確認ができない場合は、UNKNOWNの候補として扱い、脆弱性確定と断定しません。
- CVE候補は引き続きINFOのままです。バナーは未検証であり、実際にインストールされた製品・ビルドや環境条件は確定できないためです。

バックアップ後、RiskTraceのプロジェクトルート (C:\Users\cre\RiskTrace) にZIPを展開し、同じディレクトリ構成で上書きしてください。

テスト:
    python -m py_compile analyzer/vulnerability_lookup.py tests/test_vulnerability_lookup.py
    python -m unittest discover -s tests -v

既存のテスト28件 + M7.1 CVE照合テスト14件 = 全42件になる想定です。既存プロジェクトの他のテストが残っている前提です。

注意:
- この照合はトリアージ用です。CPE/バージョン範囲が一致しても、OS、ベンダーパッチ、ビルド、設定など他の条件が合うとは限りません。
- NVD側の configuration が省略されている場合はバージョン適用可否を独立して検証できないため、照合候補として残します。
- CVEが見つからないことは「脆弱性なし」を意味しません。
