# マイルストーン履歴

過去に配布した変更パッケージの記録。いずれも適用済み。ZIP展開手順は省略し、設計上の判断と注意だけを残す。

---

## M5 - サービス別リスク評価

対象: scanner/port_check.py, tests/test_port_check.py

- 実際のTCP接続から得られた peer IP で、ループバック／プライベート／リンクローカル／グローバル／特殊用途／不明に分類する。
- ループバック限定で検出した要確認ポートは INFO とし、外部公開の証拠ではないと明記する。
- 接続先が内部／グローバルのいずれでも、接続成功だけでインターネット全体からの到達性を証明しないと説明する。
- TCP接続のみ・HTTP応答確認・TLSハンドシェイク確認を Evidence に明示し、ポート番号だけでサービスを断定しない。
- Server ヘッダーは偽装可能な未検証バナーとして記録する。
- TLS証明書の検証失敗 Finding にもネットワーク範囲の文脈を加え、ループバックのみなら INFO にする。
- M5 自動テスト4件を追加。

注意: TCP接続で確認できるのは検査端末から当該ポートに接続できたことだけ。別端末やインターネットからの到達性は証明しない。

---

## M7.1 - CVE誤検出を減らす照合改善

対象: analyzer/vulnerability_lookup.py, tests/test_vulnerability_lookup.py
（app.py の呼び出し名 lookup_cve_candidates は維持）

- MySQL Server バナーから検索した際、明らかに MySQL Client / C API 向けの CVE 候補を除外する。
- NVD の CPE configuration にある vendor/product を確認する。
- versionStartIncluding / versionStartExcluding / versionEndIncluding / versionEndExcluding と観測バージョンを比較する。
- 製品・バージョン条件に一致しない候補は該当 CVE として出さず、フィルター結果を INFO として記録する。
- CPE 構成が返らず独立確認できない場合は UNKNOWN 候補として扱い、脆弱性確定と断定しない。
- CVE 候補は INFO のまま。バナーが未検証で、実インストール製品・ビルド・環境条件を確定できないため。

注意: 照合はトリアージ用。CPE とバージョン範囲が一致しても OS・ベンダーパッチ・ビルド・設定の一致は保証しない。NVD 側 configuration が省略されている場合は候補として残す。CVE が見つからないことは脆弱性なしを意味しない。

---

## M9 - レポートエクスポート (JSON / CSV)

対象: report_export.py, tests/test_report_export.py

- GET /export/<scan_id>/json と GET /export/<scan_id>/csv を追加。
- register_export_routes(app, get_scan, get_findings) を app 生成直後に一度だけ登録する。ルート内や execute_scan 内では呼ばない。
- エクスポートは status が COMPLETED のときのみ許可。
- JSON はスキャンメタデータ・オプション・重大度別サマリ・全 Finding を含む。
- CSV は Finding 1件1行。Excel の日本語向けに UTF-8 BOM。数式解釈され得るセルはアポストロフィを前置する。
- シリアライズの純粋テストは Flask 非依存、ルートテストは Flask 導入時のみ実行。