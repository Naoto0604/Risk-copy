from flask import Flask, render_template, request
from urllib.parse import urlparse, urljoin
import uuid
import json
import requests
import threading
from engine.legacy_crawl import crawl_urls as crawl,normalize_url
from engine.legacy_checks import run_checks
from engine.legacy_scoring import calculate_risk_score, get_risk_level
from analyzer.correlation import correlate_findings
from analyzer.attack_path import generate_attack_paths
from analyzer.priority import aggregate_priorities, calculate_priority
from analyzer.comparison import compare_findings
from engine.cve import lookup_cve_candidates
from flask import Flask, render_template, request, redirect
from flask import make_response
from engine.legacy_ports import check_web_ports
from engine.legacy_export import register_export_routes
# ======= #5 追加 =======
# データベース読み込み用import
from database.models import (
    init_db,
    create_scan,
    update_scan_status,
    create_findings,
    get_scan,
    get_findings
)
app = Flask(__name__)
# ===== #5 追加 =====
init_db()
register_export_routes(app, get_scan, get_findings)
# =============================================================
# #9 Risk Map用
# =============================================================

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def get_highest_severity(findings):
    """
    Finding一覧から最も高いSeverityを取得する
    #9 Risk Map用
    """

    if not findings:
        return "INFO"

    highest = "INFO"

    for finding in findings:
        severity = finding.get("severity", "INFO")

        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = severity
    return highest

def build_risk_map(target_url, discovered_urls, findings, correlations):
    """
    Risk Map表示用のデータを作成する

    構造:
    Internet
        ↓
    Target URL
        ↓
    Discovered URL
        ↓
    Finding
        ↓
    Correlation

    #9 Risk Map

    """
    # ----------------------------------------------------------
    # FindingをURLごとにまとめる
    # ----------------------------------------------------------

    findings_by_url = {}
    for finding in findings:

        finding_url = finding.get("url")

        if not finding_url:
            continue

        if finding_url not in findings_by_url:
            findings_by_url[finding_url] = []

        findings_by_url[finding_url].append(finding)
    # ------------------------------------------------------------
    # URL一覧を作成
    # ------------------------------------------------------------

    urls = set()

    if target_url:
        urls.add(target_url)

    if discovered_urls:

        for discovered_url in discovered_urls:
            urls.add(discovered_url)

    # Findingに存在するURLも追加
    for finding_url in findings_by_url:
        urls.add(finding_url)

    # ------------------------------------------------------------
    # ページ情報を作成
    # ------------------------------------------------------------

    pages = []

    for page_url in sorted(urls):

        page_findings = findings_by_url.get(
            page_url,
            []
        )

        pages.append({
            "url": page_url,
            "findings": page_findings,
            "severity": get_highest_severity(page_findings)
        })
    # ------------------------------------------------------------
    # Correlationを整理
    # ------------------------------------------------------------

    risk_correlations = []

    for correlation in correlations:

        risk_correlations.append({
            "title": correlation.get("title"),
            "severity": correlation.get("severity", "HIGH"),
            "url": correlation.get("url"),
            "description": correlation.get("description")
        })
    # ------------------------------------------------------------
    # Risk Mapデータ
    # ------------------------------------------------------------

    return {
        "target_url": target_url,
        "pages": pages,
        "correlations": risk_correlations,
        "summary": {
            "high_risk_pages": sum(
                page["severity"] in {"HIGH", "CRITICAL"} for page in pages
            ),
            "medium_risk_pages": sum(
                page["severity"] == "MEDIUM" for page in pages
            ),
        },
    }


def summarize_findings(findings):
    """Group overview rows by finding kind while keeping raw Findings intact."""
    grouped = {}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        key = (
            finding.get("type") or "UNKNOWN",
            finding.get("subtype") or "",
            finding.get("title") or "Untitled finding",
            (finding.get("severity") or "INFO").upper(),
        )
        summary = grouped.setdefault(key, {
            "type": key[0],
            "subtype": key[1],
            "title": key[2],
            "severity": key[3],
            "finding_count": 0,
            "urls": {},
        })
        summary["finding_count"] += 1
        url = finding.get("url")
        if url:
            summary["urls"][url] = summary["urls"].get(url, 0) + 1

    summaries = []
    for summary in grouped.values():
        summary["page_count"] = len(summary["urls"])
        summary["page_details"] = [
            {"url": url, "finding_count": count}
            for url, count in sorted(summary["urls"].items())
        ]
        summaries.append(summary)
    return sorted(
        summaries,
        key=lambda item: (
            -item["finding_count"], item["title"], item["type"], item["subtype"]
        ),
    )
# ================================================================
# TOP
# ================================================================

@app.route("/")
def index():
    return render_template(
        "index.html"
    )

# ============================================================
# 【#13 A-1】 URL入力バリデーション
# ============================================================
def is_valid_url(url):
    """
    スキャン対象URLが正しい形式か判定する

    #13 A-1
    - URLが空でないこと
    - http / https であること
    - ホスト名が存在すること
    """
    # URLが空の場合
    if not url:
        return False
    try:
        # URLを解析
        result = urlparse(url)

        # ----------------------------------------------------
        # 【#13 A-1】通信プロトコルチェック
        # http / https 以外はスキャン対象外
        # ----------------------------------------------------
        if result.scheme not in ["http", "https"]:
            return False
        
        # ----------------------------------------------------
        # 【#13 A-1】ホスト名チェック
        # netlocが存在しないURLは無効
        # ----------------------------------------------------
        if not result.netloc:
            return False

        return True

    except Exception:
        # URL解析中にエラーが発生した場合
        return False

# ============================================================
# 【#13 A-3】リダイレクト制御
# ============================================================
MAX_REDIRECTS = 5

def safe_request(url):
    """
    リダイレクトを制御しながらHTTPリクエストを実行する。

    - 最大リダイレクト数を MAX_REDIRECTS 回に制限
    - HTTP / HTTPS 以外へのリダイレクトを拒否
    - 診断対象外ホストへのリダイレクトを拒否
    - 無限リダイレクトを防止
    """

    original_parsed = urlparse(url)

    # 開始URLを検証
    if (
        original_parsed.scheme not in ("http", "https")
        or not original_parsed.hostname
        or original_parsed.username is not None
        or original_parsed.password is not None
    ):
        raise requests.RequestException(
            f"開始URLが不正です: {url}"
        )

    # ホスト名とポートを含む接続先を基準にする
    original_host = original_parsed.netloc.lower()

    redirect_history = []
    current_url = url

    for redirect_count in range(MAX_REDIRECTS + 1):

        response = requests.get(
            current_url,
            timeout=5,
            allow_redirects=False,
        )

        # リダイレクトではない場合
        if response.status_code not in (301, 302, 303, 307, 308):
            response.history = redirect_history
            return response

        # リダイレクト先を取得
        location = response.headers.get("Location")

        if not location:
            response.history = redirect_history
            return response

        # 上限に達している場合は、追加のリダイレクトを追わない
        if redirect_count >= MAX_REDIRECTS:
            response.close()
            raise requests.TooManyRedirects(
                f"リダイレクト回数が上限"
                f"({MAX_REDIRECTS})を超えました: {url}"
            )

        # 相対URLを絶対URLに変換
        next_url = urljoin(current_url, location)
        parsed_next = urlparse(next_url)

        # HTTP / HTTPS 以外へのリダイレクトを拒否
        if parsed_next.scheme not in ("http", "https"):
            response.close()
            raise requests.RequestException(
                f"Redirect先のプロトコルが不正です: {next_url}"
            )

        # 認証情報を含むURLを拒否
        if (
            not parsed_next.hostname
            or parsed_next.username is not None
            or parsed_next.password is not None
        ):
            response.close()
            raise requests.RequestException(
                f"Redirect先のURLが不正です: {next_url}"
            )

        # 診断対象外のホスト・ポートへのリダイレクトを拒否
        if parsed_next.netloc.lower() != original_host:
            response.close()
            raise requests.RequestException(
                f"診断対象外へのRedirectを拒否しました: {next_url}"
            )

        # HTTPS から HTTP へのダウングレードを拒否
        if (
            urlparse(current_url).scheme == "https"
            and parsed_next.scheme == "http"
        ):
            response.close()
            raise requests.RequestException(
                f"HTTPSからHTTPへのRedirectを拒否しました: {next_url}"
            )

        # リダイレクト履歴を保存して次へ
        redirect_history.append(response)
        current_url = next_url

    # 通常ここには到達しないが、安全側に倒す
    raise requests.TooManyRedirects(
        f"リダイレクト回数が上限を超えました: {url}"
    )
# ============================================================
# Scan
# ============================================================
@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get("url")

    # 選択された診断項目を取得
    enabled_checks = set(request.form.getlist("checks"))

    # 許可する診断項目
    allowed_checks = {
        "https",
        "headers",
        "cookies",
        "redirects",
        "ports",
    }

    # 不正な値を除外
    enabled_checks &= allowed_checks

    # 1項目も選択されていない場合はエラー
    if not enabled_checks:
        return "診断項目を1つ以上選択してください。", 400

    if not url:
        return "URLを入力してください。", 400

    if not is_valid_url(url):
        return "無効なURL形式です。", 400

    # 選択された分析機能をフォームから取得
    analysis_options = set(
        request.form.getlist("analysis")
    )

    # 使用可能な分析機能を定義
    allowed_analysis_options = {
        "score",
        "correlation",
        "attack_path",
        "priority",
    }

    # 許可された選択肢だけを残す
    analysis_options &= allowed_analysis_options

    
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme

    # Scan ID発行
    scan_id = str(uuid.uuid4())

    # DBにRUNNING保存
    create_scan(
        scan_id=scan_id,
        target_url=url,
        protocol=protocol,
        status="RUNNING",
        analysis_options=analysis_options,
        checks_options=enabled_checks
    )   

    # バックグラウンドで診断開始
    thread = threading.Thread(
        target=execute_scan,
        args=(scan_id, url, protocol,enabled_checks,analysis_options)
    )

    thread.start()

    # 診断中画面を表示
    return render_template(
        "scanning.html",
        scan_id=scan_id,
        url=url,
        protocol=protocol,
        status="RUNNING",
        compare_scan_id=""
    )

def execute_scan(scan_id, url, protocol,enabled_checks=None,analysis_options=None):

    # 分析機能が指定されていない場合は全機能を有効にする
    if analysis_options is None:
        analysis_options = {
            "score",
            "correlation",
            "attack_path",
            "priority",
        }
    else:
        analysis_options = set(analysis_options)

    try:  
        # ==============================
        # Crawler
        # ==============================

        discovered_urls = crawl(
           url,
           max_pages=10
       )
       # 開始URLは必ず検査する。クロールが空を返しても（開始URLが
       # リダイレクトする、全取得が失敗する等）検査が空回りしないようにする。
        start_url = normalize_url(url) or url
        if start_url not in discovered_urls:
           discovered_urls = set(discovered_urls) | {start_url}        
        # ==============================
        # #4 Security Check
        # ==============================

        findings = []
        checked_count = 0
        # Webポート確認
        if enabled_checks and "ports" in enabled_checks:
            try:
                port_findings = check_web_ports(url)
                findings.extend(port_findings)
            except ValueError as e:
                print(f"[Port Check] 対象URLエラー: {e}")
        # ============================================================
        # 【#13 A-2】HTTP通信例外処理
        # ============================================================

        for discovered_url in discovered_urls:

            try:
                # ----------------------------------------------------
                # 【#13 A-3】
                # ----------------------------------------------------    
                response = safe_request(discovered_url)
                # ----------------------------------------------------
                # Security Check
                # 通信に成功したURLだけチェックする
                # ----------------------------------------------------

                findings.extend(
                    run_checks(
                        discovered_url,
                        response,
                        enabled_checks=enabled_checks
                    )
                )
                checked_count += 1
            except requests.RequestException as e:
                # ----------------------------------------------------
                # 【#13 A-2】
                # HTTP通信に失敗してもスキャン全体は停止しない
                #
                # 例：
                # - ConnectionError
                # - Timeout
                # - HTTP通信関連のエラー
                #
                # エラーになったURLだけスキップして
                # 次のURLの診断を続行する
                # ----------------------------------------------------
                print(
                    f"[#13 A-2] HTTP通信エラー: "
                    f"{discovered_url} / {e}"
                )
                continue

        # ==============================
        # M7: NVD CVE candidate lookup
        # Run only when TCP port/service checks were selected. Banner-derived
        # product/version strings are unverified, so outputs stay INFO and are
        # treated as candidates rather than confirmed vulnerabilities.
        # ==============================
        if enabled_checks and "ports" in enabled_checks:
            try:
                findings.extend(lookup_cve_candidates(findings))
            except Exception as lookup_error:
                # CVE enrichment must never fail the primary security scan.
                print(f"[M7 CVE Lookup] Enrichment skipped: {lookup_error}")

        # ==============================
        # #5 Finding DB保存
        # ==============================

        create_findings(
            scan_id=scan_id,
            findings=findings
        )

        # ============================================================
        # #6 Risk Scoring
        # ============================================================

        risk_score = None
        risk_level = None

        if "score" in analysis_options:
            risk_score = calculate_risk_score(findings)
            risk_level = get_risk_level(risk_score)


        # ============================================================
        # #7 Risk Correlation
        # ============================================================

        correlations = []

        if "correlation" in analysis_options:
            correlations = correlate_findings(findings)


        # ============================================================
        # #8 Attack Path
        # ============================================================

        attack_paths = []

        if "attack_path" in analysis_options:
            attack_paths = generate_attack_paths(
                findings,
                correlations
            )


        # ============================================================
        # #10 Priority
        # ============================================================

        priorities = []
        priority_groups = []

        if "priority" in analysis_options:
            priorities = calculate_priority(
                findings,
                correlations,
                attack_paths
            )
            priority_groups = aggregate_priorities(priorities)


        # ============================================================
        # #9 Risk Map
        # ============================================================

        risk_map = build_risk_map(
            target_url=url,
            discovered_urls=discovered_urls,
            findings=findings,
            correlations=correlations
        )
        # ==============================
        # Scan完了
        # ==============================

        update_scan_status(
            scan_id=scan_id,
            status="COMPLETED"
        )
        
    except Exception as e:
        # 詳細はサーバー側のコンソールに出力する
        print(f"Scan Error: {e}")

        # ブラウザには内部情報を出しすぎず、
        # 失敗したことと確認先を伝える
        error_message = (
            f"診断処理に失敗しました（{type(e).__name__}）。"
            " 詳細はサーバー側のコンソールを確認してください。"
        )

        update_scan_status(
            scan_id=scan_id,
            status="FAILED",
            error_message=error_message,
        )

# ============================================================
# Rescan
# 前回の診断設定・分析設定を引き継いで再診断する
# ============================================================

@app.route("/rescan/<scan_id>", methods=["POST"])
def rescan(scan_id):
    # ① 比較元のScanを取得
    previous_scan = get_scan(scan_id)

    if not previous_scan:
        return "比較元Scanが見つかりません。", 404

    # ② 前回の対象URLとプロトコルを取得
    url = previous_scan["target_url"]
    protocol = previous_scan["protocol"]

    # ③ デフォルト設定と許可する設定を分ける
    # portsは許可するが、デフォルトでは有効にしない
    default_checks = {
        "https",
        "headers",
        "cookies",
        "redirects",
    }
    allowed_checks = default_checks | {"ports"}

    default_analysis = {
        "score",
        "correlation",
        "attack_path",
        "priority",
    }
    allowed_analysis = default_analysis.copy()

    # 前回の診断項目を読み込む
    try:
        raw_checks = json.loads(
            previous_scan["checks_options"]
        )

        if (
            not isinstance(raw_checks, list)
            or any(not isinstance(item, str) for item in raw_checks)
        ):
            raise ValueError("診断項目の形式が不正です")

        # 許可された項目だけを引き継ぐ
        # 空リストの場合は空のままにする
        checks_options = set(raw_checks) & allowed_checks

    except (KeyError, TypeError, ValueError):
        checks_options = default_checks.copy()

    # 前回の分析機能を読み込む
    try:
        raw_analysis = json.loads(
            previous_scan["analysis_options"]
        )

        if (
            not isinstance(raw_analysis, list)
            or any(not isinstance(item, str) for item in raw_analysis)
        ):
            raise ValueError("分析機能の形式が不正です")

        # 許可された機能だけを引き継ぐ
        # 空リストの場合は空のままにする
        analysis_options = set(raw_analysis) & allowed_analysis

    except (KeyError, TypeError, ValueError):
        analysis_options = default_analysis.copy()

    # ④ 新しいScan IDを発行
    new_scan_id = str(uuid.uuid4())

    # ⑤ 前回と同じ設定で新しいScanをDBに保存
    create_scan(
        scan_id=new_scan_id,
        target_url=url,
        protocol=protocol,
        status="RUNNING",
        analysis_options=analysis_options,
        checks_options=checks_options,
    )

    # ⑥ 前回の診断設定・分析設定を渡して実行
    thread = threading.Thread(
        target=execute_scan,
        args=(
            new_scan_id,
            url,
            protocol,
            checks_options,
            analysis_options,
        ),
    )

    thread.start()

    # ⑦ 再診断中の画面を表示
    return render_template(
        "scanning.html",
        scan_id=new_scan_id,
        url=url,
        protocol=protocol,
        status="RUNNING",
        compare_scan_id=scan_id,
    )


@app.route("/status/<scan_id>")
def scan_status(scan_id):
    scan_data = get_scan(scan_id)

    if not scan_data:
        return {
            "status": "NOT_FOUND",
            "error_message": None,
        }, 404

    return {
        "status": scan_data["status"],
        "error_message": scan_data["error_message"],
    }


def _saved_option_set(scan, field, allowed):
    """Return a validated saved Scan option set, or None for unreadable data."""
    try:
        value = json.loads(scan[field])
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return None
    return set(value) & allowed


def _build_scan_comparison(before_scan, after_scan, before_findings, after_findings):
    """Build a comparison while keeping scope changes visible to the user."""
    check_options = {"https", "headers", "cookies", "redirects", "ports"}
    analysis_options = {"score", "correlation", "attack_path", "priority"}
    before_checks = _saved_option_set(before_scan, "checks_options", check_options)
    after_checks = _saved_option_set(after_scan, "checks_options", check_options)
    before_analysis = _saved_option_set(before_scan, "analysis_options", analysis_options)
    after_analysis = _saved_option_set(after_scan, "analysis_options", analysis_options)

    checks_comparable = before_checks is not None and after_checks is not None
    checks_match = checks_comparable and before_checks == after_checks
    score_comparable = (
        before_analysis is not None
        and after_analysis is not None
        and "score" in before_analysis
        and "score" in after_analysis
    )

    comparison = compare_findings(before_findings, after_findings)
    comparison.update({
        "before_checks": sorted(before_checks) if before_checks is not None else None,
        "after_checks": sorted(after_checks) if after_checks is not None else None,
        "checks_comparable": checks_comparable,
        "checks_match": checks_match,
        "score_comparable": score_comparable,
        "before_risk_score": None,
        "before_risk_level": None,
        "after_risk_score": None,
        "after_risk_level": None,
        "score_delta": None,
    })

    if score_comparable:
        before_score = calculate_risk_score(before_findings)
        after_score = calculate_risk_score(after_findings)
        comparison.update({
            "before_risk_score": before_score,
            "before_risk_level": get_risk_level(before_score),
            "after_risk_score": after_score,
            "after_risk_level": get_risk_level(after_score),
            "score_delta": after_score - before_score,
        })
    return comparison


# ============================================================
# Result
# ============================================================

@app.route("/result/<scan_id>")
def result(scan_id):
    """
    DBから診断結果を取得し、選択された分析機能を実行して
    結果画面に渡す。
    """

    # ========================================================
    # ① DBからScan情報を取得
    # ========================================================

    scan_data = get_scan(scan_id)

    if not scan_data:
        return "Scanが見つかりません。", 404

    if scan_data["status"] != "COMPLETED":
        return "診断が完了していません。", 409

    findings = get_findings(scan_id)
    findings_list = [dict(finding) for finding in findings]

    # Scanの基本情報
    url = scan_data["target_url"]
    protocol = scan_data["protocol"]
    status = scan_data["status"]

    # ========================================================
    # ② DBから分析機能の選択内容を取得
    # ========================================================

    all_analysis_options = {
        "score",
        "correlation",
        "attack_path",
        "priority",
    }

    try:
        saved_options = json.loads(
            scan_data["analysis_options"]
        )

        if not isinstance(saved_options, list):
            raise ValueError("分析機能の保存形式が不正です")

        # 許可された分析機能だけを使う
        analysis_options = (
            set(saved_options) & all_analysis_options
        )

    except (KeyError, TypeError, ValueError):
        # 古いデータなどで設定を読み取れない場合
        # 従来どおり全分析機能を有効にする
        analysis_options = all_analysis_options.copy()

    # ========================================================
    # ③ Risk Score
    # ========================================================

    risk_score = None
    risk_level = None

    if "score" in analysis_options:
        risk_score = calculate_risk_score(
            findings_list
        )
        risk_level = get_risk_level(
            risk_score
        )

    # ========================================================
    # ④ Risk Correlation
    # ========================================================

    correlations = []

    if "correlation" in analysis_options:
        correlations = correlate_findings(
            findings_list
        )

    # ========================================================
    # ⑤ Attack Path
    # ========================================================

    attack_paths = []

    if "attack_path" in analysis_options:
        # Attack PathがCorrelationを必要とするため、
        # 選択されていない場合も内部計算に利用する
        attack_path_correlations = correlations

        if "correlation" not in analysis_options:
            attack_path_correlations = correlate_findings(
                findings_list
            )

        attack_paths = generate_attack_paths(
            findings_list,
            attack_path_correlations
        )

    # ========================================================
    # ⑥ Remediation Priority
    # ========================================================

    priorities = []
    priority_groups = []

    if "priority" in analysis_options:
        # Priorityに必要な依存分析を準備する
        priority_correlations = correlations

        if "correlation" not in analysis_options:
            priority_correlations = correlate_findings(
                findings_list
            )

        priority_attack_paths = attack_paths

        if "attack_path" not in analysis_options:
            priority_attack_paths = generate_attack_paths(
                findings_list,
                priority_correlations
            )

        priorities = calculate_priority(
            findings_list,
            priority_correlations,
            priority_attack_paths
        )
        priority_groups = aggregate_priorities(priorities)

    # ========================================================
    # ⑦ Before / After 比較
    # ========================================================

    comparison = None

    compare_scan_id = request.args.get(
        "compare_scan_id"
    )

    if compare_scan_id:
        compare_scan = get_scan(
            compare_scan_id
        )

        if not compare_scan:
            return "比較元Scanが見つかりません。", 404

        # 別サイトとの比較を防止する
        if compare_scan["target_url"] != url:
            return "比較対象URLが一致しません。", 400

        if compare_scan["status"] != "COMPLETED":
            return "比較元Scanが完了していません。", 409

        before_findings = [
            dict(finding) for finding in get_findings(compare_scan_id)
        ]
        comparison = _build_scan_comparison(
            compare_scan, scan_data, before_findings, findings_list
        )
        comparison["before_scan_id"] = compare_scan_id

    # ========================================================
    # ⑧ Risk Map
    # ========================================================

    discovered_urls = sorted({
        finding.get("url")
        for finding in findings_list
        if finding.get("url")
    })

    risk_map = build_risk_map(
        target_url=url,
        discovered_urls=discovered_urls,
        findings=findings_list,
        correlations=correlations
    )
    finding_summaries = summarize_findings(findings_list)

    # ========================================================
    # ⑨ 結果画面にデータを渡す
    # ========================================================

    return render_template(
        "result.html",
        scan_id=scan_id,
        url=url,
        protocol=protocol,
        status=status,
        discovered_urls=discovered_urls,
        findings=findings_list,
        risk_score=risk_score,
        risk_level=risk_level,
        correlations=correlations,
        attack_paths=attack_paths,
        priorities=priorities,
        priority_groups=priority_groups,
        risk_map=risk_map,
        finding_summaries=finding_summaries,
        comparison=comparison,
        analysis_options=analysis_options
    )

# ============================================================
# #12 Report
# 診断結果を読み込み、レポート画面を表示する
# ============================================================

@app.route("/report/<scan_id>")
def report(scan_id):
    """DBに保存された診断結果からレポートを作成する。"""

    # ① DBからScan情報を取得
    scan_data = get_scan(scan_id)

    if not scan_data:
        return "Scanが見つかりません。", 404

    if scan_data["status"] != "COMPLETED":
        return "診断が完了していないため、レポートを作成できません。", 409

    # ② Finding一覧を取得
    findings = get_findings(scan_id)
    findings_list = [dict(finding) for finding in findings]

    comparison = None
    compare_scan_id = request.args.get("compare_scan_id")
    if compare_scan_id:
        compare_scan = get_scan(compare_scan_id)
        if not compare_scan:
            return "比較元Scanが見つかりません。", 404
        if compare_scan["target_url"] != scan_data["target_url"]:
            return "比較対象URLが一致しません。", 400
        if compare_scan["status"] != "COMPLETED":
            return "比較元Scanが完了していません。", 409
        before_findings = [
            dict(finding) for finding in get_findings(compare_scan_id)
        ]
        comparison = _build_scan_comparison(
            compare_scan, scan_data, before_findings, findings_list
        )
        comparison["before_scan_id"] = compare_scan_id

    # ③ Scanの基本情報
    url = scan_data["target_url"]
    protocol = scan_data["protocol"]
    status = scan_data["status"]
    scan_date = scan_data["created_at"]

    # ④ 保存された分析機能の選択内容を取得
    all_analysis_options = {
        "score",
        "correlation",
        "attack_path",
        "priority",
    }

    try:
        saved_options = json.loads(
            scan_data["analysis_options"]
        )

        if not isinstance(saved_options, list):
            raise ValueError("分析機能の保存形式が不正です")

        analysis_options = (
            set(saved_options) & all_analysis_options
        )

    except (KeyError, TypeError, ValueError):
        # 過去のデータなどで選択内容が読めない場合
        analysis_options = all_analysis_options.copy()

    # ⑤ Risk Score
    risk_score = None
    risk_level = None

    if "score" in analysis_options:
        risk_score = calculate_risk_score(findings_list)
        risk_level = get_risk_level(risk_score)

    # ⑥ Risk Correlation
    correlations = []

    if "correlation" in analysis_options:
        correlations = correlate_findings(findings_list)

    # ⑦ Attack Path
    attack_paths = []

    if "attack_path" in analysis_options:
        # Attack Pathが必要とするCorrelationを内部計算
        attack_path_correlations = correlations

        if "correlation" not in analysis_options:
            attack_path_correlations = correlate_findings(
                findings_list
            )

        attack_paths = generate_attack_paths(
            findings_list,
            attack_path_correlations
        )

    # ⑧ Remediation Priority
    priorities = []
    priority_groups = []

    if "priority" in analysis_options:
        # Priorityに必要な関連分析を準備
        priority_correlations = correlations

        if "correlation" not in analysis_options:
            priority_correlations = correlate_findings(
                findings_list
            )

        priority_attack_paths = attack_paths

        if "attack_path" not in analysis_options:
            priority_attack_paths = generate_attack_paths(
                findings_list,
                priority_correlations
            )

        priorities = calculate_priority(
            findings_list,
            priority_correlations,
            priority_attack_paths
        )
        priority_groups = aggregate_priorities(priorities)

    # ⑨ FindingからURL一覧を作成
    discovered_urls = sorted({
        finding.get("url")
        for finding in findings_list
        if finding.get("url")
    })

    # ⑩ Risk Map
    risk_map = build_risk_map(
        target_url=url,
        discovered_urls=discovered_urls,
        findings=findings_list,
        correlations=correlations
    )

    # ⑪ レポート画面にデータを渡す
    return render_template(
        "report.html",
        scan_id=scan_id,
        url=url,
        protocol=protocol,
        status=status,
        scan_date=scan_date,
        discovered_urls=discovered_urls,
        findings=findings_list,
        risk_score=risk_score,
        risk_level=risk_level,
        correlations=correlations,
        attack_paths=attack_paths,
        priorities=priorities,
        priority_groups=priority_groups,
        risk_map=risk_map,
        comparison=comparison,
        analysis_options=analysis_options
    )





# ============================================================
# 以下：テスト用ページ
# ============================================================
@app.route("/login")
def login():
    return "<h1>Login Page</h1><a href='/'>Home</a>"


@app.route("/about")
def about():
    return "<h1>About Page</h1><a href='/'>Home</a>"


@app.route("/contact")
def contact():
    return "<h1>Contact Page</h1><a href='/'>Home</a>"
@app.route("/test/redirect")
def redirect_test():
    return redirect("/login", code=302)

@app.route("/test/meta-redirect")
def meta_redirect_test():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta http-equiv="refresh" content="0; url=/login">
        <title>Meta Redirect Test</title>
    </head>
    <body>
        Meta Refresh Test
    </body>
    </html>
    """

@app.route("/test/js-redirect")
def js_redirect_test():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>JS Redirect Test</title>
    </head>
    <body>
        <script>
            window.location.href = "/login";
        </script>

        JavaScript Redirect Test
    </body>
    </html>
    """

@app.route("/test/http")
def test_http():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>HTTPS Test</title>
    </head>
    <body>
        <h1>HTTPS Test Page</h1>
        <p>This page is for testing HTTPS detection.</p>
    </body>
    </html>
    """

@app.route("/test/headers")
def test_headers():
    response = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Header Test</title>
    </head>
    <body>
        <h1>Security Header Test</h1>
    </body>
    </html>
    """

    return response


@app.route("/test/cookie")
def test_cookie():
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cookie Test</title>
    </head>
    <body>
        <h1>Cookie Test Page</h1>
        <p>This page is for testing Cookie security.</p>
    </body>
    </html>
    """)

    response.set_cookie(
        "test_cookie",
        "risktrace_test",
        httponly=True,
        samesite="Lax"
    )

    return response

@app.route("/test/crawler")
def test_crawler():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Crawler Test</title>
    </head>
    <body>
        <h1>Crawler Test</h1>

        <a href="/test/http">HTTP Test</a>
        <a href="/test/cookie">Cookie Test</a>
        <a href="/test/headers">Header Test</a>
        <a href="/test/meta-redirect">Meta Redirect Test</a>
        <a href="/test/js-redirect">JS Redirect Test</a>
    </body>
    </html>
    """

# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)
