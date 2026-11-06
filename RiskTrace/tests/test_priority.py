import unittest

from analyzer.priority import aggregate_priorities, calculate_priority
from analyzer.priority import aggregate_priorities, calculate_priority, priority_rows

class TestCalculatePriority(unittest.TestCase):

    def make_finding(
        self,
        severity="MEDIUM",
        url="https://example.test/",
        finding_type="SECURITY_HEADER",
        title="Test finding",
    ):
        return {
            "type": finding_type,
            "severity": severity,
            "title": title,
            "url": url,
            "description": "Test description",
        }

    def test_empty_findings_returns_empty_list(self):
        """Findingが空なら優先順位も空になる。"""
        self.assertEqual(
            calculate_priority([], [], []),
            [],
        )

    def test_info_findings_are_excluded(self):
        """INFOのFindingは優先順位の対象外にする。"""
        findings = [
            self.make_finding(severity="INFO"),
        ]

        self.assertEqual(
            calculate_priority(findings, [], []),
            [],
        )

    def test_matching_correlation_adds_two_points(self):
        """対応する複合リスクがあれば2点加算する。"""
        finding = self.make_finding(
            severity="HIGH",
            finding_type="HTTPS",
        )

        correlations = [{
            "related_findings": [{
                "type": "HTTPS",
                "url": finding["url"],
            }],
        }]

        result = calculate_priority(
            [finding],
            correlations,
            [],
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["priority_score"], 5)
        self.assertEqual(result[0]["priority"], "高")

    def test_unrelated_correlation_adds_no_points(self):
        """URLが異なるFindingには複合リスク加点をしない。"""
        finding = self.make_finding(
            severity="HIGH",
            finding_type="HTTPS",
        )

        correlations = [{
            "related_findings": [{
                "type": "HTTPS",
                "url": "https://other.test/",
            }],
        }]

        result = calculate_priority(
            [finding],
            correlations,
            [],
        )

        self.assertEqual(result[0]["priority_score"], 3)

    def test_https_attack_path_adds_three_points(self):
        """HTTPS未使用が攻撃経路に含まれる場合は3点加算する。"""
        finding = self.make_finding(
            severity="HIGH",
            finding_type="HTTPS",
        )

        attack_paths = [{
            "url": finding["url"],
            "steps": ["HTTPS未使用"],
        }]

        result = calculate_priority(
            [finding],
            [],
            attack_paths,
        )

        self.assertEqual(result[0]["priority_score"], 6)
        self.assertEqual(result[0]["priority"], "高")

    def test_security_header_attack_path_adds_one_point(self):
        """ヘッダー不足が攻撃経路に含まれる場合は1点加算する。"""
        finding = self.make_finding(
            severity="MEDIUM",
            finding_type="SECURITY_HEADER",
        )

        attack_paths = [{
            "url": finding["url"],
            "steps": ["セキュリティヘッダー不足"],
        }]

        result = calculate_priority(
            [finding],
            [],
            attack_paths,
        )

        self.assertEqual(result[0]["priority_score"], 3)
        self.assertEqual(result[0]["priority"], "中")

    def test_priorities_are_sorted_by_score_descending(self):
        """スコアの高いFindingから順に並ぶ。"""
        low_finding = self.make_finding(
            severity="LOW",
            url="https://example.test/low",
        )

        high_finding = self.make_finding(
            severity="HIGH",
            url="https://example.test/high",
            finding_type="HTTPS",
        )

        medium_finding = self.make_finding(
            severity="MEDIUM",
            url="https://example.test/medium",
            finding_type="SECURITY_HEADER",
        )

        correlations = [{
            "related_findings": [{
                "type": "HTTPS",
                "url": high_finding["url"],
            }],
        }]

        attack_paths = [{
            "url": medium_finding["url"],
            "steps": ["セキュリティヘッダー不足"],
        }]

        result = calculate_priority(
            [low_finding, high_finding, medium_finding],
            correlations,
            attack_paths,
        )

        scores = [item["priority_score"] for item in result]

        self.assertEqual(scores, [5, 3, 1])

    def test_same_remediation_is_grouped_with_all_affected_urls(self):
        findings = [
            self.make_finding(url=f"https://example.test/{index}")
            for index in range(7)
        ]
        individual = calculate_priority(findings, [], [])
        result = aggregate_priorities(individual)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["finding_count"], 7)
        self.assertEqual(result[0]["page_count"], 7)
        self.assertEqual(len(result[0]["affected_urls"]), 7)
        self.assertEqual(len(result[0]["findings"]), 7)

    def test_priority_calculation_remains_individual_per_finding(self):
        findings = [
            self.make_finding(url=f"https://example.test/{index}")
            for index in range(7)
        ]
        self.assertEqual(len(calculate_priority(findings, [], [])), 7)

    def test_different_header_subtypes_remain_separate_actions(self):
        first = self.make_finding(url="https://example.test/a")
        first["subtype"] = "Content-Security-Policy"
        second = self.make_finding(url="https://example.test/b")
        second["subtype"] = "X-Frame-Options"
        self.assertEqual(len(aggregate_priorities(
            calculate_priority([first, second], [], [])
        )), 2)

    def test_different_categories_remain_separate(self):
        first = self.make_finding(finding_type="SECURITY_HEADER")
        second = self.make_finding(finding_type="COOKIE")
        groups = aggregate_priorities(calculate_priority([first, second], [], []))
        self.assertEqual(len(groups), 2)

    def test_legacy_findings_without_subtype_are_grouped(self):
        first = self.make_finding(url="https://example.test/a")
        second = self.make_finding(url="https://example.test/b")
        first.pop("subtype", None)
        second.pop("subtype", None)
        groups = aggregate_priorities(calculate_priority([first, second], [], []))
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["finding_count"], 2)

    def test_normalized_title_variants_group_together(self):
        first = self.make_finding(title="  CSP   is missing ", url="https://example.test/a")
        second = self.make_finding(title="csp is MISSING", url="https://example.test/b")
        groups = aggregate_priorities(calculate_priority([first, second], [], []))
        self.assertEqual(len(groups), 1)

    def test_group_uses_maximum_score_and_sorts_groups_by_score(self):
        items = [
            {"type": "A", "title": "first", "subtype": "x", "severity": "MEDIUM", "priority_score": 5.2, "priority": "中", "url": "https://example.test/a", "recommended_action": "fix", "evidence": "a"},
            {"type": "A", "title": "first", "subtype": "x", "severity": "HIGH", "priority_score": 6.0, "priority": "高", "url": "https://example.test/b", "recommended_action": "fix", "evidence": "b"},
            {"type": "B", "title": "second", "subtype": "y", "severity": "LOW", "priority_score": 4.0, "priority": "低", "url": "https://example.test/c", "recommended_action": "other"},
        ]
        groups = aggregate_priorities(items)
        self.assertEqual([group["priority_score"] for group in groups], [6.0, 4.0])
        self.assertEqual(groups[0]["finding_count"], 2)
        self.assertEqual(groups[0]["severity"], "HIGH")
        self.assertEqual(groups[0]["priority"], "高")
        self.assertEqual(groups[0]["priority_score"], 6.0)  # never summed

    def test_group_keeps_evidence_and_does_not_mutate_inputs(self):
        findings = [
            {**self.make_finding(url="https://example.test/a"), "evidence": "evidence-a"},
            {**self.make_finding(url="https://example.test/b"), "evidence": "evidence-b"},
        ]
        original = [dict(finding) for finding in findings]
        priorities = calculate_priority(findings, [], [])
        groups = aggregate_priorities(priorities)
        self.assertEqual(findings, original)
        self.assertEqual(
            [entry["evidence"] for entry in groups[0]["findings"]],
            ["evidence-a", "evidence-b"],
        )
        self.assertTrue(all("finding" in entry for entry in groups[0]["findings"]))

    def test_empty_aggregation_returns_empty_list(self):
        self.assertEqual(aggregate_priorities([]), [])

    def test_canonical_url_forms_count_as_one_page_but_two_findings(self):
        findings = [
            self.make_finding(url="https://EXAMPLE.test/a#one"),
            self.make_finding(url="https://example.test/a#two"),
        ]
        groups = aggregate_priorities(calculate_priority(findings, [], []))
        self.assertEqual(groups[0]["finding_count"], 2)
        self.assertEqual(groups[0]["page_count"], 1)

    def test_critical_finding_gets_highest_priority(self):
        """CRITICALのFindingは単独でも最優先になる。"""
        finding = self.make_finding(severity="CRITICAL")

        result = calculate_priority(
            [finding],
            [],
            [],
        )

        self.assertEqual(result[0]["priority_score"], 4)
        self.assertEqual(result[0]["priority"], "最優先")

    def test_priority_label_boundaries(self):
        """優先順位スコアの境界値で正しいラベルを返す。"""
        cases = [
            # severity, type, correlation, attack_path, score, label
            ("LOW", "SECURITY_HEADER", False, False, 1, "低"),
            ("MEDIUM", "SECURITY_HEADER", False, False, 2, "低"),
            ("MEDIUM", "SECURITY_HEADER", False, True, 3, "中"),
            ("HIGH", "SECURITY_HEADER", False, True, 4, "中"),
            ("HIGH", "HTTPS", True, False, 5, "高"),
            ("HIGH", "SECURITY_HEADER", True, True, 6, "高"),
            ("CRITICAL", "SECURITY_HEADER", True, True, 7, "最優先"),
            ("HIGH", "HTTPS", True, True, 8, "最優先"),
        ]

        for severity, finding_type, has_correlation, has_path, expected_score, expected_label in cases:
            with self.subTest(
                severity=severity,
                expected_score=expected_score,
            ):
                finding = self.make_finding(
                    severity=severity,
                    finding_type=finding_type,
                )

                correlations = []
                if has_correlation:
                    correlations = [{
                        "related_findings": [{
                            "type": finding_type,
                            "url": finding["url"],
                        }],
                    }]

                attack_paths = []
                if has_path:
                    steps = (
                        ["HTTPS未使用"]
                        if finding_type == "HTTPS"
                        else ["セキュリティヘッダー不足"]
                    )
                    attack_paths = [{
                        "url": finding["url"],
                        "steps": steps,
                    }]

                result = calculate_priority(
                    [finding],
                    correlations,
                    attack_paths,
                )

                self.assertEqual(
                    result[0]["priority_score"],
                    expected_score,
                )
                self.assertEqual(
                    result[0]["priority"],
                    expected_label,
                )

    def test_alternative_web_ports_have_web_specific_priority_reasons(self):
        cases = [
            (8080, "代替HTTP", "管理画面等が公開されていないか"),
            (8443, "代替HTTPS", "TLS設定と公開範囲"),
        ]
        for port, service, expected_text in cases:
            with self.subTest(port=port):
                finding = {
                    "type": "PORT_SCAN",
                    "subtype": "TCP_PORT_OPEN",
                    "severity": "LOW",
                    "title": f"{service} port observed",
                    "url": "https://example.test/",
                    "evidence": (
                        f"Port: {port}\n"
                        f"Expected service (port-based guess): {service}\n"
                        "Service identification: TCP_CONNECTION_ONLY\n"
                        "Network scope: PUBLIC"
                    ),
                }
                result = calculate_priority([finding], [], [])[0]
                self.assertIn(expected_text, result["priority_reason"])
                self.assertIn("実際のサービスは未確認", result["priority_reason"])
                self.assertEqual(result["severity"], "LOW")

    def test_correlation_bonus_requires_matching_subtype(self):
        finding = self.make_finding(
            severity="HIGH",
            finding_type="SECURITY_HEADER",
            title="CSP missing",
        )
        finding["subtype"] = "Content-Security-Policy"
        correlations = [{
            "related_findings": [{
                "type": "SECURITY_HEADER",
                "subtype": "X-Frame-Options",
                "url": finding["url"],
                "title": "X-Frame-Options missing",
            }],
        }]
        result = calculate_priority([finding], correlations, [])[0]
        self.assertEqual(result["priority_score"], 3)

    def test_attack_path_bonus_only_applies_to_related_finding(self):
        https_finding = self.make_finding(
            severity="HIGH",
            finding_type="HTTPS",
            title="HTTPS is not used",
        )
        header_finding = self.make_finding(
            severity="MEDIUM",
            finding_type="SECURITY_HEADER",
            title="CSP missing",
        )
        https_finding["evidence"] = "Observed HTTP response"
        header_finding["evidence"] = "Observed HTTP response"
        path = {
            "url": https_finding["url"],
            "steps": ["HTTPS未使用", "セキュリティヘッダー不足"],
            "related_findings": [https_finding],
        }
        result = calculate_priority([https_finding, header_finding], [], [path])
        scores = {item["type"]: item["priority_score"] for item in result}
        self.assertEqual(scores["HTTPS"], 7.5)
        self.assertEqual(scores["SECURITY_HEADER"], 5.2)

class TestPriorityFromFindings(unittest.TestCase):

    def finding(self, rule_id="headers.csp-missing", severity="MEDIUM", why=""):
        from engine.rule_runner import Finding

        return Finding(
            id="fnd_x",
            rule_id=rule_id,
            title="CSP が無い",
            severity=severity,
            confidence="high",
            subject="https://example.test/",
            message="CSP がありません。",
            why=why,
            fix="CSP を付けます。",
            verify="",
        )

    def test_header_rule_maps_to_security_header(self):
        row = priority_rows([self.finding()])[0]
        self.assertEqual(row["type"], "SECURITY_HEADER")
        self.assertGreater(row["priority_score"], 0)

    def test_transport_rule_maps_to_https(self):
        row = priority_rows([self.finding("transport.https-missing", "HIGH")])[0]
        self.assertEqual(row["type"], "HTTPS")

    def test_port_evidence_sets_the_reason(self):
        why = "Host: example.test\nPort: 6379\nNetwork scope: PUBLIC"
        row = priority_rows([self.finding("ports.open-sensitive-port", "LOW", why)])[0]
        self.assertEqual(row["network_scope"], "PUBLIC")
        self.assertIn("Redis", row["priority_reason"])

    def test_info_rule_is_excluded(self):
        self.assertEqual(priority_rows([self.finding("transport.https-present", "INFO")]), [])

    def test_empty_input(self):
        self.assertEqual(priority_rows([]), [])


if __name__ == "__main__":
    unittest.main()
