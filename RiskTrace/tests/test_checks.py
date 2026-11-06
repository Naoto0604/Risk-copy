import unittest
from types import SimpleNamespace
from engine.legacy_checks import check_security_headers, check_cookies


class TestSecurityHeaders(unittest.TestCase):

    def test_hsts_subtype_is_correct(self):
        response = SimpleNamespace(
            url="https://example.test/",
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            },
        )

        findings = check_security_headers(response)

        hsts_findings = [
            finding
            for finding in findings
            if finding["title"] == "HSTSが設定されていません"
        ]

        self.assertEqual(len(hsts_findings), 1)
        self.assertEqual(
            hsts_findings[0]["subtype"],
            "Strict-Transport-Security",
        )

    def test_missing_x_frame_options_is_detected(self):
        response = SimpleNamespace(
            url="https://example.test/",
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Strict-Transport-Security": "max-age=31536000",
            },
        )

        findings = check_security_headers(response)

        x_frame_findings = [
            finding
            for finding in findings
            if finding.get("subtype") == "X-Frame-Options"
        ]

        self.assertEqual(len(x_frame_findings), 1)

    def test_each_set_cookie_header_is_checked(self):
        class FakeRawHeaders:
            def getlist(self, name):
                if name.lower() == "set-cookie":
                    return [
                        "sessionid=abc; HttpOnly; Secure; SameSite=Lax",
                        "theme=dark",
                    ]
                return []

        response = SimpleNamespace(
            url="https://example.test/",
            headers={
                "Set-Cookie": (
                    "sessionid=abc; HttpOnly; Secure; SameSite=Lax"
                )
            },
            raw=SimpleNamespace(headers=FakeRawHeaders()),
        )

        findings = check_cookies(response)
        titles = {finding["title"] for finding in findings}

        self.assertIn(
            "HttpOnly属性が設定されていません", titles
        )
        self.assertIn(
            "SameSite属性が設定されていません", titles
        )
        self.assertIn(
            "Secure属性が設定されていません", titles
        )


    def test_cookie_attributes_require_exact_names(self):
        cookie = "sessionid=notsecure; xhttponly=true; SameSite=Lax"

        class FakeRawHeaders:
            def getlist(self, name):
                if name.lower() == "set-cookie":
                    return [cookie]
                return []

        response = SimpleNamespace(
            url="https://example.test/",
            headers={"Set-Cookie": cookie},
            raw=SimpleNamespace(headers=FakeRawHeaders()),
        )

        findings = check_cookies(response)
        titles = {finding["title"] for finding in findings}

        # xhttponly は HttpOnly 属性ではない
        self.assertIn(
            "HttpOnly属性が設定されていません",
            titles,
        )

        # notsecure は Secure 属性ではない
        self.assertIn(
            "Secure属性が設定されていません",
            titles,
        )

        # SameSite=Lax は正しい属性
        self.assertNotIn(
            "SameSite属性が設定されていません",
            titles,
        )

class TestCookieSecurityPrecision(unittest.TestCase):

    def response(self, cookie_headers=(), url="https://example.test/", *, combined=False):
        headers = {}
        raw = None
        if combined:
            headers["Set-Cookie"] = cookie_headers
        elif cookie_headers:
            class FakeRawHeaders:
                def getlist(self, name):
                    return list(cookie_headers) if name.lower() == "set-cookie" else []

            headers["Set-Cookie"] = cookie_headers[0]
            raw = SimpleNamespace(headers=FakeRawHeaders())
        response = SimpleNamespace(url=url, headers=headers)
        if raw is not None:
            response.raw = raw
        return response

    def findings_by_subtype(self, response):
        return {finding["subtype"]: finding for finding in check_cookies(response)}

    def test_no_set_cookie_header_creates_no_findings(self):
        self.assertEqual(check_cookies(self.response()), [])

    def test_multiple_set_cookie_headers_are_checked_independently(self):
        findings = self.findings_by_subtype(self.response([
            "sessionid=value; HttpOnly; Secure; SameSite=Lax",
            "theme=dark; Secure; SameSite=Lax",
        ]))
        self.assertIn("COOKIE_HTTPONLY_MISSING", findings)
        self.assertIn("Cookie #2", findings["COOKIE_HTTPONLY_MISSING"]["evidence"])
        self.assertNotIn("Cookie #1", findings["COOKIE_HTTPONLY_MISSING"]["evidence"])

    def test_http_only_on_one_cookie_does_not_apply_to_another(self):
        findings = self.findings_by_subtype(self.response([
            "sessionid=value; HttpOnly; Secure; SameSite=Lax",
            "preferences=value; Secure; SameSite=Lax",
        ]))
        issue = findings["COOKIE_HTTPONLY_MISSING"]
        self.assertEqual(issue["severity"], "LOW")
        self.assertIn("Cookie #2", issue["evidence"])
        self.assertNotIn("Cookie #1", issue["evidence"])

    def test_session_cookie_missing_httponly_is_medium_candidate(self):
        findings = self.findings_by_subtype(self.response([
            "PHPSESSID=value; Secure; SameSite=Lax",
        ]))
        issue = findings["COOKIE_HTTPONLY_MISSING"]
        self.assertEqual(issue["severity"], "MEDIUM")
        self.assertIn("セッション・認証関連の可能性", issue["description"])
        self.assertIn("推定", issue["description"])

    def test_unknown_cookie_is_not_uniformly_medium(self):
        findings = check_cookies(self.response(["mystery=value; Secure; SameSite=Lax"]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "LOW")
        self.assertIn("用途不明", findings[0]["description"])

    def test_https_cookie_without_secure_is_reported(self):
        findings = self.findings_by_subtype(self.response([
            "preferences=value; HttpOnly; SameSite=Lax",
        ]))
        self.assertEqual(findings["COOKIE_SECURE_MISSING"]["severity"], "LOW")

    def test_http_response_does_not_claim_secure_is_required(self):
        findings = self.findings_by_subtype(self.response(
            ["preferences=value; HttpOnly; SameSite=Lax"],
            url="http://example.test/",
        ))
        self.assertNotIn("COOKIE_SECURE_MISSING", findings)

    def test_samesite_lax_is_recognized(self):
        self.assertEqual(check_cookies(self.response([
            "sessionid=value; HttpOnly; Secure; SameSite=Lax",
        ])), [])

    def test_samesite_strict_is_recognized_case_insensitively(self):
        self.assertEqual(check_cookies(self.response([
            "sessionid=value; hTtPoNlY; sEcUrE; sAmEsItE=Strict",
        ])), [])

    def test_samesite_none_with_secure_is_valid(self):
        self.assertEqual(check_cookies(self.response([
            "cross_site=value; HttpOnly; Secure; SameSite=None",
        ])), [])

    def test_samesite_none_without_secure_is_reported_as_combination(self):
        findings = self.findings_by_subtype(self.response([
            "cross_site=value; HttpOnly; SameSite=None",
        ]))
        self.assertIn("COOKIE_SAMESITE_NONE_WITHOUT_SECURE", findings)
        self.assertNotIn("COOKIE_SECURE_MISSING", findings)

    def test_invalid_samesite_value_is_reported_without_echoing_value(self):
        findings = self.findings_by_subtype(self.response([
            "preferences=value; HttpOnly; Secure; SameSite=InvalidSecret",
        ]))
        self.assertIn("COOKIE_SAMESITE_INVALID", findings)
        self.assertNotIn("InvalidSecret", findings["COOKIE_SAMESITE_INVALID"]["evidence"])

    def test_cookie_name_matching_is_case_insensitive(self):
        findings = self.findings_by_subtype(self.response([
            "SeSsIoNiD=value; Secure; SameSite=Lax",
        ]))
        self.assertEqual(findings["COOKIE_HTTPONLY_MISSING"]["severity"], "MEDIUM")

    def test_attribute_names_require_exact_match(self):
        findings = self.findings_by_subtype(self.response([
            "preferences=notsecure; xhttponly=true; SameSite=Lax",
        ]))
        self.assertIn("COOKIE_HTTPONLY_MISSING", findings)
        self.assertIn("COOKIE_SECURE_MISSING", findings)
        self.assertNotIn("notsecure", str(findings))

    def test_cookie_values_and_names_are_not_in_findings(self):
        findings = check_cookies(self.response([
            "access_token=SUPERSECRET; SameSite=Lax",
        ]))
        output = repr(findings)
        self.assertNotIn("SUPERSECRET", output)
        self.assertNotIn("access_token", output)
        self.assertIn("Cookie #1", output)

    def test_expires_comma_does_not_split_a_cookie(self):
        findings = check_cookies(self.response(
            "analytics=value; Expires=Wed, 21 Oct 2030 07:28:00 GMT; "
            "HttpOnly; Secure; SameSite=Lax",
            combined=True,
        ))
        self.assertEqual(findings, [])

    def test_coalesced_headers_split_after_expires_without_splitting_date(self):
        findings = self.findings_by_subtype(self.response(
            "sessionid=secret; Expires=Wed, 21 Oct 2030 07:28:00 GMT; "
            "HttpOnly; Secure; SameSite=Lax, "
            "theme=dark; Path=/; SameSite=Lax; Secure",
            combined=True,
        ))
        issue = findings["COOKIE_HTTPONLY_MISSING"]
        self.assertIn("Cookie #2", issue["evidence"])
        self.assertNotIn("secret", repr(findings))
        self.assertNotIn("21 Oct 2030", repr(findings))

    def test_evidence_reports_attribute_presence_without_values(self):
        findings = self.findings_by_subtype(self.response([
            "sessionid=value; Domain=private.example; Path=/account; "
            "Expires=Wed, 21 Oct 2030 07:28:00 GMT; Secure; SameSite=Lax",
        ]))
        evidence = findings["COOKIE_HTTPONLY_MISSING"]["evidence"]
        self.assertIn("Domain=present", evidence)
        self.assertIn("Path=present", evidence)
        self.assertIn("Expires/Max-Age=present", evidence)
        self.assertNotIn("private.example", evidence)
        self.assertNotIn("/account", evidence)


if __name__ == "__main__":
    unittest.main()
