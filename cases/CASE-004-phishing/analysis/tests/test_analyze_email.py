import tempfile
import unittest
from pathlib import Path

from analyze_email import analyze

SAMPLE = b"""From: Detran <detran@sistemadeinfracao373552>
Return-Path: detran@sistemadeinfracao373552
Subject: Urgent notice
Date: Mon, 21 Sep 2026 06:43:52 +0000
Authentication-Results: spf=none; dkim=none; dmarc=none
Received: from [127.0.1.1] (45.32.75.31) by mail.example; Mon, 21 Sep 2026 06:43:52 +0000
Content-Type: text/html

<a href="https://hotmail.com-example@fake-host.run.app/path">Click</a>
"""


class AnalyzerTests(unittest.TestCase):
    def analyze_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.eml"
            path.write_bytes(SAMPLE)
            return analyze(path)

    def test_basic_headers(self):
        result = self.analyze_fixture()
        self.assertEqual(result["headers"]["subject"], "Urgent notice")
        self.assertIn("Detran", result["headers"]["from"])

    def test_authentication(self):
        result = self.analyze_fixture()
        auth = " ".join(result["authentication"]["authentication_results"])
        self.assertIn("spf=none", auth)
        self.assertIn("dkim=none", auth)
        self.assertIn("dmarc=none", auth)
        self.assertFalse(result["authentication"]["dkim_signature_present"])

    def test_received_headers(self):
        result = self.analyze_fixture()
        self.assertTrue(any("45.32.75.31" in h for h in result["received_headers"]))
        self.assertTrue(any("127.0.1.1" in h for h in result["received_headers"]))

    def test_url_domain_and_userinfo(self):
        result = self.analyze_fixture()
        self.assertEqual(result["url_count"], 1)
        self.assertEqual(
            result["url_domains_defanged"],
            ["fake-host[.]run[.]app"]
        )

        url = result["url_analysis"][0]
        self.assertEqual(url["hostname_defanged"], "fake-host[.]run[.]app")
        self.assertTrue(url["userinfo_present"])
        self.assertTrue(url["userinfo_contains_hotmail"])
        self.assertEqual(url["userinfo_redacted"], "[redacted]")
        self.assertNotIn("hotmail.com-example", str(result))

    def test_mime_and_attachments(self):
        result = self.analyze_fixture()
        self.assertIn("text/html", result["mime_types"])
        self.assertEqual(result["attachments"], [])


if __name__ == "__main__":
    unittest.main()
