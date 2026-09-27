import unittest

from app.extraction import extract_indicators


class ExtractionUnitTests(unittest.TestCase):
    def test_supported_types_and_defanged_values(self):
        alert = (
            "hxxps://bad[.]example/path 198.51.100.8 2001:db8::1 "
            "44d88612fea8a8f36de82e1278abb02f "
            "0123456789abcdef0123456789abcdef01234567 "
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "
            "notify@example[.]org CVE-2024-12345 cdn[.]example[.]net"
        )
        extracted = extract_indicators(alert)
        pairs = {(item["type"], item["value"]) for item in extracted}
        self.assertIn(("url", "https://bad.example/path"), pairs)
        self.assertIn(("ipv4", "198.51.100.8"), pairs)
        self.assertIn(("ipv6", "2001:db8::1"), pairs)
        self.assertIn(("md5", "44d88612fea8a8f36de82e1278abb02f"), pairs)
        self.assertIn(("sha1", "0123456789abcdef0123456789abcdef01234567"), pairs)
        self.assertIn(("sha256", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), pairs)
        self.assertIn(("cve", "CVE-2024-12345"), pairs)
        self.assertIn(("domain", "cdn.example.net"), pairs)
        self.assertIn(("email", "notify@example.org"), pairs)

    def test_deduplicates_and_rejects_invalid_ipv4(self):
        extracted = extract_indicators("198.51.100.9 198.51.100.9 999.1.1.1")
        self.assertEqual([item["value"] for item in extracted if item["type"] == "ipv4"], ["198.51.100.9"])


if __name__ == "__main__":
    unittest.main()
