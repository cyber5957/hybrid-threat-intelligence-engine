import unittest

from app.enrichment import _normalize_result, aggregate


class EnrichmentTests(unittest.TestCase):
    def test_absent_otx_pulses_are_unknown_not_clean(self):
        result = _normalize_result("otx", 200, {"pulse_info": {"count": 0}})
        self.assertEqual(result["verdict"], "unknown")
        self.assertIsNone(result["risk_score"])

    def test_shodan_exposure_is_evidence_not_a_malicious_verdict(self):
        result = _normalize_result("shodan", 200, {"ports": [22, 443]})
        self.assertEqual(result["verdict"], "unknown")
        self.assertIsNone(result["risk_score"])
        self.assertIn("2 exposed port(s)", result["metadata"]["summary"])

    def test_mixed_clean_and_unknown_results_stay_unknown(self):
        verdict, score = aggregate([
            {"status": "complete", "verdict": "clean", "risk_score": 0},
            {"status": "complete", "verdict": "unknown", "risk_score": None},
        ])
        self.assertEqual(verdict, "unknown")
        self.assertIsNone(score)


if __name__ == "__main__":
    unittest.main()
