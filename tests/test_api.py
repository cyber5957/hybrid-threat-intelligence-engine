import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app import database
from app.main import app


class SentinelApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DB_PATH = Path(self.temp_dir.name) / "test.db"
        database.init_db()
        self.client = TestClient(app)
        self.headers = {"X-Admin-Username": os.getenv("SENTINEL_ADMIN_USERNAME", "admin")}

    def tearDown(self):
        self.client.close()
        self.temp_dir.cleanup()

    def test_extract_requires_admin_username(self):
        response = self.client.post("/api/extract", json={"text": "198.51.100.7"})
        self.assertEqual(response.status_code, 401)

    def test_extract_refangs_and_persists_indicators(self):
        response = self.client.post("/api/extract", headers=self.headers, json={"text": "hxxps://bad[.]example/path 2001:db8::1 CVE-2024-12345"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertGreaterEqual(body["count"], 3)
        values = {item["value"] for item in body["indicators"]}
        self.assertIn("https://bad.example/path", values)
        self.assertIn("2001:db8::1", values)
        self.assertIn("CVE-2024-12345", values)
        saved = self.client.get("/api/indicators", headers=self.headers).json()
        self.assertEqual(saved["total"], body["count"])

    def test_enrichment_without_provider_keys_stays_unknown(self):
        extracted = self.client.post("/api/extract", headers=self.headers, json={"text": "198.51.100.22"}).json()
        empty_keys = {name: "" for name in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "SHODAN_API_KEY")}
        with patch.dict(os.environ, empty_keys):
            result = self.client.post("/api/enrich", headers=self.headers, json={"alert_id": extracted["alert_id"], "indicators": [extracted["indicators"][0]["id"]]})
        self.assertEqual(result.status_code, 202)
        job = self.client.get(f"/api/jobs/{result.json()['job_id']}", headers=self.headers).json()
        self.assertEqual(job["status"], "completed")
        detail = self.client.get(f"/api/indicators/{extracted['indicators'][0]['id']}", headers=self.headers).json()
        self.assertEqual(detail["verdict"], "unknown")

    def test_provider_errors_are_saved_for_analyst_review(self):
        extracted = self.client.post("/api/extract", headers=self.headers, json={"text": "198.51.100.23"}).json()
        indicator_id = extracted["indicators"][0]["id"]
        error = {"provider": "virustotal", "verdict": "unknown", "risk_score": None,
                 "metadata": {"error": "Provider returned HTTP 429"}, "status": "error"}
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}), patch("app.enrichment._request", new=AsyncMock(return_value=error)):
            result = self.client.post("/api/enrich", headers=self.headers,
                                      json={"alert_id": extracted["alert_id"], "indicators": [indicator_id]})
        self.assertEqual(result.status_code, 202)
        job = self.client.get(f"/api/jobs/{result.json()['job_id']}", headers=self.headers).json()
        self.assertIn("HTTP 429", job["warnings"][0])
        detail = self.client.get(f"/api/indicators/{indicator_id}", headers=self.headers).json()
        self.assertEqual(detail["providers"][0]["status"], "error")


if __name__ == "__main__":
    unittest.main()
