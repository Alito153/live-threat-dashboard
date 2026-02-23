import unittest
from urllib.parse import quote
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.routers import lookup as lookup_router


def _source_ok(source: str, score: int, categories: list[str], **extra: object) -> dict:
    data = {"score": score, "categories": categories}
    data.update(extra)
    return {
        "source": source,
        "status": "ok",
        "duration_ms": 10.0,
        "data": data,
        "error": None,
    }


def _source_error(source: str, message: str) -> dict:
    return {
        "source": source,
        "status": "error",
        "duration_ms": 5.0,
        "data": {},
        "error": message,
    }


class LookupSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def setUp(self) -> None:
        lookup_router.ioc_cache.clear()

    def _assert_basic_shape(self, payload: dict) -> None:
        self.assertIn("ioc", payload)
        self.assertIn("ioc_type", payload)
        self.assertIn("risk_score", payload)
        self.assertIn("risk_level", payload)
        self.assertIn("categories", payload)
        self.assertIn("sources", payload)
        self.assertEqual(3, len(payload["sources"]))

        for source in payload["sources"]:
            self.assertIn("source", source)
            self.assertIn("status", source)
            self.assertIn("duration_ms", source)
            self.assertIn("data", source)
            self.assertIn("error", source)
            self.assertIn(source["status"], {"ok", "error"})
            self.assertIsInstance(source["data"], dict)

    def test_lookup_ip_smoke(self) -> None:
        with (
            patch("app.routers.lookup.abuseipdb.check_ip", new=AsyncMock(return_value=_source_ok("abuseipdb", 70, ["reported"]))),
            patch("app.routers.lookup.otx.get_general", new=AsyncMock(return_value=_source_ok("otx", 40, ["otx-pulse"]))),
            patch("app.routers.lookup.virustotal.lookup", new=AsyncMock(return_value=_source_ok("virustotal", 60, ["malicious-detected"]))),
        ):
            response = self.client.get("/lookup/8.8.8.8")

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        self.assertEqual("ip", payload["ioc_type"])
        self.assertIn(payload["risk_level"], {"low", "medium", "high", "critical"})
        for source in payload["sources"]:
            self.assertNotIn("raw_json", source)

    def test_lookup_domain_smoke(self) -> None:
        with (
            patch("app.routers.lookup.otx.get_general", new=AsyncMock(return_value=_source_ok("otx", 25, ["phishing"]))),
            patch("app.routers.lookup.virustotal.lookup", new=AsyncMock(return_value=_source_ok("virustotal", 35, ["malicious-detected"]))),
        ):
            response = self.client.get("/lookup/example.com")

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        self.assertEqual("domain", payload["ioc_type"])
        abuse = next(source for source in payload["sources"] if source["source"] == "abuseipdb")
        self.assertEqual("ok", abuse["status"])

    def test_lookup_hash_smoke(self) -> None:
        ioc_hash = "a" * 64
        with (
            patch("app.routers.lookup.otx.get_general", new=AsyncMock(return_value=_source_ok("otx", 30, ["malware"]))),
            patch(
                "app.routers.lookup.virustotal.lookup",
                new=AsyncMock(return_value=_source_ok("virustotal", 75, ["malicious-detected"], malicious=5)),
            ),
        ):
            response = self.client.get(f"/lookup/{ioc_hash}")

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        self.assertEqual("sha256", payload["ioc_type"])

    def test_lookup_url_smoke(self) -> None:
        url_ioc = "https://example.com/malware"
        encoded = quote(url_ioc, safe="")
        with (
            patch("app.routers.lookup.otx.get_general", new=AsyncMock(return_value=_source_ok("otx", 20, ["otx-pulse"]))),
            patch(
                "app.routers.lookup.virustotal.lookup",
                new=AsyncMock(return_value=_source_ok("virustotal", 45, ["suspicious-detected"], url_id="u-123")),
            ),
        ):
            response = self.client.get(f"/lookup/{encoded}")

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        self.assertEqual("url", payload["ioc_type"])

    def test_lookup_missing_api_key_smoke(self) -> None:
        with (
            patch("app.routers.lookup.abuseipdb.check_ip", new=AsyncMock(return_value=_source_ok("abuseipdb", 50, ["reported"]))),
            patch("app.routers.lookup.otx.get_general", new=AsyncMock(return_value=_source_error("otx", "missing_api_key: OTX_API_KEY is missing"))),
            patch("app.routers.lookup.virustotal.lookup", new=AsyncMock(return_value=_source_ok("virustotal", 25, ["clean"]))),
        ):
            response = self.client.get("/lookup/1.1.1.1")

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        otx_source = next(source for source in payload["sources"] if source["source"] == "otx")
        self.assertEqual("error", otx_source["status"])
        self.assertIn("missing_api_key", otx_source["error"])

    def test_lookup_debug_includes_raw_json_and_cache_hit(self) -> None:
        with (
            patch(
                "app.routers.lookup.abuseipdb.check_ip",
                new=AsyncMock(
                    return_value={
                        **_source_ok("abuseipdb", 55, ["reported"]),
                        "raw_json": {"sample": True},
                    }
                ),
            ),
            patch("app.routers.lookup.otx.get_general", new=AsyncMock(return_value=_source_ok("otx", 20, ["otx-pulse"]))),
            patch("app.routers.lookup.virustotal.lookup", new=AsyncMock(return_value=_source_ok("virustotal", 30, ["clean"]))),
        ):
            first = self.client.get("/lookup/9.9.9.9?debug=true")
            second = self.client.get("/lookup/9.9.9.9?debug=true")

        self.assertEqual(200, first.status_code)
        self.assertEqual(200, second.status_code)
        first_payload = first.json()
        second_payload = second.json()
        abuse = next(source for source in first_payload["sources"] if source["source"] == "abuseipdb")
        self.assertIn("raw_json", abuse)
        self.assertFalse(first_payload["debug"]["cache_hit"])
        self.assertTrue(second_payload["debug"]["cache_hit"])


if __name__ == "__main__":
    unittest.main()
