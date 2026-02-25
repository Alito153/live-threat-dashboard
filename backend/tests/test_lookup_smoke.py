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
        "duration_ms": 10,
        "data": data,
        "error": None,
    }


def _source_error(source: str, message: str) -> dict:
    return {
        "source": source,
        "status": "error",
        "duration_ms": 5,
        "data": {},
        "error": message,
    }


def _payload(ioc: str, ioc_type: str) -> dict:
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk_score": 42,
        "risk_level": "medium",
        "categories": ["test"],
        "sources": [
            {**_source_ok("abuseipdb", 30, ["reported"]), "raw_json": {"x": 1}},
            {**_source_ok("otx", 40, ["otx-pulse"]), "raw_json": {"y": 2}},
            _source_error("virustotal", "missing_api_key: VIRUSTOTAL_API_KEY is missing"),
        ],
    }


class LookupSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.persist_patcher = patch("app.routers.lookup._maybe_persist_lookup_ioc", new=AsyncMock(return_value=123))
        cls.persist_mock = cls.persist_patcher.start()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.persist_patcher.stop()

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

    def test_lookup_ip_smoke(self) -> None:
        with patch("app.routers.lookup.enrich_ioc", new=AsyncMock(return_value=_payload("8.8.8.8", "ip"))):
            response = self.client.get("/lookup/8.8.8.8")
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        self.assertEqual("ip", payload["ioc_type"])
        for source in payload["sources"]:
            self.assertNotIn("raw_json", source)

    def test_lookup_domain_smoke(self) -> None:
        with patch("app.routers.lookup.enrich_ioc", new=AsyncMock(return_value=_payload("example.com", "domain"))):
            response = self.client.get("/lookup/example.com")
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        self.assertEqual("domain", payload["ioc_type"])

    def test_lookup_hash_smoke(self) -> None:
        ioc_hash = "a" * 64
        with patch("app.routers.lookup.enrich_ioc", new=AsyncMock(return_value=_payload(ioc_hash, "sha256"))):
            response = self.client.get(f"/lookup/{ioc_hash}")
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        self.assertEqual("sha256", payload["ioc_type"])

    def test_lookup_url_smoke(self) -> None:
        url_ioc = "https://example.com/malware"
        encoded = quote(url_ioc, safe="")
        with patch("app.routers.lookup.enrich_ioc", new=AsyncMock(return_value=_payload(url_ioc, "url"))):
            response = self.client.get(f"/lookup/{encoded}")
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        self.assertEqual("url", payload["ioc_type"])

    def test_lookup_missing_api_key_smoke(self) -> None:
        with patch("app.routers.lookup.enrich_ioc", new=AsyncMock(return_value=_payload("1.1.1.1", "ip"))):
            response = self.client.get("/lookup/1.1.1.1")
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)
        vt = next(source for source in payload["sources"] if source["source"] == "virustotal")
        self.assertEqual("error", vt["status"])
        self.assertIn("missing_api_key", vt["error"])

    def test_lookup_debug_includes_raw_json_and_cache_hit(self) -> None:
        with patch("app.routers.lookup.enrich_ioc", new=AsyncMock(return_value=_payload("9.9.9.9", "ip"))):
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
        self.assertIn("db_ioc_id", first_payload["debug"])

    def test_lookup_continues_if_persist_fails(self) -> None:
        with patch("app.routers.lookup._maybe_persist_lookup_ioc", new=AsyncMock(return_value=None)), patch(
            "app.routers.lookup.enrich_ioc", new=AsyncMock(return_value=_payload("4.4.4.4", "ip"))
        ):
            response = self.client.get("/lookup/4.4.4.4")
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self._assert_basic_shape(payload)


if __name__ == "__main__":
    unittest.main()
