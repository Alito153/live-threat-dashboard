import base64
import unittest
from unittest.mock import patch

from app.sources import virustotal


def _encoded_url_id(url_value: str) -> str:
    return base64.urlsafe_b64encode(url_value.encode("utf-8")).decode("utf-8").strip("=")


class VirusTotalUrlTests(unittest.IsolatedAsyncioTestCase):
    async def test_lookup_url_uses_encoded_url_id_for_get(self) -> None:
        test_url = "http://example.com"
        expected_url_id = _encoded_url_id(test_url)
        observed_urls: list[str] = []

        async def fake_request_json(method: str, url: str, **_: object) -> dict:
            observed_urls.append(url)
            if method == "POST" and url.endswith("/api/v3/urls"):
                # This id is an analysis id from VT submit endpoint, not a URL id.
                return {
                    "ok": True,
                    "status_code": 200,
                    "duration_ms": 9,
                    "data": {"data": {"id": "u-analysis-id-not-url-id"}},
                }

            if method == "GET" and url.endswith(f"/api/v3/urls/{expected_url_id}"):
                return {
                    "ok": True,
                    "status_code": 200,
                    "duration_ms": 7,
                    "data": {
                        "data": {
                            "attributes": {
                                "last_analysis_stats": {
                                    "harmless": 10,
                                    "malicious": 0,
                                    "suspicious": 0,
                                    "undetected": 30,
                                    "timeout": 0,
                                },
                                "tags": [],
                                "reputation": 0,
                            }
                        }
                    },
                }

            self.fail(f"Unexpected request: {method} {url}")

        with patch.object(virustotal, "VIRUSTOTAL_API_KEY", "dummy-key"), patch.object(
            virustotal, "request_json", side_effect=fake_request_json
        ):
            result = await virustotal.lookup("url", test_url, debug=True)

        self.assertEqual("ok", result["status"])
        self.assertEqual(expected_url_id, result["data"]["url_id"])
        self.assertIn("/api/v3/urls", observed_urls[0])
        self.assertTrue(observed_urls[1].endswith(f"/api/v3/urls/{expected_url_id}"))


if __name__ == "__main__":
    unittest.main()
