import unittest
from unittest.mock import AsyncMock, patch

from app.enrichment import enrich_ioc


def _source_ok(name: str, data: dict) -> dict:
    return {
        "source": name,
        "status": "ok",
        "duration_ms": 10,
        "data": data,
        "error": None,
    }


class EnrichmentScoringTests(unittest.IsolatedAsyncioTestCase):
    async def test_otx_only_signal_is_capped_to_low(self) -> None:
        otx_payload = _source_ok(
            "otx",
            {
                "score": 100,
                "categories": ["otx-pulse"],
                "pulse_count": 40,
            },
        )
        vt_payload = _source_ok(
            "virustotal",
            {
                "score": 0,
                "categories": [],
                "malicious": 0,
            },
        )

        with patch("app.enrichment.otx.get_general", new=AsyncMock(return_value=otx_payload)), patch(
            "app.enrichment.virustotal.lookup", new=AsyncMock(return_value=vt_payload)
        ):
            result = await enrich_ioc("youtube.com", include_raw=False)

        self.assertLessEqual(result["risk_score"], 20)
        self.assertEqual("low", result["risk_level"])

    async def test_otx_can_raise_score_when_corroborated(self) -> None:
        otx_payload = _source_ok(
            "otx",
            {
                "score": 100,
                "categories": ["otx-pulse"],
                "pulse_count": 40,
            },
        )
        vt_payload = _source_ok(
            "virustotal",
            {
                "score": 50,
                "categories": ["malicious-detected"],
                "malicious": 3,
            },
        )

        with patch("app.enrichment.otx.get_general", new=AsyncMock(return_value=otx_payload)), patch(
            "app.enrichment.virustotal.lookup", new=AsyncMock(return_value=vt_payload)
        ):
            result = await enrich_ioc("suspicious-example.com", include_raw=False)

        self.assertGreater(result["risk_score"], 20)
        self.assertIn(result["risk_level"], {"medium", "high", "critical"})


if __name__ == "__main__":
    unittest.main()
