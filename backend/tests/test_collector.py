import unittest

from app.collector import CollectorService, EnrichmentWrite, IOCRow


class _FakeRepository:
    def __init__(self, due_rows: list[IOCRow]) -> None:
        self.due_rows = due_rows
        self.fetch_calls: list[tuple[float, int]] = []
        self.saved: list[EnrichmentWrite] = []

    def fetch_due_iocs(self, ttl_seconds: float, batch_size: int) -> list[IOCRow]:
        self.fetch_calls.append((ttl_seconds, batch_size))
        return list(self.due_rows)

    def save_enrichments(self, rows: list[EnrichmentWrite]) -> None:
        self.saved.extend(rows)


class CollectorServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_process_once_selects_due_ioc_and_saves_summary_payload(self) -> None:
        due = [IOCRow(id=1, type="ip", value="8.8.8.8")]
        repo = _FakeRepository(due)

        async def fake_enrich(value: str) -> dict:
            self.assertEqual("8.8.8.8", value)
            return {
                "ioc": value,
                "ioc_type": "ip",
                "risk_score": 55,
                "risk_level": "medium",
                "categories": ["reported"],
                "sources": [
                    {
                        "source": "abuseipdb",
                        "status": "ok",
                        "duration_ms": 12,
                        "data": {"score": 55, "categories": ["reported"]},
                        "error": None,
                    }
                ],
            }

        service = CollectorService(
            repo,
            fake_enrich,
            interval_seconds=10,
            batch_size=10,
            ttl_seconds=600,
        )

        processed = await service.process_once()

        self.assertEqual(1, processed)
        self.assertEqual([(600.0, 10)], repo.fetch_calls)
        self.assertEqual(1, len(repo.saved))
        self.assertEqual(1, repo.saved[0].ioc_id)
        self.assertEqual(55, repo.saved[0].payload["risk_score"])


if __name__ == "__main__":
    unittest.main()
