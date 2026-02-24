from __future__ import annotations

import asyncio
import logging
import signal
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.config import (
    COLLECTOR_BATCH_SIZE,
    COLLECTOR_ENABLED,
    COLLECTOR_INTERVAL_SECONDS,
    DATABASE_URL,
    ENRICH_TTL_SECONDS,
)
from app.enrichment import enrich_ioc

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IOCRow:
    id: int
    type: str
    value: str


@dataclass(frozen=True)
class EnrichmentWrite:
    ioc_id: int
    payload: dict[str, Any]


class CollectorRepository(Protocol):
    def fetch_due_iocs(self, ttl_seconds: float, batch_size: int) -> list[IOCRow]: ...

    def save_enrichments(self, rows: list[EnrichmentWrite]) -> None: ...


class PostgresCollectorRepository:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def fetch_due_iocs(self, ttl_seconds: float, batch_size: int) -> list[IOCRow]:
        sql = """
            SELECT id, type, value
            FROM ioc
            WHERE last_enriched_at IS NULL
               OR last_enriched_at < NOW() - (%s * INTERVAL '1 second')
            ORDER BY COALESCE(last_enriched_at, to_timestamp(0)), id
            LIMIT %s
        """
        with psycopg.connect(self.database_url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (ttl_seconds, batch_size))
                rows = cur.fetchall()
        return [IOCRow(id=row["id"], type=row["type"], value=row["value"]) for row in rows]

    def save_enrichments(self, rows: list[EnrichmentWrite]) -> None:
        if not rows:
            return

        insert_enrichment_sql = """
            INSERT INTO enrichment (ioc_id, source, score, raw_json, fetched_at)
            VALUES (%s, %s, %s, %s, NOW())
        """
        upsert_summary_sql = """
            INSERT INTO ioc_summary (ioc_id, risk_score, risk_level, categories, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (ioc_id)
            DO UPDATE SET
                risk_score = EXCLUDED.risk_score,
                risk_level = EXCLUDED.risk_level,
                categories = EXCLUDED.categories,
                updated_at = NOW()
        """
        update_ioc_sql = """
            UPDATE ioc
            SET last_enriched_at = NOW()
            WHERE id = %s
        """

        with psycopg.connect(self.database_url) as conn:
            with conn.cursor() as cur:
                for row in rows:
                    payload = row.payload
                    sources = payload.get("sources", [])
                    for source in sources:
                        source_payload = source if isinstance(source, dict) else {"source": "unknown", "status": "error", "data": {}, "error": "invalid_source_payload"}
                        source_name = str(source_payload.get("source", "unknown"))
                        score_raw = (source_payload.get("data") or {}).get("score") if source_payload.get("status") == "ok" else None
                        score = int(score_raw) if isinstance(score_raw, (int, float)) else None
                        cur.execute(
                            insert_enrichment_sql,
                            (row.ioc_id, source_name, score, Jsonb(source_payload)),
                        )

                    categories = payload.get("categories", [])
                    if not isinstance(categories, list):
                        categories = []
                    cur.execute(
                        upsert_summary_sql,
                        (
                            row.ioc_id,
                            int(payload.get("risk_score", 0)),
                            str(payload.get("risk_level", "low")),
                            Jsonb(categories),
                        ),
                    )
                    cur.execute(update_ioc_sql, (row.ioc_id,))
            conn.commit()


class CollectorService:
    def __init__(
        self,
        repository: CollectorRepository,
        enrich_fn: Callable[[str], Awaitable[dict[str, Any]]],
        *,
        interval_seconds: float,
        batch_size: int,
        ttl_seconds: float,
    ) -> None:
        self.repository = repository
        self.enrich_fn = enrich_fn
        self.interval_seconds = max(1.0, float(interval_seconds))
        self.batch_size = max(1, int(batch_size))
        self.ttl_seconds = max(1.0, float(ttl_seconds))

    async def process_once(self) -> int:
        iocs = self.repository.fetch_due_iocs(self.ttl_seconds, self.batch_size)
        if not iocs:
            logger.info("collector no_due_ioc ttl_seconds=%.1f batch_size=%s", self.ttl_seconds, self.batch_size)
            return 0

        logger.info("collector processing_count=%s", len(iocs))
        writes = await self._enrich_batch(iocs)
        self.repository.save_enrichments(writes)
        logger.info("collector persisted_count=%s", len(writes))
        return len(writes)

    async def run_forever(self, stop_event: asyncio.Event) -> None:
        logger.info(
            "collector started enabled=%s interval_seconds=%.1f batch_size=%s ttl_seconds=%.1f",
            COLLECTOR_ENABLED,
            self.interval_seconds,
            self.batch_size,
            self.ttl_seconds,
        )
        while not stop_event.is_set():
            try:
                await self.process_once()
            except psycopg.Error as exc:
                logger.exception("collector database_error=%s", exc)
            except Exception as exc:
                logger.exception("collector unexpected_error=%s", exc)

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                pass
        logger.info("collector stopped")

    async def _enrich_batch(self, iocs: list[IOCRow]) -> list[EnrichmentWrite]:
        tasks = [self._safe_enrich(ioc) for ioc in iocs]
        results = await asyncio.gather(*tasks)
        return [item for item in results if item is not None]

    async def _safe_enrich(self, ioc: IOCRow) -> EnrichmentWrite | None:
        try:
            payload = await self.enrich_fn(ioc.value)
            if not isinstance(payload, dict):
                logger.error("collector invalid_enrichment_payload ioc_id=%s value=%s", ioc.id, ioc.value)
                return None
            return EnrichmentWrite(ioc_id=ioc.id, payload=payload)
        except Exception as exc:
            logger.exception("collector enrichment_error ioc_id=%s value=%s err=%s", ioc.id, ioc.value, exc)
            return None


async def _run_collector() -> None:
    repository = PostgresCollectorRepository(DATABASE_URL)
    service = CollectorService(
        repository,
        lambda value: enrich_ioc(value, include_raw=True),
        interval_seconds=COLLECTOR_INTERVAL_SECONDS,
        batch_size=COLLECTOR_BATCH_SIZE,
        ttl_seconds=ENRICH_TTL_SECONDS,
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass
    await service.run_forever(stop_event)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    try:
        asyncio.run(_run_collector())
    except KeyboardInterrupt:
        logger.info("collector interrupted")


if __name__ == "__main__":
    main()
