from __future__ import annotations

import logging
from typing import Optional

import anyio
import psycopg

from app.config import DATABASE_URL, DB_CONNECT_TIMEOUT

logger = logging.getLogger(__name__)


def _insert_or_get_ioc_sync(database_url: str, ioc_type: str, ioc_value: str) -> Optional[int]:
    sql = """
        WITH existing AS (
            SELECT id
            FROM ioc
            WHERE type = %s AND value = %s
            ORDER BY id
            LIMIT 1
        ),
        inserted AS (
            INSERT INTO ioc(type, value)
            SELECT %s, %s
            WHERE NOT EXISTS (SELECT 1 FROM existing)
            RETURNING id
        )
        SELECT id FROM inserted
        UNION ALL
        SELECT id FROM existing
        LIMIT 1
    """
    with psycopg.connect(database_url, connect_timeout=DB_CONNECT_TIMEOUT) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (ioc_type, ioc_value, ioc_type, ioc_value))
            row = cur.fetchone()
        conn.commit()

    if row is None:
        return None
    return int(row[0])


async def persist_lookup_ioc(ioc_type: str, ioc_value: str) -> Optional[int]:
    if not ioc_value:
        return None
    if not DATABASE_URL:
        logger.debug("lookup_persist skipped: DATABASE_URL missing")
        return None

    try:
        return await anyio.to_thread.run_sync(_insert_or_get_ioc_sync, DATABASE_URL, ioc_type, ioc_value)
    except psycopg.Error as exc:
        logger.warning("lookup_persist db_error ioc_type=%s ioc=%s err=%s", ioc_type, ioc_value, exc)
        return None
    except OSError as exc:
        logger.warning("lookup_persist network_error ioc_type=%s ioc=%s err=%s", ioc_type, ioc_value, exc)
        return None
