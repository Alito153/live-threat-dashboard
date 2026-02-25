import asyncio
import logging
from copy import deepcopy

from fastapi import APIRouter, Query

from app.cache import TTLCache
from app.config import CACHE_MAX_ITEMS, CACHE_TTL_SECONDS, LOOKUP_AUTO_INSERT_IOC, LOOKUP_DB_WRITE_TIMEOUT, SOURCE_TIMEOUT
from app.db import persist_lookup_ioc
from app.enrichment import detect_ioc_type, enrich_ioc, strip_raw_for_public

router = APIRouter(prefix="/lookup", tags=["lookup"])

ioc_cache = TTLCache(ttl_seconds=CACHE_TTL_SECONDS, max_items=CACHE_MAX_ITEMS)
logger = logging.getLogger(__name__)


async def _maybe_persist_lookup_ioc(ioc_type: str, ioc_value: str) -> int | None:
    if not LOOKUP_AUTO_INSERT_IOC:
        return None

    try:
        return await asyncio.wait_for(persist_lookup_ioc(ioc_type, ioc_value), timeout=LOOKUP_DB_WRITE_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning(
            "lookup_persist timeout ioc_type=%s ioc=%s timeout_s=%.2f",
            ioc_type,
            ioc_value,
            LOOKUP_DB_WRITE_TIMEOUT,
        )
        return None
    except Exception as exc:
        logger.warning("lookup_persist unexpected_error ioc_type=%s ioc=%s err=%s", ioc_type, ioc_value, exc)
        return None


@router.get("/{ioc:path}")
async def lookup_ioc(ioc: str, debug: bool = Query(False, description="Include source raw JSON, durations and errors")):
    ioc_clean = ioc.strip()
    ioc_type = detect_ioc_type(ioc_clean)
    persisted_ioc_id = await _maybe_persist_lookup_ioc(ioc_type, ioc_clean)

    cache_hit = False
    cached = ioc_cache.get(ioc_clean)
    if cached is None:
        payload = await enrich_ioc(ioc_clean, include_raw=True)
        ioc_cache.set(ioc_clean, payload)
    else:
        payload = cached
        cache_hit = True

    response = strip_raw_for_public(deepcopy(payload), debug=debug)
    if debug:
        response["debug"] = {
            "cache_hit": cache_hit,
            "db_ioc_id": persisted_ioc_id,
            "db_auto_insert_enabled": LOOKUP_AUTO_INSERT_IOC,
            "source_durations_ms": {source["source"]: source["duration_ms"] for source in response["sources"]},
            "source_errors": {
                source["source"]: source["error"]
                for source in response["sources"]
                if source.get("status") == "error" and source.get("error")
            },
            "source_timeout_s": SOURCE_TIMEOUT,
        }
    return response
