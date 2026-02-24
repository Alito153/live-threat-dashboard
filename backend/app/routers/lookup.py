from copy import deepcopy

from fastapi import APIRouter, Query

from app.cache import TTLCache
from app.config import CACHE_MAX_ITEMS, CACHE_TTL_SECONDS, SOURCE_TIMEOUT
from app.enrichment import enrich_ioc, strip_raw_for_public

router = APIRouter(prefix="/lookup", tags=["lookup"])

ioc_cache = TTLCache(ttl_seconds=CACHE_TTL_SECONDS, max_items=CACHE_MAX_ITEMS)


@router.get("/{ioc:path}")
async def lookup_ioc(ioc: str, debug: bool = Query(False, description="Include source raw JSON, durations and errors")):
    ioc_clean = ioc.strip()

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
            "source_durations_ms": {source["source"]: source["duration_ms"] for source in response["sources"]},
            "source_errors": {
                source["source"]: source["error"]
                for source in response["sources"]
                if source.get("status") == "error" and source.get("error")
            },
            "source_timeout_s": SOURCE_TIMEOUT,
        }
    return response
