import asyncio
import ipaddress
import logging
import re
from copy import deepcopy
from time import perf_counter
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Query

from app.cache import TTLCache
from app.config import CACHE_MAX_ITEMS, CACHE_TTL_SECONDS, SOURCE_TIMEOUT
from app.scoring import compute_risk
from app.sources import abuseipdb, otx, virustotal
from app.sources.http_client import source_error, source_ok

router = APIRouter(prefix="/lookup", tags=["lookup"])
logger = logging.getLogger(__name__)

SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
SOURCE_WEIGHTS = {"virustotal": 0.5, "abuseipdb": 0.3, "otx": 0.2}

ioc_cache = TTLCache(ttl_seconds=CACHE_TTL_SECONDS, max_items=CACHE_MAX_ITEMS)


def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    if SHA256_RE.match(ioc):
        return "sha256"
    if SHA1_RE.match(ioc):
        return "sha1"
    if MD5_RE.match(ioc):
        return "md5"
    return "domain"


def _source_not_applicable(name: str, ioc_type: str) -> dict[str, Any]:
    return source_ok(
        name,
        0,
        {
            "score": 0,
            "categories": [],
            "confidence": 0,
            "ioc_type": ioc_type,
            "note": "not_applicable_for_ioc_type",
        },
    )


def _ensure_source_shape(name: str, result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return source_error(name, 0, "network_error: invalid source response type", data={})
    required = {"source", "status", "duration_ms", "data", "error"}
    if not required.issubset(result.keys()):
        return source_error(name, 0, "network_error: invalid source response format", data={})

    normalized = dict(result)
    if normalized.get("status") not in {"ok", "error"}:
        normalized["status"] = "error"
        normalized["error"] = "network_error: invalid source status"
    if not isinstance(normalized.get("duration_ms"), int):
        try:
            normalized["duration_ms"] = int(round(float(normalized.get("duration_ms", 0))))
        except (TypeError, ValueError):
            normalized["duration_ms"] = 0
    if not isinstance(normalized.get("data"), dict):
        normalized["data"] = {}
    if normalized.get("status") == "ok":
        normalized["error"] = None
    elif not isinstance(normalized.get("error"), str):
        normalized["error"] = "unknown_error"
    normalized["source"] = name
    return normalized


async def _run_source(
    name: str,
    source_fn: Callable[..., Awaitable[dict[str, Any]]],
    *args: Any,
) -> tuple[str, dict[str, Any]]:
    started = perf_counter()
    try:
        result = await asyncio.wait_for(source_fn(*args, debug=True), timeout=SOURCE_TIMEOUT)
        normalized = _ensure_source_shape(name, result)
        logger.info("lookup source=%s status=%s duration_ms=%s", name, normalized["status"], normalized["duration_ms"])
        return name, normalized
    except asyncio.TimeoutError:
        elapsed = int(round((perf_counter() - started) * 1000))
        logger.warning("lookup source=%s status=timeout duration_ms=%s timeout_s=%.1f", name, elapsed, SOURCE_TIMEOUT)
        return name, source_error(name, elapsed, f"timeout: source timeout after {SOURCE_TIMEOUT:.1f}s", data={})
    except Exception as exc:
        elapsed = int(round((perf_counter() - started) * 1000))
        logger.exception("lookup source=%s status=exception duration_ms=%s", name, elapsed)
        return name, source_error(name, elapsed, f"network_error: {exc}", data={})


def _safe_score(value: Any) -> int:
    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    return 0


def _level_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _aggregate_categories(sources: list[dict[str, Any]]) -> list[str]:
    categories: list[str] = []
    seen: set[str] = set()
    for source in sources:
        if source.get("status") != "ok":
            continue
        for category in (source.get("data") or {}).get("categories", []):
            if isinstance(category, str) and category and category not in seen:
                seen.add(category)
                categories.append(category)
    return categories


def _aggregate_risk(ioc_type: str, sources: list[dict[str, Any]]) -> tuple[int, str]:
    weighted_total = 0.0
    weight_sum = 0.0
    source_map = {item["source"]: item for item in sources}

    for source in sources:
        if source.get("status") != "ok":
            continue
        weight = SOURCE_WEIGHTS.get(source.get("source"), 0.0)
        if weight <= 0:
            continue
        weighted_total += _safe_score((source.get("data") or {}).get("score")) * weight
        weight_sum += weight

    weighted_score = int(round(weighted_total / weight_sum)) if weight_sum > 0 else 0

    abuse_data = (source_map.get("abuseipdb") or {}).get("data") if (source_map.get("abuseipdb") or {}).get("status") == "ok" else None
    otx_data = (source_map.get("otx") or {}).get("data") if (source_map.get("otx") or {}).get("status") == "ok" else None
    vt_data = (source_map.get("virustotal") or {}).get("data") if (source_map.get("virustotal") or {}).get("status") == "ok" else None
    legacy = compute_risk(ioc_type, abuse_data, otx_data, vt_data)
    legacy_score = min(100, int(legacy.get("risk_points", 0)) * 20)

    risk_score = max(weighted_score, legacy_score)
    return risk_score, _level_from_score(risk_score)


def _strip_for_normal(source: dict[str, Any], debug: bool) -> dict[str, Any]:
    if debug:
        return source
    out = dict(source)
    out.pop("raw_json", None)
    if out.get("status") == "error":
        out["data"] = {}
    return out


async def _lookup_uncached(ioc: str, ioc_type: str) -> dict[str, Any]:
    source_results: dict[str, dict[str, Any]] = {
        "abuseipdb": _source_not_applicable("abuseipdb", ioc_type),
        "otx": source_error("otx", 0, "network_error: source not executed", data={}),
        "virustotal": source_error("virustotal", 0, "network_error: source not executed", data={}),
    }

    tasks = [
        _run_source("otx", otx.get_general, ioc_type, ioc),
        _run_source("virustotal", virustotal.lookup, ioc_type, ioc),
    ]
    if ioc_type == "ip":
        tasks.append(_run_source("abuseipdb", abuseipdb.check_ip, ioc))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    for item in gathered:
        if isinstance(item, Exception):
            logger.exception("lookup source task crashed", exc_info=item)
            continue
        source_name, source_value = item
        source_results[source_name] = _ensure_source_shape(source_name, source_value)

    sources = [source_results["abuseipdb"], source_results["otx"], source_results["virustotal"]]
    risk_score, risk_level = _aggregate_risk(ioc_type, sources)
    categories = _aggregate_categories(sources)
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "categories": categories,
        "sources": sources,
    }


@router.get("/{ioc:path}")
async def lookup_ioc(ioc: str, debug: bool = Query(False, description="Include source raw JSON, durations and errors")):
    ioc_clean = ioc.strip()
    ioc_type = detect_ioc_type(ioc_clean)

    cache_hit = False
    cached = ioc_cache.get(ioc_clean)
    if cached is None:
        payload = await _lookup_uncached(ioc_clean, ioc_type)
        ioc_cache.set(ioc_clean, payload)
    else:
        payload = cached
        cache_hit = True

    response = deepcopy(payload)
    response["sources"] = [_strip_for_normal(source, debug) for source in response["sources"]]

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
