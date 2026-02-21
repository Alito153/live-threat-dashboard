import asyncio
import ipaddress
import logging
import re
from time import perf_counter
from typing import Any, Callable

from fastapi import APIRouter, Query

from app.config import SOURCE_TIMEOUT
from app.scoring import compute_risk
from app.sources import abuseipdb, otx, virustotal
from app.sources.http_client import error_result, skipped_result

router = APIRouter(prefix="/lookup", tags=["lookup"])
logger = logging.getLogger(__name__)

SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")


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


def _is_valid_source_result(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if "ok" not in data or "status_code" not in data or "duration_ms" not in data:
        return False
    if data.get("ok"):
        return "data" in data
    return "error" in data


def _prune_source_payload(source: Any, *, debug: bool, drop_submit: bool = False) -> Any:
    if debug or not isinstance(source, dict):
        return source
    if not source.get("ok"):
        return source

    payload = source.get("data")
    if not isinstance(payload, dict):
        return source

    pruned_source = dict(source)
    pruned_payload = dict(payload)
    pruned_payload.pop("raw", None)
    if drop_submit:
        pruned_payload.pop("submit", None)
    pruned_source["data"] = pruned_payload
    return pruned_source


def _source_state(source: dict[str, Any]) -> str:
    if source.get("ok"):
        info = (source.get("data") or {}).get("info")
        if isinstance(info, str) and "skipped" in info.lower():
            return "skipped"
        return "ok"
    return "error"


def _score_data(source: dict[str, Any]) -> dict[str, Any] | None:
    if source.get("ok") and isinstance(source.get("data"), dict):
        return source["data"]
    return None


async def call_source_with_timeout(
    name: str,
    fn: Callable[..., dict[str, Any]],
    *args: Any,
) -> tuple[str, dict[str, Any], float]:
    start = perf_counter()
    try:
        result = await asyncio.wait_for(asyncio.to_thread(fn, *args), timeout=SOURCE_TIMEOUT)
        elapsed_ms = (perf_counter() - start) * 1000

        if not _is_valid_source_result(result):
            normalized = error_result(
                "network_error",
                f"Invalid source response format from {name}",
                duration_ms=elapsed_ms,
                details={"source": name},
            )
            logger.error("lookup source=%s status=invalid_result elapsed_ms=%.1f", name, elapsed_ms)
            return name, normalized, elapsed_ms

        logger.info("lookup source=%s status=%s elapsed_ms=%.1f", name, _source_state(result), elapsed_ms)
        return name, result, elapsed_ms
    except asyncio.TimeoutError:
        elapsed_ms = (perf_counter() - start) * 1000
        timeout_result = error_result(
            "timeout",
            f"source timeout after {SOURCE_TIMEOUT:.1f}s",
            duration_ms=elapsed_ms,
            details={"source": name},
        )
        logger.warning(
            "lookup source=%s status=timeout elapsed_ms=%.1f timeout_s=%.1f",
            name,
            elapsed_ms,
            SOURCE_TIMEOUT,
        )
        return name, timeout_result, elapsed_ms
    except Exception as exc:
        elapsed_ms = (perf_counter() - start) * 1000
        exception_result = error_result(
            "network_error",
            f"Unhandled error while calling {name}",
            duration_ms=elapsed_ms,
            details=str(exc),
        )
        logger.exception("lookup source=%s status=exception elapsed_ms=%.1f", name, elapsed_ms)
        return name, exception_result, elapsed_ms


@router.get("/{ioc:path}")
async def lookup_ioc(
    ioc: str,
    debug: bool = Query(False, description="Include full raw source payloads for debugging"),
):
    total_start = perf_counter()
    ioc_type = detect_ioc_type(ioc)

    source_results: dict[str, dict[str, Any]] = {
        "abuseipdb": skipped_result("AbuseIPDB skipped for non-ip IOC"),
        "otx": error_result("network_error", "OTX call not executed", duration_ms=0.0),
        "virustotal": error_result("network_error", "VirusTotal call not executed", duration_ms=0.0),
    }

    tasks = [
        call_source_with_timeout("otx", otx.get_general, ioc_type, ioc),
        call_source_with_timeout("virustotal", virustotal.lookup, ioc_type, ioc),
    ]
    if ioc_type == "ip":
        tasks.append(call_source_with_timeout("abuseipdb", abuseipdb.check_ip, ioc))

    results = await asyncio.gather(*tasks)

    source_durations_ms: dict[str, float] = {
        "abuseipdb": round(source_results["abuseipdb"]["duration_ms"], 1),
        "otx": 0.0,
        "virustotal": 0.0,
    }
    source_status: dict[str, str] = {
        "abuseipdb": _source_state(source_results["abuseipdb"]),
        "otx": "error",
        "virustotal": "error",
    }

    for name, result, elapsed_ms in results:
        source_results[name] = result
        source_durations_ms[name] = round(elapsed_ms, 1)
        source_status[name] = _source_state(result)

    abuse_for_score = _score_data(source_results["abuseipdb"])
    otx_for_score = _score_data(source_results["otx"])
    vt_for_score = _score_data(source_results["virustotal"])
    summary = compute_risk(ioc_type, abuse_for_score, otx_for_score, vt_for_score)

    total_elapsed_ms = (perf_counter() - total_start) * 1000
    abuse_out = _prune_source_payload(source_results["abuseipdb"], debug=debug)
    otx_out = _prune_source_payload(source_results["otx"], debug=debug)
    vt_out = _prune_source_payload(source_results["virustotal"], debug=debug, drop_submit=True)

    return {
        "ioc": ioc,
        "type": ioc_type,
        "summary": summary,
        "meta": {
            "duration_ms": round(total_elapsed_ms, 1),
            "source_timeout_s": SOURCE_TIMEOUT,
            "source_durations_ms": source_durations_ms,
            "source_status": source_status,
        },
        "abuseipdb": abuse_out,
        "otx": otx_out,
        "virustotal": vt_out,
    }
