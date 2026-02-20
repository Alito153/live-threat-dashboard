import re
import asyncio
import ipaddress
import logging
from time import perf_counter
from typing import Any, Callable
from fastapi import APIRouter, Query

from app.config import SOURCE_TIMEOUT
from app.sources import abuseipdb, otx, virustotal
from app.scoring import compute_risk

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


def _prune_source_payload(data: Any, *, debug: bool, drop_submit: bool = False) -> Any:
    if debug or not isinstance(data, dict):
        return data

    pruned = dict(data)
    pruned.pop("raw", None)
    if drop_submit:
        pruned.pop("submit", None)
    return pruned


async def call_source_with_timeout(name: str, fn: Callable[..., dict[str, Any]], *args: Any) -> tuple[str, dict[str, Any], float]:
    start = perf_counter()
    try:
        data = await asyncio.wait_for(asyncio.to_thread(fn, *args), timeout=SOURCE_TIMEOUT)
        elapsed_ms = (perf_counter() - start) * 1000
        state = "error" if isinstance(data, dict) and data.get("error") else "ok"
        logger.info("lookup source=%s status=%s elapsed_ms=%.1f", name, state, elapsed_ms)
        return name, data, elapsed_ms
    except asyncio.TimeoutError:
        elapsed_ms = (perf_counter() - start) * 1000
        logger.warning("lookup source=%s status=timeout elapsed_ms=%.1f timeout_s=%.1f", name, elapsed_ms, SOURCE_TIMEOUT)
        return name, {"error": f"source timeout after {SOURCE_TIMEOUT:.1f}s"}, elapsed_ms
    except Exception as exc:
        elapsed_ms = (perf_counter() - start) * 1000
        logger.exception("lookup source=%s status=exception elapsed_ms=%.1f", name, elapsed_ms)
        return name, {"error": str(exc)}, elapsed_ms


@router.get("/{ioc:path}")
async def lookup_ioc(ioc: str, debug: bool = Query(False, description="Include full raw source payloads for debugging")):
    total_start = perf_counter()
    ioc_type = detect_ioc_type(ioc)

    tasks = [
        call_source_with_timeout("otx", otx.get_general, ioc_type, ioc),
        call_source_with_timeout("virustotal", virustotal.lookup, ioc_type, ioc),
    ]
    if ioc_type == "ip":
        tasks.append(call_source_with_timeout("abuseipdb", abuseipdb.check_ip, ioc))

    results = await asyncio.gather(*tasks)

    abuse_data = None
    otx_data = None
    vt_data = None
    source_durations_ms: dict[str, float] = {}
    source_status: dict[str, str] = {}

    for name, data, elapsed_ms in results:
        source_durations_ms[name] = round(elapsed_ms, 1)
        source_status[name] = "error" if isinstance(data, dict) and data.get("error") else "ok"
        if name == "abuseipdb":
            abuse_data = data
        elif name == "otx":
            otx_data = data
        elif name == "virustotal":
            vt_data = data

    summary = compute_risk(ioc_type, abuse_data, otx_data, vt_data)
    total_elapsed_ms = (perf_counter() - total_start) * 1000

    abuse_data_out = _prune_source_payload(abuse_data, debug=debug)
    otx_data_out = _prune_source_payload(otx_data, debug=debug)
    vt_data_out = _prune_source_payload(vt_data, debug=debug, drop_submit=True)

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
        "abuseipdb": abuse_data_out,
        "otx": otx_data_out,
        "virustotal": vt_data_out,
    }
