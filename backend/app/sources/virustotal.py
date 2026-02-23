import base64
from typing import Any

from ..config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL, HTTP_TIMEOUT
from .http_client import missing_api_key_source, request_json, source_from_http_result, source_ok


SOURCE_NAME = "virustotal"
BASE = f"{VIRUSTOTAL_BASE_URL}/api/v3"


def _headers() -> dict[str, str]:
    return {"x-apikey": VIRUSTOTAL_API_KEY}


def _url_id(url_value: str) -> str:
    encoded = base64.urlsafe_b64encode(url_value.encode("utf-8")).decode("utf-8")
    return encoded.strip("=")


def _to_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return 0


def _extract_common(payload: dict[str, Any]) -> dict[str, Any]:
    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}

    harmless = _to_int(stats.get("harmless"))
    malicious = _to_int(stats.get("malicious"))
    suspicious = _to_int(stats.get("suspicious"))
    undetected = _to_int(stats.get("undetected"))
    timeout = _to_int(stats.get("timeout"))
    reputation = attrs.get("reputation")

    rep_boost = 0
    if isinstance(reputation, int) and reputation < 0:
        rep_boost = min(20, abs(reputation) // 5)
    score = min(100, max(0, malicious * 15 + suspicious * 8 + rep_boost))

    categories: list[str] = []
    raw_tags = attrs.get("tags", []) or []
    for tag in raw_tags:
        if isinstance(tag, str) and tag not in categories:
            categories.append(tag)
    if malicious > 0 and "malicious-detected" not in categories:
        categories.append("malicious-detected")
    if suspicious > 0 and "suspicious-detected" not in categories:
        categories.append("suspicious-detected")

    return {
        "score": score,
        "categories": categories,
        "confidence": min(100, malicious * 12 + suspicious * 6),
        "harmless": harmless,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "timeout": timeout,
        "reputation": reputation,
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


async def lookup(ioc_type: str, ioc: str, debug: bool = False) -> dict[str, Any]:
    """
    VirusTotal v3 lookup for ip/domain/file-hash/url.
    """
    if not VIRUSTOTAL_API_KEY:
        return missing_api_key_source(SOURCE_NAME, "VIRUSTOTAL_API_KEY")

    if ioc_type == "ip":
        return await _lookup_get(f"/ip_addresses/{ioc}", ioc_type=ioc_type, debug=debug)
    if ioc_type == "domain":
        return await _lookup_get(f"/domains/{ioc}", ioc_type=ioc_type, debug=debug)
    if ioc_type in {"sha256", "sha1", "md5"}:
        return await _lookup_get(f"/files/{ioc}", ioc_type=ioc_type, debug=debug)
    if ioc_type == "url":
        return await _lookup_url(ioc, debug=debug)

    return source_ok(
        SOURCE_NAME,
        0.0,
        {
            "score": 0,
            "categories": [],
            "ioc_type": ioc_type,
            "note": "not_applicable_for_ioc_type",
        },
    )


async def _lookup_get(endpoint: str, *, ioc_type: str, debug: bool) -> dict[str, Any]:
    result = await request_json(
        "GET",
        BASE + endpoint,
        headers=_headers(),
        timeout=HTTP_TIMEOUT,
        max_retries=1,
    )
    if not result.get("ok"):
        return source_from_http_result(SOURCE_NAME, result, debug=debug)

    payload = result.get("data") or {}
    data = _extract_common(payload)
    data["ioc_type"] = ioc_type
    return source_ok(
        SOURCE_NAME,
        result.get("duration_ms", 0.0),
        data,
        raw_json=payload if debug else None,
    )


async def _lookup_url(url_value: str, *, debug: bool) -> dict[str, Any]:
    submit_result = await request_json(
        "POST",
        BASE + "/urls",
        headers=_headers(),
        data={"url": url_value},
        timeout=HTTP_TIMEOUT,
        max_retries=1,
    )
    if not submit_result.get("ok"):
        return source_from_http_result(
            SOURCE_NAME,
            submit_result,
            debug=debug,
            extra_error_details={"step": "submit_url"},
        )

    submit_payload = submit_result.get("data") or {}
    url_id = ((submit_payload.get("data") or {}).get("id")) or _url_id(url_value)

    lookup_result = await request_json(
        "GET",
        BASE + f"/urls/{url_id}",
        headers=_headers(),
        timeout=HTTP_TIMEOUT,
        max_retries=1,
    )
    total_duration = float(submit_result.get("duration_ms") or 0.0) + float(lookup_result.get("duration_ms") or 0.0)
    if not lookup_result.get("ok"):
        return source_from_http_result(
            SOURCE_NAME,
            lookup_result,
            debug=debug,
            override_duration_ms=total_duration,
            extra_error_details={
                "step": "lookup_url",
                "url_id": url_id,
                "submit_status_code": submit_result.get("status_code"),
            },
        )

    lookup_payload = lookup_result.get("data") or {}
    data = _extract_common(lookup_payload)
    data["ioc_type"] = "url"
    data["url_id"] = url_id
    raw_json = {"lookup": lookup_payload, "submit": submit_payload} if debug else None
    return source_ok(SOURCE_NAME, total_duration, data, raw_json=raw_json)
