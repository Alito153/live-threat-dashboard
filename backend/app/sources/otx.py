from typing import Any

from ..config import OTX_API_KEY, OTX_BASE_URL, HTTP_TIMEOUT
from .http_client import missing_api_key_source, request_json, source_from_http_result, source_ok


SOURCE_NAME = "otx"


def _otx_type(ioc_type: str) -> str | None:
    return {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "sha256": "file",
        "sha1": "file",
        "md5": "file",
    }.get(ioc_type)


def _unique(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


async def get_general(ioc_type: str, ioc: str, debug: bool = False) -> dict[str, Any]:
    """
    AlienVault OTX indicator general endpoint.
    """
    if not OTX_API_KEY:
        return missing_api_key_source(SOURCE_NAME, "OTX_API_KEY")

    t = _otx_type(ioc_type)
    if not t:
        return source_ok(
            SOURCE_NAME,
            0.0,
            {
                "score": 0,
                "categories": [],
                "pulse_count": 0,
                "ioc_type": ioc_type,
                "note": "not_applicable_for_ioc_type",
            },
        )

    url = f"{OTX_BASE_URL}/api/v1/indicators/{t}/{ioc}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    result = await request_json(
        "GET",
        url,
        headers=headers,
        timeout=HTTP_TIMEOUT,
        max_retries=1,
    )
    if not result.get("ok"):
        return source_from_http_result(SOURCE_NAME, result, debug=debug)

    payload = result.get("data") or {}
    pulse_info = payload.get("pulse_info", {}) or {}
    pulses = pulse_info.get("pulses", []) or []
    pulse_count = pulse_info.get("count", len(pulses))
    if not isinstance(pulse_count, int):
        pulse_count = len(pulses)

    score = max(0, min(100, pulse_count * 8))

    tags: list[str] = []
    pulse_names: list[str] = []
    for pulse in pulses[:10]:
        pulse_name = pulse.get("name")
        if isinstance(pulse_name, str):
            pulse_names.append(pulse_name)
        for tag in (pulse.get("tags") or []):
            if isinstance(tag, str):
                tags.append(tag)

    categories = _unique(tags)
    if pulse_count > 0 and "otx-pulse" not in categories:
        categories.insert(0, "otx-pulse")

    data = {
        "score": score,
        "categories": categories,
        "confidence": min(100, pulse_count * 10),
        "pulse_count": pulse_count,
        "top_pulses": pulse_names[:5],
        "ioc_type": ioc_type,
    }
    return source_ok(
        SOURCE_NAME,
        result.get("duration_ms", 0.0),
        data,
        raw_json=payload if debug else None,
    )
