from typing import Any

from ..config import ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL, HTTP_TIMEOUT
from .http_client import missing_api_key_source, request_json, source_from_http_result, source_ok


SOURCE_NAME = "abuseipdb"


def _clamp_score(value: Any) -> int:
    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    return 0


async def check_ip(ip: str, debug: bool = False) -> dict[str, Any]:
    """
    AbuseIPDB check endpoint.
    """
    if not ABUSEIPDB_API_KEY:
        return missing_api_key_source(SOURCE_NAME, "ABUSEIPDB_API_KEY")

    url = f"{ABUSEIPDB_BASE_URL}/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    result = await request_json(
        "GET",
        url,
        headers=headers,
        params=params,
        timeout=HTTP_TIMEOUT,
        max_retries=1,
    )
    if not result.get("ok"):
        return source_from_http_result(SOURCE_NAME, result, debug=debug)

    payload = (result.get("data") or {}).get("data", {}) or {}
    score = _clamp_score(payload.get("abuseConfidenceScore"))
    total_reports = payload.get("totalReports")

    categories: list[str] = []
    if score >= 80:
        categories.append("abuse-high")
    elif score >= 40:
        categories.append("abuse-medium")
    elif score >= 1:
        categories.append("abuse-low")
    if isinstance(total_reports, int) and total_reports > 0:
        categories.append("reported")

    data = {
        "score": score,
        "categories": categories,
        "confidence": score,
        "abuse_confidence_score": score,
        "abuseConfidenceScore": score,
        "total_reports": total_reports,
        "country_code": payload.get("countryCode"),
        "isp": payload.get("isp"),
        "domain": payload.get("domain"),
        "usage_type": payload.get("usageType"),
        "last_reported_at": payload.get("lastReportedAt"),
    }
    return source_ok(
        SOURCE_NAME,
        result.get("duration_ms", 0.0),
        data,
        raw_json=payload if debug else None,
    )
