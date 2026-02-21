from typing import Any, Dict

from ..config import ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL, HTTP_TIMEOUT
from .http_client import missing_api_key_result, request_json


def check_ip(ip: str) -> Dict[str, Any]:
    """
    AbuseIPDB: check an IP reputation.
    Docs: https://docs.abuseipdb.com/
    """
    if not ABUSEIPDB_API_KEY:
        return missing_api_key_result("ABUSEIPDB_API_KEY")

    url = f"{ABUSEIPDB_BASE_URL}/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    res = request_json(
        "GET",
        url,
        headers=headers,
        params=params,
        timeout=HTTP_TIMEOUT,
        max_retries=1,
    )
    if not res.get("ok"):
        return res

    payload = (res.get("data") or {}).get("data", {}) or {}
    res["data"] = {
        "abuseConfidenceScore": payload.get("abuseConfidenceScore"),
        "totalReports": payload.get("totalReports"),
        "countryCode": payload.get("countryCode"),
        "isp": payload.get("isp"),
        "domain": payload.get("domain"),
        "usageType": payload.get("usageType"),
        "lastReportedAt": payload.get("lastReportedAt"),
        "raw": payload,
    }
    return res
