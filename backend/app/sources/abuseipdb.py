from typing import Any, Dict
import requests

from ..config import ABUSEIPDB_API_KEY, HTTP_TIMEOUT


def check_ip(ip: str) -> Dict[str, Any]:
    """
    AbuseIPDB: check an IP reputation.
    Docs: https://docs.abuseipdb.com/
    """
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY missing"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        d = (r.json() or {}).get("data", {}) or {}

        return {
            "abuseConfidenceScore": d.get("abuseConfidenceScore"),
            "totalReports": d.get("totalReports"),
            "countryCode": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usageType": d.get("usageType"),
            "lastReportedAt": d.get("lastReportedAt"),
            "raw": d,
        }
    except Exception as e:
        return {"error": str(e)}