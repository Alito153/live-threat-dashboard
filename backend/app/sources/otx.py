from typing import Any, Dict
import requests

from ..config import OTX_API_KEY, HTTP_TIMEOUT


def _otx_type(ioc_type: str) -> str | None:
    return {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "sha256": "file",
        "sha1": "file",
        "md5": "file",
    }.get(ioc_type)


def get_general(ioc_type: str, ioc: str) -> Dict[str, Any]:
    """
    AlienVault OTX indicator 'general' endpoint.
    Docs: https://otx.alienvault.com/api
    """
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY missing"}

    t = _otx_type(ioc_type)
    if not t:
        return {"error": f"Unsupported ioc_type={ioc_type} for OTX"}

    url = f"https://otx.alienvault.com/api/v1/indicators/{t}/{ioc}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json() or {}

        pulse_info = data.get("pulse_info", {}) or {}
        pulses = pulse_info.get("pulses", []) or []

        pulse_summaries = []
        for p in pulses[:10]:
            pulse_summaries.append(
                {
                    "name": p.get("name"),
                    "id": p.get("id"),
                    "created": p.get("created"),
                    "modified": p.get("modified"),
                    "tags": p.get("tags", []) or [],
                    "TLP": p.get("TLP"),
                }
            )

        return {
            "pulse_count": pulse_info.get("count", len(pulses)),
            "pulses": pulse_summaries,
            "raw": data,
        }
    except Exception as e:
        return {"error": str(e)}