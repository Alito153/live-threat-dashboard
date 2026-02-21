from typing import Any, Dict

from ..config import OTX_API_KEY, OTX_BASE_URL, HTTP_TIMEOUT
from .http_client import missing_api_key_result, request_json


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
        return missing_api_key_result("OTX_API_KEY")

    t = _otx_type(ioc_type)
    if not t:
        return {
            "ok": True,
            "status_code": None,
            "duration_ms": 0.0,
            "data": {"info": f"OTX skipped for unsupported ioc_type={ioc_type}"},
        }

    url = f"{OTX_BASE_URL}/api/v1/indicators/{t}/{ioc}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    res = request_json(
        "GET",
        url,
        headers=headers,
        timeout=HTTP_TIMEOUT,
        max_retries=1,
    )
    if not res.get("ok"):
        return res

    payload = res.get("data") or {}
    pulse_info = payload.get("pulse_info", {}) or {}
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

    res["data"] = {
        "pulse_count": pulse_info.get("count", len(pulses)),
        "pulses": pulse_summaries,
        "raw": payload,
    }
    return res
