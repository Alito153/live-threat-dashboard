from typing import Any, Dict
import base64

from ..config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL, HTTP_TIMEOUT
from .http_client import missing_api_key_result, request_json

BASE = f"{VIRUSTOTAL_BASE_URL}/api/v3"


def _headers() -> Dict[str, str]:
    return {"x-apikey": VIRUSTOTAL_API_KEY}


def _extract_common(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract useful fields and AV stats when available.
    """
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}

    return {
        "harmless": stats.get("harmless"),
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "undetected": stats.get("undetected"),
        "timeout": stats.get("timeout"),
        "reputation": attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "tags": attrs.get("tags", []) or [],
    }


def _url_id(url_value: str) -> str:
    """
    VT v3 URL identifier is base64(url) without '=' padding.
    """
    encoded = base64.urlsafe_b64encode(url_value.encode("utf-8")).decode("utf-8")
    return encoded.strip("=")


def lookup(ioc_type: str, ioc: str) -> Dict[str, Any]:
    """
    VirusTotal v3 lookup for:
    - ip / domain / file hash -> direct GET
    - url -> submit (POST /urls) then GET /urls/{id}
    Docs: https://docs.virustotal.com/reference/overview
    """
    if not VIRUSTOTAL_API_KEY:
        return missing_api_key_result("VIRUSTOTAL_API_KEY")

    if ioc_type == "ip":
        return _lookup_get(f"/ip_addresses/{ioc}")

    if ioc_type == "domain":
        return _lookup_get(f"/domains/{ioc}")

    if ioc_type in {"sha256", "sha1", "md5"}:
        return _lookup_get(f"/files/{ioc}")

    if ioc_type == "url":
        submit_res = _submit_url(ioc)
        if not submit_res.get("ok"):
            return submit_res

        submit_data = submit_res.get("data") or {}
        url_id = submit_data.get("url_id") or _url_id(ioc)

        url_res = _lookup_get(f"/urls/{url_id}")
        if not url_res.get("ok"):
            error_block = dict(url_res.get("error") or {})
            existing_details = error_block.get("details")
            if isinstance(existing_details, dict):
                details = dict(existing_details)
            elif existing_details is None:
                details = {}
            else:
                details = {"upstream": existing_details}
            details["url_id"] = url_id
            details["submit_status_code"] = submit_res.get("status_code")
            details["submit_duration_ms"] = submit_res.get("duration_ms")
            error_block["details"] = details
            url_res["error"] = error_block
            url_res["duration_ms"] = round(
                (submit_res.get("duration_ms") or 0.0) + (url_res.get("duration_ms") or 0.0),
                1,
            )
            return url_res

        merged_data = dict(url_res.get("data") or {})
        merged_data["url_id"] = url_id
        merged_data["submit"] = submit_data.get("submit")
        url_res["data"] = merged_data
        url_res["duration_ms"] = round(
            (submit_res.get("duration_ms") or 0.0) + (url_res.get("duration_ms") or 0.0),
            1,
        )
        return url_res

    return {
        "ok": True,
        "status_code": None,
        "duration_ms": 0.0,
        "data": {"info": f"VT lookup skipped for type={ioc_type}"},
    }


def _lookup_get(endpoint: str) -> Dict[str, Any]:
    res = request_json(
        "GET",
        BASE + endpoint,
        headers=_headers(),
        timeout=HTTP_TIMEOUT,
        max_retries=1,
    )
    if not res.get("ok"):
        return res

    payload = res.get("data") or {}
    out = _extract_common(payload)
    out["raw"] = payload
    res["data"] = out
    return res


def _submit_url(url_value: str) -> Dict[str, Any]:
    """
    POST /urls with form data {url: ...}
    """
    res = request_json(
        "POST",
        BASE + "/urls",
        headers=_headers(),
        data={"url": url_value},
        timeout=HTTP_TIMEOUT,
        max_retries=1,
    )
    if not res.get("ok"):
        return res

    payload = res.get("data") or {}
    url_id = (payload.get("data") or {}).get("id")
    res["data"] = {
        "url_id": url_id,
        "submit": payload,
    }
    return res
