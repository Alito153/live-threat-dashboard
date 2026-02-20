from typing import Any, Dict
import base64
import requests

from ..config import VIRUSTOTAL_API_KEY, HTTP_TIMEOUT

BASE = "https://www.virustotal.com/api/v3"


def _headers() -> Dict[str, str]:
    return {"x-apikey": VIRUSTOTAL_API_KEY}


def _extract_common(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrait des champs utiles + stats AV si disponibles.
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
    (Alternative: POST /urls returns an id too, but this is deterministic.)
    """
    encoded = base64.urlsafe_b64encode(url_value.encode("utf-8")).decode("utf-8")
    return encoded.strip("=")


def lookup(ioc_type: str, ioc: str) -> Dict[str, Any]:
    """
    VirusTotal v3 lookup for:
    - ip / domain / file hash → direct GET
    - url → submit (POST /urls) then GET /urls/{id} (or deterministic id)
    Docs: https://docs.virustotal.com/reference/overview
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY missing"}

    try:
        if ioc_type == "ip":
            return _lookup_get(f"/ip_addresses/{ioc}")

        if ioc_type == "domain":
            return _lookup_get(f"/domains/{ioc}")

        if ioc_type in {"sha256", "sha1", "md5"}:
            return _lookup_get(f"/files/{ioc}")

        if ioc_type == "url":
            # 1) Submit URL (creates/refreshes analysis)
            submit_res = _submit_url(ioc)

            # 2) Fetch URL object
            # Prefer id returned by submit if available; fallback to deterministic id.
            url_id = submit_res.get("url_id") or _url_id(ioc)
            url_obj = _lookup_get(f"/urls/{url_id}")

            # Merge: include submit meta + url object fields
            merged = {
                **url_obj,
                "url_id": url_id,
                "submit": submit_res.get("submit"),
            }
            return merged

        return {"info": f"VT lookup skipped for type={ioc_type}"}

    except Exception as e:
        return {"error": str(e)}


def _lookup_get(endpoint: str) -> Dict[str, Any]:
    r = requests.get(BASE + endpoint, headers=_headers(), timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    data = r.json() or {}

    out = _extract_common(data)
    out["raw"] = data  # keep full payload for debug if you want
    return out


def _submit_url(url_value: str) -> Dict[str, Any]:
    """
    POST /urls with form data {url: ...}
    Returns an id like "u-<...>" that can be used in GET /urls/{id}
    """
    r = requests.post(
        BASE + "/urls",
        headers=_headers(),
        data={"url": url_value},
        timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()
    j = r.json() or {}
    url_id = (j.get("data") or {}).get("id")

    return {
        "url_id": url_id,
        "submit": j,  # raw submit response (small)
    }