from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from time import perf_counter, sleep
from typing import Any, Mapping

import requests

from ..config import HTTP_TIMEOUT


def ok_result(data: dict[str, Any], status_code: int | None, duration_ms: float) -> dict[str, Any]:
    return {
        "ok": True,
        "status_code": status_code,
        "duration_ms": round(duration_ms, 1),
        "data": data,
    }


def error_result(
    error_type: str,
    message: str,
    *,
    status_code: int | None = None,
    duration_ms: float = 0.0,
    details: Any = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"type": error_type, "message": message}
    if details is not None:
        error["details"] = details

    return {
        "ok": False,
        "status_code": status_code,
        "duration_ms": round(duration_ms, 1),
        "error": error,
    }


def missing_api_key_result(key_name: str) -> dict[str, Any]:
    return error_result(
        "missing_api_key",
        f"{key_name} is missing",
        status_code=None,
        duration_ms=0.0,
    )


def skipped_result(reason: str) -> dict[str, Any]:
    return ok_result({"info": reason}, status_code=None, duration_ms=0.0)


def _elapsed_ms(start: float) -> float:
    return (perf_counter() - start) * 1000


def _parse_retry_after(header_value: str | None) -> float | None:
    if not header_value:
        return None

    value = header_value.strip()
    if value.isdigit():
        return max(0.0, float(value))

    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None

    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    return max(0.0, (dt - now).total_seconds())


def _http_error_details(response: requests.Response) -> dict[str, Any]:
    details: dict[str, Any] = {"reason": response.reason}
    content_type = response.headers.get("Content-Type")
    if content_type:
        details["content_type"] = content_type

    body_excerpt = (response.text or "").strip()
    if body_excerpt:
        details["body_excerpt"] = body_excerpt[:300]

    return details


def request_json(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    data: Mapping[str, Any] | None = None,
    json_data: Mapping[str, Any] | None = None,
    timeout: float | tuple[float, float] = HTTP_TIMEOUT,
    max_retries: int = 1,
    base_backoff_seconds: float = 0.6,
) -> dict[str, Any]:
    start = perf_counter()
    attempt = 0

    while True:
        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json_data,
                timeout=timeout,
            )
        except requests.exceptions.Timeout:
            return error_result(
                "timeout",
                f"Timeout while calling {method.upper()} {url}",
                duration_ms=_elapsed_ms(start),
            )
        except requests.exceptions.RequestException as exc:
            return error_result(
                "network_error",
                f"Network error while calling {method.upper()} {url}",
                duration_ms=_elapsed_ms(start),
                details=str(exc),
            )

        status_code = response.status_code
        if 200 <= status_code < 300:
            try:
                payload = response.json() if response.content else {}
            except ValueError:
                return error_result(
                    "http_error",
                    "Upstream returned non-JSON response",
                    status_code=status_code,
                    duration_ms=_elapsed_ms(start),
                    details=_http_error_details(response),
                )
            return ok_result(payload, status_code=status_code, duration_ms=_elapsed_ms(start))

        should_retry = (status_code == 429 or status_code >= 500) and attempt < max_retries
        if should_retry:
            retry_after = _parse_retry_after(response.headers.get("Retry-After"))
            delay = retry_after if retry_after is not None else base_backoff_seconds * (2**attempt)
            sleep(max(0.0, delay))
            attempt += 1
            continue

        return error_result(
            "http_error",
            f"Upstream HTTP error {status_code}",
            status_code=status_code,
            duration_ms=_elapsed_ms(start),
            details=_http_error_details(response),
        )
