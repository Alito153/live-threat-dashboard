from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import partial
from time import perf_counter
from typing import Any, Mapping

import anyio
import requests

from ..config import HTTP_TIMEOUT


def _round_ms(value: float) -> int:
    return max(0, int(round(float(value))))


def source_ok(
    source: str,
    duration_ms: float,
    data: dict[str, Any] | None = None,
    *,
    raw_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "source": source,
        "status": "ok",
        "duration_ms": _round_ms(duration_ms),
        "data": data or {},
        "error": None,
    }
    if raw_json is not None:
        out["raw_json"] = raw_json
    return out


def source_error(
    source: str,
    duration_ms: float,
    error: str,
    *,
    data: dict[str, Any] | None = None,
    raw_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "source": source,
        "status": "error",
        "duration_ms": _round_ms(duration_ms),
        "data": data or {},
        "error": error,
    }
    if raw_json is not None:
        out["raw_json"] = raw_json
    return out


def missing_api_key_source(source: str, key_name: str) -> dict[str, Any]:
    return source_error(source, 0, f"missing_api_key: {key_name} is missing")


def source_from_http_result(
    source: str,
    result: dict[str, Any],
    *,
    debug: bool = False,
    override_duration_ms: float | None = None,
    extra_error_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    duration_ms = result.get("duration_ms") if override_duration_ms is None else override_duration_ms
    duration_ms = float(duration_ms or 0.0)

    if result.get("ok"):
        payload = result.get("data")
        return source_ok(source, duration_ms, payload if isinstance(payload, dict) else {})

    err = result.get("error") or {}
    err_type = err.get("type", "http_error")
    err_message = err.get("message", "upstream request failed")
    status_code = result.get("status_code")
    message = f"{err_type}: {err_message}"
    if status_code is not None:
        message += f" (status={status_code})"

    debug_data: dict[str, Any] = {}
    if debug:
        debug_data["error_type"] = err_type
        debug_data["status_code"] = status_code
        details = err.get("details")
        if details is not None:
            debug_data["error_details"] = details
        if extra_error_details:
            debug_data.update(extra_error_details)

    return source_error(source, duration_ms, message, data=debug_data)


def _elapsed_ms(start: float) -> float:
    return (perf_counter() - start) * 1000.0


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


def _do_request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None,
    params: Mapping[str, Any] | None,
    data: Mapping[str, Any] | None,
    json_data: Mapping[str, Any] | None,
    timeout: float | tuple[float, float],
) -> requests.Response:
    return requests.request(
        method=method.upper(),
        url=url,
        headers=headers,
        params=params,
        data=data,
        json=json_data,
        timeout=timeout,
    )


async def request_json(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    data: Mapping[str, Any] | None = None,
    json_data: Mapping[str, Any] | None = None,
    timeout: float | tuple[float, float] = HTTP_TIMEOUT,
    max_retries: int = 1,
    base_backoff_seconds: float = 0.4,
) -> dict[str, Any]:
    start = perf_counter()
    attempt = 0

    while True:
        try:
            request_call = partial(
                _do_request,
                method,
                url,
                headers=headers,
                params=params,
                data=data,
                json_data=json_data,
                timeout=timeout,
            )
            response = await anyio.to_thread.run_sync(request_call)
        except requests.exceptions.Timeout:
            return {
                "ok": False,
                "status_code": None,
                "duration_ms": _round_ms(_elapsed_ms(start)),
                "error": {
                    "type": "timeout",
                    "message": f"Timeout while calling {method.upper()} {url}",
                },
            }
        except requests.exceptions.RequestException as exc:
            return {
                "ok": False,
                "status_code": None,
                "duration_ms": _round_ms(_elapsed_ms(start)),
                "error": {
                    "type": "network_error",
                    "message": f"Network error while calling {method.upper()} {url}",
                    "details": str(exc),
                },
            }

        status_code = response.status_code
        if 200 <= status_code < 300:
            try:
                payload = response.json() if response.content else {}
            except ValueError:
                return {
                    "ok": False,
                    "status_code": status_code,
                    "duration_ms": _round_ms(_elapsed_ms(start)),
                    "error": {
                        "type": "http_error",
                        "message": "Upstream returned non-JSON response",
                        "details": _http_error_details(response),
                    },
                }
            return {
                "ok": True,
                "status_code": status_code,
                "duration_ms": _round_ms(_elapsed_ms(start)),
                "data": payload,
            }

        should_retry = (status_code == 429 or status_code >= 500) and attempt < max_retries
        if should_retry:
            retry_after = _parse_retry_after(response.headers.get("Retry-After"))
            delay = retry_after if retry_after is not None else base_backoff_seconds * (2**attempt)
            await anyio.sleep(max(0.0, min(delay, 3.0)))
            attempt += 1
            continue

        return {
            "ok": False,
            "status_code": status_code,
            "duration_ms": _round_ms(_elapsed_ms(start)),
            "error": {
                "type": "http_error",
                "message": f"Upstream HTTP error {status_code}",
                "details": _http_error_details(response),
            },
        }
