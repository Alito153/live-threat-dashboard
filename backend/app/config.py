import os
from dotenv import load_dotenv

load_dotenv()

def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


_legacy_timeout = _float_env("HTTP_TIMEOUT", 12.0)
HTTP_CONNECT_TIMEOUT = _float_env("HTTP_CONNECT_TIMEOUT", 4.0)
HTTP_READ_TIMEOUT = _float_env("HTTP_READ_TIMEOUT", _legacy_timeout)
HTTP_TIMEOUT = (HTTP_CONNECT_TIMEOUT, HTTP_READ_TIMEOUT)
SOURCE_TIMEOUT = _float_env("SOURCE_TIMEOUT", HTTP_CONNECT_TIMEOUT + HTTP_READ_TIMEOUT + 1.0)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
