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


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


_legacy_timeout = _float_env("HTTP_TIMEOUT", 12.0)
HTTP_CONNECT_TIMEOUT = _float_env("HTTP_CONNECT_TIMEOUT", 4.0)
HTTP_READ_TIMEOUT = _float_env("HTTP_READ_TIMEOUT", _legacy_timeout)
HTTP_TIMEOUT = (HTTP_CONNECT_TIMEOUT, HTTP_READ_TIMEOUT)
SOURCE_TIMEOUT = _float_env("SOURCE_TIMEOUT", HTTP_CONNECT_TIMEOUT + HTTP_READ_TIMEOUT + 1.0)
CACHE_TTL_SECONDS = _float_env("CACHE_TTL_SECONDS", 300.0)
CACHE_MAX_ITEMS = _int_env("CACHE_MAX_ITEMS", 2048)
COLLECTOR_ENABLED = _bool_env("COLLECTOR_ENABLED", False)
COLLECTOR_INTERVAL_SECONDS = _float_env("COLLECTOR_INTERVAL_SECONDS", 10.0)
COLLECTOR_BATCH_SIZE = _int_env("COLLECTOR_BATCH_SIZE", 10)
ENRICH_TTL_SECONDS = _float_env("ENRICH_TTL_SECONDS", 600.0)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/live_threat_dashboard")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

ABUSEIPDB_BASE_URL = os.getenv("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com").rstrip("/")
OTX_BASE_URL = os.getenv("OTX_BASE_URL", "https://otx.alienvault.com").rstrip("/")
VIRUSTOTAL_BASE_URL = os.getenv("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com").rstrip("/")
