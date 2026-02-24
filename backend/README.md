## Live Threat Dashboard Backend

FastAPI backend for IOC enrichment (AbuseIPDB, OTX, VirusTotal), with:
- `GET /lookup/{ioc}` API
- in-memory TTL cache for API responses
- PostgreSQL live collector (`python -m app.collector`) that continuously enriches IOC rows and stores results for Grafana

## Prerequisites

- Python 3.11+ (Windows OK)
- PostgreSQL
- Grafana (optional but recommended for live dashboards)

## Setup (PowerShell)

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Environment Variables (`backend/.env`)

Required (API keys):
- `ABUSEIPDB_API_KEY`
- `OTX_API_KEY`
- `VIRUSTOTAL_API_KEY`

Timeouts and cache:
- `HTTP_TIMEOUT=10`
- `HTTP_CONNECT_TIMEOUT=4`
- `HTTP_READ_TIMEOUT=10`
- `SOURCE_TIMEOUT=10`
- `CACHE_TTL_SECONDS=300`
- `CACHE_MAX_ITEMS=2048`

Collector / DB:
- `DATABASE_URL=postgresql://postgres:postgres@localhost:5432/live_threat_dashboard`
- `COLLECTOR_ENABLED=true`
- `COLLECTOR_INTERVAL_SECONDS=10`
- `COLLECTOR_BATCH_SIZE=10`
- `ENRICH_TTL_SECONDS=600`

## Database Initialization

Run `db/init.sql` in PostgreSQL (psql, DBeaver, pgAdmin, etc).

Tables created/updated:
- `ioc`
- `enrichment`
- `ioc_summary`
- plus indexes and `ioc.last_enriched_at`

## Add IOC to Enrich

```sql
INSERT INTO ioc(type, value)
VALUES
  ('ip', '8.8.8.8'),
  ('domain', 'google.com'),
  ('url', 'http://example.com');
```

## Run API

```powershell
cd backend
python -m uvicorn app.main:app --reload
```

Quick checks:

```powershell
curl.exe -s "http://127.0.0.1:8000/health"
curl.exe -s "http://127.0.0.1:8000/lookup/8.8.8.8"
curl.exe -s "http://127.0.0.1:8000/lookup/8.8.8.8?debug=true"
```

## Run Live Collector

```powershell
cd backend
python -m app.collector
```

Collector behavior:
- loops every `COLLECTOR_INTERVAL_SECONDS`
- processes up to `COLLECTOR_BATCH_SIZE` IOC per cycle
- re-enriches only IOC with:
  - `last_enriched_at IS NULL`, or
  - `last_enriched_at < NOW() - ENRICH_TTL_SECONDS`

## Verify DB is Filling

Latest summary rows:

```sql
SELECT s.updated_at, i.type, i.value, s.risk_score, s.risk_level, s.categories
FROM ioc_summary s
JOIN ioc i ON i.id = s.ioc_id
ORDER BY s.updated_at DESC
LIMIT 100;
```

Latest source details:

```sql
SELECT e.fetched_at, i.value, e.source, e.score, e.raw_json
FROM enrichment e
JOIN ioc i ON i.id = e.ioc_id
ORDER BY e.fetched_at DESC
LIMIT 100;
```

Due IOC check:

```sql
SELECT id, type, value, last_enriched_at
FROM ioc
ORDER BY COALESCE(last_enriched_at, to_timestamp(0)), id;
```

## Grafana SQL Examples

Panel 1: latest IOC scores

```sql
SELECT
  s.updated_at AS "time",
  i.type,
  i.value,
  s.risk_score,
  s.risk_level
FROM ioc_summary s
JOIN ioc i ON i.id = s.ioc_id
ORDER BY s.updated_at DESC
LIMIT 100;
```

Panel 2: source error rate over time

```sql
SELECT
  e.fetched_at AS "time",
  e.source,
  COUNT(*) FILTER (WHERE (e.raw_json->>'status') = 'error') AS error_count,
  COUNT(*) AS total_count
FROM enrichment e
GROUP BY e.fetched_at, e.source
ORDER BY e.fetched_at DESC;
```

Panel 3: avg source score by source

```sql
SELECT
  date_trunc('minute', e.fetched_at) AS "time",
  e.source,
  AVG(e.score) AS avg_score
FROM enrichment e
WHERE e.score IS NOT NULL
GROUP BY 1, 2
ORDER BY 1 DESC;
```

Recommended Grafana refresh:
- dashboard refresh: `5s` or `10s`
- keep `ENRICH_TTL_SECONDS` high enough (example `600`) to avoid unnecessary API pressure

## Manual Test Plan

1. Start PostgreSQL.
2. Apply `db/init.sql`.
3. Insert IOC rows into `ioc`.
4. Start API (`uvicorn`) and check `/health`.
5. Start collector (`python -m app.collector`).
6. Confirm `ioc_summary` and `enrichment` are updated.
7. Temporarily clear one API key in `.env` (example `VIRUSTOTAL_API_KEY=`), restart collector, and confirm:
   - collector continues running,
   - rows are still written,
   - failing source has `status=error` in `enrichment.raw_json`.

## Tests

Run unit/smoke tests:

```powershell
cd backend
python -m unittest discover -s tests -p "test_*.py" -v
```

Or with pytest:

```powershell
cd backend
python -m pytest -q
```
