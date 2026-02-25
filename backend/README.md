# LIVE-THREAT-DASHBOARD Backend

FastAPI backend + PostgreSQL collector for IOC enrichment (AbuseIPDB, OTX, VirusTotal) with Grafana-ready tables.

## Problem Solved

Threat analysts should not have to query multiple intelligence platforms manually for each IOC.
This backend centralizes enrichment, scoring, and historical storage in one pipeline.

## How The Backend Works

1. `/lookup/{ioc}` detects IOC type and runs source enrichments.
2. Responses are normalized into a stable schema (`ok/error`, data, error, duration).
3. Global risk (`risk_score`, `risk_level`, `categories`) is computed from successful sources.
4. Collector process continuously refreshes due IOCs and persists results to PostgreSQL.
5. Grafana reads summary/history tables for real-time visualization.

## Business Value

- Reduced triage time for SOC/CSIRT teams.
- Standardized IOC risk evaluation across analysts.
- Live visibility for operations/security managers.
- Historical evidence for incident reviews and reporting.

## 1) Prerequisites

- Docker Desktop (Windows)
- PowerShell

No local `psql` installation is required on Windows.

## 2) Environment setup (no secrets committed)

At repository root:

1. Copy `.env.example` to `.env`
2. Fill API keys in `.env`

Example `.env`:

```env
DATABASE_URL=postgresql://threat:threat@threat_db:5432/threatdb
COLLECTOR_ENABLED=true
COLLECTOR_INTERVAL_SECONDS=10
COLLECTOR_BATCH_SIZE=10
ENRICH_TTL_SECONDS=600

HTTP_TIMEOUT=10
HTTP_CONNECT_TIMEOUT=4
HTTP_READ_TIMEOUT=10
SOURCE_TIMEOUT=10

ABUSEIPDB_API_KEY=
OTX_API_KEY=
VIRUSTOTAL_API_KEY=
```

`docker-compose.yml` injects these variables into `threat_api`, with Docker-safe defaults.

## 3) Run stack (API + DB + Grafana)

From repository root:

```powershell
docker compose up -d --build
docker ps
```

Expected containers:
- `threat_api` (port 8000)
- `threat_db` (port 5432)
- `threat_grafana` (port 3000)

Grafana provisioning is automatic at startup:
- datasource: `ThreatDB`
- dashboard folder: `Live Threat`
- dashboard: `Live Threat Overview`

## 4) Apply DB schema (`db/init.sql`) from PowerShell

Use pipe (not `<`):

```powershell
Get-Content .\db\init.sql | docker exec -i threat_db psql -U threat -d threatdb
```

## 5) Insert IOC rows for live enrichment

```powershell
@'
INSERT INTO ioc(type, value)
VALUES
  ('ip','8.8.8.8'),
  ('domain','google.com'),
  ('url','http://example.com');
'@ | docker exec -i threat_db psql -U threat -d threatdb
```

## 6) Run API checks

```powershell
curl.exe -s "http://127.0.0.1:8000/health"
curl.exe -s "http://127.0.0.1:8000/lookup/8.8.8.8"
curl.exe -s "http://127.0.0.1:8000/lookup/8.8.8.8?debug=true"
```

## 7) Run collector in backend container

```powershell
docker exec -it threat_api python -m app.collector
```

Expected logs:
- `collector boot database_target=threat_db:5432/threatdb ...`
- if disabled: `collector disabled (COLLECTOR_ENABLED=false). Exiting.`

## 8) Verify DB is filling

### Latest summaries (`ioc_summary`)

```powershell
@'
SELECT s.updated_at, i.type, i.value, s.risk_score, s.risk_level, s.categories
FROM ioc_summary s
JOIN ioc i ON i.id = s.ioc_id
ORDER BY s.updated_at DESC
LIMIT 100;
'@ | docker exec -i threat_db psql -U threat -d threatdb
```

### Latest source enrichments (`enrichment`)

```powershell
@'
SELECT e.fetched_at, i.value, e.source, e.score, e.raw_json
FROM enrichment e
JOIN ioc i ON i.id = e.ioc_id
ORDER BY e.fetched_at DESC
LIMIT 100;
'@ | docker exec -i threat_db psql -U threat -d threatdb
```

## 9) Grafana SQL examples

### Panel: latest IOC scores

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

### Panel: source score trend

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

### Panel: source error volume

```sql
SELECT
  date_trunc('minute', e.fetched_at) AS "time",
  e.source,
  COUNT(*) FILTER (WHERE e.raw_json->>'status' = 'error') AS error_count
FROM enrichment e
GROUP BY 1, 2
ORDER BY 1 DESC;
```

Recommended Grafana refresh: `5s` to `10s`.

## 10) Tests

From repository root:

```powershell
cd .\backend
python -m unittest discover -s tests -p "test_*.py" -v
python -m pytest -q
```

## Notes

- Collector selects only IOC due for refresh:
  - `last_enriched_at IS NULL` or older than `ENRICH_TTL_SECONDS`
- Collector stores:
  - per-source payloads in `enrichment.raw_json`
  - global score/level/categories in `ioc_summary`
- `ioc.last_enriched_at` is updated after each processed IOC run.
