CREATE TABLE IF NOT EXISTS ioc (
  id SERIAL PRIMARY KEY,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE ioc
ADD COLUMN IF NOT EXISTS last_enriched_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS enrichment (
  id SERIAL PRIMARY KEY,
  ioc_id INT REFERENCES ioc(id),
  source TEXT NOT NULL,
  score INT,
  raw_json JSONB,
  fetched_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ioc_summary (
  ioc_id INT PRIMARY KEY REFERENCES ioc(id) ON DELETE CASCADE,
  risk_score INT NOT NULL,
  risk_level TEXT NOT NULL,
  categories JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_last_enriched_at
ON ioc (last_enriched_at);

CREATE INDEX IF NOT EXISTS idx_enrichment_ioc_source_fetched
ON enrichment (ioc_id, source, fetched_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_summary_updated_at
ON ioc_summary (updated_at DESC);
