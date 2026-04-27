-- Sentinel Cloud: Initial Supabase Schema (v1.0)
-- Architecture: Optimized for Time-Series Analytics & Tenant Isolation

-------------------------------------------------------------------------------
-- 1. EXTENSIONS & ENUMS
-------------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE risk_level_enum AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-------------------------------------------------------------------------------
-- 2. CORE TABLES
-------------------------------------------------------------------------------

CREATE TABLE intelligence_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL, -- References auth.users in Supabase
    repo_hash VARCHAR(255) NOT NULL,
    event_hash VARCHAR(255) UNIQUE NOT NULL,
    category VARCHAR(100) NOT NULL,
    pattern VARCHAR(100) NOT NULL,
    risk_score FLOAT NOT NULL,
    risk_level risk_level_enum GENERATED ALWAYS AS (
        CASE 
            WHEN risk_score >= 0.80 THEN 'CRITICAL'::risk_level_enum
            WHEN risk_score >= 0.60 THEN 'HIGH'::risk_level_enum
            WHEN risk_score >= 0.30 THEN 'MEDIUM'::risk_level_enum
            ELSE 'LOW'::risk_level_enum
        END
    ) STORED,
    confidence FLOAT DEFAULT 0.0,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE event_metrics (
    event_id UUID PRIMARY KEY,
    scan_time_ms INTEGER NOT NULL,
    files_scanned INTEGER NOT NULL,
    CONSTRAINT fk_event
        FOREIGN KEY(event_id) 
        REFERENCES intelligence_events(id)
        ON DELETE CASCADE
);

CREATE TABLE event_features (
    event_id UUID PRIMARY KEY,
    entropy FLOAT,
    uses_eval BOOLEAN DEFAULT FALSE,
    dynamic_require BOOLEAN DEFAULT FALSE,
    CONSTRAINT fk_event_features
        FOREIGN KEY(event_id) 
        REFERENCES intelligence_events(id)
        ON DELETE CASCADE
);

-------------------------------------------------------------------------------
-- 3. INDEXING (Query Performance Optimization)
-------------------------------------------------------------------------------
-- Index for Time-series dashboard queries (Top Threats / Recent Activity)
CREATE INDEX idx_events_user_time ON intelligence_events(user_id, timestamp DESC);

-- Index for Repo-specific filtering
CREATE INDEX idx_events_repo ON intelligence_events(repo_hash);

-- Index for Threat categorization analytics
CREATE INDEX idx_events_category ON intelligence_events(category);

-------------------------------------------------------------------------------
-- 4. MATERIALIZED VIEWS (Analytics Acceleration)
-------------------------------------------------------------------------------
-- Pre-aggregates daily threat counts. This prevents heavy scans on large datasets.
CREATE MATERIALIZED VIEW daily_threats AS
SELECT 
  date_trunc('day', timestamp) AS day,
  user_id,
  category,
  COUNT(*) AS total_threats,
  AVG(risk_score) AS avg_risk
FROM intelligence_events
GROUP BY day, user_id, category;

-- Note: In production, trigger a REFRESH MATERIALIZED VIEW via pg_cron or edge functions.
CREATE UNIQUE INDEX idx_mv_daily_threats ON daily_threats(day, user_id, category);

-------------------------------------------------------------------------------
-- 5. ROW LEVEL SECURITY (RLS) - Data Isolation
-------------------------------------------------------------------------------
ALTER TABLE intelligence_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_features ENABLE ROW LEVEL SECURITY;

-- Users can only read their own events
CREATE POLICY "Users see their own events"
ON intelligence_events
FOR SELECT
USING (auth.uid() = user_id);

-- Enforce foreign key visibility constraints
CREATE POLICY "Users see their own metrics"
ON event_metrics
FOR SELECT
USING (EXISTS (
    SELECT 1 FROM intelligence_events e 
    WHERE e.id = event_metrics.event_id 
    AND e.user_id = auth.uid()
));

CREATE POLICY "Users see their own features"
ON event_features
FOR SELECT
USING (EXISTS (
    SELECT 1 FROM intelligence_events e 
    WHERE e.id = event_features.event_id 
    AND e.user_id = auth.uid()
));

-- (Insert Policies are handled securely via the Node.js API Service Role, 
--  so direct client inserts can be disabled/restricted).
