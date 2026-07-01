-- Sentinel Cloud: Migration (v2.0) - Baseline & Audit Architecture

-------------------------------------------------------------------------------
-- 1. EXTEND REPOSITORIES (Baseline Debt)
-------------------------------------------------------------------------------
ALTER TABLE intelligence_events 
ADD COLUMN IF NOT EXISTS origin TEXT DEFAULT 'pr',
ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL,
ADD COLUMN IF NOT EXISTS is_baseline BOOLEAN DEFAULT FALSE;

-------------------------------------------------------------------------------
-- 2. CREATE AUDIT LOGS (Security Compliance)
-------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action TEXT NOT NULL, -- e.g. 'DELETE_LOG', 'PIN_LOG', 'UPDATE_NOTE'
    actor_id UUID, -- NULL if system
    target_id UUID NOT NULL, -- id of the scan/event
    metadata JSONB DEFAULT '{}',
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Index for security audits
CREATE INDEX idx_audit_target ON audit_logs(target_id);
CREATE INDEX idx_audit_time ON audit_logs(timestamp DESC);

-------------------------------------------------------------------------------
-- 3. ENABLE RLS FOR AUDIT LOGS
-------------------------------------------------------------------------------
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Note: Policies would be applied based on your auth setup.
