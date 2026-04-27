-- SENTINEL ELITE SCHEMA v1.0
-- Automated Deployment Script

-- 1. Repository Orquestration Table
CREATE TABLE IF NOT EXISTS repositories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  github_id BIGINT UNIQUE NOT NULL,
  github_full_name TEXT NOT NULL,
  owner_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Security: Row Level Security
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;

-- 3. Policies: Owner Isolation
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE policyname = 'Users can manage their own repositories'
    ) THEN
        CREATE POLICY "Users can manage their own repositories" 
        ON repositories 
        FOR ALL 
        TO authenticated 
        USING (auth.uid() = owner_id);
    END IF;
END $$;

-- 4. Forensic Scan Logs
CREATE TABLE IF NOT EXISTS scan_logs (
  id BIGSERIAL PRIMARY KEY,
  repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  risk_level INT NOT NULL,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE scan_logs ENABLE ROW LEVEL SECURITY;

DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE policyname = 'Users can view logs of their own repositories'
    ) THEN
        CREATE POLICY "Users can view logs of their own repositories" 
        ON scan_logs 
        FOR SELECT 
        TO authenticated 
        USING (
          EXISTS (
            SELECT 1 FROM repositories 
            WHERE repositories.id = scan_logs.repository_id 
            AND repositories.owner_id = auth.uid()
          )
        );
    END IF;
END $$;
