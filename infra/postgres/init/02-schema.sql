-- 02-schema.sql: Cyber Range metadata and configuration schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Users (mirrors Keycloak user identity)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('red', 'blue', 'soc', 'admin')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Builds (CI/CD commits tested)
CREATE TABLE IF NOT EXISTS builds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    commit_hash TEXT NOT NULL,
    image_tag TEXT NOT NULL,
    readiness_score NUMERIC,
    gate_result TEXT CHECK (gate_result IN ('pass', 'fail', 'pending')) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Labs (Reusable Dockerfile & Compose environments)
CREATE TABLE IF NOT EXISTS labs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    dockerfile_content TEXT,
    compose_content TEXT,
    image_tag TEXT,
    uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('uploaded', 'scanning', 'built', 'failed', 'archived')) DEFAULT 'uploaded',
    safety_scan_result JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Sessions (Sandbox lifecycles)
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    lab_id UUID REFERENCES labs(id) ON DELETE SET NULL,
    build_id UUID REFERENCES builds(id) ON DELETE SET NULL,
    target_image TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('creating', 'active', 'destroyed')) DEFAULT 'creating',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    destroyed_at TIMESTAMP WITH TIME ZONE,
    archive_path TEXT
);

-- Attack Scenarios
CREATE TABLE IF NOT EXISTS scenarios (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    definition_yaml TEXT NOT NULL,
    mitre_techniques TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Sigma Rules
CREATE TABLE IF NOT EXISTS sigma_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mitre_technique TEXT NOT NULL,
    sigma_yaml TEXT NOT NULL,
    compiled_query TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Readiness Scores
CREATE TABLE IF NOT EXISTS readiness_scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    build_id UUID REFERENCES builds(id) ON DELETE CASCADE,
    coverage_pct NUMERIC NOT NULL,
    avg_detection_latency_sec NUMERIC NOT NULL,
    unresolved_incidents INTEGER NOT NULL DEFAULT 0,
    score NUMERIC NOT NULL,
    computed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- MITRE ATT&CK reference catalogue
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id TEXT PRIMARY KEY,
    tactic_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    sub_technique_of TEXT
);

-- Seed Default Tenant and Users
INSERT INTO tenants (id, name) VALUES ('00000000-0000-0000-0000-000000000123', 'Default Enterprise (org-123)') ON CONFLICT (id) DO NOTHING;
INSERT INTO tenants (id, name) VALUES ('00000000-0000-0000-0000-000000000999', 'Secondary Enterprise (org-999)') ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, tenant_id, username, role) VALUES 
('11111111-1111-1111-1111-111111111111', '00000000-0000-0000-0000-000000000123', 'red1', 'red'),
('22222222-2222-2222-2222-222222222222', '00000000-0000-0000-0000-000000000123', 'blue1', 'blue'),
('33333333-3333-3333-3333-333333333333', '00000000-0000-0000-0000-000000000123', 'soc1', 'soc'),
('44444444-4444-4444-4444-444444444444', '00000000-0000-0000-0000-000000000123', 'admin1', 'admin'),
('55555555-5555-5555-5555-555555555555', '00000000-0000-0000-0000-000000000999', 'other_tenant_user', 'blue')
ON CONFLICT (id) DO NOTHING;
