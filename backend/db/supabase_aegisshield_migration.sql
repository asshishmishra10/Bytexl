-- ============================================================
-- AegisShield – Digital Risk Protection: Supabase Schema Migration
-- ============================================================
-- Run this in Supabase SQL Editor to support centralized AegisShield
-- brand monitoring data (brands, assets, detections, cases, audit logs).
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA extensions;
SET search_path TO public, extensions;

-- ---------- Helper: auto-update updated_at ----------
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 1. BRANDS (Brand Digital Twin Ground Truth)
CREATE TABLE IF NOT EXISTS brands (
    id                       SERIAL PRIMARY KEY,
    name                     VARCHAR(200) NOT NULL UNIQUE,
    official_domains         JSONB DEFAULT '[]'::JSONB,
    handles                  JSONB DEFAULT '[]'::JSONB,
    app_ids                  JSONB DEFAULT '[]'::JSONB,
    developers               JSONB DEFAULT '[]'::JSONB,
    logo_hash                VARCHAR(128),
    official_app_description TEXT,
    embeddings_ref           VARCHAR(500),
    exec_names               JSONB DEFAULT '[]'::JSONB,
    allowlist                JSONB DEFAULT '[]'::JSONB,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. ASSETS (Target Candidates: Profiles, Apps, Domains)
CREATE TABLE IF NOT EXISTS assets (
    id          SERIAL PRIMARY KEY,
    brand_id    INTEGER NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    type        VARCHAR(50) NOT NULL,
    value       TEXT NOT NULL,
    source      VARCHAR(100),
    provenance  VARCHAR(50) NOT NULL DEFAULT 'live',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_assets_brand_id ON assets(brand_id);
CREATE INDEX IF NOT EXISTS ix_assets_type ON assets(type);

-- 3. DETECTIONS (Fused Verdicts, Scores, SHAP & Reason Codes)
CREATE TABLE IF NOT EXISTS detections (
    id                    SERIAL PRIMARY KEY,
    asset_id              INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    component_scores_json JSONB DEFAULT '{}'::JSONB,
    model_score           DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    rule_score            DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    final_score           DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    tier                  INTEGER NOT NULL DEFAULT 0,
    reason_codes_json     JSONB DEFAULT '[]'::JSONB,
    shap_json             JSONB DEFAULT '{}'::JSONB,
    model_version         VARCHAR(50) DEFAULT 'v1.0.0',
    rule_version          VARCHAR(50) DEFAULT 'v1.0.0',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_detections_asset_id ON detections(asset_id);
CREATE INDEX IF NOT EXISTS ix_detections_tier ON detections(tier);
CREATE INDEX IF NOT EXISTS ix_detections_final_score ON detections(final_score);

-- 4. CASES (Investigation Case Management)
CREATE TABLE IF NOT EXISTS cases (
    id           SERIAL PRIMARY KEY,
    detection_id INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    status       VARCHAR(50) NOT NULL DEFAULT 'open',
    priority     VARCHAR(20) NOT NULL DEFAULT 'medium',
    assignee_id  VARCHAR(36) NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at    TIMESTAMPTZ NULL,

    CONSTRAINT cases_status_check
        CHECK (LOWER(status) IN ('open', 'reviewing', 'escalated', 'closed')),
    CONSTRAINT cases_priority_check
        CHECK (LOWER(priority) IN ('low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS ix_cases_detection_id ON cases(detection_id);
CREATE INDEX IF NOT EXISTS ix_cases_status ON cases(status);

-- 5. CASE NOTES (Analyst Investigation Findings)
CREATE TABLE IF NOT EXISTS case_notes (
    id         SERIAL PRIMARY KEY,
    case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id    VARCHAR(36) NULL REFERENCES users(id) ON DELETE SET NULL,
    text       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_case_notes_case_id ON case_notes(case_id);

-- 6. AUDIT EVENTS (Immutable Chain of Custody)
CREATE TABLE IF NOT EXISTS audit_events (
    id             SERIAL PRIMARY KEY,
    actor          VARCHAR(120) NOT NULL,
    role           VARCHAR(64) NOT NULL,
    action         VARCHAR(100) NOT NULL,
    case_id        INTEGER NULL REFERENCES cases(id) ON DELETE CASCADE,
    previous_state VARCHAR(50),
    new_state      VARCHAR(50),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_audit_events_case_id ON audit_events(case_id);

-- GRANTS FOR CLIENT SDK ACCESS
GRANT ALL ON ALL TABLES IN SCHEMA public TO postgres, service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated, anon;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated, anon;
