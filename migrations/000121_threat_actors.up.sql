-- Threat Actor profiles for CTEM prioritization enrichment.
-- Links threat actors to CVEs, techniques, and industries for contextual risk scoring.

CREATE TABLE IF NOT EXISTS threat_actors (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    aliases TEXT[] DEFAULT '{}',
    description TEXT DEFAULT '',
    -- Classification
    actor_type VARCHAR(30) NOT NULL DEFAULT 'unknown',
    -- apt, cybercrime, hacktivist, insider, nation_state, unknown
    sophistication VARCHAR(20) DEFAULT 'unknown',
    -- low, medium, high, advanced, unknown
    motivation VARCHAR(50),
    -- financial, espionage, disruption, ideology, unknown
    -- Attribution
    country_of_origin VARCHAR(3),
    -- ISO 3166-1 alpha-3
    first_seen DATE,
    last_seen DATE,
    is_active BOOLEAN DEFAULT TRUE,
    -- MITRE ATT&CK mapping
    mitre_group_id VARCHAR(20),
    -- e.g., G0016 (APT29)
    ttps JSONB DEFAULT '[]',
    -- array of {tactic, technique_id, technique_name}
    -- Targeting
    target_industries TEXT[] DEFAULT '{}',
    target_regions TEXT[] DEFAULT '{}',
    -- External references
    external_references JSONB DEFAULT '[]',
    -- array of {source, url, description}
    -- Metadata
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_threat_actors_tenant ON threat_actors(tenant_id);
CREATE INDEX idx_threat_actors_type ON threat_actors(tenant_id, actor_type);
CREATE INDEX idx_threat_actors_active ON threat_actors(tenant_id, is_active);
CREATE INDEX idx_threat_actors_mitre ON threat_actors(mitre_group_id);

-- Link threat actors to CVEs (many-to-many)
CREATE TABLE IF NOT EXISTS threat_actor_cves (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    threat_actor_id UUID NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
    cve_id VARCHAR(30) NOT NULL,
    confidence VARCHAR(20) DEFAULT 'medium',
    -- low, medium, high, confirmed
    source VARCHAR(100),
    first_observed DATE,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, threat_actor_id, cve_id)
);

CREATE INDEX idx_threat_actor_cves_tenant ON threat_actor_cves(tenant_id);
CREATE INDEX idx_threat_actor_cves_actor ON threat_actor_cves(threat_actor_id);
CREATE INDEX idx_threat_actor_cves_cve ON threat_actor_cves(cve_id);

-- Report schedules for recurring report generation
CREATE TABLE IF NOT EXISTS report_schedules (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    -- Report config
    report_type VARCHAR(30) NOT NULL,
    -- executive_summary, technical, compliance, risk_posture, remediation_progress
    format VARCHAR(10) NOT NULL DEFAULT 'html',
    options JSONB DEFAULT '{}',
    -- Delivery config
    recipients JSONB DEFAULT '[]',
    -- array of {email, name}
    delivery_channel VARCHAR(20) DEFAULT 'email',
    -- email, webhook, slack
    integration_id UUID,
    -- Schedule
    cron_expression VARCHAR(100) NOT NULL,
    timezone VARCHAR(50) DEFAULT 'UTC',
    is_active BOOLEAN DEFAULT TRUE,
    -- Tracking
    last_run_at TIMESTAMPTZ,
    last_status VARCHAR(20),
    next_run_at TIMESTAMPTZ,
    run_count INT DEFAULT 0,
    -- Metadata
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_report_schedules_tenant ON report_schedules(tenant_id);
CREATE INDEX idx_report_schedules_active ON report_schedules(tenant_id, is_active);
