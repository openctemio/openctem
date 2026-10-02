-- Migration 000189: Continuous Threat Modeling — data foundation
-- (RFC: docs/rfcs/RFC-continuous-threat-modeling.md — "Data model")
--
-- Two RUNTIME tables (tenant-scoped, fully regenerated each CTEM cycle) and two
-- CATALOG tables (global seed, tenant-agnostic, versioned). The runtime tables
-- carry tenant_id; the catalog tables are global read-only seed data (see
-- migration 000190 for the seed rows).

-- ---------------------------------------------------------------------------
-- Runtime: one row per generated threat model, keyed to a scope.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_models (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope_type        VARCHAR(20) NOT NULL   -- crown_jewel|business_unit|asset_group|tenant
        CHECK (scope_type IN ('crown_jewel','business_unit','asset_group','tenant')),
    scope_ref_id      UUID,                  -- asset/BU/group id (NULL for tenant-wide)
    name              VARCHAR(255) NOT NULL,
    generated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    input_hash        TEXT,                  -- hash(graph+findings+profiles) → skip no-op regen
    technique_dataset_version VARCHAR(20),   -- ATT&CK version threats were computed against
    -- cached rollups
    threats_total     INT DEFAULT 0,
    threats_open      INT DEFAULT 0,
    threats_mitigated INT DEFAULT 0,
    threats_covered   INT DEFAULT 0,
    coverage_pct      NUMERIC(5,2) DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One model per (tenant, scope). A tenant-wide model uses scope_ref_id=NULL;
    -- Postgres treats NULLs as distinct in a UNIQUE index, but there is only ever
    -- one scope_type='tenant' row per tenant so this remains effectively unique.
    UNIQUE (tenant_id, scope_type, scope_ref_id)
);

CREATE INDEX IF NOT EXISTS idx_threat_models_tenant
    ON threat_models(tenant_id);

-- ---------------------------------------------------------------------------
-- Runtime: one row per (attacker × chain-hop × technique) enumerated threat.
-- Fully regenerated per model (delete-and-insert inside a tx) — no drift, no
-- stale-row reconciliation. Status is derived at generation time and cached.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_model_threats (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    threat_model_id     UUID NOT NULL REFERENCES threat_models(id) ON DELETE CASCADE,
    attacker_profile_id UUID REFERENCES attacker_profiles(id) ON DELETE SET NULL,
    entry_point_asset_id UUID,              -- chain entry point
    target_asset_id     UUID,               -- chain target (crown jewel / critical)
    hop_asset_id        UUID,               -- asset the technique applies at
    hop_index           INT,                -- position on the chain
    chain_fingerprint   TEXT,               -- stable id for the exposure chain
    technique_id        VARCHAR(20),        -- ATT&CK Txxxx
    tactic              VARCHAR(50),
    mitigation_id       VARCHAR(20),        -- ATT&CK Mxxxx
    status              VARCHAR(20) NOT NULL DEFAULT 'theoretical'
        CHECK (status IN ('open','mitigated','covered','accepted','theoretical')),
    status_reason       TEXT,               -- human-readable derivation
    evidence_finding_id UUID,               -- the finding that set the status (nullable)
    score               NUMERIC(6,2) DEFAULT 0,  -- inherits chain.Score × technique weight
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tmt_model  ON threat_model_threats(threat_model_id);
CREATE INDEX IF NOT EXISTS idx_tmt_status ON threat_model_threats(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_tmt_tech   ON threat_model_threats(tenant_id, technique_id);

-- ---------------------------------------------------------------------------
-- Catalog: ATT&CK technique → mitigation, seeded from MITRE ATT&CK. Global,
-- versioned, tenant-agnostic. See migration 000190 for the seed rows.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_technique_mitigations (
    technique_id       VARCHAR(20) NOT NULL,   -- Txxxx / Txxxx.yyy
    technique_name     VARCHAR(255) NOT NULL,
    tactic             VARCHAR(50)  NOT NULL,
    mitigation_id      VARCHAR(20)  NOT NULL,   -- Mxxxx
    mitigation_name    VARCHAR(255) NOT NULL,
    mitigation_summary TEXT,
    dataset_version    VARCHAR(20)  NOT NULL,   -- e.g. "attack-16.1"
    PRIMARY KEY (technique_id, mitigation_id, dataset_version)
);

-- ---------------------------------------------------------------------------
-- Catalog: which techniques apply to which asset-type / edge / capability.
-- Hand-curated to OpenCTEM's asset-type + attack-path relationship taxonomies.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS technique_applicability (
    technique_id      VARCHAR(20) NOT NULL,
    asset_type        VARCHAR(50) NOT NULL,   -- matches assets.asset_type taxonomy
    edge_type         VARCHAR(40),            -- optional relationship_type context (NULL = any)
    min_network       VARCHAR(20),            -- external|internal (attacker capability gate)
    min_credential    VARCHAR(20),            -- none|user|admin
    requires_persistence BOOLEAN DEFAULT FALSE,
    dataset_version   VARCHAR(20) NOT NULL,
    PRIMARY KEY (technique_id, asset_type, dataset_version)
);
