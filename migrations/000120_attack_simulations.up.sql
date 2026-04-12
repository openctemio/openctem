-- Attack Simulation / BAS (Breach and Attack Simulation) tables
-- Supports MITRE ATT&CK mapped simulation campaigns and control effectiveness testing.

CREATE TABLE IF NOT EXISTS attack_simulations (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',
    -- simulation_type: atomic (single technique), campaign (multi-step), control_test
    simulation_type VARCHAR(30) NOT NULL DEFAULT 'atomic',
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    -- MITRE ATT&CK mapping
    mitre_tactic VARCHAR(100),
    mitre_technique_id VARCHAR(20),
    mitre_technique_name VARCHAR(255),
    -- Configuration
    target_assets JSONB DEFAULT '[]',
    config JSONB DEFAULT '{}',
    -- Scheduling
    schedule_cron VARCHAR(100),
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    -- Results summary (cached from latest run)
    total_runs INT DEFAULT 0,
    last_result VARCHAR(20),
    detection_rate NUMERIC(5,2) DEFAULT 0,
    prevention_rate NUMERIC(5,2) DEFAULT 0,
    -- Metadata
    tags TEXT[] DEFAULT '{}',
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_attack_simulations_tenant ON attack_simulations(tenant_id);
CREATE INDEX idx_attack_simulations_type ON attack_simulations(tenant_id, simulation_type);
CREATE INDEX idx_attack_simulations_status ON attack_simulations(tenant_id, status);
CREATE INDEX idx_attack_simulations_mitre ON attack_simulations(tenant_id, mitre_technique_id);

CREATE TABLE IF NOT EXISTS attack_simulation_runs (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    simulation_id UUID NOT NULL REFERENCES attack_simulations(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    -- Results per technique step
    result VARCHAR(20),
    -- detected, prevented, bypassed, error
    detection_result VARCHAR(20),
    prevention_result VARCHAR(20),
    -- Detailed results
    steps JSONB DEFAULT '[]',
    output JSONB DEFAULT '{}',
    error_message TEXT,
    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INT,
    -- Who triggered
    triggered_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_simulation_runs_tenant ON attack_simulation_runs(tenant_id);
CREATE INDEX idx_simulation_runs_sim ON attack_simulation_runs(simulation_id);
CREATE INDEX idx_simulation_runs_status ON attack_simulation_runs(tenant_id, status);

-- Control effectiveness tracking (maps security controls to simulation results)
CREATE TABLE IF NOT EXISTS control_tests (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',
    -- Framework mapping (CIS, NIST, ISO 27001, PCI-DSS, etc.)
    framework VARCHAR(50) NOT NULL,
    control_id VARCHAR(50) NOT NULL,
    control_name VARCHAR(255),
    category VARCHAR(100),
    -- Testing config
    test_procedure TEXT,
    expected_result TEXT,
    -- Latest result
    status VARCHAR(20) NOT NULL DEFAULT 'untested',
    -- pass, fail, partial, not_applicable, untested
    last_tested_at TIMESTAMPTZ,
    last_tested_by UUID,
    evidence TEXT,
    notes TEXT,
    -- Risk mapping
    risk_level VARCHAR(20) DEFAULT 'medium',
    -- Link to simulations that validate this control
    linked_simulation_ids UUID[] DEFAULT '{}',
    -- Metadata
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_control_tests_tenant ON control_tests(tenant_id);
CREATE INDEX idx_control_tests_framework ON control_tests(tenant_id, framework);
CREATE INDEX idx_control_tests_status ON control_tests(tenant_id, status);
