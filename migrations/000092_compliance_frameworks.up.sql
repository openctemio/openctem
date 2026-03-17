-- =============================================
-- Phase 2: Compliance Framework Mapping
-- 4 tables: frameworks, controls, assessments, finding_mappings
-- =============================================

-- Compliance Frameworks (system-managed + tenant-custom)
CREATE TABLE compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(50) NOT NULL,
    version VARCHAR(50),
    description TEXT,
    category VARCHAR(50),
    total_controls INTEGER DEFAULT 0,
    is_system BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_compliance_frameworks_slug ON compliance_frameworks(slug) WHERE tenant_id IS NULL;
CREATE INDEX idx_compliance_frameworks_tenant ON compliance_frameworks(tenant_id) WHERE tenant_id IS NOT NULL;

-- Compliance Controls (individual requirements)
CREATE TABLE compliance_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    parent_control_id UUID REFERENCES compliance_controls(id),
    sort_order INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_controls_framework ON compliance_controls(framework_id);
CREATE UNIQUE INDEX idx_compliance_controls_unique ON compliance_controls(framework_id, control_id);

-- Control Assessments (tenant-scoped, point-in-time)
CREATE TABLE compliance_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id),
    control_id UUID NOT NULL REFERENCES compliance_controls(id),
    status VARCHAR(30) NOT NULL DEFAULT 'not_assessed',
    priority VARCHAR(20),
    owner VARCHAR(255),
    notes TEXT,
    evidence_type VARCHAR(30),
    evidence_ids UUID[] DEFAULT '{}',
    evidence_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    assessed_by UUID REFERENCES users(id),
    assessed_at TIMESTAMPTZ,
    due_date DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_assessments_tenant ON compliance_assessments(tenant_id);
CREATE INDEX idx_compliance_assessments_framework ON compliance_assessments(tenant_id, framework_id);
CREATE UNIQUE INDEX idx_compliance_assessments_unique ON compliance_assessments(tenant_id, control_id);

-- Finding-to-Control Mapping
CREATE TABLE compliance_finding_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    control_id UUID NOT NULL REFERENCES compliance_controls(id),
    impact VARCHAR(20) DEFAULT 'direct',
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_compliance_finding_mappings_tenant ON compliance_finding_mappings(tenant_id);
CREATE INDEX idx_compliance_finding_mappings_finding ON compliance_finding_mappings(finding_id);
CREATE INDEX idx_compliance_finding_mappings_control ON compliance_finding_mappings(control_id);
CREATE UNIQUE INDEX idx_compliance_finding_mappings_unique ON compliance_finding_mappings(tenant_id, finding_id, control_id);
