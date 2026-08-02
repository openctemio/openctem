-- Business unit criticality, risk tolerance, and parent hierarchy.
-- Previously these were UI-only phantom fields with no backing columns
-- (risk aggregation fell back to a hardcoded 'medium'). This adds real
-- persistence. Enum values mirror business_services.criticality
-- (migration 000152) so the scale stays consistent platform-wide.
ALTER TABLE business_units
    ADD COLUMN IF NOT EXISTS criticality VARCHAR(20) NOT NULL DEFAULT 'medium'
      CHECK (criticality IN ('critical','high','medium','low')),
    ADD COLUMN IF NOT EXISTS risk_tolerance VARCHAR(20) NOT NULL DEFAULT 'medium'
      CHECK (risk_tolerance IN ('low','medium','high')),
    -- Self-referential hierarchy. ON DELETE SET NULL so removing a parent
    -- re-parents children to the root instead of cascade-deleting them.
    ADD COLUMN IF NOT EXISTS parent_id UUID REFERENCES business_units(id) ON DELETE SET NULL;

-- Defense-in-depth: a BU can never be its own parent (service layer also
-- enforces same-tenant + full ancestor-cycle rejection).
ALTER TABLE business_units
    DROP CONSTRAINT IF EXISTS business_units_no_self_parent;
ALTER TABLE business_units
    ADD CONSTRAINT business_units_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id);

CREATE INDEX IF NOT EXISTS idx_business_units_parent
    ON business_units(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_business_units_criticality
    ON business_units(tenant_id, criticality);
