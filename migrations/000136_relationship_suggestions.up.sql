CREATE TABLE IF NOT EXISTS relationship_suggestions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  target_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  relationship_type VARCHAR(50) NOT NULL,
  reason TEXT NOT NULL,
  confidence DECIMAL(3,2) NOT NULL DEFAULT 1.00,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  reviewed_by UUID REFERENCES users(id),
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_suggestion_status CHECK (status IN ('pending', 'approved', 'dismissed')),
  CONSTRAINT uq_suggestion UNIQUE(tenant_id, source_asset_id, target_asset_id, relationship_type)
);

CREATE INDEX idx_suggestions_tenant_status ON relationship_suggestions(tenant_id, status);
CREATE INDEX idx_suggestions_source ON relationship_suggestions(source_asset_id);
CREATE INDEX idx_suggestions_target ON relationship_suggestions(target_asset_id);
