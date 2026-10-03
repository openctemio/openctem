ALTER TABLE threat_models DROP CONSTRAINT IF EXISTS uq_threat_models_scope;
ALTER TABLE threat_models
    ADD CONSTRAINT threat_models_tenant_id_scope_type_scope_ref_id_key
    UNIQUE (tenant_id, scope_type, scope_ref_id);
