-- Back to the application-written chain. hash_version stays, so version 2
-- chain rows keep their version (the application of the previous release
-- cannot verify them; re-applying the up migration can). The dropped foreign keys come back NOT VALID
-- so rows naming deleted accounts or organizations are kept as they are.
DROP TRIGGER IF EXISTS audit_chain_rebaseline_entries_refuse_update ON audit_chain_rebaseline_entries;
DROP TRIGGER IF EXISTS audit_chain_rebaselines_refuse_update ON audit_chain_rebaselines;
DROP TRIGGER IF EXISTS audit_chain_anchors_refuse_update ON audit_chain_anchors;
DROP TRIGGER IF EXISTS audit_log_chain_refuse_truncate ON audit_log_chain;
DROP TRIGGER IF EXISTS audit_log_chain_refuse_update ON audit_log_chain;
DROP TRIGGER IF EXISTS audit_log_refuse_truncate ON audit_logs;
DROP TRIGGER IF EXISTS audit_log_refuse_update ON audit_logs;
DROP FUNCTION IF EXISTS audit_log_refuse_change();

DROP TRIGGER IF EXISTS audit_log_chain_append ON audit_logs;
DROP FUNCTION IF EXISTS audit_log_chain_append();
DROP FUNCTION IF EXISTS audit_log_row_hash(text, audit_logs);
DROP FUNCTION IF EXISTS audit_log_row_payload(audit_logs);

ALTER TABLE audit_log_chain DROP CONSTRAINT IF EXISTS uq_audit_log_chain_tenant_prev;
ALTER TABLE audit_log_chain ALTER COLUMN hash_version SET DEFAULT 1;

ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_tenant_id_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants(id) ON DELETE SET NULL NOT VALID;
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_actor_id_fkey FOREIGN KEY (actor_id)
    REFERENCES users(id) ON DELETE SET NULL NOT VALID;
