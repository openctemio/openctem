-- Give back UPDATE and DELETE to the roles that may insert (the API role).
DO $$
DECLARE
    g record;
BEGIN
    FOR g IN SELECT DISTINCT grantee FROM information_schema.role_table_grants
              WHERE table_schema = 'public' AND table_name = 'admin_audit_logs'
                AND privilege_type = 'INSERT' AND grantee NOT IN (current_user, 'PUBLIC') LOOP
        EXECUTE format('GRANT UPDATE, DELETE ON public.admin_audit_logs TO %I', g.grantee);
    END LOOP;
END
$$;
DROP TRIGGER IF EXISTS admin_audit_refuse_truncate ON admin_audit_logs;
DROP TRIGGER IF EXISTS admin_audit_refuse_change ON admin_audit_logs;
DROP TRIGGER IF EXISTS admin_audit_chain_append ON admin_audit_logs;
DROP FUNCTION IF EXISTS admin_audit_prune(timestamptz, integer);
DROP TABLE IF EXISTS admin_audit_chain_anchors;
DROP FUNCTION IF EXISTS admin_audit_refuse_change();
DROP FUNCTION IF EXISTS admin_audit_chain_append();
DROP FUNCTION IF EXISTS admin_audit_chain_tail();
DROP FUNCTION IF EXISTS admin_audit_row_hash(text, admin_audit_logs);
DROP FUNCTION IF EXISTS admin_audit_row_payload(admin_audit_logs);
DROP INDEX IF EXISTS idx_admin_audit_chain_position;
ALTER TABLE admin_audit_logs
    DROP COLUMN IF EXISTS hash,
    DROP COLUMN IF EXISTS prev_hash,
    DROP COLUMN IF EXISTS chain_position;
-- Rows may name administrators deleted since the up migration: clear those
-- references, then restore the foreign key.
UPDATE admin_audit_logs l SET admin_id = NULL
 WHERE admin_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM admin_users a WHERE a.id = l.admin_id);
ALTER TABLE admin_audit_logs
    ADD CONSTRAINT admin_audit_logs_admin_id_fkey FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE SET NULL;
COMMENT ON TABLE admin_audit_logs IS NULL;
