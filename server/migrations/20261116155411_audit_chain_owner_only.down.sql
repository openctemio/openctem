-- Back to the guard of audit_log_db_chain: no DELETE trigger, the rebaseline
-- opened by the setting openctem.audit_rebaseline, and the roles that append
-- audit rows given back what they held before (DELETE on all five tables,
-- UPDATE on audit_log_chain, INSERT on the three evidence tables). The API of
-- the previous release prunes and rebaselines with those grants.

-- Locks: the eight triggers this migration added are dropped (DROP TRIGGER
-- takes ACCESS EXCLUSIVE on its table for the moment it runs; lock_timeout
-- bounds the wait); the others are replaced in place (SHARE ROW EXCLUSIVE).
-- No row is read or changed.

SET LOCAL lock_timeout = '10s';

DO $$
DECLARE
    g record;
BEGIN
    FOR g IN SELECT DISTINCT grantee
               FROM information_schema.role_table_grants
              WHERE table_schema = 'public' AND table_name = 'audit_logs'
                AND privilege_type = 'INSERT'
                AND grantee NOT IN (current_user, 'PUBLIC') LOOP
        EXECUTE format('GRANT DELETE ON public.audit_logs TO %I', g.grantee);
        EXECUTE format('GRANT UPDATE, DELETE ON public.audit_log_chain TO %I', g.grantee);
        EXECUTE format('GRANT INSERT, DELETE ON public.audit_chain_anchors, public.audit_chain_rebaselines, public.audit_chain_rebaseline_entries TO %I', g.grantee);
    END LOOP;
END
$$;

DROP FUNCTION IF EXISTS audit_chain_rebaseline_apply(uuid, uuid, uuid, integer, bigint, uuid[], bigint[], text[], text[], text[], text[]);
DROP FUNCTION IF EXISTS audit_chain_prune_prefix(uuid, bigint, text, uuid[], text, text);

DROP TRIGGER IF EXISTS audit_chain_rebaseline_entries_refuse_truncate ON audit_chain_rebaseline_entries;
DROP TRIGGER IF EXISTS audit_chain_rebaseline_entries_refuse_delete ON audit_chain_rebaseline_entries;
DROP TRIGGER IF EXISTS audit_chain_rebaselines_refuse_truncate ON audit_chain_rebaselines;
DROP TRIGGER IF EXISTS audit_chain_rebaselines_refuse_delete ON audit_chain_rebaselines;
DROP TRIGGER IF EXISTS audit_chain_anchors_refuse_truncate ON audit_chain_anchors;
DROP TRIGGER IF EXISTS audit_chain_anchors_refuse_delete ON audit_chain_anchors;
DROP TRIGGER IF EXISTS audit_log_chain_refuse_delete ON audit_log_chain;
DROP TRIGGER IF EXISTS audit_log_refuse_delete ON audit_logs;

CREATE OR REPLACE FUNCTION audit_log_refuse_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Nested IFs: PL/pgSQL does not short-circuit AND, and NEW has no
    -- audit_log_id on the other tables.
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'audit_log_chain'
       AND current_setting('openctem.audit_rebaseline', true) = 'on' THEN
        IF NEW.audit_log_id = OLD.audit_log_id
           AND NEW.tenant_id = OLD.tenant_id
           AND NEW.chain_position = OLD.chain_position
           AND NEW.hash_version = OLD.hash_version
           AND NEW.created_at = OLD.created_at THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION '% is append-only (% refused)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE OR REPLACE TRIGGER audit_log_refuse_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();
CREATE OR REPLACE TRIGGER audit_log_refuse_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse_change();
CREATE OR REPLACE TRIGGER audit_log_chain_refuse_update
    BEFORE UPDATE ON audit_log_chain
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();
CREATE OR REPLACE TRIGGER audit_log_chain_refuse_truncate
    BEFORE TRUNCATE ON audit_log_chain
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_anchors_refuse_update
    BEFORE UPDATE ON audit_chain_anchors
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_rebaselines_refuse_update
    BEFORE UPDATE ON audit_chain_rebaselines
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_rebaseline_entries_refuse_update
    BEFORE UPDATE ON audit_chain_rebaseline_entries
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();

DROP FUNCTION IF EXISTS audit_chain_refuse_change();
