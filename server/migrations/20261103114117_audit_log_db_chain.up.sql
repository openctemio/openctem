-- Tenant audit log: chained by the database in the inserting transaction, over
-- the whole row, and closed to UPDATE and TRUNCATE.
-- See docs/architecture/audit-hash-chain.md.
--
-- expand-contract-ok: removes no data; TRUNCATE appears only in the triggers that refuse it
--
-- Before this migration the chain row was written by the application after the
-- audit row, in a second transaction, and hashed only action, resource type,
-- resource id, result and time. Every path that inserted into audit_logs
-- directly (repository transactions, triggers, data migrations) left its row
-- unchained, and actor, changes, metadata and message could be edited without
-- a trace. Two foreign keys also rewrote audit rows: deleting a user nulled
-- actor_id and deleting an organization nulled tenant_id, which moved its rows
-- into the tenant-less (system) view.

-- 1. Audit rows outlive the accounts and organizations they name. The ids stay
--    as recorded (pseudonymous references), and retention removes the rows.
--    Dropped first: the backfill below names organizations that no longer exist.
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_actor_id_fkey;
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_tenant_id_fkey;

-- 2. Give rows of deleted organizations their organization back. Their chain
--    row still carries it, and the version 1 hash does not cover tenant_id, so
--    this changes no hash.
UPDATE audit_logs l
   SET tenant_id = c.tenant_id
  FROM audit_log_chain c
 WHERE c.audit_log_id = l.id
   AND l.tenant_id IS NULL
   AND c.tenant_id <> 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid;

-- 3. Hash version per chain row: 1 = the application hash over
--    action|resource_type|resource_id|result and time, 2 = the database hash
--    over the whole row (below).
ALTER TABLE audit_log_chain
    ADD COLUMN IF NOT EXISTS hash_version smallint NOT NULL DEFAULT 1;
ALTER TABLE audit_log_chain DROP CONSTRAINT IF EXISTS chk_audit_chain_hash_version;
ALTER TABLE audit_log_chain
    ADD CONSTRAINT chk_audit_chain_hash_version CHECK (hash_version IN (1, 2));

-- Two rows of one chain linking to the same predecessor is a fork. Checked at
-- commit so a rebaseline can rewrite a chain in one statement.
ALTER TABLE audit_log_chain
    ADD CONSTRAINT uq_audit_log_chain_tenant_prev UNIQUE (tenant_id, prev_hash)
    DEFERRABLE INITIALLY DEFERRED;

-- 4. The canonical text a version 2 hash covers: every column except the
--    actor's e-mail, IP address and user agent. Those are personal data that an
--    erasure may have to remove; actor_id identifies the actor. The time is
--    whole microseconds since the epoch, as stored.
CREATE OR REPLACE FUNCTION audit_log_row_payload(l audit_logs)
RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = public, pg_temp
AS $$
    SELECT jsonb_build_array(
        2, l.id, l.tenant_id, l.actor_id, l.action, l.resource_type, l.resource_id,
        l.resource_name, l.changes, l.result, l.severity, l.message, l.metadata,
        l.request_id, l.session_id,
        (extract(epoch FROM l.logged_at) * 1000000)::bigint
    )::text
$$;

-- hash = hex(SHA-256(prev_hash || '|' || payload)); pkg/crypto
-- ComputeAuditRowHash computes the same from the payload text.
CREATE OR REPLACE FUNCTION audit_log_row_hash(prev text, l audit_logs)
RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = public, pg_temp
AS $$
    SELECT encode(sha256(convert_to(coalesce(prev, '') || '|' || audit_log_row_payload(l), 'UTF8')), 'hex')
$$;

-- 5. Chain every new audit row in the transaction that inserts it, under the
--    per-chain advisory lock the application, retention and rebaseline take
--    (same key: hashtext('audit_log_chain'), hashtext(<chain id>)). Tenant-less
--    rows extend the system chain (all-f sentinel).
CREATE OR REPLACE FUNCTION audit_log_chain_append()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    chain uuid := coalesce(NEW.tenant_id, 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid);
    prev  text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('audit_log_chain'), hashtext(chain::text));
    SELECT hash INTO prev
      FROM audit_log_chain
     WHERE tenant_id = chain
     ORDER BY chain_position DESC
     LIMIT 1;
    IF NOT FOUND THEN
        SELECT anchor_hash INTO prev
          FROM audit_chain_anchors
         WHERE tenant_id = chain
         ORDER BY last_chain_position DESC
         LIMIT 1;
    END IF;
    prev := coalesce(prev, '');
    INSERT INTO audit_log_chain (audit_log_id, tenant_id, prev_hash, hash, hash_version)
    VALUES (NEW.id, chain, prev, audit_log_row_hash(prev, NEW), 2);
    RETURN NULL;
END
$$;

DROP TRIGGER IF EXISTS audit_log_chain_append ON audit_logs;
CREATE TRIGGER audit_log_chain_append
    AFTER INSERT ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_log_chain_append();

-- 6. No UPDATE or TRUNCATE of audit rows or of the chain evidence. A
--    rebaseline may rewrite prev_hash and hash of chain rows (and nothing else)
--    in a transaction that set openctem.audit_rebaseline = 'on'.
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

DROP TRIGGER IF EXISTS audit_log_refuse_update ON audit_logs;
CREATE TRIGGER audit_log_refuse_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();
DROP TRIGGER IF EXISTS audit_log_refuse_truncate ON audit_logs;
CREATE TRIGGER audit_log_refuse_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse_change();

DROP TRIGGER IF EXISTS audit_log_chain_refuse_update ON audit_log_chain;
CREATE TRIGGER audit_log_chain_refuse_update
    BEFORE UPDATE ON audit_log_chain
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();
DROP TRIGGER IF EXISTS audit_log_chain_refuse_truncate ON audit_log_chain;
CREATE TRIGGER audit_log_chain_refuse_truncate
    BEFORE TRUNCATE ON audit_log_chain
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse_change();

DROP TRIGGER IF EXISTS audit_chain_anchors_refuse_update ON audit_chain_anchors;
CREATE TRIGGER audit_chain_anchors_refuse_update
    BEFORE UPDATE ON audit_chain_anchors
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();
DROP TRIGGER IF EXISTS audit_chain_rebaselines_refuse_update ON audit_chain_rebaselines;
CREATE TRIGGER audit_chain_rebaselines_refuse_update
    BEFORE UPDATE ON audit_chain_rebaselines
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();
DROP TRIGGER IF EXISTS audit_chain_rebaseline_entries_refuse_update ON audit_chain_rebaseline_entries;
CREATE TRIGGER audit_chain_rebaseline_entries_refuse_update
    BEFORE UPDATE ON audit_chain_rebaseline_entries
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_change();
