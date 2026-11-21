-- Tenant audit log: only the schema owner may delete or rewrite audit rows and
-- their chain evidence, and only through two owner-rights functions.
-- See docs/architecture/audit-hash-chain.md (Who may change the chain).
--
-- expand-contract-ok: removes no data; DELETE and TRUNCATE appear only in the functions and triggers that guard them
--
-- Before this migration the API's role kept DELETE on audit_logs,
-- audit_log_chain and the three evidence tables, and the trigger that closes
-- audit_log_chain to UPDATE let a rewrite of prev_hash and hash through for any
-- session that set openctem.audit_rebaseline = 'on', a custom setting every
-- role may set. A holder of the API's database credentials could therefore
-- remove rows from an organization's chain, re-hash the rest and remove the
-- rebaseline evidence, and verification would still pass.
--
-- After it:
--   * audit_chain_prune_prefix (retention) and audit_chain_rebaseline_apply
--     (rebaseline) are SECURITY DEFINER functions owned by the schema owner,
--     with a pinned search_path. They are the only way to delete or rewrite.
--     Retention deletes only the oldest prefix of one chain, only rows older
--     than 365 days, and always records an anchor. A rebaseline archives every
--     hash it overwrites, a version 2 row only gets the hash the database
--     itself computes for it, and every rewritten entry must link.
--   * The guard trigger lets a DELETE or an UPDATE through only when it runs
--     as the table's owner (current_user, which inside the functions is the
--     owner) AND the function declared the operation. The old setting
--     openctem.audit_rebaseline no longer opens anything.
--   * Every role other than the owner loses UPDATE, DELETE and TRUNCATE on
--     audit_logs and audit_log_chain (INSERT stays: rows are appended and the
--     chain trigger runs as the inserting role), and INSERT, UPDATE, DELETE
--     and TRUNCATE on audit_chain_anchors, audit_chain_rebaselines and
--     audit_chain_rebaseline_entries (only the functions write them).
--   * Roles that may append audit rows get EXECUTE on the two functions;
--     PUBLIC does not.
--
-- An installation whose API connects as the schema owner (one role for
-- migrations and the API) keeps working. The owner can always change its own
-- tables (and drop triggers), so there the database cannot stop a holder of
-- those credentials; the triggers still refuse a DELETE or UPDATE that does
-- not go through the functions. The API logs a warning at start-up in that
-- case (docs/deployment/database-roles.md).
--
-- Locks: every trigger is created with CREATE OR REPLACE TRIGGER (never DROP
-- TRIGGER, which takes ACCESS EXCLUSIVE and would queue reads behind it). That
-- takes a SHARE ROW EXCLUSIVE lock on each of the five tables for the moment
-- it runs: appends (and other writes) wait, reads do not. No row is read or
-- rewritten, so the time does not grow with the table. lock_timeout bounds the
-- wait behind a long writer. GRANT, REVOKE and CREATE FUNCTION change the
-- catalog only. Requires PostgreSQL 14 or later (CREATE OR REPLACE TRIGGER).

SET LOCAL lock_timeout = '10s';

-- 1. The guard, as a new function (it replaces audit_log_refuse_change, which
--    is dropped below once no trigger uses it).
CREATE OR REPLACE FUNCTION audit_chain_refuse_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    op text := coalesce(current_setting('openctem.audit_chain_op', true), '');
BEGIN
    -- Nested IFs: PL/pgSQL does not short-circuit AND, and NEW has no
    -- audit_log_id on the other tables.
    IF op IN ('prune', 'rebaseline')
       AND current_user = (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = TG_RELID) THEN
        IF TG_OP = 'DELETE' AND op = 'prune'
           AND TG_TABLE_NAME IN ('audit_logs', 'audit_log_chain', 'audit_chain_rebaseline_entries') THEN
            RETURN OLD;
        END IF;
        IF TG_OP = 'UPDATE' AND op = 'rebaseline' AND TG_TABLE_NAME = 'audit_log_chain' THEN
            IF NEW.audit_log_id = OLD.audit_log_id
               AND NEW.tenant_id = OLD.tenant_id
               AND NEW.chain_position = OLD.chain_position
               AND NEW.hash_version = OLD.hash_version
               AND NEW.created_at = OLD.created_at THEN
                RETURN NEW;
            END IF;
        END IF;
    END IF;
    RAISE EXCEPTION '% is append-only (% refused)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

-- 2. The UPDATE and TRUNCATE triggers of audit_log_db_chain move to the new
--    guard (same names, replaced in place); the old guard, the one the setting
--    opened, goes.
CREATE OR REPLACE TRIGGER audit_log_refuse_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_log_refuse_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_log_chain_refuse_update
    BEFORE UPDATE ON audit_log_chain
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_log_chain_refuse_truncate
    BEFORE TRUNCATE ON audit_log_chain
    FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_anchors_refuse_update
    BEFORE UPDATE ON audit_chain_anchors
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_rebaselines_refuse_update
    BEFORE UPDATE ON audit_chain_rebaselines
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_rebaseline_entries_refuse_update
    BEFORE UPDATE ON audit_chain_rebaseline_entries
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
DROP FUNCTION IF EXISTS audit_log_refuse_change();

-- 3. DELETE is refused on all five tables (it had no trigger), TRUNCATE on the
--    three evidence tables too.
CREATE OR REPLACE TRIGGER audit_log_refuse_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_log_chain_refuse_delete
    BEFORE DELETE ON audit_log_chain
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_anchors_refuse_delete
    BEFORE DELETE ON audit_chain_anchors
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_anchors_refuse_truncate
    BEFORE TRUNCATE ON audit_chain_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_rebaselines_refuse_delete
    BEFORE DELETE ON audit_chain_rebaselines
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_rebaselines_refuse_truncate
    BEFORE TRUNCATE ON audit_chain_rebaselines
    FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_rebaseline_entries_refuse_delete
    BEFORE DELETE ON audit_chain_rebaseline_entries
    FOR EACH ROW EXECUTE FUNCTION audit_chain_refuse_change();
CREATE OR REPLACE TRIGGER audit_chain_rebaseline_entries_refuse_truncate
    BEFORE TRUNCATE ON audit_chain_rebaseline_entries
    FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_refuse_change();

-- 4. Retention: delete the oldest prefix of one chain, up to and including
--    p_last_position, after an archive of it was stored. The ids must be
--    exactly the chain's entries up to that position, the entry at that
--    position must still carry p_anchor_hash, and every row must be older
--    than 365 days (the shortest retention the API allows). The anchor
--    (counts and times computed here) is recorded in the same transaction.
--    SQLSTATE OC409 means the chain is not what the caller read; the caller
--    retries on its next run.
CREATE OR REPLACE FUNCTION audit_chain_prune_prefix(
    p_tenant uuid,
    p_last_position bigint,
    p_anchor_hash text,
    p_audit_log_ids uuid[],
    p_archive_path text,
    p_archive_sha256 text)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    sys       constant uuid := 'ffffffff-ffff-ffff-ffff-ffffffffffff';
    n_ids     integer := coalesce(cardinality(p_audit_log_ids), 0);
    at_before bigint;
    matching  bigint;
    last_hash text;
    n_rows    bigint;
    oldest    timestamptz;
    newest    timestamptz;
BEGIN
    IF p_tenant IS NULL OR p_last_position IS NULL OR n_ids = 0
       OR coalesce(p_archive_path, '') = '' OR coalesce(p_archive_sha256, '') = '' THEN
        RAISE EXCEPTION 'audit chain prune: tenant, position, ids and archive are required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A suspended or deleting organization (legal hold) keeps its history.
    IF EXISTS (SELECT 1 FROM tenants WHERE id = p_tenant AND status <> 'active') THEN
        RAISE EXCEPTION 'audit chain prune: organization % is not active', p_tenant
            USING ERRCODE = 'OC409';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('audit_log_chain'), hashtext(p_tenant::text));

    SELECT count(*) FILTER (WHERE chain_position <= p_last_position),
           count(*) FILTER (WHERE chain_position <= p_last_position AND audit_log_id = ANY (p_audit_log_ids)),
           max(hash) FILTER (WHERE chain_position = p_last_position)
      INTO at_before, matching, last_hash
      FROM audit_log_chain
     WHERE tenant_id = p_tenant;
    IF at_before <> n_ids OR matching <> n_ids OR last_hash IS DISTINCT FROM p_anchor_hash THEN
        RAISE EXCEPTION 'audit chain prune: chain % changed since it was read', p_tenant
            USING ERRCODE = 'OC409';
    END IF;

    SELECT count(*), min(l.logged_at), max(l.logged_at)
      INTO n_rows, oldest, newest
      FROM audit_log_chain c
      JOIN audit_logs l ON l.id = c.audit_log_id
     WHERE c.tenant_id = p_tenant
       AND c.chain_position <= p_last_position
       AND (l.tenant_id = p_tenant OR (p_tenant = sys AND l.tenant_id IS NULL));
    IF n_rows <> n_ids THEN
        RAISE EXCEPTION 'audit chain prune: chain % names rows outside it', p_tenant
            USING ERRCODE = 'OC409';
    END IF;
    IF newest >= now() - interval '365 days' THEN
        RAISE EXCEPTION 'audit chain prune: rows newer than 365 days are kept'
            USING ERRCODE = 'check_violation';
    END IF;

    INSERT INTO audit_chain_anchors (tenant_id, anchor_hash, last_chain_position, pruned_count,
                                     oldest_logged_at, newest_logged_at, archive_path, archive_sha256)
    VALUES (p_tenant, p_anchor_hash, p_last_position, n_ids, oldest, newest, p_archive_path, p_archive_sha256);

    PERFORM set_config('openctem.audit_chain_op', 'prune', true);
    DELETE FROM audit_chain_rebaseline_entries
     WHERE tenant_id = p_tenant AND audit_log_id = ANY (p_audit_log_ids);
    DELETE FROM audit_log_chain
     WHERE tenant_id = p_tenant AND audit_log_id = ANY (p_audit_log_ids);
    DELETE FROM audit_logs
     WHERE id = ANY (p_audit_log_ids)
       AND (tenant_id = p_tenant OR (p_tenant = sys AND tenant_id IS NULL));
    GET DIAGNOSTICS n_rows = ROW_COUNT;
    PERFORM set_config('openctem.audit_chain_op', '', true);
    IF n_rows <> n_ids THEN
        RAISE EXCEPTION 'audit chain prune: chain % changed while pruning', p_tenant
            USING ERRCODE = 'OC409';
    END IF;
    RETURN n_ids;
END
$$;

COMMENT ON FUNCTION audit_chain_prune_prefix(uuid, bigint, text, uuid[], text, text) IS
    'Audit retention: deletes the oldest prefix (older than 365 days) of one tenant chain and records its anchor. Runs as the schema owner; the only DELETE path for audit rows.';

-- 5. Rebaseline: record the rebaseline, archive the old and new hashes of
--    every rewritten entry, and overwrite them, in the caller's transaction.
--    Refused (SQLSTATE OC409) when the chain tail moved or an entry no longer
--    holds the hashes the caller read. A version 2 entry only gets the hash
--    the database computes for its row, and every rewritten entry must link to
--    the entry before it (or the chain's newest retention anchor).
CREATE OR REPLACE FUNCTION audit_chain_rebaseline_apply(
    p_rebaseline_id uuid,
    p_tenant uuid,
    p_actor_id uuid,
    p_entries_total integer,
    p_last_position bigint,
    p_audit_log_ids uuid[],
    p_positions bigint[],
    p_old_prev text[],
    p_old_hash text[],
    p_new_prev text[],
    p_new_hash text[])
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    sys      constant uuid := 'ffffffff-ffff-ffff-ffff-ffffffffffff';
    n        integer := coalesce(cardinality(p_audit_log_ids), 0);
    tail     bigint;
    affected bigint;
    bad      bigint;
    start    text;
BEGIN
    IF p_rebaseline_id IS NULL OR p_tenant IS NULL OR p_last_position IS NULL
       OR coalesce(cardinality(p_positions), 0) <> n OR coalesce(cardinality(p_old_prev), 0) <> n
       OR coalesce(cardinality(p_old_hash), 0) <> n OR coalesce(cardinality(p_new_prev), 0) <> n
       OR coalesce(cardinality(p_new_hash), 0) <> n THEN
        RAISE EXCEPTION 'audit chain rebaseline: inconsistent arguments'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('audit_log_chain'), hashtext(p_tenant::text));

    SELECT coalesce(max(chain_position), 0) INTO tail FROM audit_log_chain WHERE tenant_id = p_tenant;
    IF tail <> p_last_position THEN
        RAISE EXCEPTION 'audit chain rebaseline: chain tail is at position %, rebaseline walked to %',
            tail, p_last_position
            USING ERRCODE = 'OC409';
    END IF;

    INSERT INTO audit_chain_rebaselines (id, tenant_id, actor_id, entries_total, entries_rewritten)
    VALUES (p_rebaseline_id, p_tenant, p_actor_id, p_entries_total, n);
    IF n = 0 THEN
        RETURN 0;
    END IF;

    INSERT INTO audit_chain_rebaseline_entries
        (rebaseline_id, tenant_id, audit_log_id, chain_position,
         old_prev_hash, old_hash, new_prev_hash, new_hash)
    SELECT p_rebaseline_id, p_tenant, v.id, v.pos, v.old_prev, v.old_hash, v.new_prev, v.new_hash
      FROM unnest(p_audit_log_ids, p_positions, p_old_prev, p_old_hash, p_new_prev, p_new_hash)
           AS v(id, pos, old_prev, old_hash, new_prev, new_hash);

    PERFORM set_config('openctem.audit_chain_op', 'rebaseline', true);
    UPDATE audit_log_chain c
       SET prev_hash = v.new_prev, hash = v.new_hash
      FROM unnest(p_audit_log_ids, p_old_prev, p_old_hash, p_new_prev, p_new_hash)
           AS v(id, old_prev, old_hash, new_prev, new_hash)
     WHERE c.tenant_id = p_tenant
       AND c.audit_log_id = v.id
       AND c.prev_hash = v.old_prev
       AND c.hash = v.old_hash;
    GET DIAGNOSTICS affected = ROW_COUNT;
    PERFORM set_config('openctem.audit_chain_op', '', true);
    IF affected <> n THEN
        RAISE EXCEPTION 'audit chain rebaseline: % of % entries still held the hashes the rebaseline read',
            affected, n
            USING ERRCODE = 'OC409';
    END IF;

    SELECT count(*) INTO bad
      FROM unnest(p_audit_log_ids, p_new_prev, p_new_hash) AS v(id, new_prev, new_hash)
      JOIN audit_log_chain c ON c.tenant_id = p_tenant AND c.audit_log_id = v.id AND c.hash_version = 2
      JOIN audit_logs l ON l.id = c.audit_log_id
                       AND (l.tenant_id = p_tenant OR (p_tenant = sys AND l.tenant_id IS NULL))
     WHERE v.new_hash IS DISTINCT FROM audit_log_row_hash(v.new_prev, l);
    IF bad > 0 THEN
        RAISE EXCEPTION 'audit chain rebaseline: % version 2 entries would not hash their row', bad
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    SELECT coalesce((SELECT anchor_hash FROM audit_chain_anchors
                      WHERE tenant_id = p_tenant
                      ORDER BY last_chain_position DESC
                      LIMIT 1), '')
      INTO start;
    SELECT count(*) INTO bad
      FROM (SELECT c.audit_log_id, c.prev_hash,
                   lag(c.hash) OVER (ORDER BY c.chain_position) AS before
              FROM audit_log_chain c
             WHERE c.tenant_id = p_tenant) w
     WHERE w.audit_log_id = ANY (p_audit_log_ids)
       AND w.prev_hash IS DISTINCT FROM coalesce(w.before, start);
    IF bad > 0 THEN
        RAISE EXCEPTION 'audit chain rebaseline: % rewritten entries would not link', bad
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN n;
END
$$;

COMMENT ON FUNCTION audit_chain_rebaseline_apply(uuid, uuid, uuid, integer, bigint, uuid[], bigint[], text[], text[], text[], text[]) IS
    'Audit chain rebaseline: archives and rewrites prev_hash/hash of one tenant chain. Runs as the schema owner; the only UPDATE path for audit_log_chain.';

-- 6. Privileges. Nobody but the owner keeps a write that could remove or
--    rewrite history, whatever it was granted before (the least-privilege
--    bootstrap grants the API role full DML on every table).
DO $$
DECLARE
    g record;
BEGIN
    FOR g IN SELECT DISTINCT grantee, table_name
               FROM information_schema.role_table_grants
              WHERE table_schema = 'public'
                AND table_name IN ('audit_logs', 'audit_log_chain', 'audit_chain_anchors',
                                   'audit_chain_rebaselines', 'audit_chain_rebaseline_entries')
                AND grantee NOT IN (current_user, 'PUBLIC')
                AND grantee <> (SELECT pg_get_userbyid(relowner) FROM pg_class
                                 WHERE oid = ('public.' || table_name)::regclass) LOOP
        IF g.table_name IN ('audit_logs', 'audit_log_chain') THEN
            EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.%I FROM %I', g.table_name, g.grantee);
        ELSE
            EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I FROM %I', g.table_name, g.grantee);
        END IF;
    END LOOP;
END
$$;

REVOKE EXECUTE ON FUNCTION audit_chain_prune_prefix(uuid, bigint, text, uuid[], text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION audit_chain_rebaseline_apply(uuid, uuid, uuid, integer, bigint, uuid[], bigint[], text[], text[], text[], text[]) FROM PUBLIC;

-- The roles that append audit rows (the API role) call them.
DO $$
DECLARE
    g record;
BEGIN
    FOR g IN SELECT DISTINCT grantee
               FROM information_schema.role_table_grants
              WHERE table_schema = 'public' AND table_name = 'audit_logs'
                AND privilege_type = 'INSERT'
                AND grantee NOT IN (current_user, 'PUBLIC') LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION audit_chain_prune_prefix(uuid, bigint, text, uuid[], text, text) TO %I', g.grantee);
        EXECUTE format('GRANT EXECUTE ON FUNCTION audit_chain_rebaseline_apply(uuid, uuid, uuid, integer, bigint, uuid[], bigint[], text[], text[], text[], text[]) TO %I', g.grantee);
    END LOOP;
END
$$;
