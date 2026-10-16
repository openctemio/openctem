-- The platform administrators' audit log becomes append-only and hash-chained.
--
-- Every row is linked into one SHA-256 chain computed by the database itself
-- (a BEFORE INSERT trigger), so every writer is covered: the API, the console
-- service and the bootstrap CLI. Editing or deleting a row is refused by a
-- trigger; the only deletion is the retention prune (admin_audit_prune), which
-- removes the oldest prefix of the chain and records where the chain stood in
-- admin_audit_chain_anchors, so the rest stays verifiable.
--
-- admin_audit_logs is small (one row per administrator action), so the
-- one-time backfill below runs in this transaction.
--
-- expand-contract-ok: SET NOT NULL is on the new chain columns, which the BEFORE INSERT trigger fills for every writer (old app versions included), so no write can leave them NULL; TRUNCATE appears only in the trigger that refuses it.
--
-- A NEW COLUMN on admin_audit_logs must be added to admin_audit_row_payload
-- (in a new migration), or it is not covered by the hash:
-- TestAdminAuditChainCoversEveryColumn_DB fails until it is.

-- The administrator a row names is history: deleting the administrator must
-- not rewrite the row (the foreign key's ON DELETE SET NULL did).
ALTER TABLE admin_audit_logs DROP CONSTRAINT IF EXISTS admin_audit_logs_admin_id_fkey;

ALTER TABLE admin_audit_logs
    ADD COLUMN IF NOT EXISTS chain_position bigint,
    ADD COLUMN IF NOT EXISTS prev_hash text,
    ADD COLUMN IF NOT EXISTS hash text;

-- Where the chain stood after each retention prune: the next remaining row
-- links to the newest anchor's hash.
CREATE TABLE IF NOT EXISTS admin_audit_chain_anchors (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_position bigint NOT NULL,
    hash           text NOT NULL,
    pruned_rows    bigint NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_audit_chain_anchors_position
    ON admin_audit_chain_anchors (chain_position);

-- The canonical content of one row: every column but the chain columns, in a
-- fixed order. jsonb renders deterministically; the timestamp is epoch
-- microseconds so the session time zone never changes the text.
CREATE OR REPLACE FUNCTION admin_audit_row_payload(r admin_audit_logs)
RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = public, pg_temp
AS $$
    SELECT jsonb_build_array(
        r.id, r.admin_id, r.admin_email, r.action, r.resource_type, r.resource_id,
        r.resource_name, r.request_method, r.request_path, r.request_body,
        r.response_status, r.ip_address, r.user_agent, r.success, r.error_message,
        r.severity,
        (extract(epoch FROM r.created_at) * 1000000)::bigint
    )::text
$$;

-- hash = SHA-256(prev_hash | payload), hex.
CREATE OR REPLACE FUNCTION admin_audit_row_hash(prev text, r admin_audit_logs)
RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = public, pg_temp
AS $$
    SELECT encode(sha256(convert_to(coalesce(prev, '') || '|' || admin_audit_row_payload(r), 'UTF8')), 'hex')
$$;

-- The chain tail: the newest row, else the newest anchor, else the genesis.
CREATE OR REPLACE FUNCTION admin_audit_chain_tail(OUT tail_position bigint, OUT tail_hash text)
LANGUAGE plpgsql STABLE
SET search_path = public, pg_temp
AS $$
BEGIN
    SELECT chain_position, hash INTO tail_position, tail_hash
      FROM admin_audit_logs
     WHERE chain_position IS NOT NULL
     ORDER BY chain_position DESC
     LIMIT 1;
    IF tail_position IS NULL THEN
        SELECT chain_position, hash INTO tail_position, tail_hash
          FROM admin_audit_chain_anchors
         ORDER BY chain_position DESC
         LIMIT 1;
    END IF;
    IF tail_position IS NULL THEN
        tail_position := 0;
        tail_hash := '';
    END IF;
END
$$;

-- Backfill: chain the existing rows in the order they were written.
DO $$
DECLARE
    r    admin_audit_logs;
    pos  bigint := 0;
    prev text := '';
BEGIN
    FOR r IN SELECT * FROM admin_audit_logs ORDER BY created_at, id LOOP
        pos := pos + 1;
        r.chain_position := pos;
        r.prev_hash := prev;
        prev := admin_audit_row_hash(prev, r);
        UPDATE admin_audit_logs
           SET chain_position = pos, prev_hash = r.prev_hash, hash = prev
         WHERE id = r.id;
    END LOOP;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_audit_chain_position
    ON admin_audit_logs (chain_position);
ALTER TABLE admin_audit_logs
    ALTER COLUMN chain_position SET NOT NULL,
    ALTER COLUMN prev_hash SET NOT NULL,
    ALTER COLUMN hash SET NOT NULL;

-- Append: serialised by a transaction-scoped advisory lock, so two writers
-- can never extend the same tail. Whatever the caller sent for the chain
-- columns is overwritten.
CREATE OR REPLACE FUNCTION admin_audit_chain_append()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    t record;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('admin_audit_chain'));
    SELECT * INTO t FROM admin_audit_chain_tail();
    IF NEW.id IS NULL THEN
        NEW.id := uuid_generate_v7();
    END IF;
    IF NEW.created_at IS NULL THEN
        NEW.created_at := now();
    END IF;
    NEW.chain_position := t.tail_position + 1;
    NEW.prev_hash := t.tail_hash;
    NEW.hash := admin_audit_row_hash(t.tail_hash, NEW);
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS admin_audit_chain_append ON admin_audit_logs;
CREATE TRIGGER admin_audit_chain_append
    BEFORE INSERT ON admin_audit_logs
    FOR EACH ROW EXECUTE FUNCTION admin_audit_chain_append();

-- Append-only: no update, no delete, no truncate. The single exception is a
-- delete inside admin_audit_prune, which runs as the table's owner and sets
-- a transaction-local flag; the application role is not the owner, so it
-- cannot take that path itself.
CREATE OR REPLACE FUNCTION admin_audit_refuse_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('openctem.admin_audit_prune', true) = 'on'
       AND current_user = (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = TG_RELID) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'admin_audit_logs is append-only (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

DROP TRIGGER IF EXISTS admin_audit_refuse_change ON admin_audit_logs;
CREATE TRIGGER admin_audit_refuse_change
    BEFORE UPDATE OR DELETE ON admin_audit_logs
    FOR EACH ROW EXECUTE FUNCTION admin_audit_refuse_change();

DROP TRIGGER IF EXISTS admin_audit_refuse_truncate ON admin_audit_logs;
CREATE TRIGGER admin_audit_refuse_truncate
    BEFORE TRUNCATE ON admin_audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION admin_audit_refuse_change();

-- Anchors are append-only too (only the prune writes them).
DROP TRIGGER IF EXISTS admin_audit_anchor_refuse_change ON admin_audit_chain_anchors;
CREATE TRIGGER admin_audit_anchor_refuse_change
    BEFORE UPDATE OR DELETE ON admin_audit_chain_anchors
    FOR EACH ROW EXECUTE FUNCTION admin_audit_refuse_change();

-- Retention: delete up to max_rows of the oldest rows written before cutoff,
-- never newer than one year ago, as a prefix of the chain (stops at the first
-- newer row), and anchor the chain at the last deleted row. Returns the
-- number of rows deleted. SECURITY DEFINER: it runs as the table's owner,
-- the only role whose delete the append-only trigger lets through.
CREATE OR REPLACE FUNCTION admin_audit_prune(cutoff timestamptz, max_rows integer)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    floor_at  timestamptz := now() - interval '365 days';
    last_pos  bigint;
    last_hash text;
    n         bigint;
BEGIN
    IF max_rows IS NULL OR max_rows < 1 THEN
        RETURN 0;
    END IF;
    IF cutoff IS NULL OR cutoff > floor_at THEN
        cutoff := floor_at;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('admin_audit_chain'));

    -- The oldest rows in chain order, up to the first row that is too new.
    SELECT max(p.chain_position), count(*) INTO last_pos, n
      FROM (SELECT chain_position, created_at,
                   bool_and(created_at < cutoff) OVER (ORDER BY chain_position) AS all_old
              FROM admin_audit_logs
             ORDER BY chain_position
             LIMIT max_rows) p
     WHERE p.all_old;
    IF last_pos IS NULL OR n = 0 THEN
        RETURN 0;
    END IF;
    SELECT hash INTO last_hash FROM admin_audit_logs WHERE chain_position = last_pos;

    PERFORM set_config('openctem.admin_audit_prune', 'on', true);
    DELETE FROM admin_audit_logs WHERE chain_position <= last_pos;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('openctem.admin_audit_prune', 'off', true);

    INSERT INTO admin_audit_chain_anchors (chain_position, hash, pruned_rows)
    VALUES (last_pos, last_hash, n);
    RETURN n;
END
$$;

-- No role but the owner may change or remove rows, whatever it was granted
-- before (the least-privilege bootstrap grants the API role full DML on every
-- table). Anchors are written only by admin_audit_prune.
DO $$
DECLARE
    g record;
BEGIN
    FOR g IN SELECT DISTINCT grantee, table_name
               FROM information_schema.role_table_grants
              WHERE table_schema = 'public'
                AND table_name IN ('admin_audit_logs', 'admin_audit_chain_anchors')
                AND grantee NOT IN (current_user, 'PUBLIC')
                AND grantee <> (SELECT pg_get_userbyid(relowner) FROM pg_class
                                 WHERE oid = ('public.' || table_name)::regclass) LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.%I FROM %I', g.table_name, g.grantee);
        IF g.table_name = 'admin_audit_chain_anchors' THEN
            EXECUTE format('REVOKE INSERT ON public.%I FROM %I', g.table_name, g.grantee);
        END IF;
    END LOOP;
END
$$;

-- Retention runs as the API role (granted EXECUTE by the least-privilege
-- bootstrap) or the owner; nobody else.
REVOKE EXECUTE ON FUNCTION admin_audit_prune(timestamptz, integer) FROM PUBLIC;

COMMENT ON TABLE admin_audit_logs IS
    'Platform administrator actions. Append-only (trigger) and hash-chained (chain_position, prev_hash, hash); retention only through admin_audit_prune.';
