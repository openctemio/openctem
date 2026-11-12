-- Remediation tasks created from a custom query
-- (docs/rfcs/RFC-098-remediation-tasks.md, "Tasks from a query").
--
-- One row per task that was created from a query: the query text and its
-- language version, the membership mode (snapshot: the matches at creation
-- only; auto: new matches join later) and, for auto mode, its state. The
-- query always runs as owner_user_id (the creator) with that person's
-- current data scope; the auto-include worker suspends the task when the
-- owner leaves the organization or loses access, so it never runs ownerless.
--
-- Live impact: a new empty table, and the join_source CHECK of
-- remediation_task_members gains 'query' (a small table, re-validated in
-- place; the list is read back so values other migrations added are kept).

CREATE TABLE IF NOT EXISTS remediation_task_queries (
    task_id          uuid         NOT NULL,
    tenant_id        uuid         NOT NULL,
    query_text       text         NOT NULL,
    query_version    smallint     NOT NULL DEFAULT 1,
    mode             varchar(8)   NOT NULL DEFAULT 'snapshot',
    auto_state       varchar(10),
    auto_reason      varchar(32),
    member_cap       integer      NOT NULL DEFAULT 1000,
    owner_user_id    uuid,
    last_run_at      timestamptz,
    last_added_count integer      NOT NULL DEFAULT 0,
    total_added      integer      NOT NULL DEFAULT 0,
    created_at       timestamptz  NOT NULL DEFAULT now(),
    updated_at       timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_remediation_task_queries PRIMARY KEY (task_id),
    CONSTRAINT fk_remediation_task_queries_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_task_queries_task FOREIGN KEY (tenant_id, task_id)
        REFERENCES remediation_tasks (tenant_id, id) ON DELETE CASCADE,
    -- A deleted account leaves the row ownerless: the worker suspends it.
    CONSTRAINT fk_remediation_task_queries_owner FOREIGN KEY (owner_user_id)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_remediation_task_queries_text CHECK (length(query_text) BETWEEN 1 AND 4096),
    CONSTRAINT chk_remediation_task_queries_version CHECK (query_version > 0),
    CONSTRAINT chk_remediation_task_queries_mode CHECK (mode IN ('snapshot', 'auto')),
    CONSTRAINT chk_remediation_task_queries_auto_state CHECK (
        (mode = 'snapshot' AND auto_state IS NULL AND auto_reason IS NULL)
        OR (mode = 'auto' AND auto_state IN ('active', 'paused', 'suspended'))),
    CONSTRAINT chk_remediation_task_queries_reason CHECK (
        (auto_state = 'suspended') = (auto_reason IS NOT NULL)),
    CONSTRAINT chk_remediation_task_queries_cap CHECK (member_cap BETWEEN 1 AND 1000),
    CONSTRAINT chk_remediation_task_queries_counts CHECK (last_added_count >= 0 AND total_added >= 0)
);

COMMENT ON TABLE remediation_task_queries IS
    'The custom query a remediation task was created from, its membership mode (snapshot or auto) and the auto-include state.';
COMMENT ON COLUMN remediation_task_queries.owner_user_id IS
    'The person whose current data scope every run of the query uses (the creator); NULL after the account was deleted, which suspends auto mode.';
COMMENT ON COLUMN remediation_task_queries.auto_reason IS
    'Why auto mode is suspended: owner_removed, owner_lost_access, task_closed or query_invalid.';

CREATE INDEX IF NOT EXISTS idx_remediation_task_queries_tenant
    ON remediation_task_queries (tenant_id);
-- The worker's work list: active auto tasks, least recently run first.
CREATE INDEX IF NOT EXISTS idx_remediation_task_queries_auto_due
    ON remediation_task_queries (last_run_at NULLS FIRST) WHERE mode = 'auto' AND auto_state = 'active';
CREATE INDEX IF NOT EXISTS idx_remediation_task_queries_owner
    ON remediation_task_queries (owner_user_id) WHERE owner_user_id IS NOT NULL;

-- A member that joined through the task's query (auto include or a
-- confirmed re-run).
DO $$
DECLARE
    vals text[];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_remediation_task_members_join_source' AND c.conrelid = 'remediation_task_members'::regclass;
    IF vals IS NOT NULL AND NOT 'query' = ANY (vals) THEN
        ALTER TABLE remediation_task_members DROP CONSTRAINT chk_remediation_task_members_join_source;
        EXECUTE format('ALTER TABLE remediation_task_members ADD CONSTRAINT chk_remediation_task_members_join_source CHECK (join_source IN (%s))',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM unnest(vals || 'query'::text) AS v));
    END IF;
END;
$$;
