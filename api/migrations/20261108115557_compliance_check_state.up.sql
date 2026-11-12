-- Compliance check state (docs/architecture/compliance-checks.md).
--
-- A benchmark check result (finding_type compliance) is a state of one
-- control on one asset, not a vulnerability: a FAILED result keeps a finding
-- open, every result (passed, failed, warning, not applicable, error) is the
-- latest state of its control with its evidence, and every change of result
-- or evidence is kept as history. Nothing here rewrites existing findings.

-- The benchmark level of a compliance finding (CIS Level 1 or 2, a STIG
-- category, the framework's own tier), from the importer's data: 1 is the
-- baseline every system should meet. NULL when the source names none.
-- Nullable without a default: a catalog-only change.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS compliance_level smallint;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_compliance_level;
ALTER TABLE findings ADD CONSTRAINT chk_findings_compliance_level
    CHECK (compliance_level IS NULL OR compliance_level BETWEEN 1 AND 3) NOT VALID;
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_compliance_level;
COMMENT ON COLUMN findings.compliance_level IS
    'Benchmark level of a compliance check (1 baseline, 2 and 3 stricter tiers); NULL when the source names none.';

-- The latest result of each control on each asset.
CREATE TABLE IF NOT EXISTS compliance_check_states (
    id                uuid         NOT NULL DEFAULT gen_random_uuid(),
    tenant_id         uuid         NOT NULL,
    asset_id          uuid         NOT NULL,
    benchmark_key     varchar(160) NOT NULL,
    benchmark_name    varchar(500) NOT NULL,
    benchmark_version varchar(100),
    framework         varchar(50),
    control_id        varchar(200) NOT NULL,
    control_name      varchar(500),
    compliance_level  smallint,
    result            varchar(20)  NOT NULL,
    scanner_severity  varchar(20),
    evidence          jsonb        NOT NULL DEFAULT '{}'::jsonb,
    evidence_hash     varchar(64)  NOT NULL DEFAULT '',
    tool_name         varchar(100),
    -- The finding of a failed (or warning) result of this control; kept
    -- when the control passes later, so the history links to it.
    finding_id        uuid,
    first_seen_at     timestamptz  NOT NULL,
    last_checked_at   timestamptz  NOT NULL,
    last_changed_at   timestamptz  NOT NULL,
    created_at        timestamptz  NOT NULL DEFAULT now(),
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_compliance_check_states PRIMARY KEY (id),
    CONSTRAINT uq_compliance_check_states_control UNIQUE (tenant_id, asset_id, benchmark_key, control_id),
    CONSTRAINT fk_compliance_check_states_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    -- Composite: a state of one tenant never points at another tenant's asset.
    CONSTRAINT fk_compliance_check_states_asset FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_compliance_check_states_finding FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE SET NULL,
    CONSTRAINT chk_compliance_check_states_result
        CHECK (result IN ('pass', 'fail', 'manual', 'not_applicable', 'error')),
    CONSTRAINT chk_compliance_check_states_level
        CHECK (compliance_level IS NULL OR compliance_level BETWEEN 1 AND 3)
);
COMMENT ON TABLE compliance_check_states IS
    'Latest result of each benchmark control on each asset (pass, fail, manual for a scanner warning, not_applicable, error) with its evidence.';
CREATE INDEX IF NOT EXISTS idx_compliance_check_states_benchmark
    ON compliance_check_states (tenant_id, benchmark_key, control_id);
CREATE INDEX IF NOT EXISTS idx_compliance_check_states_asset
    ON compliance_check_states (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_compliance_check_states_finding
    ON compliance_check_states (finding_id) WHERE finding_id IS NOT NULL;

-- Every observed change of a control's result or evidence, and the first
-- observation. Append-only: a state never loses what it was.
CREATE TABLE IF NOT EXISTS compliance_check_results (
    id              uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       uuid        NOT NULL,
    -- The state the row belonged to when written (NULL once that state is
    -- gone, e.g. folded into another asset's by a merge); the control is
    -- named by (asset_id, benchmark_key, control_id), which a merge moves.
    state_id        uuid,
    asset_id        uuid        NOT NULL,
    benchmark_key   varchar(160) NOT NULL,
    control_id      varchar(200) NOT NULL,
    result          varchar(20) NOT NULL,
    previous_result varchar(20),
    evidence        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    benchmark_version varchar(100),
    tool_name       varchar(100),
    finding_id      uuid,
    -- ingest (a scan or an import) or backfill (the compliance-checks command).
    source          varchar(20) NOT NULL DEFAULT 'ingest',
    observed_at     timestamptz NOT NULL,
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_compliance_check_results PRIMARY KEY (id),
    CONSTRAINT fk_compliance_check_results_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_compliance_check_results_state FOREIGN KEY (state_id) REFERENCES compliance_check_states (id) ON DELETE SET NULL,
    CONSTRAINT chk_compliance_check_results_result
        CHECK (result IN ('pass', 'fail', 'manual', 'not_applicable', 'error')),
    CONSTRAINT chk_compliance_check_results_source CHECK (source IN ('ingest', 'backfill'))
);
COMMENT ON TABLE compliance_check_results IS
    'History of benchmark control results: the first observation and every change of result or evidence. Append-only; kept when its asset is merged into another.';
CREATE INDEX IF NOT EXISTS idx_compliance_check_results_control
    ON compliance_check_results (tenant_id, asset_id, benchmark_key, control_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_check_results_state
    ON compliance_check_results (state_id) WHERE state_id IS NOT NULL;

-- Precomputed posture per asset and benchmark (the dashboard figure): one
-- row per (tenant, asset, benchmark) with the count of controls per result.
-- excepted_count: failed controls whose finding is accepted or a false
-- positive. Organization figures are sums over the rows a viewer may see.
CREATE TABLE IF NOT EXISTS compliance_posture (
    tenant_id            uuid         NOT NULL,
    asset_id             uuid         NOT NULL,
    benchmark_key        varchar(160) NOT NULL,
    benchmark_name       varchar(500) NOT NULL,
    benchmark_version    varchar(100),
    framework            varchar(50),
    pass_count           integer      NOT NULL DEFAULT 0,
    fail_count           integer      NOT NULL DEFAULT 0,
    manual_count         integer      NOT NULL DEFAULT 0,
    not_applicable_count integer      NOT NULL DEFAULT 0,
    error_count          integer      NOT NULL DEFAULT 0,
    excepted_count       integer      NOT NULL DEFAULT 0,
    last_checked_at      timestamptz  NOT NULL,
    updated_at           timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_compliance_posture PRIMARY KEY (tenant_id, asset_id, benchmark_key),
    CONSTRAINT fk_compliance_posture_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_compliance_posture_asset FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);
COMMENT ON TABLE compliance_posture IS
    'Precomputed benchmark posture per asset: controls per result. Pass rate = pass / (pass + fail); excepted failures are counted inside fail_count.';

-- Recomputes the posture rows of one asset from its check states; returns
-- the number of rows written or removed.
CREATE OR REPLACE FUNCTION compliance_posture_recompute(p_tenant uuid, p_asset uuid)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_total integer;
BEGIN
    IF p_tenant IS NULL OR p_asset IS NULL THEN
        RAISE EXCEPTION 'compliance_posture_recompute: tenant and asset are required';
    END IF;
    WITH src AS MATERIALIZED (
        SELECT s.benchmark_key,
               (array_agg(s.benchmark_name ORDER BY s.last_checked_at DESC))[1] AS benchmark_name,
               (array_agg(s.benchmark_version ORDER BY s.last_checked_at DESC))[1] AS benchmark_version,
               (array_agg(s.framework ORDER BY s.last_checked_at DESC))[1] AS framework,
               count(*) FILTER (WHERE s.result = 'pass')::integer AS pass_count,
               count(*) FILTER (WHERE s.result = 'fail')::integer AS fail_count,
               count(*) FILTER (WHERE s.result = 'manual')::integer AS manual_count,
               count(*) FILTER (WHERE s.result = 'not_applicable')::integer AS not_applicable_count,
               count(*) FILTER (WHERE s.result = 'error')::integer AS error_count,
               count(*) FILTER (WHERE s.result = 'fail' AND f.status IN ('accepted', 'false_positive'))::integer AS excepted_count,
               max(s.last_checked_at) AS last_checked_at
        FROM compliance_check_states s
        LEFT JOIN findings f ON f.id = s.finding_id AND f.tenant_id = s.tenant_id
        WHERE s.tenant_id = p_tenant AND s.asset_id = p_asset
        GROUP BY s.benchmark_key
    ), del AS (
        DELETE FROM compliance_posture p
        WHERE p.tenant_id = p_tenant AND p.asset_id = p_asset
          AND NOT EXISTS (SELECT 1 FROM src WHERE src.benchmark_key = p.benchmark_key)
        RETURNING 1
    ), ups AS (
        INSERT INTO compliance_posture AS p (tenant_id, asset_id, benchmark_key, benchmark_name, benchmark_version,
            framework, pass_count, fail_count, manual_count, not_applicable_count, error_count, excepted_count,
            last_checked_at, updated_at)
        SELECT p_tenant, p_asset, benchmark_key, benchmark_name, benchmark_version, framework, pass_count,
               fail_count, manual_count, not_applicable_count, error_count, excepted_count, last_checked_at, now()
        FROM src
        ON CONFLICT ON CONSTRAINT pk_compliance_posture DO UPDATE
            SET benchmark_name = EXCLUDED.benchmark_name, benchmark_version = EXCLUDED.benchmark_version,
                framework = EXCLUDED.framework, pass_count = EXCLUDED.pass_count, fail_count = EXCLUDED.fail_count,
                manual_count = EXCLUDED.manual_count, not_applicable_count = EXCLUDED.not_applicable_count,
                error_count = EXCLUDED.error_count, excepted_count = EXCLUDED.excepted_count,
                last_checked_at = EXCLUDED.last_checked_at, updated_at = now()
            WHERE (p.benchmark_name, p.benchmark_version, p.framework, p.pass_count, p.fail_count, p.manual_count,
                   p.not_applicable_count, p.error_count, p.excepted_count, p.last_checked_at)
                IS DISTINCT FROM
                  (EXCLUDED.benchmark_name, EXCLUDED.benchmark_version, EXCLUDED.framework, EXCLUDED.pass_count,
                   EXCLUDED.fail_count, EXCLUDED.manual_count, EXCLUDED.not_applicable_count, EXCLUDED.error_count,
                   EXCLUDED.excepted_count, EXCLUDED.last_checked_at)
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM del) + (SELECT count(*) FROM ups) INTO v_total;
    RETURN v_total;
END;
$$;
COMMENT ON FUNCTION compliance_posture_recompute(uuid, uuid) IS
    'Compliance posture: recomputes the per-benchmark control counts of one asset from compliance_check_states; returns rows changed.';

-- The dashboard maintainer also refreshes the compliance posture of an asset
-- whose findings changed (bit 1: an accepted failure is an exception) or
-- whose check states changed (bit 32). Restated from 002963 with that one
-- addition.
CREATE OR REPLACE FUNCTION dash_process_dirty(p_tenant uuid, p_limit integer)
RETURNS TABLE (claimed integer, assets integer, recomputed integer, changed integer, oldest_marked_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE
    v_ids     bigint[];
    v_asset   uuid;
    v_reasons integer;
BEGIN
    IF p_tenant IS NULL THEN
        RAISE EXCEPTION 'dash_process_dirty: tenant is required';
    END IF;
    claimed := 0; assets := 0; recomputed := 0; changed := 0;

    SELECT array_agg(c.id), min(c.marked_at) INTO v_ids, oldest_marked_at
    FROM (SELECT d.id, d.marked_at FROM dash_dirty_assets d
          WHERE d.tenant_id = p_tenant
          ORDER BY d.id
          LIMIT GREATEST(COALESCE(p_limit, 500), 1)
          FOR UPDATE SKIP LOCKED) c;
    claimed := COALESCE(cardinality(v_ids), 0);
    IF claimed = 0 THEN
        RETURN NEXT;
        RETURN;
    END IF;

    FOR v_asset, v_reasons IN
        SELECT d.asset_id, bit_or(d.reasons)::integer
        FROM dash_dirty_assets d
        WHERE d.tenant_id = p_tenant AND d.id = ANY (v_ids)
        GROUP BY d.asset_id
        ORDER BY d.asset_id
    LOOP
        assets := assets + 1;
        IF v_reasons & 17 <> 0 THEN
            changed := changed + dash_recompute_asset(p_tenant, v_asset);
            recomputed := recomputed + 1;
        END IF;
        IF v_reasons & 33 <> 0 AND v_asset <> '00000000-0000-0000-0000-000000000000'::uuid THEN
            changed := changed + compliance_posture_recompute(p_tenant, v_asset);
        END IF;
    END LOOP;

    DELETE FROM dash_dirty_assets d WHERE d.tenant_id = p_tenant AND d.id = ANY (v_ids);
    RETURN NEXT;
END;
$$;
COMMENT ON FUNCTION dash_process_dirty(uuid, integer) IS
    'Dashboard facts: claims up to p_limit dirty rows of the tenant (FOR UPDATE SKIP LOCKED), recomputes assets whose ORed reasons include 1 or 16, refreshes the compliance posture for 1 or 32, deletes exactly the claimed rows; one transaction.';

COMMENT ON TABLE dash_dirty_assets IS
    'Dashboard facts: assets to recompute. reasons bits: 1 findings changed, 2 asset row changed (insert, delete, watched attribute), 4 asset group membership, 8 asset ownership, 16 an open finding crossed an age band, 32 compliance check states changed. asset_id all-zero = findings without an asset. Several rows per asset may exist; the maintainer ORs them.';
