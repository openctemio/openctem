-- Reverts 20261108115557_compliance_check_state: dash_process_dirty as in 002963,
-- the compliance check tables, the posture function and findings.compliance_level.
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
    END LOOP;

    DELETE FROM dash_dirty_assets d WHERE d.tenant_id = p_tenant AND d.id = ANY (v_ids);
    RETURN NEXT;
END;
$$;
COMMENT ON FUNCTION dash_process_dirty(uuid, integer) IS
    'Dashboard facts: claims up to p_limit dirty rows of the tenant (FOR UPDATE SKIP LOCKED), recomputes assets whose ORed reasons include 1 or 16, deletes exactly the claimed rows; one transaction.';
COMMENT ON TABLE dash_dirty_assets IS
    'Dashboard facts: assets to recompute. reasons bits: 1 findings changed, 2 asset row changed (insert, delete, watched attribute), 4 asset group membership, 8 asset ownership, 16 an open finding crossed an age band. asset_id all-zero = findings without an asset. Several rows per asset may exist; the maintainer ORs them.';
DROP FUNCTION IF EXISTS compliance_posture_recompute(uuid, uuid);
DROP TABLE IF EXISTS compliance_posture;
DROP TABLE IF EXISTS compliance_check_results;
DROP TABLE IF EXISTS compliance_check_states;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_compliance_level;
ALTER TABLE findings DROP COLUMN IF EXISTS compliance_level;
