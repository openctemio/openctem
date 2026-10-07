-- Backfill for the ingest rule "the asset's name wins over a contradicting
-- reported type" (reconcileTypeWithName):
--   * ip_address whose name is a DNS name (not an IP literal)  -> domain
--   * domain/subdomain whose name is an IP literal              -> ip_address
-- The sub-type is cleared (neither target has sub-types), asset_class and
-- asset_lens follow from trg_assets_registry_class. Row-local: every row is
-- judged by its own name only. A row whose target (tenant, type, name) is
-- already taken is skipped with a NOTICE, so no unique key can be violated.
-- Each change writes a system-actor audit row, like the other automated
-- changes (actor_id NULL).

DO $$
DECLARE
    r        RECORD;
    is_ip    boolean;
    target   text;
    moved    integer := 0;
    skipped  integer := 0;
BEGIN
    FOR r IN
        SELECT id, tenant_id, name, asset_type, sub_type
          FROM assets
         WHERE asset_type IN ('ip_address', 'domain', 'subdomain')
           AND deleted_at IS NULL
    LOOP
        is_ip := false;
        BEGIN
            -- inet also accepts "10.0.0.0/24" and "1.2.3.4/32": only a bare
            -- address (optionally bracketed IPv6) is an IP literal here.
            IF r.name !~ '/' THEN
                PERFORM btrim(r.name, '[]')::inet;
                is_ip := true;
            END IF;
        EXCEPTION WHEN invalid_text_representation THEN
            is_ip := false;
        END;

        target := NULL;
        IF r.asset_type = 'ip_address' THEN
            IF NOT is_ip
               AND lower(r.name) ~ '^[a-z0-9_*-]{1,63}(\.[a-z0-9_*-]{1,63})+\.?$'
               AND regexp_replace(lower(r.name), '^.*\.', '') ~ '[^0-9.]'
            THEN
                target := 'domain';
            END IF;
        ELSIF is_ip THEN
            target := 'ip_address';
        END IF;

        CONTINUE WHEN target IS NULL;

        IF EXISTS (SELECT 1 FROM assets o
                    WHERE o.tenant_id = r.tenant_id AND o.name = r.name
                      AND o.asset_type = target AND o.id <> r.id) THEN
            RAISE NOTICE 'retype_assets_by_name: skipped asset % (tenant %): % "%" already exists as %',
                r.id, r.tenant_id, r.asset_type, r.name, target;
            skipped := skipped + 1;
            CONTINUE;
        END IF;

        UPDATE assets SET asset_type = target, sub_type = NULL, updated_at = now()
         WHERE id = r.id;

        INSERT INTO audit_logs (tenant_id, actor_id, actor_email, action, resource_type,
                                resource_id, resource_name, result, severity, message, metadata)
        VALUES (r.tenant_id, NULL, 'system@migration-001151', 'asset.type_corrected', 'asset',
                r.id::text, r.name, 'success', 'low',
                format('Asset type corrected from %s to %s to match its name', r.asset_type, target),
                jsonb_build_object('old_type', r.asset_type, 'old_sub_type', r.sub_type,
                                   'new_type', target, 'reason', 'type_contradicts_name',
                                   'automated', true));
        moved := moved + 1;
    END LOOP;
    RAISE NOTICE 'retype_assets_by_name: % retyped, % skipped', moved, skipped;
END $$;
