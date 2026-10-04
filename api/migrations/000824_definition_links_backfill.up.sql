-- Backfill the definition links (RFC-044 §8 P1).
-- https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-044-issue-definitions-and-findings.md
--
-- 1. definition_identifiers: one primary identifier per definition, its own
--    (namespace, external_id), in its scope, asserted by its origin.
-- 2. finding_definitions: every finding linked to the catalog
--    (findings.vulnerability_id) gets that definition as its primary link
--    (ord 0, asserted by the report that named the CVE), and
--    findings.definition_id is set to it. A finding without a catalog link
--    gets its primary definition when ingest writes the links.
--
-- Safe on large tables: batches by id (5000 definitions, 2000 findings), each
-- committed on its own, so no lock is held longer than one batch. The
-- findings batches suspend the updated_at trigger inside their own
-- transaction: filling a denormalized column is not a change to the finding,
-- and an updated_at bump would re-export every linked finding to the
-- integrations that sync by it. The trigger is enabled again before the batch
-- commits, so no other session ever runs without it. A batch that cannot get
-- its lock within 5 s retries. Re-running is harmless (ON CONFLICT DO NOTHING,
-- IS DISTINCT FROM).
--
-- ONE statement on purpose: COMMIT inside a DO block is allowed only when the
-- block is not part of a larger transaction.
DO $$
DECLARE
    nil_id   CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
    last_id  uuid;
    next_id  uuid;
    attempts int;
BEGIN
    -- 1. Primary identifiers. Only definition_identifiers is written, so no
    --    lock on a hot table beyond the foreign-key row checks.
    last_id := nil_id;
    LOOP
        SELECT b.id INTO next_id
        FROM (SELECT id FROM vulnerabilities WHERE id > last_id ORDER BY id LIMIT 5000) b
        ORDER BY b.id DESC
        LIMIT 1;
        EXIT WHEN next_id IS NULL;

        INSERT INTO definition_identifiers
            (namespace, external_id, tenant_id, scope_tenant_id, definition_id, is_primary, asserted_by)
        SELECT v.namespace, v.external_id, v.tenant_id, v.scope_tenant_id, v.id, TRUE, v.origin
        FROM vulnerabilities v
        WHERE v.id > last_id AND v.id <= next_id
          AND v.external_id IS NOT NULL
        ON CONFLICT DO NOTHING;

        COMMIT;
        last_id := next_id;
    END LOOP;

    -- 2. Primary finding links and findings.definition_id.
    last_id := nil_id;
    LOOP
        SELECT b.id INTO next_id
        FROM (SELECT id FROM findings WHERE id > last_id ORDER BY id LIMIT 2000) b
        ORDER BY b.id DESC
        LIMIT 1;
        EXIT WHEN next_id IS NULL;

        IF EXISTS (SELECT 1 FROM findings f
                   WHERE f.id > last_id AND f.id <= next_id
                     AND f.vulnerability_id IS NOT NULL) THEN
            attempts := 0;
            LOOP
                BEGIN
                    PERFORM set_config('lock_timeout', '5s', true);
                    -- findings.definition_id's link key is deferred; check it
                    -- per statement here, so no trigger event is still pending
                    -- when the updated_at trigger is enabled again.
                    SET CONSTRAINTS ALL IMMEDIATE;
                    ALTER TABLE findings DISABLE TRIGGER trigger_findings_updated_at;

                    INSERT INTO finding_definitions
                        (finding_id, tenant_id, definition_id, definition_scope, role, ord, asserted_by)
                    SELECT f.id, f.tenant_id, v.id, v.scope_tenant_id, 'primary', 0, 'report'
                    FROM findings f
                    JOIN vulnerabilities v ON v.id = f.vulnerability_id
                    WHERE f.id > last_id AND f.id <= next_id
                      AND v.scope_tenant_id IN (nil_id, f.tenant_id)
                    ON CONFLICT DO NOTHING;

                    UPDATE findings f
                    SET definition_id = fd.definition_id
                    FROM finding_definitions fd
                    WHERE fd.finding_id = f.id
                      AND fd.tenant_id = f.tenant_id
                      AND fd.ord = 0
                      AND f.id > last_id AND f.id <= next_id
                      AND f.definition_id IS DISTINCT FROM fd.definition_id;

                    ALTER TABLE findings ENABLE TRIGGER trigger_findings_updated_at;
                    EXIT;
                EXCEPTION WHEN lock_not_available THEN
                    attempts := attempts + 1;
                    IF attempts >= 60 THEN
                        RAISE;
                    END IF;
                    PERFORM pg_sleep(1);
                END;
            END LOOP;
        END IF;

        COMMIT;
        last_id := next_id;
    END LOOP;
END
$$;
