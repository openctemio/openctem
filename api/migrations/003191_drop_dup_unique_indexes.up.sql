-- Three unique indexes repeat another unique index on the same two columns
-- (column order swapped, which a unique index serves equally):
--   findings              uq_findings_tenant_id_id         = ux_findings_id_tenant
--   groups                uq_groups_tenant_id_id           = groups_id_tenant_key
--   remediation_campaigns uq_remediation_campaigns_tenant_id_id = ux_remediation_campaigns_id_tenant
-- Foreign keys may be bound to the index being dropped, and PostgreSQL cannot
-- re-point them, so each dependent key is dropped and re-added unchanged (NOT
-- VALID, then validated) so it binds to the surviving index. Rows are not
-- touched; the constraint definitions are copied from the catalog.
SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
  r record;
  t record;
BEGIN
  CREATE TEMP TABLE _fk_rebind (conname text, tbl regclass, def text) ON COMMIT DROP;

  FOR t IN
    SELECT * FROM (VALUES
      ('findings',              'uq_findings_tenant_id_id',              'ux_findings_id_tenant',             false),
      ('groups',                'uq_groups_tenant_id_id',                'groups_id_tenant_key',              true),
      ('remediation_campaigns', 'uq_remediation_campaigns_tenant_id_id', 'ux_remediation_campaigns_id_tenant', true)
    ) AS v(tbl, dropped, kept, is_constraint)
  LOOP
    -- never drop without the surviving twin
    IF to_regclass(t.kept) IS NULL OR to_regclass(t.dropped) IS NULL THEN
      CONTINUE;
    END IF;
    INSERT INTO _fk_rebind
      SELECT c.conname, c.conrelid::regclass, pg_get_constraintdef(c.oid)
      FROM pg_constraint c WHERE c.contype = 'f' AND c.conindid = t.dropped::regclass;
    FOR r IN SELECT conname, tbl FROM _fk_rebind LOOP
      EXECUTE format('ALTER TABLE %s DROP CONSTRAINT IF EXISTS %I', r.tbl, r.conname);
    END LOOP;
    IF t.is_constraint THEN
      EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', t.tbl, t.dropped);
    ELSE
      EXECUTE format('DROP INDEX %I', t.dropped);
    END IF;
  END LOOP;

  FOR r IN SELECT * FROM _fk_rebind LOOP
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s NOT VALID', r.tbl, r.conname, r.def);
    EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT %I', r.tbl, r.conname);
  END LOOP;
END $$;
