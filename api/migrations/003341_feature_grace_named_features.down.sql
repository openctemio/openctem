DELETE FROM tenant_module_grace g WHERE NOT EXISTS (SELECT 1 FROM modules m WHERE m.id = g.module_id);

ALTER TABLE tenant_module_grace
    ADD CONSTRAINT tenant_module_grace_module_id_fkey FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE;

COMMENT ON COLUMN tenant_module_grace.module_id IS NULL;
