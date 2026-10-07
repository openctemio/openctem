-- Reverts 001170. Lossy by necessity:
-- - assets rated 'none' (Not rated) become 'low', the nearest level the old
--   CHECK allows;
-- - policies with no info SLA get the previous default of 90 days. Deadlines
--   cleared from open informational findings are not restored.

UPDATE assets SET criticality = 'low' WHERE criticality = 'none';
ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_criticality;
ALTER TABLE assets ADD CONSTRAINT chk_assets_criticality CHECK (
    criticality IN ('low', 'medium', 'high', 'critical')
);

UPDATE sla_policies SET info_days = 90 WHERE info_days = 0;
ALTER TABLE sla_policies ALTER COLUMN info_days SET DEFAULT 365;
