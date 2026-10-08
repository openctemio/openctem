-- No-op by design. 001331 folded property synonyms into their canonical keys
-- (a data fix). The fold is not reversible: once two spellings were merged,
-- which row held which spelling is not recorded, and every write path folds
-- the old names again anyway. Rolling back the schema needs nothing here.
SELECT 1;
