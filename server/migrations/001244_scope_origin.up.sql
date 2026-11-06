-- How a scope entry or exclusion came to exist (research/53 §4.6): the
-- Scope page shows "Added by …", "Accepted from a review rule", "Allowed from
-- a refused scan", and so on. Set by the creating path; existing rows are
-- manual, except rows the platform wrote (created_by system:…).
ALTER TABLE scope_targets
    ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'manual';
ALTER TABLE scope_exclusions
    ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'manual';

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin IN
    ('manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system'));
ALTER TABLE scope_exclusions DROP CONSTRAINT IF EXISTS chk_scope_exclusions_origin;
ALTER TABLE scope_exclusions ADD CONSTRAINT chk_scope_exclusions_origin CHECK (origin IN
    ('manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system'));

UPDATE scope_targets SET origin = 'system' WHERE created_by LIKE 'system:%' AND origin = 'manual';
UPDATE scope_exclusions SET origin = 'system' WHERE created_by LIKE 'system:%' AND origin = 'manual';
