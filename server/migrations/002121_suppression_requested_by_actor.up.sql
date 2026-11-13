-- A suppression request that no user made (a CI job's .openctem.yml, an
-- inline ignore comment, an ignore file) names its requester here, for
-- example "ci:gitlab:alice". requested_by stays the user, NULL for these.
ALTER TABLE suppression_rules
    ADD COLUMN IF NOT EXISTS requested_by_actor VARCHAR(255);

ALTER TABLE suppression_rules
    DROP CONSTRAINT IF EXISTS chk_suppression_rules_requested_by_actor;
ALTER TABLE suppression_rules
    ADD CONSTRAINT chk_suppression_rules_requested_by_actor
    CHECK (requested_by_actor IS NULL OR length(requested_by_actor) BETWEEN 1 AND 255);
