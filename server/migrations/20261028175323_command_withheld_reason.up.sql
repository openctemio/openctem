-- Why the dispatch gate last withheld a pending command
-- (docs/architecture/placement.md): the placement code of the refusal
-- (grant_credentials, intensity, local_policy_refuses, ...) and when it was
-- recorded. The gate runs in code after the poll query; without this a job
-- every sensor withholds waits for its run deadline with no reason. Only
-- the code is stored: never the sensor, the targets or the job settings.
-- Written at most every few minutes per command (rate-limited in the API).
--
-- Live impact: two nullable columns without a default on commands (catalog
-- change only, no rewrite, no backfill).

ALTER TABLE commands
    ADD COLUMN IF NOT EXISTS withheld_reason varchar(64),
    ADD COLUMN IF NOT EXISTS withheld_at timestamptz;

COMMENT ON COLUMN commands.withheld_reason IS
    'Placement code of the last dispatch-gate refusal of this pending command (no sensor, target or setting data).';
