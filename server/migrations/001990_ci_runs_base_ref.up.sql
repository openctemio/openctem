-- The pull request's base branch a CI run is compared with (RFC-077 G-5).
-- Signed by GitHub (base_ref claim), reported by the job elsewhere; it only
-- picks among the repository's branches that count as exposure.
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS base_ref VARCHAR(255) NOT NULL DEFAULT '';
