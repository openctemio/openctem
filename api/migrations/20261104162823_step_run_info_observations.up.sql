-- Info-severity matches of template scanners a step run filed as exposures
-- instead of findings (docs/architecture/exposure-taxonomy.md, "Template
-- scanner info matches"). A constant default: no table rewrite.
ALTER TABLE scan_run_steps
    ADD COLUMN IF NOT EXISTS info_observations integer NOT NULL DEFAULT 0;
