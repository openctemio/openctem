-- scan_step_params (up)
-- A scan's per-step overrides of capability standard params (research/426
-- P0.1): {"<step_key>" | "*:<capability>": {"<param>": value}}. A constant
-- default, so the column add rewrites nothing.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS step_params jsonb NOT NULL DEFAULT '{}'::jsonb;
