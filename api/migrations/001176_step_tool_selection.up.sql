-- How a pipeline step picks its tool, and what a step run resolved.
--
-- A step is a capability node: it names a capability and the platform picks
-- the tool. pipeline_steps.tool pins one tool (strict). prefer_tools, new,
-- is an ordered list of tools to try instead of the catalog order; empty
-- means any implementation, the catalog default first.
--
-- step_runs.capability, new, records the versioned capability a step run
-- ran (scan.ports@1), next to the tool it resolved (step_runs.tool), so a
-- run says what ran whichever tool the platform picked.
--
-- A defaulted and a nullable column: no table rewrite, no backfill.

ALTER TABLE pipeline_steps
    ADD COLUMN IF NOT EXISTS prefer_tools text[] DEFAULT '{}'::text[] NOT NULL;

ALTER TABLE step_runs
    ADD COLUMN IF NOT EXISTS capability character varying(100);

COMMENT ON COLUMN pipeline_steps.prefer_tools IS 'Ordered tools to try for the step capability when no tool is pinned; empty means any implementation, the catalog default first.';
COMMENT ON COLUMN step_runs.capability IS 'Versioned capability the step run ran (scan.ports@1); NULL for a step the catalog cannot place.';
