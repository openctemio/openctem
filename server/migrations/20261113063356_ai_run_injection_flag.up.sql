-- A run on an AI worker is applied in a later request than the one that
-- built its bundle (docs/architecture/ai-analysis.md, "Runs on an AI
-- worker"). The bundle's injection flag decides that the output may only
-- become comments, so it is stored on the run instead of living in memory.
--
-- Live impact: no data changes. A boolean column with a constant default is
-- a catalog change only (no table rewrite); existing runs read false.
ALTER TABLE ai_runs ADD COLUMN injection_suspected boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN ai_runs.injection_suspected IS
    'The bundle sent for the run carried text that matched an injection pattern: its output may only become comments.';
