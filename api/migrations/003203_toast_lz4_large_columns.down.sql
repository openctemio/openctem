SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
  c record;
BEGIN
  FOR c IN
    SELECT * FROM (VALUES
      ('findings', 'description'), ('findings', 'scanner_output'), ('findings', 'source_extra'),
      ('ai_triage_results', 'raw_response'),
      ('commands', 'payload'), ('commands', 'result'),
      ('command_logs', 'lines'),
      ('ingest_reports', 'header'), ('ingest_jobs', 'payload'),
      ('sensor_manifests', 'manifest'),
      ('finding_evidence', 'content')
    ) AS v(tbl, col)
  LOOP
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = c.tbl AND column_name = c.col) THEN
      EXECUTE format('ALTER TABLE %I ALTER COLUMN %I SET COMPRESSION DEFAULT', c.tbl, c.col);
    END IF;
  END LOOP;
END $$;
