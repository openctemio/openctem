-- Large jsonb/text/bytea columns compress with lz4 instead of pglz (faster
-- compress and decompress, similar ratio). The change is metadata only: values
-- written from now on use lz4, existing values keep the method they were
-- stored with and stay readable. On a server built without lz4 support the
-- migration does nothing.
SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
  c record;
BEGIN
  BEGIN
    SET LOCAL default_toast_compression = 'lz4';
  EXCEPTION WHEN invalid_parameter_value OR feature_not_supported THEN
    RAISE NOTICE 'lz4 compression is not available on this server; leaving columns on the default';
    RETURN;
  END;

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
      EXECUTE format('ALTER TABLE %I ALTER COLUMN %I SET COMPRESSION lz4', c.tbl, c.col);
    END IF;
  END LOOP;
END $$;
