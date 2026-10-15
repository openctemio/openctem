-- No-op by design. 002137 relabelled misconfiguration and secret findings
-- filed as SCA (a data fix). Which rows held the wrong label is not recorded,
-- restoring it has no value, and ingest files them by type anyway. Rolling
-- back the schema needs nothing here.
SELECT 1;
