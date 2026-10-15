-- resolution_method is replaced by closure_reason / verification (closure.go),
-- backfilled by finding_closure_backfill. No code reads it any more.
-- Upgrade note: stop the API while migrating (an older binary reads it).
ALTER TABLE findings DROP COLUMN resolution_method;
