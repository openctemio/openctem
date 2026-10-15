-- resolution_method is replaced by closure_reason / verification (closure.go),
-- backfilled by finding_closure_backfill. No code reads it any more.
-- Upgrade note: stop the API while migrating (an older binary reads it).
-- expand-contract-ok: contract step in the same release (owner rule: minimal back-compat); no code reads resolution_method after this change, and the upgrade stops the API while migrating
ALTER TABLE findings DROP COLUMN resolution_method;
