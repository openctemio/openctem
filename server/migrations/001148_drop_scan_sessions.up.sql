-- Retire scan_sessions (RFC-046 D2: one model, Scan -> Run -> Task; CI runs
-- live in ci_runs). Its only writer was the sensor protocol v1 scan
-- registration, removed with protocol v1; since then nothing writes it. Its
-- readers are gone with it: the /api/v1/scan-sessions routes, the web hooks,
-- and the CI coverage query, which now reads completed scan runs
-- (ingest_reports bound to a completed command). Rows written before
-- protocol v1 was removed are dropped; the pre-upgrade backup keeps them.
--
-- expand-contract-ok: contract step; no code reads or writes scan_sessions
DROP TABLE IF EXISTS scan_sessions;
