-- The KEV sync clears in_kev on rows whose CVE left the catalog. Without an
-- index on the flag that statement read the whole table (about 345 000 rows)
-- on every sync to find the ~1 800 flagged ones.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vuln_event_state_in_kev ON vuln_event_state (vuln_id) WHERE in_kev;
