-- expand-contract-ok: contract step in the same PR that stops reading the column; the table was added in an unreleased train and the column only held a counter that nothing reads
-- The release feed is signed directly by one pinned online key (RFC-105), so
-- there is no key set version to remember. Instance-level table, no tenant
-- data; the column held only a counter.
ALTER TABLE version_check_state DROP COLUMN IF EXISTS keyset_version;
