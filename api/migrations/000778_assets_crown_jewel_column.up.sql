-- The crown-jewel flag lives in assets.is_crown_jewel (owner decision O5).
--
-- Migration 000126 added the column, but the API wrote the flag into
-- properties->'is_crown_jewel' and every reader but the scoping summary read
-- it from there, so the two disagreed. From this migration on the column is
-- the only source: the crown-jewel endpoint writes it, every reader reads it,
-- and is_crown_jewel is a reserved key that properties no longer accept.
--
-- Backfill: only JSON true or the string "true" (any case) mark a crown jewel,
-- the same rule the property reads used. Any other value (false, "x", a
-- number, an object) leaves the column false. A column already true stays
-- true. The key is then removed from properties so it cannot drift again.
--
-- expand-contract-ok: SET NOT NULL is safe because every row is backfilled
-- first and no code writes NULL (the column has DEFAULT FALSE and no API path
-- writes it except the crown-jewel endpoint, which writes a boolean). Removing
-- the properties key only drops a value that this release no longer reads; an
-- old pod that marks a crown jewel during the rollout writes the property and
-- the flag must be set again, which the PR notes.

UPDATE assets
   SET is_crown_jewel = TRUE
 WHERE is_crown_jewel IS DISTINCT FROM TRUE
   AND lower(properties->>'is_crown_jewel') = 'true';

UPDATE assets SET is_crown_jewel = FALSE WHERE is_crown_jewel IS NULL;

UPDATE assets
   SET properties = properties - 'is_crown_jewel'
 WHERE properties ? 'is_crown_jewel';

ALTER TABLE assets ALTER COLUMN is_crown_jewel SET DEFAULT FALSE;
ALTER TABLE assets ALTER COLUMN is_crown_jewel SET NOT NULL;

-- idx_assets_crown_jewel (000126, (tenant_id, is_crown_jewel) WHERE
-- is_crown_jewel = TRUE) already serves the readers and is kept as it is, so
-- this migration builds no index under a write lock.
--
-- Locks: the backfills touch only rows that carry the key or a NULL flag;
-- SET NOT NULL scans assets once under an ACCESS EXCLUSIVE lock (no rewrite).

COMMENT ON COLUMN assets.is_crown_jewel IS
    'Crown-jewel flag (the only source). Written by PATCH /assets/{id}/crown-jewel; never taken from properties.';
