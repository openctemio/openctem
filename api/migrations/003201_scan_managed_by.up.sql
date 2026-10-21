-- Scans the platform itself owns (continuous coverage, automatic enrichment).
-- They are identified by (managed_by, managed_key), never by name, so a
-- member's scan that happens to carry a coverage scan's name is never adopted.
-- Both columns are nullable without a default: no table rewrite.
ALTER TABLE scans
    ADD COLUMN managed_by text NULL,
    ADD COLUMN managed_key text NULL;

ALTER TABLE scans
    ADD CONSTRAINT scans_managed_by_check CHECK (
        (managed_by IS NULL AND managed_key IS NULL)
        OR (managed_by IN ('coverage', 'enrichment') AND managed_key IS NOT NULL AND managed_key <> '')
    );

-- Backfill only ownerless rows (created_by IS NULL): a scan a person created
-- or took over is a person's scan even when it carries the platform's name or tag.
UPDATE scans
   SET managed_by = 'coverage',
       managed_key = substr(name, length('Continuous coverage: ') + 1)
 WHERE created_by IS NULL
   AND managed_by IS NULL
   AND tags @> ARRAY['auto-coverage']::text[]
   AND name LIKE 'Continuous coverage: %'
   AND length(name) > length('Continuous coverage: ');

UPDATE scans
   SET managed_by = 'enrichment',
       managed_key = id::text
 WHERE created_by IS NULL
   AND managed_by IS NULL
   AND tags @> ARRAY['auto-enrichment']::text[];

CREATE UNIQUE INDEX scans_managed_key
    ON scans (tenant_id, managed_by, managed_key)
    WHERE managed_by IS NOT NULL;
