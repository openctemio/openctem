-- Identity explanation (docs/architecture/deduplication.md, "Why a finding is
-- one"): the recipe that keyed a finding and the NAMES of the fields its key
-- was built from, in recipe order. Values are never stored here: the asset id,
-- secret HMAC, path or snippet hash stay inside identity_key only.
--
-- identity_algo: "v2/<kind>" for a version-2 key, "v1/ingest", "manual/v1",
-- "pentest/v1" for the version-1 producers. Set at every keying; NULL on rows
-- keyed before this migration (a version-2 row derives both from
-- identity_key at read time, a version-1 row without it reads as legacy).
--
-- Live impact: two nullable columns without a default (catalog-only change,
-- no table rewrite) and two CHECK constraints added NOT VALID, then
-- validated under a SHARE UPDATE EXCLUSIVE lock (every row is NULL). No
-- backfill.
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS identity_algo varchar(48),
    ADD COLUMN IF NOT EXISTS identity_fields text[];

ALTER TABLE findings
    ADD CONSTRAINT chk_findings_identity_algo
    CHECK (identity_algo ~ '^[a-z0-9:/_-]{1,48}$') NOT VALID;
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_identity_algo;

ALTER TABLE findings
    ADD CONSTRAINT chk_findings_identity_fields
    CHECK (cardinality(identity_fields) <= 16) NOT VALID;
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_identity_fields;
