-- Technologies view of the external attack surface (docs/architecture/easm.md):
-- the vendor and CPE 2.3 name a fingerprinting tool reported for a technology.
-- Both nullable: most detections carry neither, and the read side falls back
-- to the vendor of the software product the technology was matched to.
--
-- Adding nullable columns without a default is a catalog-only change: no table
-- rewrite, no backfill, and only a brief ACCESS EXCLUSIVE lock; the checks are
-- validated afterwards without blocking writes.
ALTER TABLE asset_technologies
    ADD COLUMN vendor VARCHAR(128),
    ADD COLUMN cpe    VARCHAR(512),
    ADD CONSTRAINT chk_asset_technologies_vendor CHECK (vendor IS NULL OR length(vendor) > 0) NOT VALID,
    ADD CONSTRAINT chk_asset_technologies_cpe CHECK (cpe IS NULL OR cpe LIKE 'cpe:2.3:%') NOT VALID;
-- Every existing row is NULL in both; validating under the weaker lock.
ALTER TABLE asset_technologies VALIDATE CONSTRAINT chk_asset_technologies_vendor;
ALTER TABLE asset_technologies VALIDATE CONSTRAINT chk_asset_technologies_cpe;

COMMENT ON COLUMN asset_technologies.vendor IS
    'Vendor the tool reported (from its CPE); NULL when unknown. The Technologies view falls back to the matched software product''s vendor.';
COMMENT ON COLUMN asset_technologies.cpe IS
    'CPE 2.3 name the tool reported, lower case; NULL when it gave none.';
