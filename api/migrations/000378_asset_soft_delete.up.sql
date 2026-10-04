-- =============================================================================
-- Migration 000378: safe asset delete
-- =============================================================================
-- Owner decision O3 (research 12, 2026-10-03). Deleting an asset used to hard
-- delete it, and findings.asset_id ON DELETE CASCADE erased every finding of
-- the asset: its history, SLA evidence and remediation records, in one click.
--
-- From now on:
--   * a person's delete (API and UI) of an asset that has findings is refused
--     (409) with Archive offered instead;
--   * an asset without findings is soft-deleted: deleted_at / deleted_by are
--     set, it disappears from every read, and its name is freed (see the asset
--     repository's SoftDelete) so the same name can be created again;
--   * a retention job purges soft-deleted assets after a grace period;
--   * findings can no longer be cascade-deleted by an asset delete: the
--     foreign key becomes NO ACTION. NO ACTION, not RESTRICT: it is checked at
--     the end of the statement, so deleting a tenant (which cascades to its
--     assets AND its findings in one statement) keeps working, while deleting
--     an asset that still has findings fails.
--
-- Live-database safety:
--   * ADD COLUMN with no default is a catalog-only change;
--   * the new foreign key is added NOT VALID (no scan of findings) and swapped
--     in one transaction; 000379 validates it without blocking writes;
--   * lock_timeout makes the brief ACCESS EXCLUSIVE / SHARE ROW EXCLUSIVE
--     locks fail fast instead of queueing behind a long transaction.
-- =============================================================================

SET lock_timeout = '5s';

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted_by UUID REFERENCES users(id) ON DELETE SET NULL;

COMMENT ON COLUMN assets.deleted_at IS
    'Soft delete: set when a person deletes an asset that has no findings. A deleted asset is excluded from every read and purged after the retention period.';
COMMENT ON COLUMN assets.deleted_by IS 'User who deleted the asset (soft delete).';

ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_asset_id_fkey;
ALTER TABLE findings
    ADD CONSTRAINT findings_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE NO ACTION NOT VALID;

RESET lock_timeout;
