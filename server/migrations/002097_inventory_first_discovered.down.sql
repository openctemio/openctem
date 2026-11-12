-- Back to the review queue: discovered meant exactly an automatic
-- needs_review record before this migration.
UPDATE asset_attributions SET state = 'needs_review', updated_at = now()
WHERE state = 'discovered';

ALTER TABLE asset_attributions DROP CONSTRAINT chk_asset_attributions_state;
ALTER TABLE asset_attributions
    ADD CONSTRAINT chk_asset_attributions_state
        CHECK (state IN ('confirmed', 'needs_review', 'candidate', 'dependency', 'monitor_only', 'rejected'));
