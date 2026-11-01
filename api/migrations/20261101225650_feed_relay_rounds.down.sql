UPDATE version_check_state SET origin = 'import' WHERE origin = 'relay';
ALTER TABLE version_check_state DROP CONSTRAINT IF EXISTS chk_version_check_state_origin;
ALTER TABLE version_check_state ADD CONSTRAINT chk_version_check_state_origin
    CHECK (origin IS NULL OR origin IN ('online', 'import'));
DROP TABLE IF EXISTS feed_relay_rounds;
