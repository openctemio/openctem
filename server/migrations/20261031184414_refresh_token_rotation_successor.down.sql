ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS rotated_fingerprint;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS successor_id;
