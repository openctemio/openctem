ALTER TABLE version_check_state ADD COLUMN IF NOT EXISTS keyset_version bigint NOT NULL DEFAULT 0;
