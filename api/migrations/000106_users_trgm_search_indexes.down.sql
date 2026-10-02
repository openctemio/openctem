-- =============================================================================
-- Migration 106 (down): drop the trigram indexes added for member search.
-- Non-concurrent for the same golang-migrate transaction-wrap reason as
-- the .up.sql.
-- =============================================================================

DROP INDEX IF EXISTS idx_users_email_trgm;
DROP INDEX IF EXISTS idx_users_name_trgm;
