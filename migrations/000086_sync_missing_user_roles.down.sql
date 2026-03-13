-- Down migration: no-op
-- Cannot safely remove synced user_roles without knowing which were added by this migration
-- vs. which existed before. The data is idempotent and harmless.
SELECT 1;
