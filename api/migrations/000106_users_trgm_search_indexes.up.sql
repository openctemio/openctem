-- =============================================================================
-- Migration 106: Trigram indexes on users(name, email) for member picker.
--
-- The owner picker (asset detail sheet → Add Owner) does a server-side
-- ILIKE search on members.name and members.email. With only the existing
-- btree index on users(email), `ILIKE '%query%'` falls back to a sequential
-- scan once the user table grows past a few thousand rows. This migration
-- adds GIN trigram indexes which support arbitrary-position substring
-- matches in O(log n) time.
--
-- The pg_trgm extension is already enabled in 000001_extensions.up.sql so
-- we do not need to CREATE EXTENSION here.
--
-- NOTE on CONCURRENTLY: golang-migrate wraps each migration file in a
-- transaction, and `CREATE INDEX CONCURRENTLY` cannot run inside a
-- transaction block (it errors with "cannot run inside a transaction
-- block"). For OSS deployments the users table is small at startup so
-- the brief ACCESS EXCLUSIVE lock from a non-concurrent build is
-- acceptable. For large existing deployments, you should build these
-- indexes manually with CONCURRENTLY *before* running this migration:
--
--     psql ... -c "CREATE INDEX CONCURRENTLY idx_users_name_trgm  \
--                   ON users USING GIN (name gin_trgm_ops);"
--     psql ... -c "CREATE INDEX CONCURRENTLY idx_users_email_trgm \
--                   ON users USING GIN (email gin_trgm_ops);"
--
-- then this migration's IF NOT EXISTS clauses will be no-ops.
-- =============================================================================

-- Substring search on display name
CREATE INDEX IF NOT EXISTS idx_users_name_trgm
    ON users
    USING GIN (name gin_trgm_ops);

-- Substring search on email. We keep the existing btree idx_users_email
-- (it's optimal for exact equality lookups during auth) and add the
-- trigram one alongside it for the LIKE-based search path.
CREATE INDEX IF NOT EXISTS idx_users_email_trgm
    ON users
    USING GIN (email gin_trgm_ops);
