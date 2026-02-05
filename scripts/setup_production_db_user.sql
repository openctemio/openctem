-- =============================================================================
-- Production Database User Setup
-- =============================================================================
-- This script creates a non-superuser for application connections.
-- CRITICAL: RLS (Row Level Security) only works with non-superuser connections!
--
-- Usage: psql -U postgres -d exploop -f scripts/setup_production_db_user.sql
--
-- After running this script, update your DATABASE_URL:
--   DATABASE_URL=postgres://exploop_app:YOUR_PASSWORD@host:5432/exploop
-- =============================================================================

\echo '=============================================='
\echo 'Creating Production Application User'
\echo '=============================================='
\echo ''

-- =============================================================================
-- Step 1: Create Application User (Non-Superuser)
-- =============================================================================
\echo '>>> Step 1: Creating exploop_app user...'

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'exploop_app') THEN
        -- IMPORTANT: Change this password in production!
        CREATE ROLE exploop_app LOGIN PASSWORD 'change-me-in-production';
        RAISE NOTICE 'Created exploop_app role';
    ELSE
        RAISE NOTICE 'exploop_app role already exists';
    END IF;
END
$$;

\echo ''

-- =============================================================================
-- Step 2: Grant Database Access
-- =============================================================================
\echo '>>> Step 2: Granting database access...'

-- Connect to database
GRANT CONNECT ON DATABASE exploop TO exploop_app;

-- Schema access
GRANT USAGE ON SCHEMA public TO exploop_app;

\echo ''

-- =============================================================================
-- Step 3: Grant Table Permissions
-- =============================================================================
\echo '>>> Step 3: Granting table permissions (SELECT, INSERT, UPDATE, DELETE)...'

-- Grant on all existing tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO exploop_app;

-- Grant on all existing sequences (for auto-increment/serial columns)
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO exploop_app;

\echo ''

-- =============================================================================
-- Step 4: Set Default Privileges for Future Objects
-- =============================================================================
\echo '>>> Step 4: Setting default privileges for future objects...'

-- Ensure future tables created by superuser also grant to app user
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO exploop_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE ON SEQUENCES TO exploop_app;

\echo ''

-- =============================================================================
-- Step 5: Verify Setup
-- =============================================================================
\echo '>>> Step 5: Verifying setup...'
\echo ''

\echo 'User superuser status:'
SELECT rolname, rolsuper,
    CASE WHEN rolsuper THEN '❌ SUPERUSER (RLS BYPASSED!)' ELSE '✅ Non-superuser (RLS ENFORCED)' END as rls_status
FROM pg_roles
WHERE rolname IN ('exploop', 'exploop_app')
ORDER BY rolname;

\echo ''
\echo 'User privileges on schema:'
SELECT grantee, privilege_type
FROM information_schema.usage_privileges
WHERE object_schema = 'public' AND grantee = 'exploop_app';

\echo ''

-- =============================================================================
-- Summary
-- =============================================================================
\echo '=============================================='
\echo 'SETUP COMPLETE'
\echo '=============================================='
\echo ''
\echo 'Next steps:'
\echo '  1. Change the password for exploop_app in production:'
\echo '     ALTER ROLE exploop_app PASSWORD ''your-secure-password'';'
\echo ''
\echo '  2. Update your DATABASE_URL:'
\echo '     DATABASE_URL=postgres://exploop_app:YOUR_PASSWORD@host:5432/exploop'
\echo ''
\echo '  3. Verify RLS is working by connecting as exploop_app and running:'
\echo '     SELECT COUNT(*) FROM findings;  -- Should return 0 without tenant context'
\echo ''
\echo '=============================================='
