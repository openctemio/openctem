-- =============================================================================
-- RLS (Row Level Security) Test Script
-- =============================================================================
-- Run this script to verify tenant isolation is working correctly.
-- Usage: psql -U openctem -d openctem -f scripts/test_rls.sql
-- =============================================================================

\echo '=============================================='
\echo 'RLS TEST SCRIPT - Tenant Isolation Verification'
\echo '=============================================='
\echo ''

-- =============================================================================
-- SETUP: Create test user (non-superuser) if not exists
-- =============================================================================
\echo '>>> Setting up test environment...'

DO $$
BEGIN
    -- Create non-superuser for testing (superusers bypass RLS)
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rls_test_user') THEN
        CREATE ROLE rls_test_user LOGIN PASSWORD 'test_password_123';
        RAISE NOTICE 'Created rls_test_user role';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE openctem TO rls_test_user;
GRANT USAGE ON SCHEMA public TO rls_test_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rls_test_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO rls_test_user;

\echo 'Test user setup complete.'
\echo ''

-- =============================================================================
-- TEST 1: Verify RLS is enabled on all tenant-scoped tables
-- =============================================================================
\echo '>>> TEST 1: RLS Enabled Status'
\echo '----------------------------------------------'

SELECT
    tablename,
    CASE WHEN rowsecurity THEN '✅ ENABLED' ELSE '❌ DISABLED' END as rls_status
FROM pg_tables
WHERE schemaname = 'public'
AND tablename IN ('findings', 'assets', 'scans', 'agents', 'exposure_events',
                  'integrations', 'suppression_rules', 'finding_activities')
ORDER BY tablename;

\echo ''

-- =============================================================================
-- TEST 2: Verify all policies exist
-- =============================================================================
\echo '>>> TEST 2: Policy Verification'
\echo '----------------------------------------------'

SELECT
    tablename,
    policyname,
    CASE
        WHEN policyname LIKE 'tenant_isolation%' THEN '🔒 Tenant Isolation'
        WHEN policyname LIKE 'platform_admin%' THEN '👑 Admin Bypass'
        ELSE '❓ Unknown'
    END as policy_type
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;

\echo ''

-- =============================================================================
-- TEST 3: Verify helper functions exist
-- =============================================================================
\echo '>>> TEST 3: Helper Functions'
\echo '----------------------------------------------'

SELECT
    proname as function_name,
    CASE
        WHEN proname = 'current_tenant_id' THEN 'Returns UUID of current tenant from session'
        WHEN proname = 'is_platform_admin' THEN 'Returns true if session is platform admin'
        ELSE 'Unknown'
    END as description
FROM pg_proc
WHERE proname IN ('current_tenant_id', 'is_platform_admin');

\echo ''

-- =============================================================================
-- TEST 4: Get test data info
-- =============================================================================
\echo '>>> TEST 4: Test Data Summary (as superuser)'
\echo '----------------------------------------------'

SELECT
    'findings' as table_name,
    COUNT(*) as total_rows,
    COUNT(DISTINCT tenant_id) as tenant_count
FROM findings
UNION ALL
SELECT 'assets', COUNT(*), COUNT(DISTINCT tenant_id) FROM assets
UNION ALL
SELECT 'scans', COUNT(*), COUNT(DISTINCT tenant_id) FROM scans
UNION ALL
SELECT 'agents', COUNT(*), COUNT(DISTINCT tenant_id) FROM agents;

\echo ''

-- Get a valid tenant ID for testing
\echo '>>> Finding tenant with data for testing...'
SELECT tenant_id, COUNT(*) as finding_count
FROM findings
GROUP BY tenant_id
ORDER BY COUNT(*) DESC
LIMIT 1 \gset test_

\echo ''
\echo 'Test tenant ID: ' :test_tenant_id
\echo 'Finding count: ' :test_finding_count
\echo ''

-- =============================================================================
-- TEST 5-9: RLS Behavior Tests (run as non-superuser)
-- =============================================================================
\echo '=============================================='
\echo 'SWITCHING TO NON-SUPERUSER FOR RLS TESTS'
\echo '=============================================='
\echo ''

\c openctem rls_test_user

-- TEST 5: No tenant context
\echo '>>> TEST 5: No Tenant Context (should return 0)'
\echo '----------------------------------------------'
SELECT
    'findings' as table_name,
    COUNT(*) as row_count,
    CASE WHEN COUNT(*) = 0 THEN '✅ PASS' ELSE '❌ FAIL' END as status
FROM findings
UNION ALL
SELECT 'assets', COUNT(*), CASE WHEN COUNT(*) = 0 THEN '✅ PASS' ELSE '❌ FAIL' END FROM assets
UNION ALL
SELECT 'scans', COUNT(*), CASE WHEN COUNT(*) = 0 THEN '✅ PASS' ELSE '❌ FAIL' END FROM scans;

\echo ''

-- TEST 6: With wrong tenant ID
\echo '>>> TEST 6: Wrong Tenant ID (should return 0)'
\echo '----------------------------------------------'
SET app.current_tenant_id = '00000000-0000-0000-0000-000000000000';
SELECT
    'findings' as table_name,
    COUNT(*) as row_count,
    CASE WHEN COUNT(*) = 0 THEN '✅ PASS' ELSE '❌ FAIL' END as status
FROM findings;
RESET app.current_tenant_id;

\echo ''

-- TEST 7: With valid tenant ID
\echo '>>> TEST 7: Valid Tenant ID (should return data)'
\echo '----------------------------------------------'
-- Note: Using the tenant ID we found earlier
SET app.current_tenant_id = 'f59577a2-4364-4680-a7ea-faef71ce66c8';
SELECT
    'findings' as table_name,
    COUNT(*) as row_count,
    CASE WHEN COUNT(*) > 0 THEN '✅ PASS' ELSE '⚠️ NO DATA' END as status
FROM findings;
RESET app.current_tenant_id;

\echo ''

-- TEST 8: Platform admin bypass
\echo '>>> TEST 8: Platform Admin Bypass (should see all data)'
\echo '----------------------------------------------'
SET app.is_platform_admin = 'true';
SELECT
    'findings' as table_name,
    COUNT(*) as row_count,
    CASE WHEN COUNT(*) > 0 THEN '✅ PASS' ELSE '⚠️ NO DATA' END as status
FROM findings;
RESET app.is_platform_admin;

\echo ''

-- TEST 9: Context reset verification
\echo '>>> TEST 9: Context Reset (should return 0 again)'
\echo '----------------------------------------------'
SELECT
    'findings' as table_name,
    COUNT(*) as row_count,
    CASE WHEN COUNT(*) = 0 THEN '✅ PASS' ELSE '❌ FAIL' END as status
FROM findings;

\echo ''

-- =============================================================================
-- TEST 10: INSERT with tenant isolation
-- =============================================================================
\echo '>>> TEST 10: INSERT Restriction Test'
\echo '----------------------------------------------'

-- Try to insert without tenant context (should fail or insert NULL tenant)
\echo 'Attempting INSERT without tenant context...'

DO $$
BEGIN
    -- This should fail because tenant_id would be NULL
    INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint)
    VALUES (
        gen_random_uuid(),
        current_setting('app.current_tenant_id', true)::uuid,  -- Will be NULL
        '00000000-0000-0000-0000-000000000000'::uuid,
        'test',
        'rls_test',
        'Test finding',
        'low',
        'open',
        'test_fingerprint_' || gen_random_uuid()::text
    );
    RAISE NOTICE '❌ FAIL: INSERT succeeded without tenant context';
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE '✅ PASS: INSERT blocked - %', SQLERRM;
END
$$;

\echo ''

-- =============================================================================
-- SUMMARY
-- =============================================================================
\echo '=============================================='
\echo 'RLS TEST SUMMARY'
\echo '=============================================='
\echo ''
\echo 'If all tests show ✅ PASS, RLS is working correctly.'
\echo ''
\echo 'Key behaviors verified:'
\echo '  1. Tables have RLS enabled'
\echo '  2. Policies exist for tenant isolation'
\echo '  3. Policies exist for platform admin bypass'
\echo '  4. No data visible without tenant context'
\echo '  5. Wrong tenant sees no data'
\echo '  6. Correct tenant sees their data'
\echo '  7. Platform admin sees all data'
\echo '  8. Context reset blocks access again'
\echo ''
\echo '=============================================='

-- Switch back to superuser
\c openctem openctem
