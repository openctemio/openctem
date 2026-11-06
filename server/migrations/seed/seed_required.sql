-- =============================================================================
-- Required Seed Data
-- =============================================================================
-- This file contains required data that must exist for the application to work.
-- Core data (roles, permissions, modules, plans) is already handled by migrations.
-- This file is for any additional required data not covered by migrations.
--
-- Usage:
--   psql -f /seed/seed_required.sql
-- =============================================================================

-- Verify core data exists (sanity check)
DO $$
BEGIN
    -- Check that roles exist
    IF NOT EXISTS (SELECT 1 FROM roles LIMIT 1) THEN
        RAISE WARNING 'No roles found - migrations may not have run';
    END IF;

    -- Check that permissions exist
    IF NOT EXISTS (SELECT 1 FROM permissions LIMIT 1) THEN
        RAISE WARNING 'No permissions found - migrations may not have run';
    END IF;

    -- Check that modules exist
    IF NOT EXISTS (SELECT 1 FROM modules LIMIT 1) THEN
        RAISE WARNING 'No modules found - migrations may not have run';
    END IF;

    RAISE NOTICE 'Required seed data verification complete';
END $$;
