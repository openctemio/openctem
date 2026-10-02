-- =============================================================================
-- Migration 000054 DOWN: Remove Seeded SPDX Licenses
-- =============================================================================

DELETE FROM licenses WHERE spdx_id IS NOT NULL;
