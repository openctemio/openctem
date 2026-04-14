-- =============================================================================
-- Migration 000133: Fix subdomains incorrectly typed as 'domain'
-- =============================================================================
-- Detects subdomains by checking if a parent root domain exists in the system.
-- A domain X is a subdomain if another domain Y exists where X ends with '.Y'
-- and Y has fewer dots (is a shorter/higher-level domain).
-- =============================================================================

-- Fix: assets typed as 'domain' that are actually subdomains
-- (they have a parent domain in the same tenant)
UPDATE assets a1
SET asset_type = 'subdomain'
WHERE a1.asset_type = 'domain'
  AND EXISTS (
    SELECT 1 FROM assets a2
    WHERE a2.tenant_id = a1.tenant_id
      AND a2.asset_type = 'domain'
      AND a2.id != a1.id
      AND a1.name LIKE '%.' || a2.name
      AND length(a2.name) < length(a1.name)
  );
