-- =============================================================================
-- Migration 000055 DOWN: Remove Additional Capabilities + Tool-Capability Links
-- =============================================================================

-- Remove ALL built-in tool-capability links (both core and recon tools)
DELETE FROM tool_capabilities
WHERE tool_id IN (
    SELECT id FROM tools
    WHERE tenant_id IS NULL AND is_builtin = TRUE
);

-- Remove recon tools
DELETE FROM tools
WHERE tenant_id IS NULL
  AND name IN ('subfinder', 'dnsx', 'naabu', 'httpx', 'katana');

-- Remove the capabilities themselves
DELETE FROM capabilities
WHERE tenant_id IS NULL
  AND name IN ('dns', 'tech_detect', 'url_discovery', 'api', 'cloud',
               'mobile', 'compliance', 'security_analysis',
               'pipeline', 'reporting', 'ai_triage');
