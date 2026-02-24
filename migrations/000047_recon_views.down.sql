-- =============================================================================
-- Migration 000047 DOWN: Drop Recon Summary Views
-- =============================================================================

DROP VIEW IF EXISTS v_assets_http_services;
DROP VIEW IF EXISTS v_assets_ip_summary;
DROP VIEW IF EXISTS v_assets_domain_summary;
