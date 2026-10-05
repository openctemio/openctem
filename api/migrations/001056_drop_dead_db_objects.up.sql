-- Drop database objects that nothing reads or writes (legacy cleanup, wave 1).
--
-- Every object below was checked on a restore of production data migrated to
-- develop head and against api/, web/, the sensor and sdk-go sources:
--
--   * The `deprecated` schema: seven tables quarantined by 000213 (agent-era
--     metrics, audit and registration tables, email_logs, threat_actor_cves,
--     finding_regression_events, scan_profile_template_sources). 0 rows each,
--     no reader since 000213. The finding merge stops rewriting
--     deprecated.finding_regression_events in the same change.
--   * webhook_deliveries: 0 rows, never written (the outbound webhooks feature
--     never had a delivery worker and was removed by 001032). The `webhooks`
--     table itself still holds configuration rows and stays for now.
--   * v_assets_domain_summary, v_assets_http_services, v_assets_ip_summary:
--     no reader; they filter on asset types the registry no longer stores.
--   * Ten functions with no caller (code, function body, trigger, policy,
--     column default or view): permission helpers superseded by the Go
--     authorization layer, expiry helpers nothing schedules, asset-type
--     compatibility helpers superseded by the type registry, and the owner
--     scope refresh helpers made inert by 000372 (ownership is not a scope
--     grant).
--
-- Tenant isolation: unchanged. The dropped tables take their own (shadow)
-- RLS policies with them; no policy on a remaining table is touched.

DROP TABLE IF EXISTS deprecated.agent_audit_logs;
DROP TABLE IF EXISTS deprecated.agent_metrics;
DROP TABLE IF EXISTS deprecated.email_logs;
DROP TABLE IF EXISTS deprecated.finding_regression_events;
DROP TABLE IF EXISTS deprecated.registration_tokens;
DROP TABLE IF EXISTS deprecated.scan_profile_template_sources;
DROP TABLE IF EXISTS deprecated.threat_actor_cves;
-- RESTRICT: fails if anything unexpected was put in the schema.
DROP SCHEMA IF EXISTS deprecated RESTRICT;

DROP TABLE IF EXISTS public.webhook_deliveries;

DROP VIEW IF EXISTS public.v_assets_domain_summary;
DROP VIEW IF EXISTS public.v_assets_http_services;
DROP VIEW IF EXISTS public.v_assets_ip_summary;

DROP FUNCTION IF EXISTS public.can_tool_scan_asset_type(text[], text);
DROP FUNCTION IF EXISTS public.cleanup_old_audit_logs(integer);
DROP FUNCTION IF EXISTS public.expire_scope_exclusions();
DROP FUNCTION IF EXISTS public.expire_suppression_rules();
DROP FUNCTION IF EXISTS public.get_compatible_asset_types(text[]);
DROP FUNCTION IF EXISTS public.get_user_permissions(uuid, uuid);
DROP FUNCTION IF EXISTS public.refresh_access_for_direct_owner_add(uuid, uuid, character varying);
DROP FUNCTION IF EXISTS public.refresh_access_for_direct_owner_remove(uuid, uuid);
DROP FUNCTION IF EXISTS public.user_has_full_data_access(uuid, uuid);
DROP FUNCTION IF EXISTS public.user_has_permission(uuid, uuid, character varying);
