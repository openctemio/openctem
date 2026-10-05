### Removed: database objects nothing used

- Migration 001056 drops objects that had no reader or writer, all verified
  empty or unreferenced: the `deprecated` schema and its seven quarantined
  tables (000213), `webhook_deliveries` (outbound webhooks never delivered;
  the `webhooks` table stays for now), the views `v_assets_domain_summary`,
  `v_assets_http_services` and `v_assets_ip_summary`, and ten functions with
  no caller (`user_has_permission`, `get_user_permissions`,
  `user_has_full_data_access`, `expire_scope_exclusions`,
  `expire_suppression_rules`, `cleanup_old_audit_logs`,
  `can_tool_scan_asset_type`, `get_compatible_asset_types`,
  `refresh_access_for_direct_owner_add/_remove`). The down migration
  recreates them as they were.
- **Upgrade note:** none for the application. An external script or report
  that queried one of these views or functions directly stops working.
