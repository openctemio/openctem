-- SLA becomes a core module.
--
-- Every finding carries an SLA deadline, computed at ingest from the
-- organization policy (or the platform defaults) and read by the findings
-- list and detail, dashboards, My Work, exports, reports and the escalation
-- job. The sla module only gated the policy settings page and its API, so an
-- organization that switched it off still saw SLA badges and "Overdue SLA"
-- everywhere while the policy read behind them returned MODULE_NOT_ENABLED.
-- A module gates a surface it owns; it cannot switch off an attribute of a
-- core object. SLA is therefore core: always on, not toggleable.
--
-- Idempotent.

UPDATE modules SET is_core = TRUE, is_active = TRUE WHERE id = 'sla';

-- A disabled override is ignored for a core module anyway; drop it so the
-- settings page and the stored state agree.
DELETE FROM tenant_modules WHERE module_id = 'sla';
