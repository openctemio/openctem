### Behaviour change: SLA is always on

- SLA is now a core module. Every finding carries an SLA deadline that the findings
  list, dashboards, My Work, exports, reports and escalation use, but switching the
  SLA module off only hid the policy page and made the policy reads
  (`/api/v1/sla-policies`, `/api/v1/assets/{id}/sla-policy`) answer
  `MODULE_NOT_ENABLED` while SLA badges stayed visible. The SLA toggle is gone from
  Settings > Modules; reading and editing policies still needs the SLA permissions.
- Migration 001392 marks the module core and removes the organizations' SLA overrides.
