### Behaviour change: scope entries need approval only under Strict scan approval

- New organization setting **Scan approval**: Off (default), On or Strict
  (RFC-073). Owner only, with step-up re-authentication and a reason;
  approval rules (intensity, tools, asset tags, criticality, crown jewels,
  selectors, blast radius, schedule, sensor placement, zone) with Light,
  Standard and Strict presets. `GET/PUT /api/v1/organization/settings/scan-governance`.
- In Off and On a scope widening takes effect without a second person (the
  RFC-054 §7 approvals and the sole-owner self-approval apply in Strict
  only). Step-up, the dry run, member requests, exclusions, ownership proof,
  the deny list, audit and notifications are unchanged in every mode.
  Entries already pending stay pending until approved or withdrawn.
- The platform approval policy now governs scan approval:
  `/api/v1/admin/settings/scan-approval-policy` and
  `/api/v1/admin/tenants/{id}/scan-approval-policy` replace the
  `scope-policy` routes; the body field is `policy` (`tenant_controlled`,
  `off`, `on`, `strict`). Migration `001830` renames
  `tenants.scope_approval_policy` to `scan_approval_policy`.
- **Upgrade note:** an organization override of `disabled` becomes `off`;
  `required` and `tenant_controlled` overrides and a stored platform default
  are cleared (organizations start Off and their owner chooses). To keep
  approvals for an organization, its owner sets Strict, or a platform
  administrator forces `strict`.

### Security: job signer floor for intrusive scope entries

- The signer's fixed minimum of one approval for a t2 entry becomes the
  operator setting `SIGNER_LEDGER_T2_MIN_APPROVALS` (0 to 2, default 0).
- **Upgrade note:** operators running the signer who want recorded
  approvals for every organization set `SIGNER_LEDGER_MIN_APPROVALS` /
  `SIGNER_LEDGER_T2_MIN_APPROVALS` and force Strict scan approval.
