### Added: 30 days of read-only access after losing a module

- When an organization loses a module (its plan changes, the plan's modules are narrowed, a
  platform administrator denies it, or a trial grant expires), it keeps read access for 30
  days: pages and GET exports work, changes are refused with `MODULE_NOT_ENABLED` reason
  `read_only_grace`, and the module's jobs, automations and MCP tools stop at once. The
  module's pages show "Read-only until <date>", Settings > Modules shows the same badge, and
  Console > Organizations > Plan > Modules lists it as "Read-only" with the end date.
- Getting the module back ends the grace; after 30 days it is off (`not_entitled`). Data is
  never deleted.
- Migration 001632 adds `tenant_module_grace`.
