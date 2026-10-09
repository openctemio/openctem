### Fixed: every permission can be granted from the role editor

- The role editor listed permissions under modules through a hand-kept map to module ids
  that do not exist (`validation`, `campaigns`, `risk`), so pentest, SLA and remediation
  permissions were hidden even with their modules on; and the API dropped permissions
  whose module was empty or retired (`ctem:*` cycles, business services, attacker
  profiles, compensating controls, priority rules; `attack_surface:scope:*`), so they
  could not be granted from the console at all. Migration 001524 files every permission
  under a live module and the editor compares real module ids. The roles list counts
  every permission a role holds.

### Removed: module switches that switched nothing

- Migration 001524 deletes the retired or inactive modules (billing, licensing, platform,
  subscription, usage, policies, scope, secrets, sources, webhooks,
  integrations.webhooks) and the ones that gated nothing: `vulnerabilities`, `commands`
  and `remediation_tasks` (the remediation pages now follow `remediation`, like their
  API). Their organization overrides are removed.
- Sensors, groups, API keys, notification settings, integrations and
  integrations.notifications are core: the toggle API already refused to switch them off,
  and the settings page showed a switch that failed on save.
