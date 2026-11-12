### Removed: module switches that did nothing, and the switches of two modules that must always apply

- Settings > Modules no longer lists, and the registry no longer has, Risk Analysis, SBOM Export, Tools, Scan Profiles and the integration sub-modules (they gated no route, job or tool), nor Business Impact, Crown Jewels, CTEM Maturity, Executive Summary and MITRE Coverage (they hid a console page only): each page now follows the module of its parent. Their permissions and event types move to the parent; an organization's old switch for a retired module is dropped.
- Risk scoring and suppressions are always on. An organization that had switched Suppressions off does not get its rules muting again: the upgrade deactivates its approved rules (status expired, marked `deactivated_by_migration`, restored by the down migration), and the organization can approve rules again; no audit-log row is written by the migration (the log is hash-chained by the application), so this note is the record; an organization that had switched Risk Scoring off keeps the settings page.
- AI triage is not a switch on Settings > Modules (Settings > AI owns whether AI runs); an organization that had switched it off keeps AI triage off (the choice moves to its AI settings, triage use case off), and the module stays an entitlement only.

### Added: installation-wide modules

- A module can have `scope: platform` in the registry: the platform administrator's switch, off for every organization while the platform has it off, answered as `403 MODULE_NOT_ENABLED` with `reason: disabled_by_platform`. No module uses it yet.

### Fixed: MCP read tools work during the read-only grace of a module

- Read tools and prompts of a module in its read-only grace answer as the GET routes do; tools that change data stay refused.
