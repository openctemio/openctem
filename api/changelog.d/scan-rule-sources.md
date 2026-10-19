### Added: rule sources for scans and scan profiles

- A scan and a scan profile choose which detection rules run: `both` (default), `platform` or `tenant` (`rule_sources` on `POST/PUT /api/v1/scans` and `/api/v1/scan-profiles`). A scan without its own setting inherits its profile's. Migration `003137` adds `scan_profiles.rule_sources` (default `both`) and `scans.rule_sources` (NULL = inherit); no backfill.
- Every scan command carries the run's `rule_sources`. A tenant-only command is claimable only by a sensor that reports `rule.sources@1`; the placement view names `rule_sources_unsupported` for others. A platform-only run sends no custom templates.
- The rule sources a run uses (the scan's, else its profile's) are part of the scan's approval definition, so a profile edit cannot widen an approved scan to the organization's templates; `both` is left out, so existing approvals keep matching.

### Behaviour change: custom templates that cannot be resolved fail the run

- When a run is to use the organization's templates, a named template that is missing, belongs to another organization, is malformed or not active now fails the run with the template names (`CUSTOM_TEMPLATES_UNRESOLVED`) instead of the scan running without it. Fix the scan's template list, or set its rule sources to `platform`.
