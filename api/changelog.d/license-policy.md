### Added: organization license policy and license findings

- `GET/PUT /api/v1/organization/settings/license-policy` (`settings:read` / `settings:write`, audited): allow, review or deny per SPDX license id (optionally WITH an exception) or license category, optionally limited to dependency scopes; a verdict for known licenses no rule matches and one for unknown or missing licenses; an opt-in for review findings.
- Declared licenses are evaluated as SPDX expressions (`MIT OR GPL-3.0-only` passes when MIT is allowed; AND needs every term). The verdict is stored on each package link and re-evaluated on every policy change and every package write (sensor, CI, SBOM import).
- A deny verdict opens a high finding (`source = sca`, type `license`), a review verdict a medium one when opted in, per asset, package and declared licenses; findings the policy no longer flags, or whose package went away, are resolved, and reopen when flagged again.
- Migration `001841_license_policy` adds `asset_software.license_verdict` / `license_rule` and the `license` finding type (constraint added NOT VALID, then validated).
