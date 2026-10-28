### Behaviour change: ownership confirmation applies only to platform sensors of the hosted service

- Ownership confirmation of discovered assets and the wildcard-only restriction now apply only when `MANAGED_SERVICE` is true and the job runs on platform (shared) sensors. On the tenant's own sensors, and on self-hosted installs on any sensor, discovered and unclassified assets are treated as fully authorized (like `unclassified_scans: full`), and a wildcard-only name covered by an active scope entry is scanned. Rejected assets, scope exclusions, the deny list and the guardrails still refuse everywhere.
- The decision is made per job: scan create, update, clone, import and quick scan, run start, workflow runs, follow-on stages, the dry run, coverage scans and the claim-time re-check all judge the placement of the job (a job that auto placement sends to a tenant sensor is not refused; one sent to a platform sensor is checked).
- A derived name that resolves only through a wildcard record now has its own reason in a run's stage lanes (`wildcard_only`), instead of `unconfirmed`.

### Added: confirm ownership of a skipped group in one step

- `POST /easm/candidates/decisions` accepts `asset_names`: the organization's own assets named by name, alongside `asset_ids` (200 together). Same `assets:write` permission, data scope and audit as confirming one asset.
- A skipped-targets group of unconfirmed or wildcard-only names offers **Confirm ownership** and says when confirmation is required.
