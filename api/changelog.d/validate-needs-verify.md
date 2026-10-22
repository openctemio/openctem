### Behaviour change: the reachability check needs findings:verify

- `POST /api/v1/findings/{id}/validate` now requires `findings:verify` (was `findings:write`), the permission of a retest: the check is an active probe whose outcome is applied to the finding, so a role that may only write findings (for example the remediation owner) can no longer run it on its own fix. Roles and API keys that should keep it need `findings:verify`.
