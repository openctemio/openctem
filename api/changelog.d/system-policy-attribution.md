### Security: a missing actor is never the unrestricted system

- Platform policies (continuous coverage, automatic enrichment) now dispatch with an explicit system authority (`SystemPolicy`): the tenant's scope entries and the capability's tier apply, a member's act scope does not. An act-scope check with no user, no fallback user and no policy is refused instead of read as unrestricted, at dispatch and at the claim re-check.
- A caller's `actor_user_id` and `system_policy` in a run context are dropped on every scan trigger and on `POST /scan-workflows/runs`; who a run acts as is decided by the platform.

### Changed: coverage and enrichment runs are attributed to their policy and queue low

- Coverage and enrichment runs are stored as `system` runs triggered by `policy:coverage` / `policy:enrichment` (previously recorded as `manual` with no trigger). The runs API reports `trigger.type = "policy"`.
- Command queue class follows the source: a person's own start is `high`, schedules, automations and retries `normal`, platform policies `low`; the claim's existing ageing keeps low work from starving.
- **Upgrade note:** coverage and enrichment commands queued before the upgrade are withheld at the claim (no recorded policy); the next planner pass queues new ones.
