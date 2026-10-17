### Security: changing risk scoring settings needs step-up re-authentication

- `PATCH /tenants/{tenant}/settings/risk-scoring` now requires a recent re-authentication. These settings decide every asset's risk band and, through the ownership floor, finding priorities. The audit entry records the new scoring version.

### Changed: risk scoring settings show their whole-organization impact before they are applied

- `POST /settings/risk-scoring/preview` scores every asset with the new settings, the way the background worker will, instead of a 100-asset sample. It returns the score changes, band moves and the largest changes; assets outside the caller's data scope are counted but not named. When the ownership floor changes, it also returns the open findings that would change priority, the deadlines that would move earlier and the findings with a linked ticket.
- The console's Save opens this review; the settings are applied only from it.
- Saving no longer rescores in the request: the response is `{"config", "recompute": "queued", "scoring_version"}` and the workers recompute in the background. `POST /settings/risk-scoring/recalculate` queues every asset and answers `assets_queued` (was `assets_updated`).
- The preview is limited to 6 per minute per organization (429 with Retry-After): it is a dry run over every asset and open finding.
