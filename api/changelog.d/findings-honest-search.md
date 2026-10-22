### Behaviour change: Findings search matches title, file path, rule id, CVE id and asset name

- `q` on `GET /findings` (and its stats, groups and export) matches the title, file path and rule id
  (contains), the CVE id (exact, any of the finding's CVEs) and the asset name. It no longer matches the
  description: use the new opt-in filter `description_contains=…`.
- `GET /meta/filters/findings` lists the searched fields in `contract.search_fields`.
- The findings count, stats and SLA breakdown now have the 5 s statement timeout the list already had; a
  read that runs out of time answers `503 QUERY_TIMEOUT` instead of holding a connection. `GET /findings`
  is under the heavy-read rate limiter like its stats and groups.
- Migrations `003280`–`003283` add trigram (GIN `gin_trgm_ops`) indexes on `findings.title`,
  `findings.file_path`, `findings.rule_id` and `assets.name`. Each is built `CONCURRENTLY` (no write lock);
  on a large database the deploy's migrate step takes as long as the builds.
