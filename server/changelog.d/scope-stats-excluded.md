### Added: excluded and not-covered inventory counts in the scope summary

- `GET /api/v1/scope/stats` adds `inventory_excluded` (internet-facing assets an active exclusion removes) and `inventory_not_covered` (internet-facing assets no active entry covers and no exclusion removes). Both come from the existing coverage count (one query, no new request), tenant-scoped and narrowed to the caller's data scope like the other inventory counts.
- Docs: server/docs/rfcs/RFC-054-scope-model.md (§6 scope summary)
