### Fixed: continuous coverage finds its scans by key, never by name

- Coverage and automatic enrichment scans carry `managed_by` and `managed_key` (migration 003187, unique per tenant and key). A member's scan that has the same name as a coverage scan is no longer adopted and rewritten by the planner; coverage creates its own scan under another name.
- The migration marks only ownerless coverage and enrichment scans as managed; scans a person created or took over are left as they were.
- `GET /api/v1/scans` accepts `origin=user|system`.
