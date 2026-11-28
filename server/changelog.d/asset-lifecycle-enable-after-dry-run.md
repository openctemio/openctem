### Fixed: the asset lifecycle can be turned on right after a dry run

- `PUT /tenants/{tenant}/settings/asset-lifecycle` with `enabled: true` was refused ("cannot be enabled without a successful dry-run first") unless the client copied `dry_run_completed_at` back into the body: the handler checked the body before the server merged its own dry-run record. The body is now checked for its values only, and the dry-run rule reads the tenant's stored record, so enabling works after `POST .../asset-lifecycle/dry-run`. A timestamp in the body is still ignored, and a tenant without a dry run of its own is still refused.
- Docs: server/docs/architecture/asset-liveness.md
