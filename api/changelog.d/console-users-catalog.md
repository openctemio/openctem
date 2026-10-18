### Added: browse accounts by state and manage the content catalog in the platform console

- Customers > Users lists every account newest first, with state tabs and counts (all, active, not verified, locked, blocked, no MFA, platform admins), an optional search and pagination. Operations admins and super admins only; the list carries no names and no organization data, and every list view is written to the admin audit log (`platform_user.list`). `GET /api/v1/admin/platform-users` takes an optional `state` and no longer requires `q`.
- Scanning > Content catalog: the instance catalog's trust state (the trust roots stay on the server and are shown read-only), its packages and versions, and the guarded actions: import a signed bundle, publish an instance package, revoke a version (super admin, reason, step-up, audited). New read routes `GET /api/v1/admin/content-catalog/packages` and `/packages/{package_id}/versions` list the instance catalog only, never an organization's private package or installation.

### Removed: the program feed admin routes

- `GET /api/v1/admin/program-feed` and `PUT /api/v1/admin/program-feed/local-bundle` had no console page and are removed until one uses them. The stored local-bundle switch stays off, so a `PROGRAMFEED_LOCAL_BUNDLE_DIR` bundle is not imported. **Upgrade note:** none; no migration.
