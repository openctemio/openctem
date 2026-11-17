### Added: saved views for every list page

- The saved views API (`/api/v1/views`) accepts a page key for every list page of the console (scans, runs, workflows, sensors, components, exposures, emerging threats, certificates, technologies, credentials, remediation tasks and campaigns, the approval queues, members and the other settings lists), not only `findings`, `vulnerabilities` and `assets`. The keys, with the permission that reads each list, are one registry in the server; a new list registers with one line and no migration.
- A page without filter fields of its own keeps its list state (filters, sort, search) in `page_params`: at most 32 params, 1024 bytes a value, 3072 bytes together, stored as text and never run by the server. `page_params` can now be sent in the request body.
- A member keeps at most 50 views on one page (and, as before, 100 in an organization).
- Migration `20261117053831_saved_views_page_registry`: `saved_views.page` grows to 64 characters and its check becomes a shape check. No data changes; rolling it back removes the views of the newly accepted pages.
- Docs: server/docs/architecture/saved-views.md

### Behaviour change: saved views answer by page key

- `GET /api/v1/views?page=<key>` and `POST /api/v1/views` answer `400` for a page key that is not registered (was `404`) and `403` naming the missing permission when the caller may not read that page's list (was `404`). A view read by id that the caller may not use stays `404`.
- The `/api/v1/views` routes no longer require `findings:read` or `assets:read` first: a request needs the read permission of the list its page key names (the route accepts the read permission of any list that has views, the service then checks the page's own).
- Docs: server/docs/architecture/saved-views.md
