### Fixed: dead redirects and route guards removed, settings search anchors, env registry and doc drift

- The redirects from `/settings/users`, `/settings/access-control/groups` and `/scanner-templates` are gone: they sent sub-pages to pages that do not exist, and renamed pages keep no redirect.
- Twenty-two route-permission entries (`/x/**`) for pages with nothing below them are removed; a test now fails when one is added without a page.
- Settings search finds Pending invitations (Members), Create a role, the SCIM endpoint, Scope approval policy, Approval tiers and approvers, and the unowned-findings floor and CTEM bonus points in Risk scoring, and scrolls to them.
- The environment registry drops `AUTH_COOKIE_NAME` (nothing reads it) and lists `GATEWAY_VERSION`, `OPENCTEM_ADMIN_PUBLIC_URL`, `BACKUP_STATUS_DIR` and the `PG_*` memory settings the compose file uses. The authorization matrix names the real membership role route.
