### Added: optional account page link on Usage & limits

- `ACCOUNT_PORTAL_URL` (empty by default; an absolute https URL): when set and a limit or module deny applies to the organization, `GET /api/v1/organization/limits` returns it as `account_portal_url` and Settings > Usage & limits links to it for owners and admins. Self-hosted installs leave it empty and show no link.
