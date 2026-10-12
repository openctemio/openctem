### Added: web evidence and optional screenshots of web assets

- Sensors can attach captures to a web asset (final URL, status, title,
  server, the first 4 KiB of the response with secrets masked, and an optional
  screenshot) in the reserved `web_evidence` asset property; the asset page
  shows them in a Web evidence card (en, vi). RFC-081.
- Screenshots are kept only when the organization turns on "Screenshots of
  web assets" (`web_screenshots_enabled` on `/api/v1/easm/settings`, off by
  default), re-encoded to PNG within 1 MiB and 1920x2400 px, stored in the
  organization's file storage and deleted after 30 days.
- `GET /api/v1/assets/{id}/web-evidence` and
  `GET /api/v1/assets/{id}/web-evidence/{evidence_id}/screenshot`
  (`assets:read`, the asset's data scope; the image is served sandboxed).
