### Added: the web console reports error kinds for operator alerting

- `POST /api/v1/client-errors` (public, rate limited per client address and overall) counts an error the
  web console hit, by kind only (`chunk_load`, `render`, `unhandled`, `other`), in
  `openctem_web_client_errors_total{kind}`. No message, stack, URL or user detail is accepted, logged or
  stored. A spike raises the WebClientErrors alert (for example the chunk-load errors after a broken deploy).
- The web console reports uncaught errors, unhandled rejections and errors caught by its error boundaries,
  throttled to one report per kind a minute and ten per page load.
