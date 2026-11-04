### Added: organization keys for the third-party sources scan tools query

- Settings, Scanning, Tool source keys: an organization stores its own keys of
  subfinder's passive sources (securitytrails, shodan, censys, virustotal and
  the others). Keys are encrypted with `APP_ENCRYPTION_KEY`, never shown again
  (last four characters only), can be replaced, switched off and removed;
  every change needs an administrator with a fresh step-up and is audited.
- A sensor gets an organization's keys only for a task of that
  organization's job, for the job's tool, while it holds the job's lease
  (`POST /api/v2/sensor/commands/{id}/tool-credentials`). Organization
  sensors must be trusted; a shared sensor gets the keys of the job it holds
  and nothing else. Each delivery is audited.
- Design: `docs/architecture/tool-source-keys.md`.
- A key whose first part names where the tool connects (intelx and zoomeye
  `HOST:KEY`, redhuntlabs `ENDPOINT_URL:KEY`) is accepted only for the
  source's own service (no IP address, port or other host). Keys are at least
  8 characters; only the tail of a pair's secret part is shown.
