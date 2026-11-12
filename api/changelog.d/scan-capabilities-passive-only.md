### Added: the scan wizard offers a passive-only organization passive scans only

- `GET /api/v1/scans/capabilities` (`scans:read`; the organization comes from the credential) answers
  whether the organization may scan above passive (`active_scanning`).
- New and Edit Scan offer a passive-only organization Passive intensity only, and so only passive tools
  and workflows, with one line saying why. A higher intensity left in a draft or a saved scan moves to
  Passive. The server still refuses a scan above passive for such an organization.
- Workflow readiness (`GET /scan-workflows?include=readiness`) names the tool a ready step runs with
  (`tool`), so the scan wizard can say "runs with <tool>".
