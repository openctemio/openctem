### Added: Certificates view of the external attack surface

- `GET /api/v1/attack-surface/certificates` lists the tenant's certificate assets (issued to, fingerprint, issuer and organization, issued on, expires on, detection date) with an expiry status computed at read time (expired, expiring within 30 days, valid, unknown), and `GET /api/v1/attack-surface/certificates/stats` counts them by status. Both follow the list query contract (filters, sort, search, pagination), apply the caller's data scope to each certificate asset and need `assets:read`.
- The External Attack Surface section has a Certificates tab: a table with a copyable SHA-256 fingerprint, a status per row, expired and expiring-soon counts that filter the table, search and a CSV export.
