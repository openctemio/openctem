### Added: certificate exposures per host, even when the host resets every HTTP request

- The recon exposure bridge judges each https service and the certificate it served: `certificate_expired` (high), `certificate_expiring` (medium, high within 7 days), and `ssl_issue` with issue `not_yet_valid` (medium), `name_mismatch` (medium: no name of the certificate covers the host) or `foreign_certificate` (high: no name shares the host's registrable domain, typically a hosting platform's default certificate on a name that points at an unclaimed site; marked `takeover_candidate` with the host's CNAME chain). The facts come from the TLS handshake, so a host that resets every request (reported by the sensor with status 0) is judged too.
- One exposure per service and problem; a later scan that sees the host serve a certificate without the problem resolves it automatically, and seeing it again reopens it. Accepted and false-positive exposures are never changed.
- The certificate-level expiry exposure is raised only for a certificate seen without a serving host; once a scan sees a host serve it, the certificate-level one is resolved as superseded by the per-host exposures.

### Fixed: recon certificate exposures were never raised from stored certificates

- The certificate projection read a nested `certificate` map that stored certificate assets do not have (they carry flat `not_after`, `is_expired`, `is_self_signed`), so expired, expiring and self-signed certificates found by recon scans raised no exposure. It now reads both shapes.
