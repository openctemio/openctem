### Added: detected technologies per asset

- Every technology a fingerprinting probe reports (web server, framework, JavaScript library, CDN,
  hosting, WAF, analytics, security header) is kept on the asset with a category, version when known,
  the tool's confidence and first and last seen: `GET /api/v1/assets/{id}/technologies` (RFC-112).
- Only a detection that names a product with a version or a CPE becomes a software component for CVE
  matching. Security headers, hosting platforms, CDNs and versionless names no longer appear as
  "version unknown" components.
- Upgrade note: migration adds the `asset_technologies` table (new, empty; no lock on existing tables).
