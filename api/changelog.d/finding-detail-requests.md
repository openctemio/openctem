### Fixed: the finding page sends two fewer requests
- The asset's SLA policy is read from its canonical path; the old path with a trailing slash was answered with a redirect first, on every finding and asset page.
- The Tenable.sc rescan panel reads the connector list only for a Tenable.sc finding.
