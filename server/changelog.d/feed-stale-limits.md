### Fixed: the vulnerability data banner no longer comes and goes between releases, and offline sites can set the limit

- KEV arrives inside the signed vulnerability release (published every 2 to 6 hours), so its fixed
  6-hour limit made the banner flap between releases. KEV now takes the bundle's limit (12 hours by
  default) and is judged by the date the release carries; EPSS takes the bundle limit plus a day
  (at least 36 hours). The newest-record check follows a raised bundle limit.
- New console setting, System > Threat intelligence > "How old the data may be": the bundle (and
  KEV) limit, 6 to 168 hours, for a site that copies releases to `VULNFEED_BUNDLE_DIR` by hand.
  `GET`/`PUT /api/v1/admin/settings/feed-freshness` (any admin reads; super admin with a step-up
  changes it; audited as `platform.feed_freshness_limits_changed`, every administrator is told).
  A release older than 7 days is still refused.
- The KEV and EPSS cards show the bundle import's next run (every 20 minutes), not an hourly or
  daily one.
- Docs: https://docs.openctem.io/operations/vulnerability-feed-setup/
