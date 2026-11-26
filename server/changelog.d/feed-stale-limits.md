### Fixed: the vulnerability data banner no longer comes and goes between releases, and offline sites can set the limit

- **Behaviour change: the default KEV limit moved from 6 to 12 hours.** KEV arrives inside the
  signed vulnerability release (published every 2 to 6 hours), so its fixed 6-hour limit made the
  banner flap between releases. KEV now takes the bundle's limit (12 hours by default) and is
  judged by the date the release carries; EPSS takes the bundle limit plus a day (at least 36
  hours, never more than the 7 days a release is valid). The newest-record check follows a raised
  bundle limit.
- New console setting, System > Threat intelligence > "How old the data may be": the bundle (and
  KEV) limit, 6 to 168 hours, for a site that copies releases to `VULNFEED_BUNDLE_DIR` by hand.
  Raising it does not only quiet the banner: it also loosens which KEV and EPSS side data of a
  release counts as current (an older copy is no longer refused as `source_stale`).
  `GET`/`PUT /api/v1/admin/settings/feed-freshness` (any admin reads; a super admin changes it
  with a fresh step-up and a reason; a critical audit entry `platform.feed_freshness_limits_changed`,
  every administrator is told). A setting that cannot be read gives the strictest limit (6 hours).
  A release older than 7 days is still refused.
- The KEV and EPSS cards show the bundle import's next run (every 20 minutes), not an hourly or
  daily one.
- Docs: https://docs.openctem.io/operations/vulnerability-feed-setup/
