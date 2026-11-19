### Added: vulnerability data that stops arriving is an alarm in every mode, with a banner for every user

- A freshness watch checks every 10 minutes, in direct and relay mode alike: the age of each feed's data (bundle 12 hours, CISA KEV 6 hours, EPSS 36 hours), refused imports (at once), failing imports (after two runs), the age of the newest published CVE in the corpus (12 hours) and the number of CVEs published in the last 24 hours against the 30 days before. The platform administrators get one message when conditions open and one when they clear (e-mail and the alert webhook).
- While vulnerability data is out of date, every signed-in user sees a banner that cannot be dismissed, and the platform console shows each cause. The emerging-threat pages show "Data as of" the vulnerability data's publication time. New route `GET /api/v1/threat-intel/freshness` (any signed-in user; platform-wide state only) and `GET /api/v1/admin/threat-intel/freshness` (any admin).
- New gauge `openctem_feed_freshness_alerts{code}` and Prometheus rule `FeedFreshness`. Operators with their own rules file: copy the rule from `deploy/observability/prometheus/rules/openctem.yml`.
- Migration `20261118175634_cve_records_published_index` adds an index on `cve_records (published_at)`, built concurrently (no write lock).
- Docs: server/docs/architecture/intelligence-feeds.md (Freshness), server/docs/operations/monitoring.md (FeedFreshness)

### Changed: tighter stale limits for the vulnerability bundle and EPSS; the relay no longer sends its own stale alert

- The console marks the bundle feed stale after 12 hours (was 72) and EPSS after 36 hours (was 48); KEV stays at 6 hours.
- In relay mode the "feed is out of date" relay alert (48 hours) is replaced by the freshness watch, which covers every mode; relay offline and failed rounds still alert as before.
- Docs: server/docs/architecture/intelligence-feeds.md
