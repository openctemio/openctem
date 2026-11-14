### Fixed: a vulnerability feed stuck on an expired bundle is now loud

- The vulnerability bundle controller warned "corpus is stale" only when its import ran without error, so a feed failing for days (an expired pointer on the publisher) logged nothing but the 20-minute failure line. It now judges by the last successful import and warns whenever there has been none for six hours or the newest bundle is over three days old, and it returns the import error so the controller error counter sees it.
- New gauges `openctem_feed_last_success_timestamp_seconds{source}` and `openctem_feed_failing{source}` (epss, kev, vulnfeed; enabled feeds only) and a Prometheus alert `FeedStale` (bundle feed 36 hours without a successful import, KEV 12 hours, EPSS 72 hours) with promtool tests. Operators with their own rules file: copy the `FeedStale` rule from `deploy/observability/prometheus/rules/openctem.yml`.
- Threat intel, Sync status shows "Last successful import" next to a failed feed.
- Docs: none (operator monitoring page server/docs/operations/monitoring.md, anchor FeedStale)
