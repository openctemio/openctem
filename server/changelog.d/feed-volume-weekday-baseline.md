### Fixed: the "CVEs published" volume alert no longer fires on weekends and public holidays

- The check compared the last 24 hours with a flat 30-day average, so a quiet Saturday or US Thanksgiving (91 CVEs against 386) e-mailed the administrators although the catalog was complete. It now compares each of the last two 24-hour windows with the median of the same weekday over the 8 weeks before, and alerts only when both are under 30% of it (a real gap, such as no new CVEs for 48 hours, still alerts, and so does `newest_record_old` after 12 hours).
- The "resolved" message now says what holds now ("Back to normal: N CVEs in the last 24 hours (it was 91 against a usual 386)") instead of repeating the alarm text.
- Docs: server/docs/architecture/intelligence-feeds.md (Freshness), server/docs/operations/monitoring.md (FeedFreshness)
