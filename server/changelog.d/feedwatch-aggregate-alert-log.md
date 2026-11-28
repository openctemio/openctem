### Fixed: the CVE volume alert's log line says what is low

- The "feed freshness alert" log line of `volume_low` carried an empty `source=""`: the condition is about the whole CVE corpus, not one feed. It now logs `scope=corpus` with the CVEs published in the last 24 hours and the usual count for that weekday (`observed_24h`, `expected_24h`); per-feed alerts keep their `source`.
- Docs: server/docs/operations/monitoring.md
