### Fixed: databases that skipped three migrations are repaired

- Three migrations (content catalog, verified-domain sign-up policy,
  organization join requests) were merged with numbers below versions already
  applied, so databases upgraded across them never ran them. A new repair
  migration re-applies exactly their schema and seed rows idempotently: a
  no-op where they exist, complete where they were skipped. No action needed.
