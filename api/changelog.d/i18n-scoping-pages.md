### Changed: scoping overview and cycle pages follow the console language

- The scoping overview, the cycles list, the cycle detail page and its tabs, the charter sheet and the lifecycle actions now read from the en and vi catalogs (new `scoping` namespace). The readiness rows, cycle statuses, attacker-profile types and criteria summaries are translated, with plurals.
- Cycle dates use the console locale and read as "{start} to {end}" instead of an en-dash range; date-only values no longer shift a day in negative-offset timezones.
- Toasts read as plain past-tense facts ("Cycle created.") and the lessons callout uses the muted card tone instead of an amber accent.
