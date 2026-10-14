### Added: automatic coverage runs from the coverage ledger

- The asset coverage loop now starts work: for each capability of the
  policy (never an intrusive one) it takes up to 200 due pairs of a tenant,
  sends them through the scope gate as the system, records refused ones as
  blocked with the gate's code, and runs the rest on the tenant's
  "Continuous coverage: <capability>" scan (one active run per capability
  at a time). Finished runs settle their pairs: covered (with `no_output`
  when an HTTP probe found no web origin) or failed with a back-off.
- Owner decision D1: on by default; off for an organization whose scan
  approval mode is Strict. `ASSET_COVERAGE_DAILY_BUDGET` (default 5000)
  caps the attempts per organization per 24 hours.
- **Behaviour change:** with `ASSET_COVERAGE_ENABLED` on (the default), the
  automatic enrichment of new assets is off; the coverage loop resolves and
  looks up every asset its policy names.
