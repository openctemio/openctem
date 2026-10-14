### Added: the asset coverage ledger follows the coverage policy

- A new background job (`asset-coverage`, part of the attack surface module;
  `ASSET_COVERAGE_ENABLED`, default on, every `ASSET_COVERAGE_INTERVAL`,
  default 1 minute) keeps the ledger in line with the registry's coverage
  policy: every active asset gets a row per rule of its type, due at once,
  or not applicable with the reason when a precondition does not hold (a
  name that does not resolve, an open port that is not a web port, a domain
  no scope entry covers). It re-evaluates preconditions every pass. It does
  not dispatch work yet.
- `GET /api/v1/assets/{id}/coverage` (`assets:read`) explains an asset's
  coverage: per capability its state, reason, last attempt and success,
  outcome, next due time and whether it is a coverage gap.
