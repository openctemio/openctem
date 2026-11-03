### Added: edition fence and entitlement key registry

- CI check "Edition fence" (and the pre-commit hook) keeps Enterprise overlay code and the commercial brand name out of this repository; `api/ee/` and the web overlay paths are git-ignored.
- Every limit key and named feature has a description in `pkg/domain/limits`; the entitlement keys test fails on an undescribed, unknown or literal key.
- Docs: [Editions](../docs/development/editions.md); the pull request template has a "Paid feature?" checklist. No behaviour change.
