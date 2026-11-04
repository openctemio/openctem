### Added: edition fence and entitlement key registry

- CI check "Edition fence" (and the pre-commit hook) keeps extension code and restricted words out of this repository; the extension mount points are git-ignored.
- Every limit key and named feature has a description in `pkg/domain/limits`; the entitlement keys test fails on an undescribed, unknown or literal key.
- Docs: [Editions](../docs/development/editions.md); the pull request template has an extension-point checklist. No behaviour change.
