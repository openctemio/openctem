### Added: the codeql tool row

- Migration 001169 adds the built-in `codeql` row to `tools`. The sensor ships codeql and the scan-stage catalog routes `sast.code` to it, but without a row tenants could neither enable it nor see whether their sensors have it (RFC-055, D9).
- An existing platform `codeql` row is left as it is. The down migration removes only the row this migration added.
