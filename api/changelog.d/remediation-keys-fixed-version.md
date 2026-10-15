### Fixed: remediation groups are built from the fix, not from a package id or shared advice text

- A package group is now the package and the version that fixes it (`upgrade:pypi:django:4.2.30`, titled "Upgrade django to 4.2.30"): two installed versions that one upgrade fixes form one group, and no title is a raw id.
- A leaked secret is grouped only with findings of the same secret (by its fingerprint). Secrets were grouped by their advice text, so different secrets on different assets could share a group and be resolved together.
- Solution-text groups need specific text (a version or an id, not generic advice) and are kept per source.
- Keys are now derived for re-sighted findings, CVE-matching findings, findings a person creates and license findings, not only for findings a scan creates; a finding that no longer has a key leaves its group.
- **Upgrade note:** existing findings keep their old keys until the backfill runs. Dry run: `refingerprint -remediation-keys` (read-only, prints per-tenant counts); apply: `refingerprint -remediation-keys -apply`. It is idempotent and works one tenant at a time (`-tenant <id>` for one). A remediation campaign that tracks an old key (`finding_filter.remediation_key`) keeps the old key and counts nothing after the backfill; re-create it from the new group.
