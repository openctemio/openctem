### Fixed: the remediation key backfill keeps campaigns that track a key

- `refingerprint -remediation-keys` now follows its key changes in the campaigns that track a remediation group (`finding_filter.remediation_key`): a campaign moves to the new key when all of its old key's findings land on that one key and no other finding does (so a campaign never widens), with its version bumped and one audit entry per campaign. A campaign whose findings split over several keys, share the new key with other findings, or that tracks a key no finding has, is printed as a warning with its finding count and left alone.
- Per tenant, idempotent; the dry run reports what it would retarget and changes nothing.
