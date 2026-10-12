### Changed: the security ack survives base-branch merges and rebases

- `security-gate` records a digest of the pull request's security-sensitive
  lines when `security-ack` is added and keeps the label while that digest is
  unchanged. Merging `develop` in, rebasing, or pushing changes to other files
  no longer drops the ack; changing a sensitive line or adding a sensitive file
  still does, and a mismatching digest blocks the merge queue.
