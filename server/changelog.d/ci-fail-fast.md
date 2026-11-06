### Changed: CI stops doomed work after the first failed job

- In the merge queue, a failed job behind `API CI OK`, `Web CI OK`, `E2E OK` or `All-in-one OK` cancels every unfinished run of the same merge-group commit, so a group that will be ejected no longer holds runners until its slowest shard ends. Runs of other commits are never touched.
- On a pull request, a failed job cancels the rest of its own workflow run only; other workflows keep reporting separately. Fork pull requests are unaffected (read-only token).
- The Go, least-privilege, web unit and Playwright test matrices now use `fail-fast: true`.
