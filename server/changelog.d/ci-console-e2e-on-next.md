### Changed: Console E2E runs on pushes to next, Web E2E reports every shard on a push

- Console E2E now also runs on a push to `next` (same paths as its pull request trigger), so a console regression there is reported without waiting for the nightly run.
- Web E2E keeps `fail-fast` for pull requests and the queue, but on a push or the nightly run every shard finishes, so one run reports the whole suite.

Docs: server/docs/development/ci-cd.md
