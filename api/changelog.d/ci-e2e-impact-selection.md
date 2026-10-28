### Changed: Web E2E runs the specs a change needs

- Pull requests and merge-queue groups run the Playwright specs that the changed files map to (`web/e2e/impact-map.yml`) plus a smoke set, in 1 to 4 duration-balanced shards; shared or unmapped paths still run everything.
- Pushes to `develop` and a nightly run execute every spec; a failure opens or updates an `e2e-regression` issue.
