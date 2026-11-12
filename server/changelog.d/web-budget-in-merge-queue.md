### Changed: the web bundle checks run in the merge queue

- The `Build` job of Web CI (production build, tenant-bundle check, route
  JavaScript budget) now also runs in the merge queue for a web change, not
  only after the merge on develop. A change that pushes a route or the median
  over `web/scripts/route-js-budget.json` is ejected from the queue instead of
  turning develop red. Plain pull requests still do not run it. `Web CI OK`
  requires `Build` in the queue.
- Docs: server/docs/development/ci-cd.md
