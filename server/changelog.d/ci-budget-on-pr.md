### Changed: the request budget check runs on pull requests that change a page's data
- A pull request that changes `web/src/app/`, a feature's API hooks or `web/src/lib/api/` now runs the Playwright request budget job, so a page over its budget fails the PR instead of the merge queue. The full suite still runs only in the queue.
