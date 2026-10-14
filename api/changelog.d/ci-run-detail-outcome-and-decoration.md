### Added: the CI run detail shows how the verdict came about and whether it reached the code host

- `GET /api/v1/ci/runs` and `GET /api/v1/ci/runs/{id}` now return:
  - `would_fail`: the pass came only from a warn policy or a break-glass;
  - `override`: the break-glass override that let the commit pass;
  - `decoration_state` and `decoration_detail`: whether the gate check and pull request comment were posted, are waiting, or failed, with a short reason.
- Console, CI/CD → Runs:
  - running runs and passes that would have failed are marked in the list;
  - the open run is kept in the URL (`?run=`);
  - the run detail separates blocking reasons from comment-only ones and counts monitored findings;
  - it says when a break-glass let the commit pass (who, why, until when);
  - it shows the check and comment status, the tools, scan failures, the `.openctem.yml` outcome, whether the commit was signed by the CI provider, when the run was judged, and a link to the run's findings;
  - administrators can open a prefilled break-glass for a failed run's commit.
