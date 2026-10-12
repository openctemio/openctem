### Added: Coverage view and pipeline retirement in the console

- The Sensors page in runner mode has a **Coverage** view: each repository in your data scope with SAST, SCA, secrets and IaC as fresh, stale or never, gaps first, a summary (covered, not looked at, gaps) and template drift. Users with `scans:ci:write` mark a repository as expected. The CI alert links open this view.
- A CI pipeline's drawer has **Retire** (`scans:ci:write`, reason required): the findings only it reported close as source retired. Retired pipelines are hidden with the other inactive ones.
