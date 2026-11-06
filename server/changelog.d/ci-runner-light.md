### Changed: light CI jobs can run on the self-hosted runners

- A new repository variable `CI_RUNNER_LIGHT` moves the short first-stage jobs (change detection, the OpenAPI spec, the API contract, the e2e shard plan, the "... OK" gates, Workflow Lint, secret scanning, docs check) to the self-hosted runners, so they no longer queue behind the limit on GitHub-hosted runners while the heavy jobs wait for them. Same rules as `CI_RUNNER_HEAVY`: pushes and pull requests from this repository only, merge groups only through `CI_RUNNER_MERGE`, unset means GitHub-hosted. Check names do not change.
- Workflow Lint fails when a `runs-on` is not a GitHub-hosted label or an approved runner selector, and proves that every selector keeps fork pull requests on GitHub-hosted runners (`.github/scripts/check-runners.sh`).
- Jobs that call the GitHub CLI, and the fail-fast step, install a pinned, checksum-verified `gh` when the runner has none; the e2e shard planner sets up Node.js.
