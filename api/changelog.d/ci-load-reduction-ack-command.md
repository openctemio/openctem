### Changed: CI runs less on pull requests and a listed acker can acknowledge by comment

- A pull request runs the Playwright smoke set only (more with the `run-e2e` label or a changed suite); the merge queue, the nightly run, pushes to `develop` and `release/*` pull requests run the whole suite.
- The migration order check (fresh install against upgraded database) only warns on a pull request; the merge queue and `develop` still fail on it.
- `docs/` counts as documentation like `api/docs/`: a docs-only pull request skips the Go, web and CodeQL jobs.
- Heavy CI jobs go to the self-hosted pool for a share of runs (`CI_SELFHOSTED_SHARE`, default 20 percent of `github.run_id` modulo 100) and to hosted runners for the rest; `CI_RUNNER_HEAVY` and `CI_RUNNER_MERGE` still override, fork pull requests stay hosted.
- `/security-ack` and `/security-unack` on a pull request comment add or remove the `security-ack` label (only users listed under `ackers`, from the default branch, reacting with a thumbs up or down). The gate records the acker from the comment, with the same settle and carry rules as a label added by hand.
