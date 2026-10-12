### Added: the OpenCTEM gate check and pull request comment on GitHub

- After a CI run's verdict on a GitHub repository whose organization bound the
  GitHub App, the platform posts a check run **OpenCTEM gate** on the commit
  (success, failure, or neutral in warn mode; counts, reasons, up to 50 line
  annotations) and one summary comment on the pull request, updated in place.
  Make the check required in branch protection: the job cannot skip or forge
  it, since the platform posts it with the installation.
- For a pull request the check goes on the head GitHub reports, and only when
  the run judged the pull request's current merge commit. Scanner text is
  escaped; secrets never appear. Posting is queued (`ci_runs.decoration_*`,
  migration `ci_runs_decoration`), retried up to five times, and never changes
  a verdict.
