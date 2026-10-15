### Security: re-running only the CI gate job can no longer pass on an empty run

- A retry or re-run of a pipeline's gate job opened a new aggregate run with no reports, which judged nothing and
  passed; the commit check took that latest verdict. Every job, retry and re-run attempt of one pipeline run
  (pipeline, provider run id, commit) now reports into one run: a later attempt re-opens it and the verdict covers
  every attempt's reports with today's decisions, so an approved exception or a fixed flaky scan can turn it green
  without a new commit.
- Scanner failures of the earlier verdict keep failing the run until a later attempt uploads a report.
- A run that no report was uploaded to fails (`no_results`).
- Migration `ci_run_evidence_union` (runs created before it keep their old key).
