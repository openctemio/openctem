### Security: re-running only the CI gate job can no longer pass on an empty run

- A retry or re-run of a pipeline's gate job opened a new aggregate run with no reports, which judged nothing and
  passed; the commit check took that latest verdict. Every job, retry and re-run attempt of one pipeline run
  (pipeline, provider run id, commit) now reports into one run: a later attempt re-opens it and the verdict covers
  every attempt's reports with today's decisions, so an approved exception or a fixed flaky scan can turn it green
  without a new commit.
- A re-opened run keeps its last verdict for the commit check and the merged-without-a-passing-gate check until it
  is judged again, so retrying one job of a failed pipeline cannot hide its failure.
- A capability that failed in an earlier attempt keeps failing the run until a report of that capability arrives;
  a runner that sends only a failure count has the count carried until the next upload.
- A run that no report was uploaded to fails (`no_results`).
- Migration `ci_run_evidence_union` (runs created before it keep their old key).
