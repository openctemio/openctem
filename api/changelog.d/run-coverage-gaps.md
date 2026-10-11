### Added: coverage gaps on scan run tasks

- A sensor that could not fully cover some hosts of a task (the host stopped
  answering and its breaker gave it up, it kept rate-limiting the scan at the
  lowest rate, or it blocked the scan; RFC-074) reports them in the command
  result (`coverage_gaps`, `coverage_gaps_total`). The task completes, the
  step and the run end partial with code `COVERAGE_GAPS`, and the run's task
  list shows the hosts and the reason, so such a host is no longer read as
  "no findings". Batched steps count the gaps of every completed batch.
- The list is sensor-supplied: parsed defensively, unknown reasons dropped,
  at most 20 entries per task, every string cleaned to one bounded line;
  a platform sensor's detail text is redacted as its other messages are.
