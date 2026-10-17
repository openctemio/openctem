### Fixed: CI jobs joining one pipeline run at the same moment all get the run

- When several jobs of one pipeline run exchanged their tokens at the same moment, one of them could fail with
  a database unique violation and get no run, so its results never reached the platform. The insert's
  conflict target and an older unique index both matched the new aggregate runs; the older index now covers
  only the runs opened before the pipeline-run key. Migration `ci_aggregate_open_index_legacy_only`.
