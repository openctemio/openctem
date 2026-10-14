### Added: runs and the scan preview say which exclusions left targets out

- A scan run records the targets its organization's exclusions left out
  (whole, or a range scanned without its excluded addresses) with the
  matching exclusion, up to 50; `GET /scan-runs/{id}` returns them as
  `dispatch.excluded` and the scan preview as `targets.excluded_detail`. The
  run page and the preview list them as "N targets left out by exclusions"
  with links to Scoping > Out of scope.

### Security: a scan's typed target list no longer reaches the sensor in its settings

- A quick scan mirrors its typed targets into the scan's settings
  (`targets`); every job carried that list as typed in `config` and
  `scanner_config`, including names and whole ranges the exclusions had
  removed from the job's own targets. Sensors read only the job's targets,
  so nothing was scanned through it, but the payload named excluded
  targets. The list in the settings is now the job's gated targets, and the
  copy in the job's context is dropped.
