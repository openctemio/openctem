### Changed: the web console revalidates reference data instead of downloading it again

- The `/api/v1` proxy forwards `If-None-Match` and passes back the API's `ETag`
  for responses the browser may keep, and answers `304 Not Modified` without a
  body. The asset type registry (about 107 KB) is no longer downloaded again on
  every asset page load.
