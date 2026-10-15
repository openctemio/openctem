### Fixed: program jobs with a required identification reach sensors again

- The heartbeat and manifest sanitizer kept only known sensor-wide
  capabilities and did not know `http.identity@1`, so it was dropped from
  every sensor report ("ignored capabilities[N] \"http.identity@1\":
  unknown-capability" in the sensor log). Jobs on targets of a bug-bounty
  program that requires headers or a User-Agent wait for a sensor reporting
  it, so they were withheld from every sensor. It is now kept.
- **Upgrade note:** a sensor that registers a manifest sends its
  capabilities only with the manifest, which it registers at start; restart
  such sensors after upgrading so the platform records `http.identity@1`.
- Every sensor-wide capability dispatch gates on (`validate`,
  `scope.limits@1`, `net.confined@1`, `http.identity@1`) now comes from one
  list, with a test that a sanitized report keeps each of them.
