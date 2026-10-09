### Security: sensor lookups answer only about assets the sensor reaches

- `POST /api/v2/sensor/fingerprints/check`, `POST /api/v2/sensor/fingerprints/baseline-diff`
  and `GET /api/v2/sensor/suppressions` (and their protocol v3 calls) were
  tenant-wide: any sensor could confirm which finding fingerprints, repositories
  and suppressed paths existed in other scan zones. They now answer only about
  the assets the sensor reaches: the targets of the commands assigned to it
  (open, or ended in the last 24 hours) and the ranges of its scan zones.
  Outside that, a fingerprint is `missing`, a repository answers as unknown
  (every fingerprint new) and a rule on an asset is left out: the same answers
  as for something that does not exist. Collectors and sensors with a
  `collector` or `ci-runner` grant keep tenant-wide lookups. Wire shapes are
  unchanged.
- **Upgrade note:** a sensor that is neither a collector nor a `ci-runner`
  and calls baseline diff for a repository it holds no command for now gets
  every finding as new; give it the `ci-runner` profile or use a CI run token.
