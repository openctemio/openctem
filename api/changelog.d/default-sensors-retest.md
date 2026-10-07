### Fixed: default sensors run retests

- "Retest now" on a finding waited out its 30-minute deadline and ended with
  no result on every sensor with a default grant. No grant profile listed the
  `retest` job type, so the dispatch gate never offered the command.
- Every grant profile that may scan now also lists `validate` and `retest`
  (RFC-052 §5.2), with the same zones, target network, target scope and tier
  ceiling. Migration 001261 adds them to the default grant a new sensor gets
  and to every grant still on one of those profiles. A grant an administrator
  edited (profile `custom`) keeps its job types; `retest` can be added to it on
  the sensor page.
- A retest is rated at the tier of the detection it repeats: the scan tier of
  the finding's tool, under the contract the sensor reported. The retest of a
  T1 finding is T1, and only a T2 detection retests at T2. A sensor at trust
  level `new` is still capped at T0 and gets no T1 retests until it is
  promoted.
