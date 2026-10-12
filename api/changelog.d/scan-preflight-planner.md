### Added: the scope check says where a scan would run; save a scan with only its allowed targets

- `POST /scope/check` returns `routing`: where a scan of the targets would
  run (`tenant`, `platform` or `waits`), why, and which of the
  organization's own sensors would take it. In auto mode, with the platform
  setting "Require a verified domain before platform sensors scan a target"
  on, unverified targets run on the organization's own online sensor instead
  of being reported as "Proof needed"; only without one do they need proof
  (RFC-054 §6.4).
- A `zone_none` refusal of a hostname lists the private addresses it resolved
  to (`resolved`), when the platform may show them.
- An intrusive probe's `proof_required` refusal no longer offers "use your
  own sensor" (it would not help).
- `POST /scans` takes `skip_refused_targets`: the scan is saved with only
  the targets the scope check allows; the others are recorded with their
  refusal codes in `skipped_targets` on the scan and on every run (never sent
  to a sensor). Nothing the gate refuses is saved or scanned.
