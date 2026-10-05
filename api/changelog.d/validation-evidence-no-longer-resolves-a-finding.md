### Security: validation evidence no longer resolves a finding

- **A validation "not detected" keeps a `fix_applied` finding open**
  (research 18 F6, RFC-040). The only proof that the target answered was
  `raw_meta.reachable`, which the sensor asserts about its own run, so a
  hostile or broken sensor could close any `fix_applied` finding. The verdict
  is still recorded on the finding; a retest (whose reachability probe the
  platform dispatches) or a `findings:verify` holder closes it. Downgrades of
  still-open findings to `validated_fixed` (which a person still closes) and
  reopen on "detected" are unchanged.
