### Fixed: a name refused without a DNS kind never counts as NXDOMAIN

- A sensor before sdk-go v0.38.0 refuses a name as `unresolvable` without saying whether its resolver answered
  "no such name" or the lookup failed (a timeout or SERVFAIL, for example a resolver under scan load). Asset
  liveness read such a refusal as NXDOMAIN, so repeated refusals could move the name towards `gone` and, with
  closing turned on, close its findings. The refusal is now `dns_unknown`: no liveness evidence, it neither
  advances nor resets the gone streak, never parks the name, and coverage rechecks it as a failed lookup.
  Only an explicit `name_gone` is evidence of absence. The dry run uses the same rule.
- Streaks recorded before this fix are kept as they are. A tenant that turned on closing when gone can check
  the dry run before the next pass.
