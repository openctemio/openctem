### Security: a VEX statement in a scan report requests a false positive instead of setting it

- With `INGEST_VEX=enforce`, a `not_affected` statement now creates a pending
  false-positive request (actor `vex`, the justification) with a timeline
  entry, for a person with `findings:approve` to decide. Before, it set
  `false_positive` directly, with no four-eyes. Migrations `002211`/`002212`
  allow the `vex` actor (constraint NOT VALID, validated separately). The
  ingest output field `findings_vex_closed` is now `findings_vex_requested`.
- A connector sync's statements count only for assets the same report
  carries (before, every statement of a connector sync was kept).
