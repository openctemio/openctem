### Added: a retest the tool could not run says why, with what to do next

- A sensor's retest can now tell the platform why an item has no verdict: its check is not in the sensor's template set (`template_not_found`), the sensor's safety policy never runs it (`excluded_by_policy`), or the tool ended without judging it (`no_verdict`). The finding card shows what each means and a suggested action, in English and Vietnamese. A sensor that cannot connect to the target or is refused by its network confinement now reads as `unreachable` or `blocked`. Older sensors keep reading as `error`.
- Migration 003406 adds the three reason codes to the retest history's allowed values.
