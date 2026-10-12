### Fixed: a retest re-runs the template against the origin, not the matched-at URL

- A retest passed the finding's matched-at URL (`https://host/wp-admin/js/theme.js`)
  to the template as its input. The template appends its own path to the input,
  so the re-run requested the path twice, got a 404, "did not match", and the
  finding was resolved as fixed whether or not it was. The re-run now targets
  the origin (`scheme://host[:port]`) of the matched-at URL.
- Migration 001175 voids those outcomes: every finding resolved by such a
  retest, and unchanged since, returns to the status it had before the retest;
  the retest reads "unknown" with a `voided:` reason. Retest those findings again.
