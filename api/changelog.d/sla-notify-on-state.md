### Fixed: SLA breaches are announced whoever sets the status, once per SLA clock

- A breach is now announced when the deadline passes on an open finding even if another path set `overdue` first (a reopen after the deadline, an un-suppression, a status change past the deadline). Before, only breaches the 15-minute job flipped itself were notified; the others were silent.
- Each breach and each at-risk warning writes one `sla_breach` / `sla_warning` timeline entry, and notifications name the finding by its title instead of its id.
- The at-risk warning is measured from the start of the current SLA clock (new column `sla_started_at`), so a finding whose clock starts again (end of a risk acceptance, withdrawn false positive, branch promotion) no longer warns at once. A regression restart extends the clock once per reopen.
- The escalation job works in batches of 1,000 per transaction on an index of unannounced deadlines; two replicas announce each finding once.
- **Upgrade note:** migration `003261` backfills `sla_started_at`; findings already `warning` or `overdue` count as announced, so the deploy sends no notification burst. `003262`/`003263` create and drop indexes concurrently.
