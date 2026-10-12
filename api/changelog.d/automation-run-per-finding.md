### Fixed: a batch of new findings starts one automation run per finding

- A `finding_created` automation now runs once for every new finding that
  matches it. Before, it ran once per ingest batch, for the first matching
  finding only: with 40 new critical findings, "critical → ticket" filed one
  ticket.
- The same event never starts an automation twice: runs carry their subject and
  an idempotency key (migration 001222, `workflow_runs.subject_id`,
  `workflow_runs.idempotency_key`).
- Runs are bounded where they are created: 200 per automation and 5,000 per
  organization per hour. Over the limit, events are dropped and one `THROTTLED:`
  run per hour records it in the automation's history. Up to 100 runs per
  automation (500 per organization) may wait. They run 10 at a time per
  organization, and a run waits for a free slot instead of failing at once.
