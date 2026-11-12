### Added: exploration leads, links and verdicts (storage)

- New tables `explorations`, `exploration_leads`, `exploration_links` and `exploration_verdicts`
  (migration `exploration_layer`): an open question about an asset or finding with a typed next
  action, the evidence it came from, the run it was dispatched as, what that run yielded, and
  append-only verdicts. Every reference is a typed column with a composite tenant foreign key.
  Nothing reads or writes them yet; additive only, no upgrade step.
