### Fixed: the intake counts each source as the tool that reported, and names its senders

- A scan run or CI run that carries reports of several tools no longer books every tool's findings on the
  first tool that reported (a discovery tool showed the findings of the scanners after it). Each report now
  adds its counts to its own tool's row of the receipt (`ingest_receipt_tools`, migration
  `20261031193712_ingest_receipt_tools`); the receipt list's tool filter and its totals read the same rows,
  so every intake figure still equals the list it opens. Receipts written before the upgrade keep their
  counts on their first tool.
- Findings the inventory version matcher stores are booked on a receipt of the platform (`source_kind`
  `platform`, tool `version-match`) and show as their own source.
- Each intake source carries `assets` (assets its reports created or updated), `kind` (`discovery`,
  `detection` or `platform`) and `instances` (its senders: sensors, CI repositories, connectors, uploads,
  the platform, with their figures and health); a source is as unhealthy as its worst sender. Only the
  organization's own sensors are named and linked.
