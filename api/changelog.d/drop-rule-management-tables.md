### Removed: unused rule-management and finding-data-source tables

- Migration 001096 drops `rules`, `rule_sources`, `rule_bundles`,
  `rule_overrides`, `rule_sync_history` and `finding_data_sources`. They were
  empty and never wired: no route, permission or worker used them. The
  matching Go repositories, the `rule` domain package and the unused rule
  service are removed. Custom scanner content stays in template sources and
  scanner templates. The down migration recreates the tables.
