### Removed: asset and pipeline-template columns nothing used

- Migration 001068 drops `assets.freshness_status` (every row held the
  default `fresh`; staleness is the asset `stale` status),
  `assets.compliance_requirements`, `assets.last_assessment_at`,
  `assets.next_assessment_at` (never written) and
  `pipeline_templates.ui_positions` (never written). No API field exposed
  them. The down migration re-adds them with their defaults.
