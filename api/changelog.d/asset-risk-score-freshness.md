### Fixed: asset risk scores follow their findings

- An asset's risk score was recomputed only by the manual recalculation, so
  findings that arrived by CI upload, sensor ingest, import, bulk triage or
  auto-resolve never moved it (a repository with 81 open findings showed 0).
  Database triggers now queue an asset whenever an input of its score changes
  (its findings, criticality, exposure, data context, business units and
  services), and a background worker rescores queued assets per organization
  every few seconds, one rescore per asset however many findings changed.
  A daily reconcile rescores everything as a safety net.
- Asset finding counts and the risk score now count only active findings:
  accepted, false-positive, duplicate and validated-fixed findings and
  unpublished pentest drafts no longer add to `finding_count` or the score.
- Assets in the API carry `risk_scored_at` (absent = never scored) and
  `risk_score_pending` (a rescore is queued).
- Migration `002139_asset_risk_queue` adds the queue, the triggers and the
  column, and queues every asset once.
- **Upgrade note:** nothing to run. After the migration the worker rescores
  the whole inventory within minutes; watch
  `openctem_asset_risk_queue_depth` fall to 0.
