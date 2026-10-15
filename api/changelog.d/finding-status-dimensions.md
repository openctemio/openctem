### Removed: the finding statuses validated_fixed and not_observed

- Whether the scanner still reports a finding is now `observation`
  (`present` / `stale`), and whether a re-check reproduces it is `validation`
  (`reproducible` / `not_reproducible`). Both are fields beside the status, in
  the finding response and as list filters. A finding keeps its work status
  when it goes stale or a re-check no longer reproduces it.
- `status=validated_fixed` / `status=not_observed` (filters, saved views,
  `PATCH /status`) now answer 400 and name the replacement filter
  (`validation=not_reproducible`, `observation=stale`). Stored saved views and
  campaign filters are rewritten by the migration.
- A retest that confirms a fix without `retest.auto_resolve` no longer moves
  the finding; it stamps `validation = not_reproducible` and the finding waits
  in its status for a person (or a covered scan) to close it. The validation
  engine's downgrade works the same way.
- Feature-branch and branch-only expiry, a stale CI source, template drift and
  the software matcher mark findings stale instead of changing their status;
  any sighting makes them present again. A covered scan can now resolve a stale
  finding.
- Migrations `002410_finding_status_dimensions_column` (the column, a catalog
  change), `002411_finding_status_dimensions` (row moves first, the status CHECK
  replaced last and NOT VALID), `002412_finding_status_dimensions_validate`: findings in a retired status go
  back to the status they had before (from their timeline, else `confirmed`)
  with a timeline entry; live had none.
