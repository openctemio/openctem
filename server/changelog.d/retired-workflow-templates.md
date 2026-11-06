### Changed: Retired scan workflows are hidden and say what replaced them
- `GET /scan-workflows` no longer lists retired system workflows (Discover, Discover + Vuln, Web app and the older presets) unless `include_retired=true`. Each retired workflow carries `is_retired` and `superseded_by` (new column `scan_workflows.superseded_by`, migration `workflow_superseded_by`).
- Starting a scan from, or copying, a retired workflow is refused with an error that names its replacement. Existing scans and tenant copies keep working, and a copy's detail response gains `based_on_retired`.
