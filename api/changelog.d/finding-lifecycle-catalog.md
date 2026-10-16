### Added: groundwork for organization finding lifecycles (sub-statuses)

- New tables `lifecycle_sub_statuses`, `lifecycle_schemes` and `lifecycle_scheme_versions`, and a nullable
  `findings.sub_status_id` (RFC-110). A sub-status is an organization's label bound for ever to one
  canonical status (and, under a closed status, to one closure reason); the database refuses a sub-status of
  another tenant or another status, and any status change that does not name a new sub-status falls back
  to the default label. Nothing uses them yet: no behaviour changes.
- Migrations `002700_lifecycle_catalog`, `002701_findings_sub_status_fk` (foreign key `NOT VALID`),
  `002702_findings_sub_status_fk_validate` and `002703_findings_sub_status_index` (built concurrently). Every
  existing finding has no sub-status, so the validation and the index are quick; no long locks.
