### Added: suggestion members carry what a person needs to judge them

- `GET /remediation/suggestions/{id}/members` rows now include the location
  (`file_path` and `start_line`, or `network_port` and `location_targets`),
  `rule_id`, `cwe_ids`, `asset_criticality`, `package_name` and
  `installed_version`, the scanner's `recommendation` and `fix_code` (plain
  text, capped, secret shapes redacted; never the fix code of a secret
  finding) and `active_task` when a task claimed the finding since the
  suggestion was made. Rows stay limited to the caller's data scope.
