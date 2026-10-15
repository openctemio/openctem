### Added: published ticket mappings create issues and move their status

- When a Jira destination has a published field mapping, a finding's issue is
  created from the mapping's fields (custom fields, allowed values by id,
  issue type by id), and a status change moves the issue along the mapped
  workflow path, filling the resolution and required screen fields. A path
  the workflow does not allow is reported, never guessed. In dry run the
  mapping is only logged.
- Status sync jobs no longer retry what the tracker refused (4xx) or what the
  workflow cannot do.
