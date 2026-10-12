### Fixed: creating a scan workflow needs the scan workflow permission

- The "New scan workflow" button on the scan workflows page was gated on the
  automations write permission, so a member allowed to write scan workflows
  saw it disabled and a member allowed only to edit automations saw it
  enabled (the API refused them). It is now gated on
  `integrations:pipelines:write`, the permission the API checks.
- The scan page names the scan workflow a workflow scan runs and links to it,
  instead of showing a raw ID. The New scan help text no longer points to a
  "Workflow mode" that no longer exists.
