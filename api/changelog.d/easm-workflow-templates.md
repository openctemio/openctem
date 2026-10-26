### Added: EASM recon workflows with a depth that changes what runs

- New system workflows Subdomains, Standard recon, Web and Deep recon, and Passive discovery joins the set. Discover, Discover + Vuln and Web app are superseded and deactivated (scans made from them keep working).
- A workflow scan has a depth: Passive runs only steps that send nothing to the targets, Standard is the default, Deep adds steps and raises params and caps. A step's run policy sets the depth it starts at, its standard params and target cap per depth, and whether it waits for a tool.
- Steps whose tool is not installed yet (screenshots, service detection, takeover check) are skipped with the reason instead of failing the run.
- Workflow setting `continue_on_failed_dependency`: dependents of a failed step still run on what exists.
- The workflow preview takes the depth and shows skipped steps and the params each step runs with.
- Migration `easm_workflow_depth_templates` adds `scans.depth` (default `standard`) and `scan_workflow_steps.run_policy` (default `{}`); existing scans and workflows behave as before.
