### Fixed: automatic coverage runs for an organization without any scope entry
- Everything found is in scope unless excluded: an organization that has no scope entry and scans unclassified assets (`low_impact`, the default, or `full`) is no longer paused as `no_scope`. Its coverage runs, and the scope gate decides each target as before (low-impact checks for what no entry covers, tier and guardrail refusals unchanged).
- The `off` setting, the Strict scan approval mode (read as `off`) and an unreadable setting keep the `no_scope` pause.
- The Scope page and onboarding no longer say that scans refuse every target no entry covers.
