### Added: choose which detection rules a scan runs

- The New scan and Edit scan wizards have a Detection rules section for template-driven scanners (nuclei, semgrep, opengrep, betterleaks, gitleaks): run the platform rules, the organization's own templates, or both, and pick the organization's active templates. Organization templates only needs at least one template. Choosing platform rules only keeps the picked templates (shown, not editable), so they run again when the choice changes back.
- Scan profiles have the same setting (default: both); a scan can override it.
- A task waiting for a sensor that supports rule sources now says so in the placement help, with the fix (upgrade the sensor).
