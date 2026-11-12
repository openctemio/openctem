### Added: a step run records what it ran with, and the run map shows it

- Each step run now stores the standard params its command carried (for example the nuclei severities and tags) with the layer that set each one (workflow step, depth overlay, scan override, fixed by the stage, platform port set), and what the sensor reported it ran with and ignored. The run map card and the step panel show "severity low..critical (depth default)", the tags, and the settings the sensor ignored, so a run with no findings is explainable.
- The workflow editor inspector shows the depth overlay values of a step (standard and deep) and lets the author edit them per depth; system templates stay read-only. Saving a workflow from the editor no longer drops the steps' depth overlays.
- Migration 20261104165321 adds two nullable columns to `scan_run_steps` (no rewrite).
