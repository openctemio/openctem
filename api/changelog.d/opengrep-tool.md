### Added: opengrep as a SAST tool

- `opengrep` is a known built-in tool. It has a platform tools row (migration `opengrep_tool`), it is an implementation of the `sast.code` stage next to semgrep (semgrep stays the default), it takes capability jobs, it counts as passive in scan intensity, and its findings are classified as SAST even when a report names no capability.
- Findings carry over from semgrep: a finding a semgrep run stored is the finding the first opengrep run of the same rules reports, with the same row and triage, re-keyed to the version-2 identity. Integration test `sast_engine_change_test.go`; this needs sensors and ci reporting with the ctis `opengrep` format.
- Scan profile tool choices list Opengrep. Their descriptions are translated (en, vi); the unused `TOOL_DESCRIPTIONS` export is removed.
