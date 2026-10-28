### Added: AI analysis of a finding through the analyze contract

- `POST /api/v1/findings/{id}/ai/analyze` runs `triage.v1`, `remediation.v1` or `summary.v1` on the built-in executor: the bundle holds only the fields the use case's data class ceiling allows, sensitive values are masked with a per-run key and the mapping stays on the platform, the prompt template id and digest are recorded, the output must satisfy the kind's JSON Schema, placeholders are mapped back by the platform (unknown ones force review, secrets never), and the results are stored as AI suggestions under the organization's mode. Refused while the use case is off; pentest findings above the AI TLP limit are refused before anything is sent.
- Completed legacy AI triage results are also recorded as runs of kind `triage.legacy` with suggestions that wait for a person.
- No migration, no operator action.
