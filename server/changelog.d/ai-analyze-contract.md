### Added: the `openctem.analyze/v1` contract for AI executors

- The job an AI executor receives, the result it returns, the typed suggestions (verdict, severity, remediation steps, summary) and the output of each kind (`triage.v1`, `remediation.v1`, `summary.v1`) are published as versioned JSON Schemas in `api/pkg/sensorproto/analyze/schemas/`, with a validator. Outputs are closed (no field a model could use to state a direction, a state or a target), bounded, and cite evidence only as `bundle:<field>` or `tool:<n>`. RFC-131 describes the design. No migration, no operator action.
