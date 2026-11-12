# The analyze contract (`openctem.analyze/v1`)

The job an AI executor receives and the result it returns, as versioned JSON
Schemas. The built-in executor (single model call in the API process) and AI
analyst workers speak the same contract, so every result goes through one
validation, provenance and governance path. Design: [RFC-131](../rfcs/RFC-131-ai-analysis.md).

Status: shipped (schemas and validator). Planned: the built-in executor writing
runs through it, the analyst worker.

## Schemas

In `api/pkg/sensorproto/analyze/schemas/`, embedded in the API and readable with
`analyze.SchemaJSON(id)`:

| File | `$id` |
|---|---|
| `job.v1.schema.json` | `https://openctem.io/schemas/analyze/job/v1.json` |
| `result.v1.schema.json` | `https://openctem.io/schemas/analyze/result/v1.json` |
| `suggestion.v1.schema.json` | `https://openctem.io/schemas/analyze/suggestion/v1.json` |
| `output.triage.v1.schema.json` | `https://openctem.io/schemas/analyze/output/triage/v1.json` (`openctem.ai.triage/v1`) |
| `output.remediation.v1.schema.json` | `https://openctem.io/schemas/analyze/output/remediation/v1.json` (`openctem.ai.remediation/v1`) |
| `output.summary.v1.schema.json` | `https://openctem.io/schemas/analyze/output/summary/v1.json` (`openctem.ai.summary/v1`) |

## Kinds

| Kind | Use case | Output | Suggestion kinds | Runs on |
|---|---|---|---|---|
| `triage.v1` | triage | `openctem.ai.triage/v1` | verdict, severity, remediation steps, summary (one each) | built-in or worker |
| `remediation.v1` | remediation | `openctem.ai.remediation/v1` | remediation steps | built-in or worker |
| `summary.v1` | summary | `openctem.ai.summary/v1` | summary | built-in or worker |

## Rules every output meets

- closed objects: no field outside the schema, so a model cannot add a
  direction, a state, a target or a note;
- enums and bounds on every value (verdict, severity, effort, confidence 0..1,
  text lengths, at most 20 remediation steps, 16 evidence items);
- evidence references only as `bundle:<field>` or `tool:<n>`; the platform then
  checks each one exists in the run;
- at most one suggestion of each kind;
- the document is the JSON object alone (no prose around it);
- a refusal names the failing location and keyword, never the content.

## Go API

`analyze.ParseOutput(kind, raw)`, `analyze.ParseResult(raw)`,
`analyze.MarshalJob(job)` (refuses to emit a job a conforming executor would
refuse), `analyze.Validate(schemaID, doc)`, `analyze.LookupKind(name)`.

## Key files

- `api/pkg/sensorproto/analyze/` (schemas, types, validator, test vectors)
