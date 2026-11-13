# The analyze contract (`openctem.analyze/v1`)

The job an AI executor receives and the result it returns, as versioned JSON
Schemas. The built-in executor (single model call in the API process) and AI
analyst workers speak the same contract, so every result goes through one
validation, provenance and governance path. Design: [RFC-131](../rfcs/RFC-131-ai-analysis.md).

Status: shipped (schemas and validator). Planned: the built-in executor writing
runs through it, the analyst worker.

## Schemas

In `server/pkg/sensorproto/analyze/schemas/`, embedded in the API and readable with
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

## The bundle in a job

The job's `bundle` describes the context the executor may read: its digest,
data class, the fields sent and the fields withheld, and whether it is
masked. A worker also needs the context itself, so a job for a worker may
carry it inline:

- `bundle.text` (optional, a string of at most 196608 characters) is the
  bundle as the executor reads it. When `bundle.masked` is true it is the
  masked bundle: sensitive values are placeholders such as `HOST_1` or
  `URL_3`.
- The placeholder mapping stays on the platform, which un-masks the result
  after it returns. A worker never receives a secret value or the mapping.
- The whole job document stays within `analyze.MaxDocumentBytes`
  (262144 bytes) once encoded, so the platform trims the text by its encoded
  size, not by its character count.
- The field is additive: the contract stays `openctem.analyze/v1`, and a job
  without it is still valid (the built-in executor reads the bundle in the
  platform).

## The job on the command queue

A job for an AI worker travels as an `analyze` command. Its payload is the
job as `analyze.MarshalJob` validated it (stored as JSON, so key order and spacing may change, never the content), next to the
platform's routing key:

```json
{"job": {"contract": "openctem.analyze/v1", "job_id": "<run id>", "...": "..."},
 "required_capabilities": ["analyze.triage.v1"]}
```

The job schema is closed, so nothing the platform routes on goes inside the
job. `job_id` is the run id; the platform reads it back from its own stored
payload, never from a worker's result. See
[ai-analysis.md](ai-analysis.md), "Runs on an AI worker".

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
refuse; `Bundle.Text` carries `bundle.text`), `analyze.Validate(schemaID, doc)`, `analyze.LookupKind(name)`.

## Key files

- `server/pkg/sensorproto/analyze/` (schemas, types, validator, test vectors;
  `testdata/job.text.valid.json` is a job with `bundle.text`)
