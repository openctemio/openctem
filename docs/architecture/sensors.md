# Sensors: vocabulary, code layout and protocol v1

> RFC: [RFC-023](../rfcs/RFC-023-scan-zones-and-scanners.md) §4 (D18) and §9.5.
> Contract of the rename: [RFC-023-sensor-rename-contract.md](../rfcs/RFC-023-sensor-rename-contract.md).

## Glossary

| Term | Meaning |
|---|---|
| **Sensor** | Software on the customer side that authenticates *to* the platform with its own key and heartbeat. The umbrella term; every row of the `sensors` table. |
| **Scanner** (role) | A sensor that assesses other hosts; routed by scan zone. What every existing sensor is today. |
| **Agent** (role) | A sensor installed on an endpoint that reports only about its own host. Since RFC-023 the word *agent* means this role only. |
| **Collector** (role) | A sensor that pushes data from systems inside the customer network. |
| **Integration** | An external system the *platform* calls (Jira, Slack, Splunk out, …); no software of ours runs for it. |
| `type` | The legacy v1 classification (`worker`, `scanner`, `sensor`, `collector`, `runner`). Kept as input and storage until role + deployment replace it (RFC-023 §9.1). |
| AI agent | The AI-triage "agent" mode (`AIModeAgent`, module `ai_triage.agent`): an LLM agent, unrelated to sensors. |

Until 2026-10 the code, database and API called sensors "agents". The rename
is complete in the API: packages, types, tables, columns, permissions
(`sensors:*`), management routes (`/api/v1/sensors`), audit ids (`sensor.*`),
log fields (`sensor_id`), metrics and API environment variables (`SENSOR_*`).

## Code layout

| Layer | Package |
|---|---|
| Domain | `pkg/domain/sensor` (entity, API keys, errors, repository interfaces) |
| Application | `internal/app/sensor` (service, selector, config templates); compat shim `internal/app/sensor_service.go` |
| Persistence | `internal/infra/postgres/sensor_repository.go`, `sensor_apikey_repository.go` |
| HTTP | `internal/infra/http/handler/sensor_handler.go` (management), `ingest_handler.go` / `command_handler.go` / `scansession_handler.go` (protocol v1) |
| Health | `internal/infra/controller/sensor_health.go`, `internal/infra/jobs/sensor_health_checker.go`, `internal/infra/redis/sensor_state.go` |
| Legacy vocabulary | `pkg/sensorproto/legacyv1` |

## Protocol v1 and the legacy package

Sensors and SDKs already deployed speak protocol v1: `/api/v1/agent/*`,
`agent_id` in responses, `agent_preference` in job payloads. That vocabulary
is frozen (RFC-023 §9.2 C1) and lives in exactly one package,
`pkg/sensorproto/legacyv1`, which also owns the deprecated management path
(`/api/v1/agents` → 308 to `/api/v1/sensors` until 2027-04-01) and the table
of renamed API environment variables. Handlers build v1 responses with its
types (`legacyv1.Command`, `legacyv1.ScanSession`, `legacyv1.Heartbeat`);
route registration and the route tooling resolve its path constants.

Two tests hold the line:

- `internal/infra/http/handler/protocol_v1_golden_db_test.go` replays the v1
  flow (heartbeat, poll, acknowledge, start, complete, fail, scan session,
  ingest, renew) against real repositories and compares the responses and the
  v1 route table with golden files recorded before the rename.
- `tools/lint/sensorvocab` fails on any Go identifier, import path or file
  path that says *agent* outside `legacyv1`, the rename tooling and the
  AI-agent identifiers.

## History written in the old vocabulary

Hash-chained audit rows (`agent.*`, resource type `agent`) and append-only
asset state history (`source = 'agent'`) are never rewritten. Reads treat
both spellings as one family: `audit.Action.Canonical`,
`audit.WithHistoricalActions`, `asset.ChangeSource.Canonical`,
`asset.WithHistoricalSources`.

## Upgrading an installation

Migration 000229 converts the schema and every stored value (see the contract,
§8). `server -sensor-upgrade-check` confirms nothing is left; the API also
logs a warning at startup when it finds leftovers. Branches written before
the rename catch up with `scripts/rename/sensor-rename.sh` (type-aware rename
of identifiers, packages, comments and files).
