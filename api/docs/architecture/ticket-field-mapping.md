# Ticket field and status mapping

Design: [RFC-097](../rfcs/RFC-097-ticket-field-mapping.md). Related: [ticketing integration](ticketing-integration.md).

## Where things live

| Layer | Path | Role |
|---|---|---|
| Domain | `pkg/domain/ticketmap/` | spec, attribute catalog, template language, validation, drift, rendering, workflow paths, inbound intents and decisions, presets, import/export, diff |
| Application | `internal/app/ticketmap/` | profiles and versions, live metadata, preview, simulator, copy, suggest; object values (`values.go`) |
| Tracker | `internal/infra/jira/metadata.go`, `mapping_tracker.go` | create metadata, project statuses, resolutions, workflow transitions, issue snapshot; per-integration client |
| Storage | `internal/infra/postgres/ticket_mapping_repository.go` | `ticket_mapping_profiles`, `ticket_mapping_versions` |
| HTTP | `internal/infra/http/handler/ticket_mapping_handler.go`, routes in `routes/misc.go` | API under `/api/v1/integrations/ticket-mappings` |

## Flow

```
admin ── create profile (preset) ──► draft v1 ──► edit / import / copy ──► verify (live metadata)
                                                                   │
                                     publish (no errors, step-up) ◄┘──► published vN (snapshot kept)
                                                                         │
                     drift check: snapshot vs tracker now ──► drifted flag ┘
preview: object (in caller scope) ──► values ──► render (tier filter → template → redact → encode) ──► fields
simulate: state ──► BFS path + screen values      tracker status (+resolution) ──► intent ──► decision
```

## Invariants

- One profile per (tenant, integration, object kind, project, issue type); one open draft and one published
  version per profile (partial unique indexes).
- Inbound capability is a property of the attribute in code; the stored spec cannot widen it.
- Redaction and encoding run on every rendered value and cannot be disabled by a profile.
- An unreachable target status or a missing required transition value is an error, never a guessed status.
- A tracker never closes a finding: intents are claims and requests.
