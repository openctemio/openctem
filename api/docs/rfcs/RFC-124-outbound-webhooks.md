# RFC-124: Outbound webhooks: delivery per channel, typed events, signing and redelivery

| | |
|---|---|
| Status | Accepted (2026-10-22). Delivery per channel, the typed payload and refused redirects are implemented; signing and redelivery are in progress |
| Scope | api (`pkg/domain/outbox`, `internal/app/outbox`, `internal/infra/notifier`, `internal/infra/postgres/outbox_repository.go`, one migration) |
| Architecture | [notification-system.md](../architecture/notification-system.md) |
| Related | RFC-041 (API path design and conventions), RFC-065 (private-program routing of events) |

## 1. Summary

An organization connects notification channels (Slack, Teams, Telegram,
e-mail, Splunk HEC and a generic JSON webhook). The generic webhook is how
an organization's own automation consumes OpenCTEM events, so it must behave
like an integration contract, not like a chat message:

1. a failed channel is retried on its own, whatever the other channels did;
2. the payload names the event's type and the version of its payload;
3. a delivery cannot be bounced to another host by a redirect;
4. the receiver can prove that a delivery came from this instance and was
   not replayed (signing, section 5);
5. a delivery can be sent again on request (redelivery, section 6).

## 2. Decisions

| # | Decision | Reason |
|---|---|---|
| D1 | One delivery state per (event, channel) with its own attempts and backoff: 1 min, 5 min, 30 min, 2 h, 6 h, 12 h, 24 h, then dead (8 attempts, about 45 h). Kept as a JSONB array on the outbox entry (`notification_outbox.deliveries`), archived as one send result per channel | Partial failures are normal (one endpoint down). A JSON column keeps the entry the unit of locking (`FOR UPDATE SKIP LOCKED`) and needs no join; the archive already holds per-channel results, which the delivery history reads |
| D2 | The channel set is fixed at the first pass | An integration created later must not receive old events; a retry must not widen the audience |
| D3 | Private-program routing is checked on every pass; a channel it no longer allows is abandoned | An asset that moved into a private program must not leak through a retry |
| D4 | `event_type` is the catalogue type (`AllEventTypes`); `event_version` per type, 1 today, bumped on an incompatible change | A receiver routes on type; a version lets a type evolve without breaking receivers |
| D5 | Redirects are refused by every notifier client; the SSRF guard on each dial stays | A redirect hands the body and headers to a host the channel was not configured with |
| D6 | A refused delivery (non-2xx, transport error) is a failure | The HTTP clients reported it as a result, which the outbox counted as success |

## 3. Delivery per channel

See `docs/architecture/notification-system.md`, "Delivery per channel", for
the state machine. In short: the first pass resolves the channels; each pass
attempts only due channels; a delivered channel is never sent the event
again; the entry is rescheduled at the earliest channel retry and archived
when every channel is delivered or dead. A deleted or disconnected
integration counts failed attempts (it may come back within the window).

## 4. Payload

The generic webhook body keeps its fields and adds `event_version`,
`idempotency_key` and `occurred_at`; `event_type` changes from the constant
`notification` to the catalogue type. The idempotency key (also the
`Idempotency-Key` header) is `outbox-<event id>` and is stable across retries.

## 5. Signing

In progress. Every generic webhook delivery is signed with HMAC-SHA256 over
`<id>.<timestamp>.<body>` in the headers `webhook-id`, `webhook-timestamp`
and `webhook-signature: v1,<base64>`, with a per-integration secret that is
write-only, encrypted at rest and rotatable with an overlap window.

## 6. Redelivery

In progress. `POST /api/v1/integrations/{id}/deliveries/{delivery_id}/redeliver`
sends an archived event to one channel again, with permission and audit.

## 7. Threat model

| Threat | Control |
|---|---|
| A channel endpoint redirects deliveries to a host of its choosing | Redirects refused (D5) |
| An endpoint resolves to an internal address (SSRF, DNS rebinding) | `httpsec.SafeHTTPClient`: validated URL, resolve once per dial, blocked ranges refused |
| A retry delivers a private-program event to an org-wide channel | Routing re-checked on every pass, abandoned when not allowed (D3) |
| A new integration receives old events | Channel set fixed at the first pass (D2) |
| Duplicate delivery after a worker crash | Stable idempotency key in header and body |
| Cross-tenant delivery | Channels are the event's tenant's integrations only (`ListIntegrationsWithNotification` by the entry's tenant) |

## 8. Tests

- `pkg/domain/outbox/delivery_test.go`: backoff schedule, dead after 8 attempts, settle and archive results, manual retry revives only dead channels.
- `internal/app/outbox/channel_delivery_test.go`: a failed channel is retried after another succeeded and the delivered one is not sent again; dead after max attempts; message carries type, version and a stable key; channel set fixed at the first pass.
- `internal/infra/notifier/webhook_delivery_test.go`: redirect refused (the other host gets nothing), every client refuses redirects, payload type and version.
- `internal/infra/postgres/outbox_deliveries_db_test.go`: the delivery state survives a write and every read path.
