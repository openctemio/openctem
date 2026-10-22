### Fixed: a failed notification channel is retried even when another one got the event

- Every channel an event goes to now has its own delivery state, attempts and backoff (1 min, 5 min, 30 min, 2 h, 6 h, 12 h, 24 h; 8 attempts, then the channel is dead). Before, one channel's success marked the event done and the failed channels were never retried; a channel that got the event is never sent it again. Migration 003287 adds `notification_outbox.deliveries`.
- A refused delivery (a non-2xx answer or a transport error) is a failure and is retried. Before, the HTTP clients reported it in a way the outbox counted as a success.
- The delivery history (`GET /api/v1/integrations/{id}/notification-events`) lists each channel's attempts.

### Behaviour change: generic webhooks carry the real event type

- `event_type` in a generic webhook body is the event's catalogue type (`new_finding`, `sensor.offline`, ...) instead of always `notification`; a test delivery is `test`. New fields: `event_version` (payload version of the type, 1 today), `idempotency_key` (same value as the `Idempotency-Key` header, stable across retries) and `occurred_at`.
- The Splunk HEC event's `event_type` is the catalog type as well.
- **Upgrade note:** a receiver that matched `event_type == "notification"` must match the catalogue types instead.

### Security: notification channels never follow redirects

- Slack, Teams, Telegram, Splunk HEC and generic webhook deliveries refuse a redirect (a 3xx answer is a failed delivery) instead of following up to 10 hops, so the event body never reaches a host the channel was not configured with. The SSRF guard on every dial is unchanged.
