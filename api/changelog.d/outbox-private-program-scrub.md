### Security: private program names scrubbed in the notification outbox view

- `GET /notification-outbox` and `GET /notification-outbox/{id}` (and the retry response) now scrub the name, handle and tag of a private program from an entry's title, body, last error and metadata for an integration admin who is neither a tenant owner nor a member of that program. Owners and members read entries unchanged; the stored entry is never modified.
- The decision uses the same resolver as outbound delivery (RFC-065 §15.4). If it cannot be made the request fails (500) instead of showing the entry.
