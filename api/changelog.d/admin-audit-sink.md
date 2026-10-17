### Security: the platform administrators' audit log can be streamed off the box

- New `ADMIN_AUDIT_SINK`: every administrators' audit row is sent, as written, with its hash-chain position and hash (not the request body), and the chain head every `ADMIN_AUDIT_SINK_HEAD_INTERVAL` (default 15 minutes). Destinations: `https://…` (JSON per POST, signed with `ADMIN_AUDIT_SINK_SECRET`), `syslog+tls://` (RFC 5424, optional mutual TLS) or `file:///path` (JSON lines). Someone who controls the database can no longer re-sign the chain without the copy already sent disagreeing.
- Delivery never slows the console (queued, in order, retried; a full queue drops the newest event with an error line). A batch that does not continue the last delivered row is still sent, flagged with a `gap` field, counted and logged. A destination that cannot be used stops the API's start-up.
- **Upgrade note:** optional; nothing changes unless `ADMIN_AUDIT_SINK` is set. For a SaaS deployment, point it at the SIEM.
