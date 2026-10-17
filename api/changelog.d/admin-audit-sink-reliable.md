### Changed: the off-box audit sink delivers at least once from a durable cursor

- `ADMIN_AUDIT_SINK`: the administrators' audit rows are sent in batches with their hash-chain position and hash (not the request body or user agent), plus the chain head and the chain verification state; when nothing is new the head is sent every `ADMIN_AUDIT_SINK_HEAD_INTERVAL` (default 15 minutes). Destinations: `https://…` (HMAC-signed POST), `syslog+tls://` (optionally mutual TLS) or `file:///path` (one JSON batch per line).
- Delivery is at least once from a durable cursor (migration `admin_audit_forward_cursor`) that moves only after the destination accepted the batch, with a batch id, exponential backoff and lag, failure and chain-break metrics and logs (`openctem_admin_audit_forward_*`, `openctem_admin_audit_chain_ok`). The cursor controller runs on one replica at a time. The earlier in-memory queue, which dropped events when full, is gone.
- The shipped columns are an explicit list; a test fails when `admin_audit_logs` gets a column that is neither shipped nor withheld.
- Webhook requests carry `X-OpenCTEM-Signature` (HMAC-SHA256 over timestamp and body), `X-OpenCTEM-Timestamp` and `X-OpenCTEM-Batch-Id`.
- Mutual TLS for syslog: `ADMIN_AUDIT_SINK_SYSLOG_CA_FILE`, `ADMIN_AUDIT_SINK_SYSLOG_CLIENT_CERT`, `ADMIN_AUDIT_SINK_SYSLOG_CLIENT_KEY`.
- **Upgrade note:** optional; nothing changes unless `ADMIN_AUDIT_SINK` is set.
