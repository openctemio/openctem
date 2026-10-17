### Removed: plaintext audit sink destinations and the Bearer token

- `ADMIN_AUDIT_SINK_TOKEN` is replaced by `ADMIN_AUDIT_SINK_SECRET`: at least 32 bytes, required for an `https://` sink, and used as an HMAC-SHA256 key (the receiver verifies `X-OpenCTEM-Signature`); a Bearer header is no longer sent.
- `syslog+tcp://` and `syslog+udp://` are removed: the API refuses to start with them. Use `syslog+tls://`.
- **Upgrade note:** an API configured with `ADMIN_AUDIT_SINK_TOKEN`, `syslog+tcp://` or `syslog+udp://` must be reconfigured before upgrading.
